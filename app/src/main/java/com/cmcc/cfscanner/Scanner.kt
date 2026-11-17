package com.cmcc.cfscanner

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.random.Random

/** 一个候选 IP 的扫描结果。speedMbps 为空表示没有测速。 */
data class ScanResult(
    val ip: String,
    val latencyMs: Long,
    val egressIp: String,
    val isSpecial: Boolean,
    var speedMbps: Double? = null
)

/**
 * 移动特殊线路扫描器。
 *
 * 原理：先确认当前网络的基准出口 IP，再直连每个候选 Cloudflare IP
 * 取 trace；如果 Cloudflare 看到的出口 IP 和基准不同，说明这个 IP
 * 走了特殊线路（移动 CMIN2 精品网候选）。
 */
object Scanner {

    private const val TRACE_HOST = "speed.cloudflare.com"
    private const val TRACE_PATH = "/cdn-cgi/trace"
    private const val RANGES_URL = "https://www.cloudflare.com/ips-v4"
    private const val SPEED_PATH = "/__down?bytes=200000000"
    private const val USER_AGENT = "cmcc-cf-scanner/1.0"

    private const val CONNECT_TIMEOUT_MS = 1200
    private const val READ_TIMEOUT_MS = 3000

    /** 当前网络的出口 IP：通过 Cloudflare trace 正常解析得到。 */
    fun fetchBaseline(): String {
        val body = httpGetText("https://$TRACE_HOST$TRACE_PATH", 5000)
        for (line in body.lines()) {
            if (line.startsWith("ip=")) return line.substring(3).trim()
        }
        throw IllegalStateException("trace 里没有 ip")
    }

    /** 从 Cloudflare 官方页面拉取 IPv4 网段，返回 (起始, 结束) 区间。 */
    fun fetchRanges(): List<Pair<Long, Long>> {
        val body = httpGetText(RANGES_URL, 10000)
        val out = mutableListOf<Pair<Long, Long>>()
        for (raw in body.lines()) {
            parseCidr(raw.trim())?.let { out.add(it) }
        }
        if (out.isEmpty()) throw IllegalStateException("没有拿到 Cloudflare 网段")
        return out
    }

    /** 在网段内随机抽取 count 个不重复的 IP。 */
    fun sampleIps(ranges: List<Pair<Long, Long>>, count: Int): List<String> {
        val total = ranges.sumOf { it.second - it.first + 1 }
        val want = minOf(count.toLong(), total).toInt()
        val picked = LinkedHashSet<Long>()
        var guard = 0
        while (picked.size < want && guard < want * 20) {
            guard++
            val range = ranges[Random.nextInt(ranges.size)]
            val size = range.second - range.first + 1
            picked.add(range.first + Random.nextLong(size))
        }
        return picked.map { longToIp(it) }
    }

    /**
     * 直连候选 IP 的 443 端口（SNI 为 speed.cloudflare.com），取 /cdn-cgi/trace。
     * 如果 Cloudflare 看到的出口 IP 和基准不同，就是特殊线路候选。
     * 失败返回 null（这个 IP 直接跳过，不会让 App 崩溃）。
     */
    fun probe(ip: String, baseline: String): ScanResult? {
        val start = System.currentTimeMillis()
        var socket: SSLSocket? = null
        try {
            socket = openTls(ip, TRACE_HOST, CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS)
            val out = socket.outputStream
            val req = "GET $TRACE_PATH HTTP/1.1\r\n" +
                "Host: $TRACE_HOST\r\n" +
                "User-Agent: $USER_AGENT\r\n" +
                "Connection: close\r\n\r\n"
            out.write(req.toByteArray(Charsets.UTF_8))
            out.flush()
            val reader = BufferedReader(InputStreamReader(socket.inputStream, Charsets.UTF_8))
            var egress: String? = null
            val deadline = System.currentTimeMillis() + READ_TIMEOUT_MS
            while (System.currentTimeMillis() < deadline) {
                val line = try { reader.readLine() } catch (e: Exception) { break } ?: break
                if (line.startsWith("ip=")) {
                    egress = line.substring(3).trim()
                    break
                }
            }
            val latency = System.currentTimeMillis() - start
            if (egress.isNullOrEmpty()) return null
            return ScanResult(ip, latency, egress, egress != baseline)
        } catch (e: Exception) {
            return null
        } finally {
            try { socket?.close() } catch (e: Exception) { /* ignore */ }
        }
    }

    /** 通过候选 IP 下载测速（默认 10 秒），返回 MB/s；失败返回 null。 */
    fun speedTest(ip: String, durationSec: Int = 10): Double? {
        var socket: SSLSocket? = null
        try {
            socket = openTls(ip, TRACE_HOST, CONNECT_TIMEOUT_MS, 15000)
            val out = socket.outputStream
            val req = "GET $SPEED_PATH HTTP/1.0\r\n" +
                "Host: $TRACE_HOST\r\n" +
                "User-Agent: $USER_AGENT\r\n" +
                "Connection: close\r\n\r\n"
            out.write(req.toByteArray(Charsets.UTF_8))
            out.flush()
            val input = socket.inputStream
            val buf = ByteArray(64 * 1024)
            var total = 0L
            val startNanos = System.nanoTime()
            val endNanos = startNanos + durationSec * 1_000_000_000L
            while (System.nanoTime() < endNanos) {
                val n = try { input.read(buf) } catch (e: Exception) { -1 }
                if (n <= 0) break
                total += n
            }
            val elapsedSec = (System.nanoTime() - startNanos) / 1_000_000_000.0
            if (total <= 0 || elapsedSec <= 0) return null
            return total / 1024.0 / 1024.0 / elapsedSec
        } catch (e: Exception) {
            return null
        } finally {
            try { socket?.close() } catch (e: Exception) { /* ignore */ }
        }
    }

    /** 直连 IP:443 建 TLS 连接，SNI 指向 sniHost，连接超时受 connectTimeout 控制。 */
    private fun openTls(ip: String, sniHost: String, connectTimeout: Int, readTimeout: Int): SSLSocket {
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val socket = factory.createSocket() as SSLSocket
        socket.soTimeout = readTimeout
        socket.connect(InetSocketAddress(ip, 443), connectTimeout)
        val params: SSLParameters = socket.sslParameters
        params.serverNames = listOf(SNIHostName(sniHost))
        socket.sslParameters = params
        socket.startHandshake()
        return socket
    }

    private fun httpGetText(url: String, timeoutMs: Int): String {
        val conn = URL(url).openConnection() as HttpsURLConnection
        conn.connectTimeout = timeoutMs
        conn.readTimeout = timeoutMs
        conn.setRequestProperty("User-Agent", USER_AGENT)
        conn.inputStream.bufferedReader(Charsets.UTF_8).use { return it.readText() }
    }

    private fun ipToLong(ip: String): Long? {
        val parts = ip.split(".")
        if (parts.size != 4) return null
        var value = 0L
        for (p in parts) {
            val n = p.toIntOrNull() ?: return null
            if (n < 0 || n > 255) return null
            value = (value shl 8) or n.toLong()
        }
        return value
    }

    private fun longToIp(value: Long): String {
        return "${(value shr 24) and 0xFF}.${(value shr 16) and 0xFF}.${(value shr 8) and 0xFF}.${value and 0xFF}"
    }

    private fun parseCidr(cidr: String): Pair<Long, Long>? {
        val parts = cidr.split("/")
        if (parts.size != 2) return null
        val base = ipToLong(parts[0]) ?: return null
        val prefix = parts[1].toIntOrNull() ?: return null
        if (prefix < 0 || prefix > 32) return null
        val hostBits = 32 - prefix
        val mask = if (hostBits == 32) 0L else (-1L shl hostBits) and 0xFFFFFFFFL
        val start = base and mask
        val end = start or (mask.inv() and 0xFFFFFFFFL)
        return start to end
    }
}
