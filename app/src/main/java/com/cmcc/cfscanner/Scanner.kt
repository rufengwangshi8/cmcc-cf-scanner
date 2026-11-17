package com.cmcc.cfscanner

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.URL
import java.util.zip.GZIPInputStream
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

/** 单次探测的完整结果：成功带 trace 出口 IP，失败带简短原因。 */
sealed class ProbeOutcome {
    data class Success(val result: ScanResult) : ProbeOutcome()
    data class Failure(val reason: String) : ProbeOutcome()
}

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
    private const val TOTAL_TIMEOUT_MS = 3000
    private const val MAX_BODY_BYTES = 64 * 1024

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

    /**
     * 在全部网段里全局均匀随机抽取 count 个不重复的 IP。
     * 和 Python 脚本的 SystemRandom().sample(range(total), n) 同一个做法：
     * 先在“所有地址拼起来的总空间”里抽下标，再映射回 IP。
     * 注意不能“先随机挑一个网段、再在段内挑 IP”，那样小网段会被严重高估
     * （比如一个 /22 只有 1024 个地址，却和 52 万地址的 /13 抽到同样多的次数）。
     */
    fun sampleIps(ranges: List<Pair<Long, Long>>, count: Int): List<String> {
        val total = ranges.sumOf { it.second - it.first + 1 }
        val want = minOf(count.toLong(), total).toInt()
        val picked = LinkedHashSet<Long>()
        var guard = 0
        while (picked.size < want && guard < want * 20) {
            guard++
            picked.add(Random.nextLong(total))
        }
        // 把全局下标按网段边界映射回 IP
        val sorted = picked.sorted()
        val out = ArrayList<String>(sorted.size)
        var rangeIdx = 0
        var offset = 0L
        for (idx in sorted) {
            while (rangeIdx < ranges.size - 1) {
                val size = ranges[rangeIdx].second - ranges[rangeIdx].first + 1
                if (idx < offset + size) break
                offset += size
                rangeIdx++
            }
            out.add(longToIp(ranges[rangeIdx].first + (idx - offset)))
        }
        return out
    }

    /**
     * 直连候选 IP 的 443 端口（SNI 为 speed.cloudflare.com），取 /cdn-cgi/trace。
     * 如果 Cloudflare 看到的出口 IP 和基准不同，就是特殊线路候选。
     *
     * 请求头和响应解析和 Python 脚本（cmcc_cf_special_route_scan.py）完全一致：
     * 显式发 Accept: text/plain 和 Accept-Encoding: identity，避免服务端返回
     * gzip 压缩的正文；按 HTTP 语义解析响应头、处理 chunked 分块和 gzip 解压，
     * 再从正文里取 ip= 字段。任何一步失败都返回 Failure（带原因），不再静默丢弃，
     * 这样界面能分清“没有特殊线路”和“探测本身失败了”。
     * 单次探测总超时 3 秒，和脚本的 timeout=3.0 一致；TCP 连接超时 1.2 秒，
     * 和脚本的 connect_timeout=1.2 一致。
     */
    fun probe(ip: String, baseline: String): ProbeOutcome {
        val start = System.currentTimeMillis()
        val deadline = start + TOTAL_TIMEOUT_MS
        var socket: SSLSocket? = null
        try {
            socket = openTls(ip, TRACE_HOST, CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS)
            val out = socket.outputStream
            val req = "GET $TRACE_PATH HTTP/1.1\r\n" +
                "Host: $TRACE_HOST\r\n" +
                "User-Agent: $USER_AGENT\r\n" +
                "Accept: text/plain\r\n" +
                "Accept-Encoding: identity\r\n" +
                "Connection: close\r\n\r\n"
            out.write(req.toByteArray(Charsets.UTF_8))
            out.flush()
            val (status, _, body) = readHttpResponse(BufferedInputStream(socket.inputStream), deadline)
            if (status != 200) return ProbeOutcome.Failure("HTTP $status")
            val egress = parseTraceIp(body)
                ?: return ProbeOutcome.Failure("trace 里没有 ip")
            val latency = System.currentTimeMillis() - start
            return ProbeOutcome.Success(ScanResult(ip, latency, egress, egress != baseline))
        } catch (e: Exception) {
            return ProbeOutcome.Failure(shortReason(e))
        } finally {
            try { socket?.close() } catch (e: Exception) { /* ignore */ }
        }
    }

    /** 从 trace 正文里取 ip= 字段。 */
    private fun parseTraceIp(body: ByteArray): String? {
        for (line in body.toString(Charsets.UTF_8).lines()) {
            if (line.startsWith("ip=")) {
                val value = line.substring(3).trim()
                if (value.isNotEmpty()) return value
            }
        }
        return null
    }

    /** 失败原因缩短到一行，方便界面汇总。 */
    private fun shortReason(e: Exception): String {
        val msg = e.message?.replace('\n', ' ')?.replace('\r', ' ')?.trim()?.take(60)
        return if (msg.isNullOrEmpty()) e.javaClass.simpleName else "${e.javaClass.simpleName}: $msg"
    }

    /** 读完一个完整的 HTTP 响应：返回 (状态码, 响应头, 解码后的正文)。 */
    private fun readHttpResponse(input: BufferedInputStream, deadline: Long): Triple<Int, Map<String, String>, ByteArray> {
        val statusLine = readLineBytes(input)?.toString(Charsets.ISO_8859_1)
            ?: throw IllegalStateException("响应为空")
        val status = statusLine.split(" ").getOrNull(1)?.toIntOrNull()
            ?: throw IllegalStateException("无效状态行")
        val headers = mutableMapOf<String, String>()
        while (true) {
            val line = readLineBytes(input)?.toString(Charsets.ISO_8859_1)
                ?: throw IllegalStateException("响应头不完整")
            if (line.isEmpty()) break
            val colon = line.indexOf(':')
            if (colon > 0) {
                headers[line.substring(0, colon).trim().lowercase()] = line.substring(colon + 1).trim()
            }
        }
        val rawBody: ByteArray = when {
            headers["transfer-encoding"]?.lowercase()?.contains("chunked") == true ->
                readChunkedBody(input, deadline)
            headers["content-length"] != null -> {
                val length = headers["content-length"]!!.toIntOrNull()
                    ?: throw IllegalStateException("Content-Length 无效")
                if (length < 0 || length > MAX_BODY_BYTES) throw IllegalStateException("响应正文超限")
                readExact(input, length, deadline)
            }
            else -> readUntilClose(input, deadline)
        }
        val body = if (headers["content-encoding"]?.lowercase()?.contains("gzip") == true) {
            GZIPInputStream(rawBody.inputStream()).readBytes()
        } else {
            rawBody
        }
        return Triple(status, headers, body)
    }

    /** 从流里读一行（以 \n 结尾，去掉结尾的 \r\n）；EOF 返回 null。 */
    private fun readLineBytes(input: BufferedInputStream): ByteArray? {
        val buf = ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b < 0) return if (buf.size() == 0) null else buf.toByteArray()
            if (b == '\n'.code) break
            buf.write(b)
        }
        val bytes = buf.toByteArray()
        val len = bytes.size
        return if (len > 0 && bytes[len - 1] == '\r'.code.toByte()) bytes.copyOf(len - 1) else bytes
    }

    /** 按 chunked 分块编码读正文。 */
    private fun readChunkedBody(input: BufferedInputStream, deadline: Long): ByteArray {
        val out = ByteArrayOutputStream()
        while (true) {
            if (System.currentTimeMillis() > deadline) throw IllegalStateException("读响应超时")
            val sizeLine = readLineBytes(input)?.toString(Charsets.ISO_8859_1)
                ?: throw IllegalStateException("chunked 响应提前结束")
            val size = sizeLine.trim().split(";", limit = 2)[0].toIntOrNull(16)
                ?: throw IllegalStateException("chunk 长度无效")
            if (size == 0) {
                while (true) {
                    val trailer = readLineBytes(input) ?: break
                    if (trailer.isEmpty()) break
                }
                return out.toByteArray()
            }
            if (out.size() + size > MAX_BODY_BYTES) throw IllegalStateException("响应正文超限")
            out.write(readExact(input, size, deadline))
            val crlf = readExact(input, 2, deadline)
            if (crlf[0] != '\r'.code.toByte() || crlf[1] != '\n'.code.toByte()) {
                throw IllegalStateException("chunk 格式错误")
            }
        }
    }

    /** 精确读 length 个字节，不够就抛错。 */
    private fun readExact(input: BufferedInputStream, length: Int, deadline: Long): ByteArray {
        val buf = ByteArray(length)
        var off = 0
        while (off < length) {
            if (System.currentTimeMillis() > deadline) throw IllegalStateException("读响应超时")
            val n = input.read(buf, off, length - off)
            if (n < 0) throw IllegalStateException("响应提前结束")
            off += n
        }
        return buf
    }

    /** 没有长度信息时读到连接关闭或超时为止。 */
    private fun readUntilClose(input: BufferedInputStream, deadline: Long): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (System.currentTimeMillis() < deadline) {
            val n = try {
                input.read(buf)
            } catch (e: java.net.SocketTimeoutException) {
                break
            }
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > MAX_BODY_BYTES) throw IllegalStateException("响应正文超限")
        }
        return out.toByteArray()
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
