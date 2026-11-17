package com.cmcc.cfscanner

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var baselineText: TextView
    private lateinit var statusText: TextView
    private lateinit var countInput: EditText
    private lateinit var speedSwitch: SwitchCompat
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
    private lateinit var copyAllButton: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var resultsList: RecyclerView

    private val adapter = ResultAdapter { result -> copyIp(result.ip) }
    private var scanJob: Job? = null
    private val results = mutableListOf<ScanResult>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        baselineText = findViewById(R.id.baselineText)
        statusText = findViewById(R.id.statusText)
        countInput = findViewById(R.id.countInput)
        speedSwitch = findViewById(R.id.speedSwitch)
        startButton = findViewById(R.id.startButton)
        stopButton = findViewById(R.id.stopButton)
        copyAllButton = findViewById(R.id.copyAllButton)
        progressBar = findViewById(R.id.progressBar)
        resultsList = findViewById(R.id.resultsList)

        resultsList.layoutManager = LinearLayoutManager(this)
        resultsList.adapter = adapter

        startButton.setOnClickListener { startScan() }
        stopButton.setOnClickListener { stopScan() }
        copyAllButton.setOnClickListener { copyAll() }
    }

    private fun startScan() {
        val count = countInput.text.toString().toIntOrNull()?.coerceIn(100, 20000) ?: 2000
        val doSpeedTest = speedSwitch.isChecked
        results.clear()
        adapter.submitList(emptyList())
        copyAllButton.visibility = View.GONE
        startButton.isEnabled = false
        stopButton.visibility = View.VISIBLE
        progressBar.visibility = View.VISIBLE
        progressBar.isIndeterminate = true
        progressBar.progress = 0
        statusText.text = "正在确认出口 IP…"

        scanJob = lifecycleScope.launch {
            try {
                val baseline = withContext(Dispatchers.IO) { Scanner.fetchBaseline() }
                baselineText.text = "基准出口 IP：$baseline"
                statusText.text = "正在获取 Cloudflare 网段…"
                val ranges = withContext(Dispatchers.IO) { Scanner.fetchRanges() }
                val ips = Scanner.sampleIps(ranges, count)
                val found = mutableListOf<ScanResult>()
                var probedOk = 0
                var probedFailed = 0
                val failureReasons = mutableMapOf<String, Int>()
                val egressSeen = LinkedHashSet<String>()
                var done = 0
                progressBar.isIndeterminate = false
                progressBar.max = ips.size
                for (chunk in ips.chunked(100)) {
                    val probed = chunk.map { ip ->
                        async(Dispatchers.IO) { Scanner.probe(ip, baseline) }
                    }.awaitAll()
                    for (outcome in probed) {
                        when (outcome) {
                            is ProbeOutcome.Success -> {
                                probedOk++
                                if (egressSeen.size < 5) egressSeen.add(outcome.result.egressIp)
                                if (outcome.result.isSpecial) found.add(outcome.result)
                            }
                            is ProbeOutcome.Failure -> {
                                probedFailed++
                                failureReasons[outcome.reason] =
                                    (failureReasons[outcome.reason] ?: 0) + 1
                            }
                        }
                    }
                    done += chunk.size
                    progressBar.progress = done
                    statusText.text = "已扫描 $done/${ips.size}，发现 ${found.size} 个特殊线路"
                    if (!isActive) return@launch
                }
                if (doSpeedTest && found.isNotEmpty()) {
                    statusText.text = "正在给 ${found.size} 个候选测速…"
                    progressBar.isIndeterminate = true
                    for (chunk in found.chunked(2)) {
                        val speeds = chunk.map { r ->
                            async(Dispatchers.IO) { r.ip to Scanner.speedTest(r.ip) }
                        }.awaitAll()
                        for ((ip, speed) in speeds) {
                            found.firstOrNull { it.ip == ip }?.speedMbps = speed
                        }
                        if (!isActive) return@launch
                    }
                }
                // 扫描结束再确认一次基准出口（Python 脚本 BaselineGuard 的轻量版）：
                // 如果扫描期间出口 IP 变了，本次结果不可信。
                var baselineChanged = false
                try {
                    val baselineAfter = withContext(Dispatchers.IO) { Scanner.fetchBaseline() }
                    baselineChanged = baselineAfter != baseline
                } catch (e: Exception) {
                    // 复查失败不影响已出结果
                }
                found.sortWith(
                    compareByDescending<ScanResult> { it.speedMbps ?: -1.0 }
                        .thenBy { it.latencyMs }
                )
                results.clear()
                results.addAll(found)
                adapter.submitList(results.toList())
                // 诊断信息：分清“这批里确实没有特殊线路”和“探测本身失败了”。
                // 成功数接近扫描数、且出口 IP 只有一个，说明是真没有；
                // 失败数很大，说明探测没跑通，要先修网络/探测问题。
                val diag = buildString {
                    append("探测成功 $probedOk 个，失败 $probedFailed 个")
                    if (egressSeen.isNotEmpty()) {
                        append("\n见过的出口 IP：")
                        append(egressSeen.joinToString("、"))
                    }
                    val topReason = failureReasons.maxByOrNull { it.value }?.key
                    if (topReason != null) append("\n失败原因多为：$topReason")
                    if (baselineChanged) append("\n注意：扫描期间基准出口 IP 变了，本次结果可能不准")
                }
                statusText.text = if (found.isEmpty()) {
                    "没有发现特殊线路 IP，换个时间再试一次\n$diag"
                } else {
                    "完成：发现 ${found.size} 个特殊线路 IP，按下载速度排序\n$diag"
                }
                if (found.isNotEmpty()) copyAllButton.visibility = View.VISIBLE
            } catch (e: CancellationException) {
                statusText.text = "已停止"
            } catch (e: Exception) {
                statusText.text = "出错了：${e.message ?: "网络异常"}，请检查网络后重试"
            } finally {
                progressBar.visibility = View.GONE
                stopButton.visibility = View.GONE
                startButton.isEnabled = true
            }
        }
    }

    private fun stopScan() {
        scanJob?.cancel()
        statusText.text = "已停止"
        progressBar.visibility = View.GONE
        stopButton.visibility = View.GONE
        startButton.isEnabled = true
    }

    private fun copyIp(ip: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("IP", ip))
        Toast.makeText(this, "已复制 $ip", Toast.LENGTH_SHORT).show()
    }

    private fun copyAll() {
        if (results.isEmpty()) return
        val text = results.joinToString("\n") { it.ip }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("IP 列表", text))
        Toast.makeText(this, "已复制 ${results.size} 个 IP", Toast.LENGTH_SHORT).show()
    }
}
