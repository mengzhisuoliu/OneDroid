package tech.qingge.onedroid.ui.activity

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.widget.doOnTextChanged
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.topjohnwu.superuser.Shell
import tech.qingge.onedroid.R
import tech.qingge.onedroid.base.BaseActivity
import tech.qingge.onedroid.databinding.ActivityLogcatBinding
import tech.qingge.onedroid.util.LogUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class LogcatActivity : BaseActivity<ActivityLogcatBinding>() {

    companion object {
        private const val MAX_LINES = 8000
        private const val RENDER_INTERVAL = 250L

        /** 与 spinner 的 6 个选项一一对应：logcat 级别过滤参数 */
        private val LEVEL_ARGS =
            listOf("*:V", "*:V", "*:D", "*:I", "*:W", "*:E")
    }

    private var logcatProcess: Process? = null
    private var readJob: Job? = null
    private var isReading = false
    private var dirty = false
    private var lastCmd = ""

    private val lines = ArrayDeque<String>()
    private var totalAdded = 0L
    private var renderedIndex = 0L

    private val logAdapter = LogAdapter()
    private val defaultLogColor by lazy { TextView(this).textColors.defaultColor }

    private val mainHandler = Handler(Looper.getMainLooper())

    private val renderRunnable = object : Runnable {
        override fun run() {
            if (dirty) {
                render()
                dirty = false
            }
            mainHandler.postDelayed(this, RENDER_INTERVAL)
        }
    }

    private val saveFileLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
            uri ?: return@registerForActivityResult
            CoroutineScope(Dispatchers.IO).launch {
                runCatching {
                    contentResolver.openOutputStream(uri)?.use { out ->
                        synchronized(lines) {
                            lines.forEach { out.write((it + "\n").toByteArray()) }
                        }
                    }
                }.onSuccess {
                    launch(Dispatchers.Main) {
                        Toast.makeText(
                            this@LogcatActivity, R.string.save_success, Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        initToolbar()
        initLevelSpinner()
        initKeyword()
        initLogList()

        startLogcat()

        mainHandler.post(renderRunnable)
    }

    private fun initToolbar() {
        binding.toolbar.apply {
            setNavigationOnClickListener { finish() }
            setOnMenuItemClickListener { menuItem ->
                when (menuItem.itemId) {
                    R.id.start_stop -> {
                        if (isReading) {
                            stopLogcat()
                        } else {
                            startLogcat()
                        }
                    }

                    R.id.clear -> {
                        synchronized(lines) {
                            lines.clear()
                        }
                        renderedIndex = 0
                        logAdapter.replaceAll(emptyList())
                    }

                    R.id.save -> {
                        val time = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
                            .format(Date())
                        saveFileLauncher.launch("logcat_$time.txt")
                    }
                }
                true
            }
            subtitle = getString(R.string.logcat_running)
        }
    }

    private fun initLevelSpinner() {
        val levels = listOf(
            getString(R.string.all), "Verbose", "Debug", "Info", "Warn", "Error"
        )
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, levels)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        binding.spinnerLevel.adapter = adapter
        binding.spinnerLevel.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>?, view: View?, position: Int, id: Long
            ) {
                startLogcat()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {
            }
        }
    }

    private fun initKeyword() {
        binding.etKeyword.setOnEditorActionListener { _, _, _ ->
            refilter()
            false
        }
        // 关键词变化时对已有内容整体过滤一次，新日志随后增量追加
        binding.etKeyword.doOnTextChanged { _, _, _, _ -> refilter() }
    }

    /** 关键词变化时，从缓冲重建过滤视图 */
    private fun refilter() {
        val keyword = binding.etKeyword.text?.toString()?.trim() ?: ""
        val rv = binding.rvLog
        val atBottom = !rv.canScrollVertically(1)
        if (keyword.isEmpty()) {
            // 清空关键词：恢复缓冲中的全部内容
            val all = ArrayList<String>(lines.size)
            synchronized(lines) {
                renderedIndex = totalAdded
                all.addAll(lines)
            }
            logAdapter.replaceAll(all)
        } else {
            val filtered = ArrayList<String>()
            synchronized(lines) {
                lines.forEach { line ->
                    if (line.contains(keyword, ignoreCase = true)) {
                        filtered.add(line)
                    }
                }
                renderedIndex = totalAdded
            }
            logAdapter.replaceAll(filtered)
        }
        if (atBottom) {
            rv.post { rv.scrollToPosition(logAdapter.itemCount - 1) }
        }
    }

    private fun initLogList() {
        binding.rvLog.apply {
            layoutManager = LinearLayoutManager(this@LogcatActivity)
            adapter = logAdapter
            itemAnimator = null
        }
    }

    private fun currentLevelArg(): String {
        return LEVEL_ARGS[binding.spinnerLevel.selectedItemPosition]
    }

    private fun startLogcat() {
        val newCmd = "logcat -v time ${currentLevelArg()}"
        val levelChanged = newCmd != lastCmd
        if (isReading && !levelChanged) {
            return
        }
        stopLogcat()
        lastCmd = newCmd
        if (levelChanged) {
            // 切换级别后重新开始：清空旧内容，避免混入其它级别的旧日志
            synchronized(lines) {
                lines.clear()
            }
            renderedIndex = totalAdded
            logAdapter.replaceAll(emptyList())
        }

        isReading = true
        updateStartStopMenu()
        readJob = CoroutineScope(Dispatchers.IO).launch {
            val idResult = runCatching { Shell.cmd("id -u").exec() }
            val hasRoot = idResult.isSuccess &&
                idResult.getOrNull()?.out?.firstOrNull()?.trim() == "0"
            if (!hasRoot) {
                synchronized(lines) {
                    lines.add(getString(R.string.only_self_logs))
                    totalAdded++
                }
                dirty = true
            }
            var process: Process? = null
            runCatching {
                process = if (hasRoot) {
                    ProcessBuilder("su", "-c", newCmd).redirectErrorStream(true).start()
                } else {
                    ProcessBuilder("sh", "-c", newCmd).redirectErrorStream(true).start()
                }
                logcatProcess = process
                val reader = BufferedReader(InputStreamReader(process!!.inputStream))
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    if (!isReading) {
                        break
                    }
                    line?.let {
                        synchronized(lines) {
                            lines.add(it)
                            while (lines.size > MAX_LINES) {
                                lines.removeFirst()
                            }
                            totalAdded++
                        }
                        dirty = true
                    }
                }
            }.onFailure {
                LogUtil.d("logcat read error: $it")
            }
            runCatching { process?.destroy() }
            if (process != null && logcatProcess === process) {
                logcatProcess = null
            }
        }
    }

    private fun updateStartStopMenu() {
        val item = binding.toolbar.menu.findItem(R.id.start_stop) ?: return
        if (isReading) {
            item.setIcon(R.drawable.ic_stop_circle)
            item.setTitle(R.string.stop)
            binding.toolbar.subtitle = getString(R.string.logcat_running)
        } else {
            item.setIcon(R.drawable.ic_play_circle)
            item.setTitle(R.string.start)
            binding.toolbar.subtitle = getString(R.string.logcat_stopped)
        }
    }

    private fun stopLogcat() {
        isReading = false
        destroyProcess()
        readJob?.cancel()
        readJob = null
        updateStartStopMenu()
    }

    private fun destroyProcess() {
        logcatProcess?.let {
            runCatching { it.destroy() }
        }
        logcatProcess = null
    }

    private fun render() {
        val keyword = binding.etKeyword.text?.toString()?.trim() ?: ""
        val rv = binding.rvLog
        val atBottom = !rv.canScrollVertically(1)

        // append mode: 只取上次渲染后新增的行。
        // lines 是环形缓冲（超过 MAX_LINES 会移除头部），
        // 用单调递增的 totalAdded 计算新行在缓冲中的起始下标。
        val newLines = ArrayList<String>()
        synchronized(lines) {
            val skip = totalAdded - lines.size
            if (renderedIndex < skip) {
                renderedIndex = skip
            }
            if (renderedIndex > totalAdded) {
                // 缓冲被清空过，从头开始
                renderedIndex = skip
            }
            for (i in (renderedIndex - skip).toInt() until lines.size) {
                newLines.add(lines[i])
            }
            renderedIndex = totalAdded
        }
        if (newLines.isEmpty()) {
            return
        }
        if (keyword.isEmpty()) {
            logAdapter.append(newLines)
        } else {
            // 关键词过滤：只追加匹配的新行，避免整表重建造成卡顿和跳动
            logAdapter.append(newLines.filter { it.contains(keyword, ignoreCase = true) })
        }
        if (atBottom) {
            rv.post { rv.scrollToPosition(logAdapter.itemCount - 1) }
        }
    }

    private inner class LogAdapter : RecyclerView.Adapter<LogAdapter.VH>() {

        private val items = ArrayList<String>()

        fun append(newItems: List<String>) {
            if (newItems.isEmpty()) {
                return
            }
            val oldSize = items.size
            items.addAll(newItems)
            val excess = items.size - MAX_LINES
            if (excess > 0) {
                items.subList(0, excess).clear()
                notifyDataSetChanged()
            } else {
                notifyItemRangeInserted(oldSize, newItems.size)
            }
        }

        fun replaceAll(newItems: List<String>) {
            items.clear()
            items.addAll(newItems)
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_logcat_line, parent, false)
            return VH(view)
        }

        override fun getItemCount(): Int = items.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val line = items[position]
            holder.tv.text = line
            holder.tv.setTextColor(levelColor(line))
        }

        private fun levelColor(line: String): Int {
            // logcat -v time 格式："MM-DD HH:MM:SS.mmm L/tag( pid): msg"，级别字符在 19 位
            if (line.length > 20 && line[20] == '/') {
                return when (line[19]) {
                    'V' -> 0xFF9E9E9E.toInt()
                    'D' -> 0xFF64B5F6.toInt()
                    'W' -> 0xFFFFB74D.toInt()
                    'E', 'F' -> 0xFFFF5252.toInt()
                    else -> defaultLogColor
                }
            }
            return defaultLogColor
        }

        inner class VH(view: View) : RecyclerView.ViewHolder(view) {
            val tv: TextView = view.findViewById(R.id.tv_line)

            init {
                // 长按复制该行日志
                view.setOnLongClickListener {
                    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("log", tv.text))
                    Toast.makeText(
                        this@LogcatActivity, R.string.logcat_copied, Toast.LENGTH_SHORT
                    ).show()
                    true
                }
            }
        }
    }

    override fun onDestroy() {
        mainHandler.removeCallbacks(renderRunnable)
        stopLogcat()
        super.onDestroy()
    }

}
