package tech.qingge.onedroid.ui.activity

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.inputmethod.EditorInfo
import android.widget.ScrollView
import android.widget.Toast
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import com.topjohnwu.superuser.CallbackList
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import tech.qingge.onedroid.R
import tech.qingge.onedroid.base.BaseActivity
import tech.qingge.onedroid.databinding.ActivityTerminalBinding

class TerminalActivity : BaseActivity<ActivityTerminalBinding>() {

    companion object {
        private const val RENDER_INTERVAL = 200L
        private const val MAX_LINES = 6000

        /** 常用命令，点击填入输入框 */
        private val QUICK_COMMANDS = listOf(
            "ls -l", "cd /", "ps -A", "top -n 1", "df -h", "free -h",
            "ip addr", "ping -c 4 8.8.8.8", "getprop", "dumpsys battery",
            "cat /proc/cpuinfo", "logcat -d | tail -100"
        )
    }

    private var isRoot = false
    private var isExecuting = false

    private val history = mutableListOf<String>()
    private var historyIndex = -1

    /** 已执行但尚未渲染完成的输出行，由 shell 输出泵线程写入 */
    private val pendingLines = ArrayDeque<String>()
    private var dirty = false

    private val mainHandler = Handler(Looper.getMainLooper())

    private val renderRunnable = object : Runnable {
        override fun run() {
            if (dirty) {
                dirty = false
                val sb = StringBuilder()
                synchronized(pendingLines) {
                    while (pendingLines.isNotEmpty()) {
                        sb.append(pendingLines.removeFirst()).append('\n')
                    }
                }
                if (sb.isNotEmpty()) {
                    binding.tvOutput.append(sb)
                    trimOutput()
                }
            }
            mainHandler.postDelayed(this, RENDER_INTERVAL)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        initToolbar()
        initQuickCommands()
        initInput()

        mainHandler.post(renderRunnable)

        CoroutineScope(Dispatchers.IO).launch {
            val result = runCatching { Shell.cmd("id -u").exec() }
            isRoot = result.isSuccess &&
                result.getOrNull()?.out?.firstOrNull()?.trim() == "0"
            withContext(Dispatchers.Main) {
                binding.toolbar.subtitle =
                    getString(if (isRoot) R.string.terminal_root else R.string.terminal_no_root)
            }
        }
    }

    /**
     * edge-to-edge 模式下 adjustResize 不生效，
     * 手动把 IME inset 应用到根布局，保证键盘不遮挡输入框。
     */
    override fun updatePadding() {
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { v, insets ->
            val statusBar = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
            val navBar = insets.getInsets(WindowInsetsCompat.Type.navigationBars()).bottom
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
            v.updatePadding(v.paddingLeft, statusBar, v.paddingRight, maxOf(navBar, ime))
            WindowInsetsCompat.CONSUMED
        }
    }

    private fun initToolbar() {
        binding.toolbar.apply {
            setNavigationOnClickListener { finish() }
            setOnMenuItemClickListener { menuItem ->
                when (menuItem.itemId) {
                    R.id.clear -> binding.tvOutput.text = ""

                    R.id.stop -> stopCurrentCommand()
                }
                true
            }
        }
    }

    /**
     * 终止当前（可能是流式的）命令：libsu 的命令运行在持久 shell 中，
     * 无法单独取消，这里直接关闭整个 shell 进程，下一条命令会自动重建 shell。
     */
    private fun stopCurrentCommand() {
        if (!isExecuting) {
            return
        }
        runCatching { Shell.getShell().close() }
        isExecuting = false
        binding.tvOutput.append(getString(R.string.terminal_command_stopped) + "\n")
        scrollBottom()
    }

    private fun initQuickCommands() {
        val density = resources.displayMetrics.density
        QUICK_COMMANDS.forEach { cmd ->
            val tv = android.widget.TextView(this).apply {
                text = cmd
                textSize = 12f
                includeFontPadding = false
                typeface = android.graphics.Typeface.MONOSPACE
                setPadding(
                    (10 * density).toInt(), (6 * density).toInt(),
                    (10 * density).toInt(), (6 * density).toInt()
                )
                background = android.graphics.drawable.GradientDrawable().apply {
                    shape = android.graphics.drawable.GradientDrawable.RECTANGLE
                    cornerRadius = 8 * density
                    setColor(com.google.android.material.color.MaterialColors.getColor(
                        this@TerminalActivity,
                        com.google.android.material.R.attr.colorSurfaceVariant,
                        0xFFE0E0E0.toInt()
                    ))
                }
                layoutParams = android.view.ViewGroup.MarginLayoutParams(
                    android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                    android.view.ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { marginEnd = (8 * density).toInt() }
                setOnClickListener {
                    binding.etCommand.setText(cmd)
                    binding.etCommand.setSelection(binding.etCommand.text?.length ?: 0)
                    binding.etCommand.requestFocus()
                }
            }
            binding.llQuickCommands.addView(tv)
        }
    }

    private fun initInput() {
        binding.etCommand.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_GO) {
                executeCommand()
                true
            } else {
                false
            }
        }
        binding.btnRun.setOnClickListener { executeCommand() }
        binding.etCommand.setOnKeyListener { _, keyCode, event ->
            val isUp = event.action == android.view.KeyEvent.ACTION_UP
            when (keyCode) {
                android.view.KeyEvent.KEYCODE_DPAD_UP -> {
                    if (isUp && history.isNotEmpty()) {
                        if (historyIndex == -1) {
                            historyIndex = history.size - 1
                        } else if (historyIndex > 0) {
                            historyIndex--
                        }
                        binding.etCommand.setText(history[historyIndex])
                        binding.etCommand.setSelection(binding.etCommand.text?.length ?: 0)
                    }
                    true
                }

                android.view.KeyEvent.KEYCODE_DPAD_DOWN -> {
                    if (isUp && historyIndex != -1) {
                        if (historyIndex < history.size - 1) {
                            historyIndex++
                            binding.etCommand.setText(history[historyIndex])
                        } else {
                            historyIndex = -1
                            binding.etCommand.setText("")
                        }
                        binding.etCommand.setSelection(binding.etCommand.text?.length ?: 0)
                    }
                    true
                }

                else -> false
            }
        }
    }

    private fun executeCommand() {
        val command = binding.etCommand.text?.toString()?.trim() ?: ""
        if (command.isEmpty() || isExecuting) {
            return
        }
        isExecuting = true
        binding.etCommand.setText("")
        if (history.isEmpty() || history.last() != command) {
            history.add(command)
        }
        historyIndex = -1

        val prompt = if (isRoot) "# " else "$ "
        append(prompt + command + "\n", false)

        // 流式输出：libsu 通过 CallbackList 逐行回调，logcat/top 等长驻命令不会阻塞界面
        val outputList = object : CallbackList<String>() {
            override fun onAddElement(e: String) {
                synchronized(pendingLines) {
                    pendingLines.add(e)
                    dirty = true
                }
            }
        }
        Shell.cmd(command).to(outputList).submit { result ->
            runOnUiThread {
                if (isDestroyed || isFinishing) {
                    return@runOnUiThread
                }
                if (result.out.isNotEmpty()) {
                    result.out.forEach { outputList.onAddElement(it) }
                }
                if (result.err.isNotEmpty()) {
                    result.err.forEach { outputList.onAddElement(it) }
                }
                append(getString(R.string.terminal_exit_code, result.code) + "\n")
                isExecuting = false
                scrollBottom()
            }
        }
    }

    private fun trimOutput() {
        val lineCount = binding.tvOutput.layout?.lineCount ?: 0
        if (lineCount > MAX_LINES) {
            val start = binding.tvOutput.layout.getLineStart(lineCount - MAX_LINES / 2)
            binding.tvOutput.text = binding.tvOutput.text.substring(start)
        }
    }

    private fun append(text: String, scroll: Boolean = true) {
        binding.tvOutput.append(text)
        if (scroll) {
            scrollBottom()
        }
    }

    private fun scrollBottom() {
        binding.scrollView.post { binding.scrollView.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    override fun onDestroy() {
        mainHandler.removeCallbacks(renderRunnable)
        if (isExecuting) {
            runCatching { Shell.getShell().close() }
            isExecuting = false
        }
        super.onDestroy()
    }

}
