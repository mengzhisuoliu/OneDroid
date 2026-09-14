package tech.qingge.onedroid.ui.activity

import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import tech.qingge.onedroid.R
import tech.qingge.onedroid.base.BaseActivity
import tech.qingge.onedroid.databinding.ActivityNetCaptureBinding
import tech.qingge.onedroid.net.CaptureRepository
import tech.qingge.onedroid.net.HttpsCaCertUtil
import tech.qingge.onedroid.net.HttpTransaction
import tech.qingge.onedroid.net.HttpUtil
import tech.qingge.onedroid.service.CaptureVpnService
import tech.qingge.onedroid.ui.fragment.HttpTransactionDetailDialogFragment
import tech.qingge.onedroid.util.LogUtil
import java.io.File
import java.io.FileInputStream

class NetCaptureActivity : BaseActivity<ActivityNetCaptureBinding>() {

    companion object {
        private const val POLL_INTERVAL = 300L
    }

    private val transactionAdapter = TransactionAdapter()

    private val mainHandler = Handler(Looper.getMainLooper())

    private val renderRunnable = object : Runnable {
        override fun run() {
            // 拉取已被解析出的 HTTP/HTTPS 事务快照并刷新列表
            transactionAdapter.setTransactions(CaptureRepository.snapshot())
            updateStatus()
            mainHandler.postDelayed(this, POLL_INTERVAL)
        }
    }

    private val vpnPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            LogUtil.d("vpnPermissionLauncher result=${result.resultCode}")
            if (result.resultCode == RESULT_OK) {
                startCapture()
            } else {
                Toast.makeText(this, R.string.net_capture_vpn_denied, Toast.LENGTH_SHORT).show()
            }
        }

    private val saveFileLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            uri ?: return@registerForActivityResult
            val path = CaptureVpnService.pcapPath ?: return@registerForActivityResult
            sourceIo {
                contentResolver.openOutputStream(uri)?.use { out ->
                    FileInputStream(File(path)).use { it.copyTo(out) }
                }
            }
        }

    private val certSaveLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/x-x509-ca-cert")) { uri ->
            uri ?: return@registerForActivityResult
            sourceIo {
                val ok = runCatching {
                    val pem = HttpsCaCertUtil.getOrCreateCa(filesDir).certFile.readText()
                    contentResolver.openOutputStream(uri)?.use { out ->
                        out.write(pem.toByteArray(Charsets.UTF_8))
                    }
                }.isSuccess
                mainHandler.post {
                    Toast.makeText(
                        this@NetCaptureActivity,
                        if (ok) R.string.net_capture_cert_saved else R.string.net_capture_install_failed,
                        if (ok) Toast.LENGTH_LONG else Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }

    private val stopListener: (String?) -> Unit = { error ->
        mainHandler.post {
            if (isDestroyed || isFinishing) {
                return@post
            }
            if (error != null) {
                Toast.makeText(this@NetCaptureActivity, error, Toast.LENGTH_LONG).show()
            }
            updateStatus()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        initToolbar()
        initButtons()
        initPacketList()

        updateToggle()
        updateStatus()

        mainHandler.post(renderRunnable)
    }

    override fun onResume() {
        super.onResume()
        updateToggle()
    }

    private fun initToolbar() {
        binding.toolbar.apply {
            setNavigationOnClickListener { finish() }
            setOnMenuItemClickListener { menuItem ->
                when (menuItem.itemId) {
                    R.id.save -> {
                        val path = CaptureVpnService.pcapPath
                        if (path != null) {
                            saveFileLauncher.launch(File(path).name)
                        } else {
                            Toast.makeText(
                                this@NetCaptureActivity,
                                R.string.net_capture_no_file, Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                }
                true
            }
        }
    }

    private fun initButtons() {
        binding.btnToggle.setOnClickListener {
            if (CaptureVpnService.isRunning) {
                stopCapture()
            } else {
                requestVpnAndStart()
            }
        }
        binding.btnChooseApp.setOnClickListener { showAppPicker() }
        binding.btnInstallCert.setOnClickListener { installHttpsCert() }
        refreshChooseAppText()
    }

    private fun initPacketList() {
        binding.rvPackets.apply {
            layoutManager = LinearLayoutManager(this@NetCaptureActivity)
            adapter = transactionAdapter
            itemAnimator = null
        }
    }

    private fun requestVpnAndStart() {
        val prepare = VpnService.prepare(this)
        LogUtil.d("requestVpnAndStart: prepare=${if (prepare == null) "already granted" else "need permission"}")
        if (prepare != null) {
            vpnPermissionLauncher.launch(prepare)
        } else {
            startCapture()
        }
    }

    private fun startCapture() {
        LogUtil.d("startCapture: starting service")
        transactionAdapter.setTransactions(emptyList())
        binding.tvStatus.setText(R.string.net_capture_starting)
        val intent = Intent(this, CaptureVpnService::class.java)
        ContextCompat.startForegroundService(this, intent)
        binding.btnToggle.isEnabled = false
        mainHandler.postDelayed({ updateToggle() }, 500)
    }

    private fun stopCapture() {
        LogUtil.d("stopCapture: sending ACTION_STOP")
        val intent = Intent(this, CaptureVpnService::class.java)
        intent.action = CaptureVpnService.ACTION_STOP
        startService(intent)
    }

    private fun updateToggle() {
        val running = CaptureVpnService.isRunning
        binding.btnToggle.setText(if (running) R.string.net_capture_stop else R.string.net_capture_start)
        binding.btnToggle.isEnabled = true
        if (running) {
            updateStatus()
        } else if (binding.tvStatus.text.isNullOrEmpty() ||
            binding.tvStatus.text.toString() == getString(R.string.net_capture_starting)
        ) {
            binding.tvStatus.setText(R.string.net_capture_stopped_tips)
        }
    }

    private fun updateStatus() {
        val txCount = CaptureRepository.size()
        if (CaptureVpnService.isRunning) {
            binding.btnToggle.setText(R.string.net_capture_stop)
            val size = CaptureVpnService.pcapPath?.let { File(it).length() } ?: 0L
            binding.tvStatus.text = getString(
                R.string.net_capture_running, txCount, formatSize(size)
            )
        } else {
            binding.btnToggle.setText(R.string.net_capture_start)
            val path = CaptureVpnService.pcapPath
            if (path != null) {
                binding.tvStatus.text =
                    getString(R.string.net_capture_finished, txCount, path)
            } else {
                binding.tvStatus.setText(R.string.net_capture_stopped_tips)
            }
        }
    }

    // ---- 选择应用 ----

    private class AppEntry(
        val label: String,
        val pkg: String?,
        val icon: android.graphics.drawable.Drawable?
    )

    private fun refreshChooseAppText() {
        val pkg = CaptureVpnService.targetPackage
        if (pkg == null) {
            binding.btnChooseApp.setText(R.string.net_capture_all_apps)
        } else {
            val label = runCatching {
                packageManager.getApplicationLabel(
                    packageManager.getApplicationInfo(pkg, 0)
                ).toString()
            }.getOrDefault(pkg)
            binding.btnChooseApp.text = label
        }
    }

    private fun showAppPicker() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (resources.displayMetrics.density * 12).toInt()
            setPadding(pad, pad / 2, pad, 0)
        }
        val searchView = EditText(this).apply {
            hint = getString(R.string.net_capture_search_app)
            setSingleLine()
        }
        val listView = ListView(this).apply {
            divider = null
        }
        container.addView(
            searchView, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        )
        container.addView(
            listView, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (resources.displayMetrics.heightPixels * 0.55).toInt()
            )
        )
        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.net_capture_choose_app)
            .setView(container)
            .setNegativeButton(android.R.string.cancel, null)
            .create()

        val adapter = AppAdapter()
        listView.adapter = adapter
        listView.setOnItemClickListener { _, _, position, _ ->
            val entry = adapter.visible[position]
            CaptureVpnService.targetPackage = entry.pkg
            refreshChooseAppText()
            dialog.dismiss()
            if (CaptureVpnService.isRunning) {
                Toast.makeText(
                    this, R.string.net_capture_app_effect_next, Toast.LENGTH_SHORT
                ).show()
            }
        }
        searchView.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) {
                adapter.filter(s?.toString() ?: "")
            }
        })

        lifecycleScope.launch {
            val apps = withContext(Dispatchers.IO) { loadApps() }
            adapter.setData(apps)
        }
        dialog.show()
    }

    private fun loadApps(): List<AppEntry> {
        val pm = packageManager
        val result = mutableListOf(AppEntry(getString(R.string.net_capture_all_apps), null, null))
        runCatching {
            pm.getInstalledPackages(0).forEach { info ->
                if (info.packageName == packageName) {
                    return@forEach
                }
                val label = runCatching {
                    info.applicationInfo?.loadLabel(pm)?.toString()
                }.getOrNull() ?: info.packageName
                val icon = runCatching {
                    info.applicationInfo?.loadIcon(pm)
                }.getOrNull()
                result.add(AppEntry(label, info.packageName, icon))
            }
        }
        return result.sortedBy { it.label.lowercase() }
    }

    private inner class AppAdapter : BaseAdapter() {

        private val apps = mutableListOf<AppEntry>()
        val visible = mutableListOf<AppEntry>()

        fun setData(data: List<AppEntry>) {
            apps.clear()
            apps.addAll(data)
            visible.clear()
            visible.addAll(data)
            notifyDataSetChanged()
        }

        fun filter(keyword: String) {
            visible.clear()
            if (keyword.isBlank()) {
                visible.addAll(apps)
            } else {
                val k = keyword.trim()
                apps.forEach {
                    if (it.label.contains(k, true) || (it.pkg?.contains(k, true) == true)) {
                        visible.add(it)
                    }
                }
            }
            notifyDataSetChanged()
        }

        override fun getCount(): Int = visible.size

        override fun getItem(position: Int): Any = visible[position]

        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val view = convertView ?: LayoutInflater.from(parent.context)
                .inflate(R.layout.item_net_capture_app, parent, false)
            val entry = visible[position]
            view.findViewById<TextView>(R.id.tv_label).text = entry.label
            view.findViewById<TextView>(R.id.tv_pkg).text = entry.pkg ?: ""
            val iconView = view.findViewById<android.widget.ImageView>(R.id.iv_icon)
            if (entry.icon != null) {
                iconView.setImageDrawable(entry.icon)
                iconView.visibility = View.VISIBLE
            } else {
                iconView.visibility = View.GONE
            }
            return view
        }
    }

    // ---- 保存 HTTPS 证书（由用户手动安装） ----

    private fun installHttpsCert() {
        binding.btnInstallCert.isEnabled = false
        lifecycleScope.launch {
            val material = withContext(Dispatchers.IO) {
                runCatching { HttpsCaCertUtil.getOrCreateCa(filesDir) }.getOrNull()
            }
            binding.btnInstallCert.isEnabled = true
            if (material == null) {
                Toast.makeText(this@NetCaptureActivity, R.string.net_capture_install_failed,
                    Toast.LENGTH_SHORT).show()
                return@launch
            }
            certSaveLauncher.launch("OneDroidCA.crt")
        }
    }

    // ---- HTTP/HTTPS 事务列表 ----

    private inner class TransactionAdapter : RecyclerView.Adapter<TransactionAdapter.VH>() {

        private val items = ArrayList<HttpTransaction>()

        fun setTransactions(newItems: List<HttpTransaction>) {
            items.clear()
            items.addAll(newItems)
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_http_transaction, parent, false)
            return VH(view)
        }

        override fun getItemCount(): Int = items.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            holder.bind(items[position])
        }

        inner class VH(view: View) : RecyclerView.ViewHolder(view) {
            private val tvUrl: TextView = view.findViewById(R.id.tv_url)
            private val tvStatus: TextView = view.findViewById(R.id.tv_status)
            private val tvTime: TextView = view.findViewById(R.id.tv_time)

            init {
                view.setOnClickListener {
                    val position = adapterPosition
                    if (position != RecyclerView.NO_POSITION) {
                        HttpTransactionDetailDialogFragment.newInstance(items[position].id)
                            .show(supportFragmentManager, "HttpTransactionDetail")
                    }
                }
            }

            fun bind(tx: HttpTransaction) {
                val schemeTag = if (tx.isSsl) "🔒 " else ""
                tvUrl.text = "$schemeTag${tx.url}"
                val statusText = when (tx.state) {
                    HttpTransaction.STATE_PENDING -> "···"
                    HttpTransaction.STATE_ERROR -> "ERR"
                    else -> tx.responseStatusCode.toString()
                }
                tvStatus.text = statusText
                val statusColor = when (tx.state) {
                    HttpTransaction.STATE_PENDING -> 0xFF9E9E9E.toInt()
                    HttpTransaction.STATE_ERROR -> 0xFFF44336.toInt()
                    else -> statusColorForCode(tx.responseStatusCode)
                }
                tvStatus.setTextColor(statusColor)
                tvTime.text = formatTime(tx.requestTime)
                tvTime.setTextColor(Color.GRAY)
            }

            private fun statusColorForCode(code: Int): Int {
                return when {
                    code in 200..299 -> 0xFF4CAF50.toInt()
                    code in 300..399 -> 0xFFFF9800.toInt()
                    code in 400..499 -> 0xFFF44336.toInt()
                    code in 500..599 -> 0xFFE91E63.toInt()
                    else -> 0xFF2196F3.toInt()
                }
            }
        }
    }

    private fun formatTime(timeMs: Long): String {
        return java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
            .format(java.util.Date(timeMs))
    }

    private fun formatSize(size: Long): String {
        return if (size < 1024) {
            "$size B"
        } else if (size < 1024 * 1024) {
            String.format(java.util.Locale.getDefault(), "%.1f KB", size / 1024f)
        } else {
            String.format(java.util.Locale.getDefault(), "%.1f MB", size / 1024f / 1024f)
        }
    }

    private fun sourceIo(block: () -> Unit) {
        Thread {
            runCatching { block() }
        }.start()
    }

    override fun onStart() {
        super.onStart()
        CaptureVpnService.addStopListener(stopListener)
    }

    override fun onStop() {
        CaptureVpnService.removeStopListener(stopListener)
        super.onStop()
    }

    override fun onDestroy() {
        mainHandler.removeCallbacks(renderRunnable)
        super.onDestroy()
    }

}
