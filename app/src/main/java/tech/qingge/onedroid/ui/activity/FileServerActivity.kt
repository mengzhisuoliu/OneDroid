package tech.qingge.onedroid.ui.activity

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import com.hjq.permissions.Permission
import com.hjq.permissions.XXPermissions
import tech.qingge.onedroid.Constants
import tech.qingge.onedroid.R
import tech.qingge.onedroid.base.BaseActivity
import tech.qingge.onedroid.databinding.ActivityFileServerBinding
import tech.qingge.onedroid.service.FileServerService
import tech.qingge.onedroid.util.CommonPermissionCallback
import tech.qingge.onedroid.util.DeviceUtil
import tech.qingge.onedroid.util.ServiceUtil

class FileServerActivity : BaseActivity<ActivityFileServerBinding>() {

    private val serverUrl: String
        get() {
            val ip = DeviceUtil.getV4Ip().split("\n")
                .firstOrNull { it.isNotBlank() && !it.startsWith("127.") } ?: "0.0.0.0"
            return "http://$ip:${Constants.FILE_SERVER_PORT}"
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding.toolbar.setNavigationOnClickListener { finish() }

        binding.btnToggle.setOnClickListener {
            if (FileServerService.isServerRunning) {
                stopServer()
            } else {
                startServerWithPermission()
            }
        }

        binding.btnCopy.setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("url", serverUrl))
            Toast.makeText(this, R.string.file_server_url_copied, Toast.LENGTH_SHORT).show()
        }
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    private fun refreshStatus() {
        val running =
            FileServerService.isServerRunning || ServiceUtil.isServiceRunning(
                this, FileServerService::class.java.name
            )
        if (running) {
            binding.tvStatus.setText(R.string.file_server_running)
            binding.tvUrl.text = serverUrl
            binding.btnToggle.setText(R.string.file_server_stop)
        } else {
            binding.tvStatus.setText(R.string.file_server_stopped)
            binding.tvUrl.text = ""
            binding.btnToggle.setText(R.string.file_server_start)
        }
    }

    private fun startServerWithPermission() {
        if (XXPermissions.isGranted(this, Permission.MANAGE_EXTERNAL_STORAGE)) {
            startServer()
            return
        }
        XXPermissions.with(this).permission(Permission.MANAGE_EXTERNAL_STORAGE)
            .request(object : CommonPermissionCallback(this) {
                override fun onAllGranted() {
                    startServer()
                }

                override fun onDenied(
                    permissions: MutableList<String>,
                    doNotAskAgain: Boolean
                ) {
                    super.onDenied(permissions, doNotAskAgain)
                    refreshStatus()
                }
            })
    }

    private fun startServer() {
        startForegroundService(Intent(this, FileServerService::class.java))
        binding.tvStatus.postDelayed({ refreshStatus() }, 1000)
    }

    private fun stopServer() {
        stopService(Intent(this, FileServerService::class.java))
        binding.tvStatus.postDelayed({ refreshStatus() }, 500)
    }

}
