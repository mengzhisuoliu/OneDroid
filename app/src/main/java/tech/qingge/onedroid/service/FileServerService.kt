package tech.qingge.onedroid.service

import android.content.Intent
import com.yanzhenjie.andserver.AndServer
import com.yanzhenjie.andserver.Server
import dagger.hilt.android.AndroidEntryPoint
import tech.qingge.onedroid.Constants
import tech.qingge.onedroid.R
import tech.qingge.onedroid.base.BaseForegroundService
import tech.qingge.onedroid.util.DeviceUtil
import tech.qingge.onedroid.util.LogUtil
import java.io.File
import java.util.concurrent.TimeUnit

@AndroidEntryPoint
class FileServerService : BaseForegroundService() {

    companion object {
        @Volatile
        var isServerRunning = false
            private set
    }

    private var server: Server? = null

    override fun onCreate() {
        super.onCreate()
        // 上传/下载中转目录（受限路径经 root 中转用）
        tech.qingge.onedroid.server.FileServerEnv.transferDir = File(
            getExternalFilesDir(null) ?: filesDir, "transfer"
        ).apply { mkdirs() }
    }

    override fun getNotificationData(): NotificationData {
        val ip = DeviceUtil.getV4Ip().split("\n")
            .firstOrNull { it.isNotBlank() && !it.startsWith("127.") } ?: "0.0.0.0"
        return NotificationData(
            Constants.NOTIFICATION_NOTIFY_ID_FILE_SERVER,
            getString(R.string.app_name),
            getString(R.string.file_server_running) + " http://$ip:" + Constants.FILE_SERVER_PORT
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        startServer()
        return START_NOT_STICKY
    }

    private fun startServer() {
        if (server?.isRunning == true) {
            return
        }
        Thread {
            val newServer = AndServer.webServer(this)
                .port(Constants.FILE_SERVER_PORT)
                .timeout(30, TimeUnit.SECONDS)
                .listener(object : Server.ServerListener {
                    override fun onStarted() {
                        isServerRunning = true
                        LogUtil.d("file server started on port ${Constants.FILE_SERVER_PORT}")
                    }

                    override fun onStopped() {
                        isServerRunning = false
                        LogUtil.d("file server stopped")
                    }

                    override fun onException(e: Exception) {
                        isServerRunning = false
                        LogUtil.d("file server error: $e")
                    }
                })
                .build()
            server = newServer
            newServer.startup()
        }.start()
    }

    override fun onDestroy() {
        super.onDestroy()
        Thread {
            runCatching { server?.shutdown() }
            server = null
            isServerRunning = false
        }.start()
    }

}
