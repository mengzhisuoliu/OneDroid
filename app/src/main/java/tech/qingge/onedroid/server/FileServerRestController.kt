package tech.qingge.onedroid.server

import com.google.gson.Gson
import com.topjohnwu.superuser.Shell
import com.yanzhenjie.andserver.annotation.FormPart
import com.yanzhenjie.andserver.annotation.GetMapping
import com.yanzhenjie.andserver.annotation.PostMapping
import com.yanzhenjie.andserver.annotation.QueryParam
import com.yanzhenjie.andserver.annotation.RestController
import com.yanzhenjie.andserver.framework.body.FileBody
import com.yanzhenjie.andserver.framework.body.StringBody
import com.yanzhenjie.andserver.http.HttpResponse
import com.yanzhenjie.andserver.http.ResponseBody
import com.yanzhenjie.andserver.http.StatusCode
import com.yanzhenjie.andserver.http.multipart.MultipartFile
import tech.qingge.onedroid.util.LogUtil
import java.io.File
import java.net.URLDecoder

@RestController
class FileServerRestController {

    data class FileItem(
        val name: String,
        val path: String,
        val isDir: Boolean,
        val size: String
    )

    private val gson = Gson()

    private fun rootFile(): File {
        // 默认目录为设备根目录
        return File("/")
    }

    private fun resolve(path: String?): File {
        val root = rootFile().canonicalFile
        if (path.isNullOrBlank() || path == "/") {
            return root
        }
        val decoded = runCatching { URLDecoder.decode(path, "UTF-8") }.getOrDefault(path)
        // 相对路径按根目录处理
        val normalized = if (decoded.startsWith("/")) decoded else "/$decoded"
        val target = File(normalized.removeSuffix("/"))
        return runCatching { target.canonicalFile }.getOrDefault(root)
    }

    private fun appCacheDir(): File {
        return FileServerEnv.transferDir
            ?: throw IllegalStateException("file server env not ready")
    }

    private fun shellQuote(s: String): String {
        return "'" + s.replace("'", "'\\''") + "'"
    }

    private fun toItem(f: File, name: String?): FileItem {
        val isDir = runCatching { f.isDirectory }.getOrDefault(false)
        val size = if (isDir) {
            "--"
        } else {
            formatSize(runCatching { f.length() }.getOrDefault(0L))
        }
        val realName = name ?: f.name
        return FileItem(realName, f.absolutePath, isDir, size)
    }

    private fun sortItems(items: List<FileItem>): List<FileItem> {
        return items.sortedWith(
            compareByDescending<FileItem> { it.isDir }.thenBy { it.name.lowercase() }
        )
    }

    /** 用 root shell 列目录（Android 16 等系统上普通进程无法读取 / 等受限目录） */
    private fun rootListItems(dir: File): List<FileItem>? {
        return runCatching {
            val result = Shell.cmd("ls -A ${shellQuote(dir.absolutePath)}").exec()
            if (result.code != 0) {
                null
            } else {
                sortItems(result.out.filter { it.isNotBlank() }.map { name ->
                    val f = if (dir.absolutePath == "/") File("/$name") else File(dir, name)
                    toItem(f, name)
                })
            }
        }.getOrNull()
    }

    @GetMapping("/api/list")
    fun list(@QueryParam("path") path: String): String {
        val dir = resolve(path)
        if (!dir.exists() || !dir.isDirectory) {
            return "[]"
        }
        val direct = dir.listFiles()
        if (direct != null) {
            return gson.toJson(sortItems(direct.map { toItem(it, null) }))
        }
        // 普通进程无读权限时走 root shell
        return gson.toJson(rootListItems(dir) ?: emptyList<FileItem>())
    }

    @GetMapping("/api/download")
    fun download(@QueryParam("path") path: String, response: HttpResponse): ResponseBody {
        val file = resolve(path)
        if (!file.exists() || file.isDirectory) {
            response.setStatus(StatusCode.SC_NOT_FOUND)
            return StringBody("Not Found")
        }
        response.setStatus(StatusCode.SC_OK)
        response.setHeader(
            "Content-Disposition",
            "attachment; filename=\"${file.name.replace("\"", "")}\""
        )
        if (file.canRead()) {
            return FileBody(file)
        }
        // 无读权限：root 读取到缓存后发送
        val tmp = File(appCacheDir(), "dl_${System.currentTimeMillis()}_${file.name}")
        val ok = runCatching {
            Shell.cmd("cat ${shellQuote(file.absolutePath)} > ${shellQuote(tmp.absolutePath)}")
                .exec().code == 0
        }.getOrDefault(false) && tmp.exists() && tmp.length() > 0
        if (!ok) {
            response.setStatus(StatusCode.SC_FORBIDDEN)
            return StringBody("Permission denied")
        }
        tmp.deleteOnExit()
        return FileBody(tmp)
    }

    @PostMapping("/api/upload")
    fun upload(
        @FormPart("file") file: MultipartFile,
        @FormPart("targetPath") targetPath: String
    ): String {
        return try {
            val dir = resolve(targetPath)
            if (!dir.exists() || !dir.isDirectory) {
                return "fail: target dir not found"
            }
            val fileName = file.filename?.let {
                it.substringAfterLast('/').substringAfterLast('\\')
            }?.takeIf { it.isNotBlank() } ?: "upload_${System.currentTimeMillis()}"
            val dest = File(dir, fileName)
            // 统一先落到应用中转目录，再复制到目标（受限目录走 root）
            val tmp = File(appCacheDir(), "ul_${System.currentTimeMillis()}_$fileName")
            file.transferTo(tmp)
            val directOk = runCatching { tmp.copyTo(dest, overwrite = true) }.isSuccess
            if (!directOk) {
                val rootOk = runCatching {
                    Shell.cmd(
                        "cat ${shellQuote(tmp.absolutePath)} > ${shellQuote(dest.absolutePath)}"
                    ).exec().code == 0
                }.getOrDefault(false)
                tmp.delete()
                if (!rootOk) {
                    return "fail: target dir not writable"
                }
            }
            tmp.delete()
            LogUtil.d("file server upload: ${dest.absolutePath}")
            "ok"
        } catch (e: Exception) {
            LogUtil.d("file server upload error: $e")
            "fail: ${e.message}"
        }
    }

    private fun formatSize(size: Long): String {
        return when {
            size < 1024 -> "$size B"
            size < 1024 * 1024 -> String.format("%.1f KB", size / 1024f)
            size < 1024 * 1024 * 1024 -> String.format("%.1f MB", size / 1024f / 1024f)
            else -> String.format("%.1f GB", size / 1024f / 1024f / 1024f)
        }
    }

}
