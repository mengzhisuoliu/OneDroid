package tech.qingge.onedroid.server

import java.io.File

/** 供 REST 控制器使用的运行时环境（由 FileServerService 启动时初始化） */
object FileServerEnv {
    /** 上传/下载中转目录（应用外部存储私有目录） */
    @Volatile
    var transferDir: File? = null
}
