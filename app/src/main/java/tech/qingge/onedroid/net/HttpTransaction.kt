package tech.qingge.onedroid.net

/**
 * 一次被捕获的 HTTP/HTTPS 事务（一个请求 + 对应的响应）。
 * 列表里每一条就是一个 [HttpTransaction]，点进去可看请求与响应详情。
 */
data class HttpTransaction(
    val id: Long,
    val requestTime: Long,
    /** 是否经过 HTTPS 解密（MITM） */
    val isSsl: Boolean,
    var method: String,
    var scheme: String,
    var host: String,
    var port: Int,
    /** 请求路径（含 query） */
    var path: String,
    var requestHeaders: List<Pair<String, String>>,
    var requestBody: ByteArray,
    var responseStatusCode: Int,
    var responseReason: String,
    var responseHeaders: List<Pair<String, String>>,
    var responseBody: ByteArray,
    var responseTime: Long,
    /** 见 STATE_* 常量 */
    var state: Int,
    var error: String?
) {

    companion object {
        const val STATE_PENDING = 0
        const val STATE_COMPLETE = 1
        const val STATE_ERROR = 2

        /** 单个事务最多保存的请求/响应体字节数，避免大文件撑爆内存 */
        const val MAX_BODY = 1024 * 1024
    }

    val url: String
        get() {
            val authority = if ((scheme == "https" && port == 443) ||
                (scheme == "http" && port == 80)
            ) {
                host
            } else {
                "$host:$port"
            }
            return "$scheme://$authority$path"
        }

    fun requestHeader(name: String): String? =
        requestHeaders.firstOrNull { it.first.equals(name, true) }?.second

    fun responseHeader(name: String): String? =
        responseHeaders.firstOrNull { it.first.equals(name, true) }?.second

    /** 用于粗略判断是否为文本，以便决定是否展示明文 */
    fun isTextContent(headers: List<Pair<String, String>>): Boolean {
        val ct = headers.firstOrNull { it.first.equals("Content-Type", true) }?.second
            ?: return false
        return ct.contains("text", true) ||
            ct.contains("json", true) ||
            ct.contains("xml", true) ||
            ct.contains("javascript", true) ||
            ct.contains("html", true)
    }
}
