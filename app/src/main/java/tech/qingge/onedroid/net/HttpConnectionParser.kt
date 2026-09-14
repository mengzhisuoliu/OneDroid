package tech.qingge.onedroid.net

import tech.qingge.onedroid.util.LogUtil
import java.io.ByteArrayOutputStream
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets

/**
 * 单条 TCP 连接上的 HTTP/1.x 流式解析器。
 *
 * 分别把「客户端→服务端」与「服务端→客户端」的明文字节流喂入，
 * 解析出完整的请求与响应（支持 Content-Length 与 chunked 分块编码，
 * 以及连接关闭式结束），并按连接内的先后顺序把响应配对到对应的请求上，
 * 通过 [onTransaction] 回调抛出（首次出现为待响应状态，响应到达后就地更新）。
 */
class HttpConnectionParser(
    private val isSsl: Boolean,
    private val scheme: String,
    private val defaultHost: String,
    private val defaultPort: Int,
    private val onTransaction: (HttpTransaction) -> Unit
) {

    private val reqBuf = ByteArrayOutputStream()
    private val respBuf = ByteArrayOutputStream()
    /** 已解析出请求、尚未收到响应的事务，按序排队 */
    private val pending = ArrayDeque<HttpTransaction>()

    @Synchronized
    fun feedRequest(bytes: ByteArray) {
        if (bytes.isEmpty()) return
        LogUtil.d("HttpParser feedRequest: ${bytes.size}B first=${bytes[0].toInt() and 0xFF} preview=${String(bytes, 0, minOf(80, bytes.size), Charsets.US_ASCII).replace("\r","\\r").replace("\n","\\n")}")
        reqBuf.write(bytes, 0, bytes.size)
        parseRequests()
    }

    @Synchronized
    fun feedResponse(bytes: ByteArray) {
        if (bytes.isEmpty()) return
        LogUtil.d("HttpParser feedResponse: ${bytes.size}B first=${bytes[0].toInt() and 0xFF} preview=${String(bytes, 0, minOf(80, bytes.size), Charsets.US_ASCII).replace("\r","\\r").replace("\n","\\n")}")
        respBuf.write(bytes, 0, bytes.size)
        parseResponses()
    }


    /** 上游异常（连接失败等）时，把当前等待响应的请求标记为错误 */
    @Synchronized
    fun markError(message: String) {
        val tx = pending.firstOrNull()
        if (tx != null) {
            tx.state = HttpTransaction.STATE_ERROR
            tx.error = message
            onTransaction(tx)
        }
    }

    // ---- 请求解析 ----

    private fun parseRequests() {
        var buf = reqBuf.toByteArray()
        while (true) {
            val headerEnd = indexOfHeaderEnd(buf)
            if (headerEnd < 0) break
            val headerLen = headerEnd + 4
            if (buf.size < headerLen) break
            val headerSection = buf.copyOfRange(0, headerEnd)
            val requestLine = parseRequestLine(headerSection) ?: run {
                // 不是合法 HTTP 请求：放弃本条连接上剩余的字节
                LogUtil.d("HttpParser: drop non-HTTP request bytes len=${buf.size}")
                reqBuf.reset()
                return
            }
            val headers = parseHeaders(headerSection)
            val body = extractBody(headers, buf, headerLen, true) ?: break
            val total = headerLen + body.consumed
            if (buf.size < total) break

            var host = defaultHost
            var port = defaultPort
            headers.firstOrNull { it.first.equals("Host", true) }?.second?.trim()?.let { h ->
                val idx = h.indexOf(':')
                host = if (idx >= 0) h.substring(0, idx) else h
                if (idx >= 0) port = h.substring(idx + 1).toIntOrNull() ?: port
            }

            val tx = HttpTransaction(
                id = CaptureRepository.nextId(),
                requestTime = System.currentTimeMillis(),
                isSsl = isSsl,
                method = requestLine.first,
                scheme = scheme,
                host = host,
                port = port,
                path = requestLine.second,
                requestHeaders = headers,
                requestBody = body.bytes,
                responseStatusCode = 0,
                responseReason = "",
                responseHeaders = emptyList(),
                responseBody = ByteArray(0),
                responseTime = 0,
                state = HttpTransaction.STATE_PENDING,
                error = null
            )
            CaptureRepository.add(tx)
            pending.add(tx)
            onTransaction(tx)

            buf = buf.copyOfRange(total, buf.size)
            if (buf.isEmpty()) break
        }
        reqBuf.reset()
        if (buf.isNotEmpty()) reqBuf.write(buf, 0, buf.size)
    }

    // ---- 响应解析 ----

    private fun parseResponses() {
        var buf = respBuf.toByteArray()
        while (true) {
            val headerEnd = indexOfHeaderEnd(buf)
            if (headerEnd < 0) break
            val headerLen = headerEnd + 4
            if (buf.size < headerLen) break
            val headerSection = buf.copyOfRange(0, headerEnd)
            val statusLine = parseStatusLine(headerSection) ?: run {
                respBuf.reset()
                return
            }
            val headers = parseHeaders(headerSection)
            val body = extractBody(headers, buf, headerLen, false) ?: break
            val total = headerLen + body.consumed
            if (buf.size < total) break

            val tx = pending.removeFirstOrNull()
            if (tx != null) {
                tx.responseStatusCode = statusLine.first
                tx.responseReason = statusLine.second
                tx.responseHeaders = headers
                tx.responseBody = body.bytes
                tx.responseTime = System.currentTimeMillis()
                tx.state = HttpTransaction.STATE_COMPLETE
                tx.error = null
                onTransaction(tx)
            } else {
                // 没有可配对的请求（理论上不该发生）：单独记录一条响应
                val orphan = HttpTransaction(
                    id = CaptureRepository.nextId(),
                    requestTime = System.currentTimeMillis(),
                    isSsl = isSsl,
                    method = "",
                    scheme = scheme,
                    host = defaultHost,
                    port = defaultPort,
                    path = "",
                    requestHeaders = emptyList(),
                    requestBody = ByteArray(0),
                    responseStatusCode = statusLine.first,
                    responseReason = statusLine.second,
                    responseHeaders = headers,
                    responseBody = body.bytes,
                    responseTime = System.currentTimeMillis(),
                    state = HttpTransaction.STATE_COMPLETE,
                    error = null
                )
                CaptureRepository.add(orphan)
                onTransaction(orphan)
            }

            buf = buf.copyOfRange(total, buf.size)
            if (buf.isEmpty()) break
        }
        respBuf.reset()
        if (buf.isNotEmpty()) respBuf.write(buf, 0, buf.size)
    }

    // ---- 低层解析辅助 ----

    private data class BodyResult(val consumed: Int, val bytes: ByteArray)

    /** 从 [buf] 的 [start] 处解析消息体，返回消耗的字节数（含头部之后的体）与体内容；不完整返回 null */
    private fun extractBody(
        headers: List<Pair<String, String>>,
        buf: ByteArray,
        start: Int,
        isRequest: Boolean
    ): BodyResult? {
        val chunked = headers.any {
            it.first.equals("Transfer-Encoding", true) &&
                it.second.contains("chunked", true)
        }
        if (chunked) {
            return parseChunked(buf, start)
        }
        val contentLength = headers.firstOrNull {
            it.first.equals("Content-Length", true)
        }?.second?.trim()?.toLongOrNull()
        if (contentLength != null) {
            val len = contentLength.toInt()
            if (buf.size < start + len) return null
            return BodyResult(len, truncate(buf.copyOfRange(start, start + len)))
        }
        // 无 Content-Length 且非分块：请求通常无体；响应按连接关闭处理，吃掉剩余全部字节
        val remaining = buf.size - start
        if (isRequest) {
            return BodyResult(0, ByteArray(0))
        }
        return BodyResult(remaining, truncate(buf.copyOfRange(start, buf.size)))
    }

    private fun parseChunked(buf: ByteArray, start: Int): BodyResult? {
        var pos = start
        val out = ByteArrayOutputStream()
        while (true) {
            val lineEnd = indexOfCRLF(buf, pos)
            if (lineEnd < 0) return null
            val sizeLine = String(buf, pos, lineEnd - pos, StandardCharsets.US_ASCII).trim()
            val chunkSize = sizeLine.split(';').firstOrNull()?.toIntOrNull(16) ?: return null
            pos = lineEnd + 2
            if (chunkSize == 0) {
                // 块结束，后面是 trailer（可能为空）
                // 无 trailer 时直接是 \r\n；有 trailer 时是 header\r\n...\r\n\r\n
                val crlfEnd = indexOfCRLF(buf, pos)
                if (crlfEnd >= 0 && crlfEnd == pos) {
                    // 无 trailer：直接 \r\n
                    val consumed = (pos + 2) - start
                    return BodyResult(consumed, truncate(out.toByteArray()))
                }
                // 有 trailer：找 \r\n\r\n
                val trailEnd = indexOfHeaderEnd(buf, pos)
                if (trailEnd < 0) return null
                val consumed = (trailEnd + 4) - start
                return BodyResult(consumed, truncate(out.toByteArray()))
            }
            if (buf.size < pos + chunkSize + 2) return null
            out.write(buf, pos, chunkSize)
            pos += chunkSize + 2 // chunk 数据 + 结尾 CRLF
        }
    }

    private fun parseRequestLine(section: ByteArray): Pair<String, String>? {
        val firstLine = firstLineOf(section) ?: return null
        // METHOD SP request-target SP HTTP/version
        val sp1 = firstLine.indexOf(' ')
        if (sp1 <= 0) return null
        val sp2 = firstLine.indexOf(' ', sp1 + 1)
        val method = firstLine.substring(0, sp1)
        val target = if (sp2 > sp1) firstLine.substring(sp1 + 1, sp2) else firstLine.substring(sp1 + 1)
        return method to target
    }

    private fun parseStatusLine(section: ByteArray): Pair<Int, String>? {
        val firstLine = firstLineOf(section) ?: return null
        // HTTP/version SP code SP reason
        val sp1 = firstLine.indexOf(' ')
        if (sp1 <= 0) return null
        val sp2 = firstLine.indexOf(' ', sp1 + 1)
        val codeStr = if (sp2 > sp1) firstLine.substring(sp1 + 1, sp2) else firstLine.substring(sp1 + 1)
        val code = codeStr.toIntOrNull() ?: return null
        val reason = if (sp2 > sp1) firstLine.substring(sp2 + 1).trim() else ""
        return code to reason
    }

    private fun parseHeaders(section: ByteArray): List<Pair<String, String>> {
        val text = String(section, StandardCharsets.US_ASCII)
        val lines = text.split("\r\n")
        val result = ArrayList<Pair<String, String>>()
        for (i in 1 until lines.size) {
            val line = lines[i]
            if (line.isEmpty()) continue
            val idx = line.indexOf(':')
            if (idx <= 0) continue
            result.add(line.substring(0, idx).trim() to line.substring(idx + 1).trim())
        }
        return result
    }

    private fun firstLineOf(section: ByteArray): String? {
        val end = indexOfCRLF(section, 0)
        if (end < 0) return null
        return String(section, 0, end, StandardCharsets.US_ASCII)
    }

    private fun indexOfHeaderEnd(buf: ByteArray, from: Int = 0): Int {
        // 找到 \r\n\r\n
        var i = from
        while (i + 3 < buf.size) {
            if (buf[i] == '\r'.toByte() && buf[i + 1] == '\n'.toByte() &&
                buf[i + 2] == '\r'.toByte() && buf[i + 3] == '\n'.toByte()
            ) {
                return i
            }
            i++
        }
        return -1
    }

    private fun indexOfCRLF(buf: ByteArray, from: Int): Int {
        var i = from
        while (i + 1 < buf.size) {
            if (buf[i] == '\r'.toByte() && buf[i + 1] == '\n'.toByte()) {
                return i
            }
            i++
        }
        return -1
    }

    private fun truncate(bytes: ByteArray): ByteArray {
        return if (bytes.size > HttpTransaction.MAX_BODY) {
            bytes.copyOf(HttpTransaction.MAX_BODY)
        } else {
            bytes
        }
    }

    private fun String.toLongOrNull(): Long? = runCatching { toLong() }.getOrNull()
}
