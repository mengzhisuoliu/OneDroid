package tech.qingge.onedroid.net

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.Charset
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

/**
 * HTTP 报文展示辅助：处理压缩解码、字符集、JSON 格式化、二进制识别。
 */
object HttpUtil {

    /** 把头部 + 体字节转成可读文本；二进制或过大时返回占位说明 */
    fun bodyToText(headers: List<Pair<String, String>>, body: ByteArray): String {
        if (body.isEmpty()) return ""
        val decoded = decodeContentEncoding(headers, body) ?: body
        if (decoded.isEmpty()) return ""

        val isText = run {
            val ct = headers.firstOrNull { it.first.equals("Content-Type", true) }?.second ?: ""
            ct.contains("text", true) || ct.contains("json", true) ||
                ct.contains("xml", true) || ct.contains("javascript", true) ||
                ct.contains("html", true)
        }
        val charset = extractCharset(headers) ?: Charsets.UTF_8

        if (!isText) {
            // 尝试判断是否为可打印文本
            if (isMostlyPrintable(decoded)) {
                return trySafe { String(decoded, charset) } ?: binaryNote(decoded)
            }
            return binaryNote(decoded)
        }

        val raw = trySafe { String(decoded, charset) } ?: return binaryNote(decoded)
        val ct = headers.firstOrNull { it.first.equals("Content-Type", true) }?.second ?: ""
        return if (ct.contains("json", true)) {
            prettyJson(raw)
        } else {
            raw
        }
    }

    /** 头部文本：每行 `Name: Value`，便于在 TextView 中展示 */
    fun headersToText(headers: List<Pair<String, String>>): String {
        if (headers.isEmpty()) return "(无)"
        val sb = StringBuilder()
        headers.forEachIndexed { i, (k, v) ->
            if (i > 0) sb.append('\n')
            sb.append(k).append(": ").append(v)
        }
        return sb.toString()
    }

    private fun decodeContentEncoding(
        headers: List<Pair<String, String>>,
        body: ByteArray
    ): ByteArray? {
        val enc = headers.firstOrNull { it.first.equals("Content-Encoding", true) }?.second
            ?: return body
        return try {
            when {
                enc.contains("gzip", true) -> gzipDecode(body)
                enc.contains("deflate", true) -> deflateDecode(body)
                else -> body
            }
        } catch (_: Exception) {
            body
        }
    }

    private fun gzipDecode(bytes: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPInputStream(ByteArrayInputStream(bytes)).use { it.copyTo(out) }
        return out.toByteArray()
    }

    private fun deflateDecode(bytes: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        InflaterInputStream(ByteArrayInputStream(bytes), Inflater(true)).use { it.copyTo(out) }
        return out.toByteArray()
    }

    private fun extractCharset(headers: List<Pair<String, String>>): Charset? {
        val ct = headers.firstOrNull { it.first.equals("Content-Type", true) }?.second ?: return null
        val idx = ct.indexOf("charset=", ignoreCase = true)
        if (idx < 0) return null
        val name = ct.substring(idx + 8).trim().trim('"')
        return runCatching { Charset.forName(name) }.getOrNull()
    }

    private fun isMostlyPrintable(bytes: ByteArray): Boolean {
        if (bytes.size > 512) return false
        var printable = 0
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c == 9 || c == 10 || c == 13 || (c in 32..126)) printable++
        }
        return printable * 100 / bytes.size > 85
    }

    private fun binaryNote(bytes: ByteArray): String {
        return "[二进制内容，共 ${bytes.size} 字节]"
    }

    private fun trySafe(block: () -> String): String? = runCatching(block).getOrNull()

    /** 极简 JSON 美化：按括号缩进换行，不依赖第三方库 */
    private fun prettyJson(raw: String): String {
        val compact = raw.trim()
        if (!compact.startsWith("{") && !compact.startsWith("[")) return raw
        val sb = StringBuilder()
        var indent = 0
        var i = 0
        val len = compact.length
        while (i < len) {
            val c = compact[i]
            when (c) {
                '{', '[' -> {
                    sb.append(c).append('\n')
                    indent += 2
                    sb.append(" ".repeat(indent))
                }
                '}', ']' -> {
                    indent -= 2
                    sb.append('\n').append(" ".repeat(indent)).append(c)
                }
                ',' -> {
                    sb.append(c).append('\n').append(" ".repeat(indent))
                    // 跳过紧跟的空白
                    i++
                    while (i < len && compact[i] == ' ') i++
                    continue
                }
                ':' -> {
                    sb.append(": ")
                }
                '"' -> {
                    // 字符串原样拷贝，直到匹配未转义的引号
                    sb.append(c)
                    i++
                    while (i < len) {
                        val ch = compact[i]
                        sb.append(ch)
                        if (ch == '\\') {
                            if (i + 1 < len) {
                                sb.append(compact[i + 1])
                                i += 2
                                continue
                            }
                        } else if (ch == '"') {
                            i++
                            break
                        }
                        i++
                    }
                    continue
                }
                ' ', '\t', '\n', '\r' -> {
                    // 折叠空白（字符串外）
                }
                else -> sb.append(c)
            }
            i++
        }
        return sb.toString()
    }
}
