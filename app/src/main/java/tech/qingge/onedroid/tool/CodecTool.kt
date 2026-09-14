package tech.qingge.onedroid.tool

import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Base64

object CodecTool {

    enum class Format { BASE64, URL, HEX, UNICODE }

    fun encode(input: String, format: Format): String = when (format) {
        Format.BASE64 -> base64Encode(input)
        Format.URL -> urlEncode(input)
        Format.HEX -> hexEncode(input)
        Format.UNICODE -> unicodeEncode(input)
    }

    fun decode(input: String, format: Format): String = when (format) {
        Format.BASE64 -> base64Decode(input)
        Format.URL -> urlDecode(input)
        Format.HEX -> hexDecode(input)
        Format.UNICODE -> unicodeDecode(input)
    }

    fun base64Encode(input: String): String =
        Base64.getEncoder().encodeToString(input.toByteArray(StandardCharsets.UTF_8))

    fun base64Decode(input: String): String =
        String(Base64.getDecoder().decode(input), StandardCharsets.UTF_8)

    fun urlEncode(input: String): String =
        URLEncoder.encode(input, StandardCharsets.UTF_8.name())

    fun urlDecode(input: String): String =
        URLDecoder.decode(input, StandardCharsets.UTF_8.name())

    fun hexEncode(input: String): String =
        input.toByteArray(StandardCharsets.UTF_8).joinToString("") { "%02x".format(it) }

    fun hexDecode(input: String): String {
        val clean = input.replace(" ", "").replace("\n", "")
        require(clean.length % 2 == 0) { "Hex 字符串长度必须为偶数" }
        val bytes = ByteArray(clean.length / 2) { i ->
            ((Character.digit(clean[i * 2], 16) shl 4) + Character.digit(clean[i * 2 + 1], 16)).toByte()
        }
        return String(bytes, StandardCharsets.UTF_8)
    }

    fun unicodeEncode(input: String): String =
        StringBuilder(input.length * 6).apply {
            for (ch in input) {
                if (ch.code < 128) {
                    append(ch)
                } else {
                    append("\\u")
                    append("%04x".format(ch.code))
                }
            }
        }.toString()

    fun unicodeDecode(input: String): String {
        val sb = StringBuilder(input.length)
        var i = 0
        while (i < input.length) {
            if (i + 6 <= input.length && input[i] == '\\' && input[i + 1] == 'u') {
                val hex = input.substring(i + 2, i + 6)
                try {
                    sb.append(hex.toInt(16).toChar())
                    i += 6
                    continue
                } catch (_: NumberFormatException) {
                }
            }
            sb.append(input[i])
            i++
        }
        return sb.toString()
    }
}