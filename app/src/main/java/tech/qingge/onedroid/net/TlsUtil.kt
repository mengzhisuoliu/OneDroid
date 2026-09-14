package tech.qingge.onedroid.net

import tech.qingge.onedroid.util.LogUtil

/**
 * TLS 辅助：从 ClientHello 中解析 SNI 主机名（用于 HTTPS MITM 选择叶子证书）。
 */
object TlsUtil {

    /**
     * 解析 TLS ClientHello 里的 SNI（server_name）。
     * 返回 null 表示不是 ClientHello 或解析失败。
     */
    fun parseSni(data: ByteArray): String? {
        // 记录头：type(1)=0x16, version(2), length(2)
        if (data.size < 5) {
            LogUtil.d("parseSni: data too short (${data.size} < 5)")
            return null
        }
        if (data[0] != 0x16.toByte()) {
            LogUtil.d("parseSni: not TLS handshake (first byte=${data[0].toInt() and 0xFF})")
            return null
        }
        val recLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        LogUtil.d("parseSni: recLen=$recLen dataSize=${data.size}")
        var p = 5
        if (p + 4 > data.size) {
            LogUtil.d("parseSni: handshake header beyond data (p=$p + 4 > ${data.size})")
            return null
        }
        // 握手头：type(1)=0x01, length(3)
        if (data[p] != 0x01.toByte()) {
            LogUtil.d("parseSni: not ClientHello (hsType=${data[p].toInt() and 0xFF})")
            return null
        }
        val hsLen = ((data[p + 1].toInt() and 0xFF) shl 16) or
            ((data[p + 2].toInt() and 0xFF) shl 8) or (data[p + 3].toInt() and 0xFF)
        p += 4
        val hsEnd = p + hsLen
        LogUtil.d("parseSni: hsLen=$hsLen hsEnd=$hsEnd dataSize=${data.size}")
        if (hsEnd > data.size) {
            LogUtil.d("parseSni: handshake split across segments (hsEnd=$hsEnd > dataSize=${data.size})")
            return null
        }
        // version(2) + random(32)
        p += 2 + 32
        if (p >= hsEnd) {
            LogUtil.d("parseSni: ran past handshake end after random")
            return null
        }
        // session_id
        val sidLen = data[p].toInt() and 0xFF
        p += 1 + sidLen
        if (p + 2 > hsEnd) {
            LogUtil.d("parseSni: ran past handshake end after session_id")
            return null
        }
        // cipher_suites
        val csLen = ((data[p].toInt() and 0xFF) shl 8) or (data[p + 1].toInt() and 0xFF)
        p += 2 + csLen
        if (p + 1 > hsEnd) {
            LogUtil.d("parseSni: ran past handshake end after cipher_suites")
            return null
        }
        // compression_methods
        val compLen = data[p].toInt() and 0xFF
        p += 1 + compLen
        if (p + 2 > hsEnd) {
            LogUtil.d("parseSni: ran past handshake end after compression_methods")
            return null
        }
        // extensions
        val extLen = ((data[p].toInt() and 0xFF) shl 8) or (data[p + 1].toInt() and 0xFF)
        p += 2
        val extEnd = p + extLen
        LogUtil.d("parseSni: extLen=$extLen extEnd=$extEnd")
        if (extEnd > hsEnd) {
            LogUtil.d("parseSni: extensions past handshake end")
            return null
        }
        while (p + 4 <= extEnd) {
            val type = ((data[p].toInt() and 0xFF) shl 8) or (data[p + 1].toInt() and 0xFF)
            val len = ((data[p + 2].toInt() and 0xFF) shl 8) or (data[p + 3].toInt() and 0xFF)
            p += 4
            if (type == 0x0000) {
                // server_name 扩展
                if (p + 2 > extEnd) return null
                val listLen = ((data[p].toInt() and 0xFF) shl 8) or (data[p + 1].toInt() and 0xFF)
                var q = p + 2
                val listEnd = q + listLen
                if (listEnd > extEnd) return null
                while (q + 3 <= listEnd) {
                    val nameType = data[q].toInt() and 0xFF
                    val nameLen = ((data[q + 1].toInt() and 0xFF) shl 8) or (data[q + 2].toInt() and 0xFF)
                    q += 3
                    if (nameType == 0x00) { // host_name
                        if (q + nameLen > listEnd) return null
                        val host = String(data, q, nameLen, Charsets.US_ASCII)
                        LogUtil.d("parseSni: found SNI host=$host")
                        return host
                    }
                    q += nameLen
                }
                LogUtil.d("parseSni: SNI extension found but no host_name")
                return null
            }
            p += len
        }
        LogUtil.d("parseSni: no SNI extension found in ClientHello")
        return null
    }
}
