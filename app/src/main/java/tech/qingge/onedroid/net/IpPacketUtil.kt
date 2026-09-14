package tech.qingge.onedroid.net

/**
 * IPv4 包解析与构造工具（仅服务 VPN 抓包使用）。
 */
object IpPacketUtil {

    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    const val TCP_FLAG_FIN = 0x01
    const val TCP_FLAG_SYN = 0x02
    const val TCP_FLAG_RST = 0x04
    const val TCP_FLAG_PSH = 0x08
    const val TCP_FLAG_ACK = 0x10

    private var ipId = 0

    /** 解析后的 IPv4 头信息（共享底层 buffer，不拷贝） */
    class IpHeader(
        val protocol: Int,
        val srcIp: ByteArray,
        val dstIp: ByteArray,
        /** IP 头长度（含选项） */
        val headerLength: Int,
        /** IP 总长度（头 + 载荷） */
        val totalLength: Int,
        /** 分片偏移（单位 8 字节） */
        val fragmentOffset: Int,
        val moreFragments: Boolean
    )

    /**
     * 解析 IPv4 头。返回 null 表示不是合法 IPv4 包。
     * [length] 为 TUN 中实际读到的字节数，可能小于 totalLength（不会）或被截断。
     */
    fun parseIp(packet: ByteArray, length: Int): IpHeader? {
        if (length < 20) {
            return null
        }
        val version = (packet[0].toInt() shr 4) and 0xF
        if (version != 4) {
            return null
        }
        val ihl = (packet[0].toInt() and 0xF) * 4
        if (ihl < 20 || length < ihl) {
            return null
        }
        val totalLength = u16(packet, 2)
        if (totalLength < ihl) {
            return null
        }
        val flagsFrag = u16(packet, 6)
        return IpHeader(
            protocol = packet[9].toInt() and 0xFF,
            srcIp = byteArrayOf(packet[12], packet[13], packet[14], packet[15]),
            dstIp = byteArrayOf(packet[16], packet[17], packet[18], packet[19]),
            headerLength = ihl,
            totalLength = minOf(totalLength, length),
            fragmentOffset = (flagsFrag and 0x1FFF),
            moreFragments = (flagsFrag and 0x2000) != 0
        )
    }

    /** TCP 头解析结果 */
    class TcpHeader(
        val srcPort: Int,
        val dstPort: Int,
        val seq: Long,
        val ack: Long,
        val flags: Int,
        /** TCP 头长度（含选项） */
        val headerLength: Int
    )

    fun parseTcp(packet: ByteArray, ipHeader: IpHeader): TcpHeader? {
        val offset = ipHeader.headerLength
        val minLength = offset + 20
        if (ipHeader.totalLength < minLength || packet.size < minLength) {
            return null
        }
        val dataOffset = ((packet[offset + 12].toInt() shr 4) and 0xF) * 4
        if (dataOffset < 20 || offset + dataOffset > ipHeader.totalLength) {
            return null
        }
        return TcpHeader(
            srcPort = u16(packet, offset),
            dstPort = u16(packet, offset + 2),
            seq = u32(packet, offset + 4),
            ack = u32(packet, offset + 8),
            flags = packet[offset + 13].toInt() and 0x3F,
            headerLength = dataOffset
        )
    }

    fun u16(packet: ByteArray, offset: Int): Int {
        return ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
    }

    fun u32(packet: ByteArray, offset: Int): Long {
        return ((packet[offset].toLong() and 0xFF) shl 24) or
            ((packet[offset + 1].toLong() and 0xFF) shl 16) or
            ((packet[offset + 2].toLong() and 0xFF) shl 8) or
            (packet[offset + 3].toLong() and 0xFF)
    }

    private fun put16(dst: ByteArray, offset: Int, value: Int) {
        dst[offset] = ((value shr 8) and 0xFF).toByte()
        dst[offset + 1] = (value and 0xFF).toByte()
    }

    private fun put32(dst: ByteArray, offset: Int, value: Long) {
        dst[offset] = ((value shr 24) and 0xFF).toByte()
        dst[offset + 1] = ((value shr 16) and 0xFF).toByte()
        dst[offset + 2] = ((value shr 8) and 0xFF).toByte()
        dst[offset + 3] = (value and 0xFF).toByte()
    }

    /**
     * 构造完整 IPv4 + TCP 包。
     * [mss] > 0 时在 SYN/SYN-ACK 中携带 MSS 选项。
     */
    fun buildTcpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int,
        payload: ByteArray?,
        mss: Int
    ): ByteArray {
        val tcpHeaderLength = if (mss > 0) 24 else 20
        val payloadLength = payload?.size ?: 0
        val totalLength = 20 + tcpHeaderLength + payloadLength
        val packet = ByteArray(totalLength)

        // IP 头
        packet[0] = 0x45
        packet[1] = 0x00
        put16(packet, 2, totalLength)
        put16(packet, 4, ipId++ and 0xFFFF)
        put16(packet, 6, 0x4000) // DF
        packet[8] = 64
        packet[9] = PROTO_TCP.toByte()
        put16(packet, 10, 0) // checksum 先置零
        System.arraycopy(srcIp, 0, packet, 12, 4)
        System.arraycopy(dstIp, 0, packet, 16, 4)
        put16(packet, 10, checksum(packet, 0, 20))

        // TCP 头
        val t = 20
        put16(packet, t, srcPort)
        put16(packet, t + 2, dstPort)
        put32(packet, t + 4, seq)
        put32(packet, t + 8, ack)
        packet[t + 12] = ((tcpHeaderLength / 4) shl 4).toByte()
        packet[t + 13] = flags.toByte()
        put16(packet, t + 14, window)
        put16(packet, t + 16, 0) // checksum 先置零
        put16(packet, t + 18, 0) // urgent pointer
        if (mss > 0) {
            packet[t + 20] = 0x02
            packet[t + 21] = 0x04
            put16(packet, t + 22, mss)
        }
        payload?.let { System.arraycopy(it, 0, packet, t + tcpHeaderLength, it.size) }

        // TCP 校验和（含伪头）
        var sum = pseudoHeaderSum(srcIp, dstIp, PROTO_TCP, tcpHeaderLength + payloadLength)
        sum += sumRange(packet, t, tcpHeaderLength + payloadLength)
        put16(packet, t + 16, finishChecksum(sum))
        return packet
    }

    /** 构造完整 IPv4 + UDP 包 */
    fun buildUdpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLength = 8 + payload.size
        val totalLength = 20 + udpLength
        val packet = ByteArray(totalLength)

        // IP 头
        packet[0] = 0x45
        packet[1] = 0x00
        put16(packet, 2, totalLength)
        put16(packet, 4, ipId++ and 0xFFFF)
        put16(packet, 6, 0x4000) // DF
        packet[8] = 64
        packet[9] = PROTO_UDP.toByte()
        put16(packet, 10, 0)
        System.arraycopy(srcIp, 0, packet, 12, 4)
        System.arraycopy(dstIp, 0, packet, 16, 4)
        put16(packet, 10, checksum(packet, 0, 20))

        // UDP 头
        val t = 20
        put16(packet, t, srcPort)
        put16(packet, t + 2, dstPort)
        put16(packet, t + 4, udpLength)
        put16(packet, t + 6, 0) // checksum 先置零
        System.arraycopy(payload, 0, packet, t + 8, payload.size)

        // UDP 校验和（含伪头），结果为 0 时须写 0xFFFF（0 表示未计算）
        var sum = pseudoHeaderSum(srcIp, dstIp, PROTO_UDP, udpLength)
        sum += sumRange(packet, t, udpLength)
        var result = finishChecksum(sum)
        if (result == 0) {
            result = 0xFFFF
        }
        put16(packet, t + 6, result)
        return packet
    }

    private fun pseudoHeaderSum(srcIp: ByteArray, dstIp: ByteArray, protocol: Int, length: Int): Int {
        var sum = 0
        for (i in 0 until 4 step 2) {
            sum += ((srcIp[i].toInt() and 0xFF) shl 8) or (srcIp[i + 1].toInt() and 0xFF)
            sum += ((dstIp[i].toInt() and 0xFF) shl 8) or (dstIp[i + 1].toInt() and 0xFF)
        }
        sum += protocol + length
        return sum
    }

    private fun sumRange(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i < end - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (end - i == 1) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        return sum
    }

    /** 计算标准 IP 校验和（[offset, offset+length) 区间，checksum 字段须已置零） */
    fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        return finishChecksum(sumRange(data, offset, length))
    }

    private fun finishChecksum(sum: Int): Int {
        var s = sum
        while (s shr 16 != 0) {
            s = (s and 0xFFFF) + (s shr 16)
        }
        return s.inv() and 0xFFFF
    }

    fun ipToText(ip: ByteArray): String {
        return "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}." +
            "${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"
    }

    /** TCP 序号比较（mod 2^32）：a >= b */
    fun seqGE(a: Long, b: Long): Boolean {
        return (a - b) and 0xFFFFFFFFL < 0x80000000L
    }

    /** TCP 序号比较（mod 2^32）：a < b */
    fun seqLT(a: Long, b: Long): Boolean {
        return !seqGE(a, b)
    }

}
