package tech.qingge.onedroid.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * IpPacketUtil 单元测试：验证 IP/TCP 包构造与解析的正确性。
 */
class IpPacketUtilTest {

    private val srcIp = byteArrayOf(10, 0, 0, 1)
    private val dstIp = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34)

    @Test
    fun buildTcpPacket_noMss_dataOffsetIs5() {
        val pkt = IpPacketUtil.buildTcpPacket(
            srcIp, dstIp, 12345, 80, 1000L, 2000L,
            IpPacketUtil.TCP_FLAG_ACK, 65535, null, 0
        )
        // TCP 数据偏移在 byte 32（IP头20 + TCP偏移12）的高4位，应为 5（20字节头）
        val dataOffset = (pkt[32].toInt() shr 4) and 0xF
        assertEquals(5, dataOffset)
    }

    @Test
    fun buildTcpPacket_withMss_dataOffsetIs6() {
        val pkt = IpPacketUtil.buildTcpPacket(
            srcIp, dstIp, 12345, 80, 1000L, 2000L,
            IpPacketUtil.TCP_FLAG_SYN or IpPacketUtil.TCP_FLAG_ACK, 65535, null, 1460
        )
        // TCP 数据偏移应为 6（24字节头，含 MSS 选项）
        val dataOffset = (pkt[32].toInt() shr 4) and 0xF
        assertEquals(6, dataOffset)
    }

    @Test
    fun buildTcpPacket_ipChecksumValid() {
        val pkt = IpPacketUtil.buildTcpPacket(
            srcIp, dstIp, 12345, 80, 1000L, 2000L,
            IpPacketUtil.TCP_FLAG_ACK or IpPacketUtil.TCP_FLAG_PSH, 65535,
            "GET / HTTP/1.1\r\n\r\n".toByteArray(), 0
        )
        // IP 校验和（byte 10-11）应为 0（校验和覆盖整个 IP 头后为 0）
        var sum = 0
        for (i in 0 until 20 step 2) {
            sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
        }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFF, sum)
    }

    @Test
    fun buildTcpPacket_tcpChecksumValid() {
        val payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
        val pkt = IpPacketUtil.buildTcpPacket(
            srcIp, dstIp, 12345, 80, 1000L, 2000L,
            IpPacketUtil.TCP_FLAG_ACK or IpPacketUtil.TCP_FLAG_PSH, 65535, payload, 0
        )
        // TCP 校验和在 byte 36-37（IP头20 + TCP校验和偏移16）
        val tcpLen = pkt.size - 20
        // 伪头
        var sum = 0
        for (i in 0 until 4 step 2) {
            sum += ((srcIp[i].toInt() and 0xFF) shl 8) or (srcIp[i + 1].toInt() and 0xFF)
            sum += ((dstIp[i].toInt() and 0xFF) shl 8) or (dstIp[i + 1].toInt() and 0xFF)
        }
        sum += IpPacketUtil.PROTO_TCP + tcpLen
        // TCP 段
        var i = 20
        val end = pkt.size
        while (i < end - 1) {
            sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (end - i == 1) {
            sum += (pkt[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFF, sum)
    }

    @Test
    fun parseIp_roundtrip() {
        val payload = "test data".toByteArray()
        val pkt = IpPacketUtil.buildTcpPacket(
            srcIp, dstIp, 12345, 80, 1000L, 2000L,
            IpPacketUtil.TCP_FLAG_ACK, 65535, payload, 0
        )
        val header = IpPacketUtil.parseIp(pkt, pkt.size)
        assertNotNull(header)
        assertEquals(IpPacketUtil.PROTO_TCP, header!!.protocol)
        assertEquals(20, header.headerLength)
        assertArrayEquals(srcIp, header.srcIp)
        assertArrayEquals(dstIp, header.dstIp)
    }

    @Test
    fun parseTcp_roundtrip() {
        val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        val pkt = IpPacketUtil.buildTcpPacket(
            srcIp, dstIp, 12345, 80, 1000000L, 2000000L,
            IpPacketUtil.TCP_FLAG_ACK or IpPacketUtil.TCP_FLAG_PSH, 65535, payload, 0
        )
        val ipHeader = IpPacketUtil.parseIp(pkt, pkt.size)!!
        val tcpHeader = IpPacketUtil.parseTcp(pkt, ipHeader)!!
        assertEquals(12345, tcpHeader.srcPort)
        assertEquals(80, tcpHeader.dstPort)
        assertEquals(1000000L, tcpHeader.seq)
        assertEquals(2000000L, tcpHeader.ack)
        assertEquals(IpPacketUtil.TCP_FLAG_ACK or IpPacketUtil.TCP_FLAG_PSH, tcpHeader.flags)
        assertEquals(20, tcpHeader.headerLength)
    }

    @Test
    fun parseTcp_mssOption() {
        val pkt = IpPacketUtil.buildTcpPacket(
            srcIp, dstIp, 12345, 80, 1000L, 2000L,
            IpPacketUtil.TCP_FLAG_SYN or IpPacketUtil.TCP_FLAG_ACK, 65535, null, 1460
        )
        val ipHeader = IpPacketUtil.parseIp(pkt, pkt.size)!!
        val tcpHeader = IpPacketUtil.parseTcp(pkt, ipHeader)!!
        assertEquals(24, tcpHeader.headerLength)
        // MSS 选项在 TCP 偏移 20: kind=0x02, len=0x04, value=1460
        val tcpStart = 20
        assertEquals(0x02, pkt[tcpStart + 20].toInt() and 0xFF)
        assertEquals(0x04, pkt[tcpStart + 21].toInt() and 0xFF)
        val mss = ((pkt[tcpStart + 22].toInt() and 0xFF) shl 8) or (pkt[tcpStart + 23].toInt() and 0xFF)
        assertEquals(1460, mss)
    }

    @Test
    fun seqGE_basic() {
        assertTrue(IpPacketUtil.seqGE(100, 100))
        assertTrue(IpPacketUtil.seqGE(200, 100))
        assertTrue(!IpPacketUtil.seqGE(100, 200))
    }

    @Test
    fun seqGE_wraparound() {
        // 序号回绕：0xFFFFFFFF 附近应视为接近 0
        assertTrue(IpPacketUtil.seqGE(0L, 0xFFFFFFFFL))
        assertTrue(IpPacketUtil.seqGE(100L, 0xFFFFFFFFL))
        assertTrue(!IpPacketUtil.seqGE(0x80000000L, 0xFFFFFFFFL))
    }

    @Test
    fun seqLT_oppositeOfSeqGE() {
        assertEquals(!IpPacketUtil.seqGE(100, 200), IpPacketUtil.seqLT(100, 200))
        assertEquals(!IpPacketUtil.seqGE(200, 100), IpPacketUtil.seqLT(200, 100))
        assertEquals(!IpPacketUtil.seqGE(100, 100), IpPacketUtil.seqLT(100, 100))
    }

    @Test
    fun ipToText_correct() {
        assertEquals("10.0.0.1", IpPacketUtil.ipToText(srcIp))
        assertEquals("93.184.216.34", IpPacketUtil.ipToText(dstIp))
        assertEquals("127.0.0.1", IpPacketUtil.ipToText(byteArrayOf(127, 0, 0, 1)))
    }

    @Test
    fun parseIp_invalidReturnsNull() {
        assertNull(IpPacketUtil.parseIp(ByteArray(10), 10)) // 太短
        val v6 = ByteArray(40)
        v6[0] = 0x60 // IPv6
        assertNull(IpPacketUtil.parseIp(v6, 40))
    }

    @Test
    fun buildUdpPacket_checksumValid() {
        val payload = "test payload".toByteArray()
        val pkt = IpPacketUtil.buildUdpPacket(srcIp, dstIp, 12345, 53, payload)
        // IP 校验和
        var ipSum = 0
        for (i in 0 until 20 step 2) {
            ipSum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
        }
        while (ipSum shr 16 != 0) ipSum = (ipSum and 0xFFFF) + (ipSum shr 16)
        assertEquals(0xFFFF, ipSum)

        // UDP 校验和（含伪头）
        val udpLen = pkt.size - 20
        var sum = 0
        for (i in 0 until 4 step 2) {
            sum += ((srcIp[i].toInt() and 0xFF) shl 8) or (srcIp[i + 1].toInt() and 0xFF)
            sum += ((dstIp[i].toInt() and 0xFF) shl 8) or (dstIp[i + 1].toInt() and 0xFF)
        }
        sum += IpPacketUtil.PROTO_UDP + udpLen
        var i = 20
        val end = pkt.size
        while (i < end - 1) {
            sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (end - i == 1) {
            sum += (pkt[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFF, sum)
    }

    private fun assertArrayEquals(a: ByteArray, b: ByteArray) {
        assertEquals(a.size, b.size)
        for (i in a.indices) assertEquals(a[i], b[i])
    }
}