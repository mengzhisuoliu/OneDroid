package tech.qingge.onedroid.net

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * VpnTcpConnection.flagsToString 单元测试。
 */
class VpnTcpConnectionFlagsTest {

    @Test
    fun syn() {
        assertEquals("S", VpnTcpConnection.flagsToString(IpPacketUtil.TCP_FLAG_SYN))
    }

    @Test
    fun synAck() {
        assertEquals("SA", VpnTcpConnection.flagsToString(
            IpPacketUtil.TCP_FLAG_SYN or IpPacketUtil.TCP_FLAG_ACK))
    }

    @Test
    fun pshAck() {
        assertEquals("PA", VpnTcpConnection.flagsToString(
            IpPacketUtil.TCP_FLAG_PSH or IpPacketUtil.TCP_FLAG_ACK))
    }

    @Test
    fun finAck() {
        assertEquals("FA", VpnTcpConnection.flagsToString(
            IpPacketUtil.TCP_FLAG_FIN or IpPacketUtil.TCP_FLAG_ACK))
    }

    @Test
    fun rst() {
        assertEquals("R", VpnTcpConnection.flagsToString(IpPacketUtil.TCP_FLAG_RST))
    }

    @Test
    fun pureAck() {
        assertEquals("A", VpnTcpConnection.flagsToString(IpPacketUtil.TCP_FLAG_ACK))
    }

    @Test
    fun empty() {
        assertEquals("-", VpnTcpConnection.flagsToString(0))
    }

    @Test
    fun allFlags() {
        val all = IpPacketUtil.TCP_FLAG_FIN or IpPacketUtil.TCP_FLAG_SYN or
            IpPacketUtil.TCP_FLAG_RST or IpPacketUtil.TCP_FLAG_PSH or
            IpPacketUtil.TCP_FLAG_ACK
        assertEquals("FSRPA", VpnTcpConnection.flagsToString(all))
    }
}