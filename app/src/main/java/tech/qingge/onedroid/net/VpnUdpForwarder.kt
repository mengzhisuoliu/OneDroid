package tech.qingge.onedroid.net

import tech.qingge.onedroid.service.CaptureVpnService
import tech.qingge.onedroid.util.LogUtil
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * 基于 TUN 的 UDP 转发器：为每个五元组流维护一个 protect 过的 DatagramSocket，
 * 把 App 发出的 UDP 载荷原样发往真实目标，把响应按原路径回注 TUN。
 */
class VpnUdpForwarder(private val service: CaptureVpnService) {

    companion object {
        private const val IDLE_TIMEOUT_MS = 60_000
        private const val SWEEP_INTERVAL_S = 30L
    }

    private inner class UdpFlow(
        val key: String,
        val socket: DatagramSocket,
        val srcIp: ByteArray,
        val srcPort: Int,
        val dstIp: ByteArray,
        val dstPort: Int
    ) {
        @Volatile
        var lastActive = System.currentTimeMillis()
    }

    private val flows = ConcurrentHashMap<String, UdpFlow>()

    private val receiveExecutor = Executors.newCachedThreadPool { r ->
        Thread(r, "onedroid-udp-rx").apply { isDaemon = true }
    }

    private val sweepExecutor = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "onedroid-udp-sweep").apply { isDaemon = true }
    }

    init {
        sweepExecutor.scheduleWithFixedDelay(
            { sweepIdleFlows() }, SWEEP_INTERVAL_S, SWEEP_INTERVAL_S, TimeUnit.SECONDS
        )
    }

    fun handle(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, payload: ByteArray) {
        val key = "${IpPacketUtil.ipToText(srcIp)}:$srcPort->" +
            "${IpPacketUtil.ipToText(dstIp)}:$dstPort"
        while (true) {
            val existing = flows[key]
            if (existing != null) {
                existing.lastActive = System.currentTimeMillis()
                send(existing, payload)
                return
            }
            val created = createFlow(key, srcIp, srcPort, dstIp, dstPort) ?: return
            val raced = flows.putIfAbsent(key, created)
            if (raced != null) {
                closeSocket(created)
                raced.lastActive = System.currentTimeMillis()
                send(raced, payload)
                return
            }
            LogUtil.d("UdpForwarder: new flow $key")
            send(created, payload)
            return
        }
    }

    private fun createFlow(
        key: String,
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int
    ): UdpFlow? {
        return try {
            val socket = DatagramSocket()
            val protectedOk = service.protect(socket)
            if (!protectedOk) {
                LogUtil.d("UdpForwarder: protect failed for $key")
            }
            // 先 connect 再启动接收循环，避免 receive 持锁导致 connect 阻塞
            socket.connect(InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort))
            UdpFlow(key, socket, srcIp, srcPort, dstIp, dstPort).also { flow ->
                startReceiveLoop(flow)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun send(flow: UdpFlow, payload: ByteArray) {
        try {
            flow.socket.send(DatagramPacket(payload, payload.size))
        } catch (_: Exception) {
            removeFlow(flow)
        }
    }

    private fun startReceiveLoop(flow: UdpFlow) {
        receiveExecutor.execute {
            val socket = flow.socket
            runCatching { socket.soTimeout = IDLE_TIMEOUT_MS }
            val buffer = ByteArray(65535)
            try {
                while (flows.containsKey(flow.key)) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet) // 超时或 socket 关闭会抛异常退出循环
                    val n = packet.length
                    if (n <= 0) {
                        continue
                    }
                    flow.lastActive = System.currentTimeMillis()
                    // socket 已 connect，只会收到来自原目标的数据，
                    // 原样回注给发起方（src/dst 方向对调）
                    val reply = IpPacketUtil.buildUdpPacket(
                        flow.dstIp, flow.srcIp, flow.dstPort, flow.srcPort,
                        buffer.copyOf(n)
                    )
                    service.writeToTun(reply)
                }
            } catch (_: Exception) {
                // socket 超时/关闭，正常退出
            }
            removeFlow(flow)
        }
    }

    private fun removeFlow(flow: UdpFlow) {
        flows.remove(flow.key, flow)
        closeSocket(flow)
    }

    private fun closeSocket(flow: UdpFlow) {
        runCatching { flow.socket.close() }
    }

    private fun sweepIdleFlows() {
        val now = System.currentTimeMillis()
        flows.values.removeIf { flow ->
            val idle = now - flow.lastActive > IDLE_TIMEOUT_MS
            if (idle) {
                closeSocket(flow)
            }
            idle
        }
    }

    fun shutdown() {
        sweepExecutor.shutdownNow()
        flows.values.forEach { closeSocket(it) }
        flows.clear()
        receiveExecutor.shutdownNow()
    }

}
