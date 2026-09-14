package tech.qingge.onedroid.net

import tech.qingge.onedroid.net.IpPacketUtil.TCP_FLAG_ACK
import tech.qingge.onedroid.net.IpPacketUtil.TCP_FLAG_FIN
import tech.qingge.onedroid.net.IpPacketUtil.TCP_FLAG_PSH
import tech.qingge.onedroid.net.IpPacketUtil.TCP_FLAG_RST
import tech.qingge.onedroid.net.IpPacketUtil.TCP_FLAG_SYN
import tech.qingge.onedroid.service.CaptureVpnService
import tech.qingge.onedroid.util.LogUtil
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Random
import java.util.concurrent.LinkedBlockingQueue

/**
 * 基于 TUN 的 TCP 透明代理连接。
 *
 * 对手机上的 App 而言本类是"服务端"（终结来自 TUN 的 TCP 连接），
 * 对真实目标服务器而言本类是"客户端"（通过 protect 过的 socket 原样转发数据）。
 *
 * 在转发的同时，对明文字节流做 HTTP/1.x 解析（[HttpConnectionParser]），
 * 从而把每条 HTTP 请求作为一个事务展示；若检测到 TLS（首字节 0x16），
 * 则走 MITM 桥（[HttpsMitmBridge]）解密后同样解析 HTTPS 流量。
 */
class VpnTcpConnection(
    private val service: CaptureVpnService,
    private val srcIp: ByteArray,
    private val srcPort: Int,
    private val dstIp: ByteArray,
    private val dstPort: Int,
    private val clientIsn: Long
) {

    companion object {
        private const val TCP_MSS = 1460
        private const val WINDOW = 65535
        private const val CONNECT_TIMEOUT = 10_000

        @JvmStatic
        private val POISON = ByteArray(0)

        internal fun flagsToString(flags: Int): String {
            val sb = StringBuilder()
            if (flags and TCP_FLAG_FIN != 0) sb.append('F')
            if (flags and TCP_FLAG_SYN != 0) sb.append('S')
            if (flags and TCP_FLAG_RST != 0) sb.append('R')
            if (flags and TCP_FLAG_PSH != 0) sb.append('P')
            if (flags and TCP_FLAG_ACK != 0) sb.append('A')
            if (sb.isEmpty()) sb.append('-')
            return sb.toString()
        }
    }

    private val dstIpText = IpPacketUtil.ipToText(dstIp)

    /** 下一个期望来自客户端（App）的字节序号，初始越过 SYN */
    private var expectedSeq = (clientIsn + 1) and 0xFFFFFFFFL

    /** 我方（作为服务端）的初始序号，SYN 消耗一个序号 */
    private val ourIsn = Random().nextLong() and 0xFFFFFFFFL
    private var ourNxt = (ourIsn + 1) and 0xFFFFFFFFL

    @Volatile
    private var socket: Socket? = null

    /** socket 已连接且积压数据已排空，之后的客户端数据可直接转发 */
    @Volatile
    private var pipeReady = false

    @Volatile
    private var closed = false

    /** 连接建立前暂存客户端数据，保证转发顺序 */
    private val pendingToServer = ArrayList<ByteArray>()

    /** 串行化本连接的发包与序号状态变更 */
    private val sendLock = Any()

    // ---- HTTP / HTTPS 解析相关 ----
    private val initLock = Any()
    @Volatile
    private var initialized = false
    private var isTls = false
    private var httpParser: HttpConnectionParser? = null
    private var tlsBridge: HttpsMitmBridge? = null
    private var localSocket: Socket? = null
    private val clientWriteQueue = LinkedBlockingQueue<ByteArray>()
    private var localReaderThread: Thread? = null
    private var localWriterThread: Thread? = null
    /** TLS ClientHello 跨多 TCP 段时的缓冲 */
    private val tlsHandshakeBuffer = java.io.ByteArrayOutputStream()
    private val pendingTlsData = ArrayList<ByteArray>()

    private val onTransaction: (HttpTransaction) -> Unit = {
        LogUtil.d("HTTP tx #${it.id} ${it.method} ${it.url} -> ${it.responseStatusCode}")
    }

    fun handleSyn() {
        LogUtil.d("TCP conn handleSyn: $key clientIsn=$clientIsn ourIsn=$ourIsn expectedSeq=$expectedSeq dst=$dstIpText:$dstPort")
        synchronized(sendLock) {
            sendSegment(TCP_FLAG_SYN or TCP_FLAG_ACK, ourIsn, expectedSeq, null, TCP_MSS)
        }
        // 真正的上游连接在首次收到客户端数据时才建立（懒连接），保证数据顺序
    }

    fun handleClientSegment(flags: Int, seq: Long, payload: ByteArray) {
        if (closed) {
            return
        }
        val flagStr = flagsToString(flags)
        LogUtil.d("TCP rx $key flags=$flagStr seq=$seq ack=? payloadLen=${payload.size} expectedSeq=$expectedSeq")
        if (flags and TCP_FLAG_RST != 0) {
            LogUtil.d("TCP rx RST, closing $key")
            closeQuietly()
            return
        }
        if (flags and TCP_FLAG_SYN != 0) {
            // 客户端 SYN 重传：重新发送 SYN-ACK
            if (seq == clientIsn && payload.isEmpty()) {
                synchronized(sendLock) {
                    sendSegment(TCP_FLAG_SYN or TCP_FLAG_ACK, ourIsn, expectedSeq, null, TCP_MSS)
                }
            }
            return
        }
        val fin = flags and TCP_FLAG_FIN != 0
        var len = payload.size + if (fin) 1 else 0
        if (len == 0) {
            return // 纯 ACK，无需处理
        }

        var data = payload
        synchronized(sendLock) {
            if (IpPacketUtil.seqLT(seq, expectedSeq)) {
                // 重传包
                if (!IpPacketUtil.seqGE(seq + len, expectedSeq + 1)) {
                    // 完全重复，仅重复 ACK
                    sendSegment(TCP_FLAG_ACK, ourNxt, expectedSeq, null, 0)
                    return
                }
                // 部分重叠：丢弃已收到的前缀字节
                val skip = ((expectedSeq - seq) and 0xFFFFFFFFL).toInt()
                len -= skip
                if (skip < payload.size) {
                    data = payload.copyOfRange(skip, payload.size)
                } else {
                    data = ByteArray(0)
                }
            } else if (seq != expectedSeq) {
                // 序号出现空缺（TUN 场景罕见）：丢弃并重复 ACK 触发客户端重传
                sendSegment(TCP_FLAG_ACK, ourNxt, expectedSeq, null, 0)
                return
            }

            if (data.isNotEmpty() || fin) {
                // 延迟到初始化之后转发
                expectedSeq = (expectedSeq + len) and 0xFFFFFFFFL
                sendSegment(TCP_FLAG_ACK, ourNxt, expectedSeq, null, 0)
            }
        }

        if (data.isNotEmpty()) {
            LogUtil.d("TCP data -> init/forward $key len=${data.size} isTls=$isTls firstByte=${if (data.isNotEmpty()) data[0].toInt() and 0xFF else -1}")
            val ready = ensureInitialized(data)
            if (!ready) {
                // TLS ClientHello 还不完整，等待更多数据
                return
            }
            if (isTls) {
                feedClientTls(data, fin)
            } else {
                forwardToServer(data)
                httpParser?.feedRequest(data)
            }
        }

        if (fin) {
            if (isTls) {
                runCatching { localSocket?.shutdownOutput() }
            } else {
                // 客户端半关闭：告知服务端我方不再发送数据
                runCatching { socket?.shutdownOutput() }
            }
        }
    }

    private fun ensureInitialized(data: ByteArray): Boolean {
        if (initialized) return true
        synchronized(initLock) {
            if (initialized) return true
            val isTlsStart = data.isNotEmpty() && data[0] == 0x16.toByte()
            val hasBufferedTls = tlsHandshakeBuffer.size() > 0
            if (isTlsStart || hasBufferedTls) {
                // TLS ClientHello：可能跨多个 TCP 段
                tlsHandshakeBuffer.write(data, 0, data.size)
                val buf = tlsHandshakeBuffer.toByteArray()
                val sni = TlsUtil.parseSni(buf)
                if (sni != null) {
                    initialized = true
                    startTls(sni)
                    // 把之前缓冲的数据喂给 MITM 桥
                    if (buf.size > data.size) {
                        val prev = buf.copyOfRange(0, buf.size - data.size)
                        feedClientTls(prev, false)
                    }
                    return true
                }
                // SNI 还没解析出来
                if (buf.size > 16384) {
                    // 缓冲已超过 16KB，放弃等待，用 IP 直连
                    LogUtil.d("ensureInitialized: TLS handshake buffer > 16KB, giving up SNI, using dst IP")
                    initialized = true
                    startTls(dstIpText)
                    if (buf.size > data.size) {
                        val prev = buf.copyOfRange(0, buf.size - data.size)
                        feedClientTls(prev, false)
                    }
                    return true
                }
                LogUtil.d("ensureInitialized: waiting for more TLS handshake data, buffered=${buf.size}")
                return false
            } else {
                initialized = true
                startPlain()
                return true
            }
        }
    }

    private fun startPlain() {
        LogUtil.d("startPlain: $key -> $dstIpText:$dstPort (HTTP)")
        httpParser = HttpConnectionParser(
            isSsl = false,
            scheme = "http",
            defaultHost = dstIpText,
            defaultPort = dstPort,
            onTransaction = onTransaction
        )
        service.submitForwardTask { connectToServer() }
    }

    private fun startTls(host: String) {
        LogUtil.d("startTls: SNI host=$host dstPort=$dstPort $key")
        val leaf = HttpsCaCertUtil.getLeaf(host, service.filesDir)
        if (leaf == null) {
            // 未安装/生成 CA：退回透明转发（不解密，但保证 HTTPS 仍可正常使用）
            LogUtil.d("startTls: 无 CA，退回透明转发 host=$host")
            isTls = false
            startPlain()
            return
        }
        isTls = true
        tlsBridge = HttpsMitmBridge(host, dstIp, dstPort, leaf, onTransaction) { service.protectSocket(it) }
        val port = tlsBridge!!.start()
        LogUtil.d("startTls: MITM bridge port=$port for host=$host $key")
        if (port < 0) {
            LogUtil.e("VpnTcpConnection: HTTPS MITM 不可用，退回透明转发", Exception("HTTPS MITM 不可用"))
            isTls = false
            startPlain()
            return
        }
        val sock = Socket()
        val protectedOk = service.protectSocket(sock)
        LogUtil.d("startTls: protect localSocket=$protectedOk for $key")
        val connected = runCatching {
            sock.connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), CONNECT_TIMEOUT)
            sock.tcpNoDelay = true
        }.isSuccess
        LogUtil.d("startTls: localSocket connected=$connected for $key")
        if (!connected || closed) {
            runCatching { sock.close() }
            closeQuietly()
            return
        }
        localSocket = sock
        startLocalRelay(sock)
    }

    private fun startLocalRelay(sock: Socket) {
        val out = sock.getOutputStream()
        val input = sock.getInputStream()
        localWriterThread = Thread({
            try {
                while (true) {
                    val chunk = clientWriteQueue.take()
                    if (chunk === POISON) break
                    out.write(chunk)
                    out.flush()
                }
            } catch (_: Exception) {
            }
        }, "onedroid-tls-writer-$srcPort").apply { isDaemon = true; start() }

        localReaderThread = Thread({
            try {
                val buf = ByteArray(16384)
                while (!closed) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    sendToClient(buf.copyOf(n))
                }
                sendFinToClient()
            } catch (_: Exception) {
            } finally {
                closeQuietly()
            }
        }, "onedroid-tls-reader-$srcPort").apply { isDaemon = true; start() }
    }

    private fun feedClientTls(data: ByteArray, fin: Boolean) {
        if (closed) return
        clientWriteQueue.offer(data)
        if (fin) {
            runCatching { localSocket?.shutdownOutput() }
        }
    }

    private fun forwardToServer(data: ByteArray) {
        if (pipeReady) {
            val s = socket ?: return
            service.submitForwardTask {
                if (!closed) {
                    try {
                        s.getOutputStream().write(data)
                        LogUtil.d("forwardToServer: wrote ${data.size}B to server $key")
                    } catch (e: Exception) {
                        LogUtil.d("forwardToServer: error $key ${e.message}")
                        onPipeError()
                    }
                }
            }
        } else {
            synchronized(pendingToServer) {
                pendingToServer.add(data)
            }
            LogUtil.d("forwardToServer: pending ${data.size}B (pipe not ready) $key")
        }
    }

    private fun connectToServer() {
        if (closed) {
            return
        }
        LogUtil.d("connectToServer: $key -> $dstIpText:$dstPort")
        val s = Socket()
        val protectedOk = service.protectSocket(s)
        LogUtil.d("connectToServer: protect=$protectedOk for $key")
        if (!protectedOk) {
            LogUtil.e("connectToServer: protect FAILED for $key, socket will loop back VPN!", Exception("protect failed"))
        }
        val connectedOk = runCatching {
            s.connect(InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort), CONNECT_TIMEOUT)
            s.tcpNoDelay = true
        }.isSuccess
        LogUtil.d("connectToServer: connected=$connectedOk for $key")
        if (!connectedOk || closed) {
            runCatching { s.close() }
            sendRst()
            closeQuietly()
            return
        }
        socket = s
        Thread({ pumpServerToClient(s) }, "onedroid-tcp-$srcPort").apply { isDaemon = true; start() }
        // 排空任务在转发执行器队列中位于 connect 之后提交的所有转发任务之前执行，
        // 从而保证 pending 数据先于新数据写入 socket
        service.submitForwardTask {
            if (closed) {
                return@submitForwardTask
            }
            val pending = synchronized(pendingToServer) {
                val list = ArrayList(pendingToServer)
                pendingToServer.clear()
                list
            }
            try {
                val out = s.getOutputStream()
                pending.forEach { out.write(it) }
                pipeReady = true
            } catch (_: Exception) {
                onPipeError()
            }
        }
    }

    private fun pumpServerToClient(s: Socket) {
        val buffer = ByteArray(TCP_MSS)
        LogUtil.d("pumpServerToClient: start $key")
        try {
            val input = s.getInputStream()
            while (!closed) {
                val n = input.read(buffer)
                if (n <= 0) {
                    LogUtil.d("pumpServerToClient: EOF $key")
                    break
                }
                val payload = buffer.copyOf(n)
                LogUtil.d("pumpServerToClient: rx ${n}B from server $key")
                httpParser?.feedResponse(payload)
                sendToClient(payload)
            }
            // 服务端正常关闭：向客户端发送 FIN
            sendFinToClient()
            closeQuietly()
        } catch (e: Exception) {
            // 连接异常：向客户端发送 RST
            LogUtil.d("pumpServerToClient: error $key ${e.message}")
            sendRst()
            closeQuietly()
        }
    }

    /** 通过 TUN 把一段明文字节回送给客户端（App），同时推进序号 */
    private fun sendToClient(payload: ByteArray) {
        synchronized(sendLock) {
            if (closed) {
                return
            }
            sendSegment(TCP_FLAG_ACK or TCP_FLAG_PSH, ourNxt, expectedSeq, payload, 0)
            ourNxt = (ourNxt + payload.size) and 0xFFFFFFFFL
        }
    }

    private fun sendFinToClient() {
        synchronized(sendLock) {
            if (closed) {
                return
            }
            sendSegment(TCP_FLAG_FIN or TCP_FLAG_ACK, ourNxt, expectedSeq, null, 0)
            ourNxt = (ourNxt + 1) and 0xFFFFFFFFL
        }
    }

    private fun sendRst() {
        synchronized(sendLock) {
            if (!closed) {
                runCatching {
                    sendSegment(TCP_FLAG_RST or TCP_FLAG_ACK, ourNxt, expectedSeq, null, 0)
                }
            }
        }
    }

    /** 须在持有 sendLock 时调用 */
    private fun sendSegment(flags: Int, seq: Long, ack: Long, payload: ByteArray?, mss: Int) {
        val packet = IpPacketUtil.buildTcpPacket(
            dstIp, srcIp, dstPort, srcPort, seq, ack, flags, WINDOW, payload, mss
        )
        service.writeToTun(packet)
    }

    private fun onPipeError() {
        sendRst()
        closeQuietly()
    }

    fun closeQuietly() {
        synchronized(sendLock) {
            closed = true
        }
        runCatching { socket?.close() }
        socket = null
        runCatching { localSocket?.close() }
        localSocket = null
        clientWriteQueue.offer(POISON)
        tlsBridge?.shutdown()
        tlsBridge = null
        service.removeTcpConnection(this)
    }

    fun isClosed(): Boolean = closed

    val key: String = "${IpPacketUtil.ipToText(srcIp)}:$srcPort-${IpPacketUtil.ipToText(dstIp)}:$dstPort"

}
