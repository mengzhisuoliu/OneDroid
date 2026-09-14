package tech.qingge.onedroid.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.util.Log
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import tech.qingge.onedroid.Constants
import tech.qingge.onedroid.R
import tech.qingge.onedroid.net.CaptureRepository
import tech.qingge.onedroid.net.IpPacketUtil
import tech.qingge.onedroid.net.PcapWriter
import tech.qingge.onedroid.net.VpnTcpConnection
import tech.qingge.onedroid.net.VpnUdpForwarder
import tech.qingge.onedroid.ui.activity.NetCaptureActivity
import tech.qingge.onedroid.util.LogUtil
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

/**
 * 基于 VpnService 的非 root 抓包服务：
 * 建立 TUN 网卡拦截全部 IPv4 流量，TCP/UDP 通过 protect 过的 socket 原样转发到真实目标，
 * 响应包回注 TUN，同时把双向数据写入 pcap 文件（LINKTYPE_RAW），无需 root 和 tcpdump。
 */
class CaptureVpnService : VpnService() {

    companion object {
        const val ACTION_STOP = "tech.qingge.onedroid.action.STOP_CAPTURE"

        private const val MTU = 1500
        private const val VPN_ADDRESS = "10.111.222.1"
        private const val MAX_PENDING_PACKETS = 5000

        @Volatile
        var isRunning = false
            private set

        @Volatile
        var pcapPath: String? = null
            private set

        /** 指定只抓取该应用（包名），null 表示抓取全部应用；下次开始抓包时生效 */
        @Volatile
        var targetPackage: String? = null

        val packetCount = AtomicLong()

        /** 待展示的数据包，由抓包线程写入、界面线程定时读取 */
        private val pendingPackets = ArrayDeque<PacketInfo>()

        /** 停止事件（error 为 null 表示用户主动停止） */
        private val stopListeners = CopyOnWriteArrayList<(String?) -> Unit>()

        @Synchronized
        fun addPacket(packet: PacketInfo) {
            packetCount.incrementAndGet()
            if (pendingPackets.size >= MAX_PENDING_PACKETS) {
                pendingPackets.removeFirst()
            }
            pendingPackets.addLast(packet)
        }

        @Synchronized
        fun drainPackets(destination: MutableList<PacketInfo>) {
            while (pendingPackets.isNotEmpty()) {
                destination.add(pendingPackets.removeFirst())
            }
        }

        fun addStopListener(listener: (String?) -> Unit) {
            stopListeners.add(listener)
        }

        fun removeStopListener(listener: (String?) -> Unit) {
            stopListeners.remove(listener)
        }

        private fun notifyStopped(error: String?) {
            stopListeners.forEach { runCatching { it(error) } }
        }
    }

    /** 页面上展示的单条流量记录 */
    data class PacketInfo(
        val time: String,
        val proto: String,
        val src: String,
        val srcPort: Int,
        val dst: String,
        val dstPort: Int,
        val length: Int
    )

    private var tunInterface: ParcelFileDescriptor? = null
    private var tunInput: FileInputStream? = null
    private var tunOutput: FileOutputStream? = null
    private var pcapWriter: PcapWriter? = null
    private var workerThread: Thread? = null

    private val tcpConnections = ConcurrentHashMap<String, VpnTcpConnection>()
    private var forwardExecutor: ExecutorService? = null
    private var udpForwarder: VpnUdpForwarder? = null

    private val tunWriteLock = Any()
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    override fun onCreate() {
        super.onCreate()
        startForegroundCompat()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        LogUtil.d("onStartCommand action=$action")
        if (action == ACTION_STOP) {
            stopCapture()
            stopSelf()
        } else {
            startCapture()
        }
        return START_NOT_STICKY
    }

    private fun startForegroundCompat() {
        val notificationManager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            notificationManager.createNotificationChannel(
                NotificationChannel(
                    Constants.NOTIFICATION_CHANNEL_ID_FOREGROUND_SERVICE,
                    getString(R.string.foreground_service),
                    NotificationManager.IMPORTANCE_LOW
                )
            )
        }
        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, NetCaptureActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val notification: Notification =
            NotificationCompat.Builder(this, Constants.NOTIFICATION_CHANNEL_ID_FOREGROUND_SERVICE)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.net_capture_running, 0, "0 B"))
                .setSmallIcon(R.mipmap.ic_launcher_round)
                .setContentIntent(contentIntent)
                .setOngoing(true)
                .build()
        startForeground(Constants.NOTIFICATION_NOTIFY_ID_NET_CAPTURE, notification)
    }

    private fun startCapture() {
        // tunInterface/workerThread 双重防护，避免快速重复启动建立两个 TUN
        if (workerThread != null || tunInterface != null) {
            LogUtil.d("startCapture ignored: already running")
            return
        }
        LogUtil.d("startCapture begin, targetPackage=${targetPackage ?: "ALL"}")
        val dir = File(getExternalFilesDir(null), "NetCapture")
        if (!dir.exists()) {
            if (!dir.mkdirs()) {
                LogUtil.e("startCapture: cannot create dir ${dir.absolutePath}", Exception())
            }
        }
        val file = File(dir, "capture_${System.currentTimeMillis()}.pcap")
        pcapWriter = try {
            PcapWriter(file)
        } catch (e: Exception) {
            LogUtil.e("startCapture: create pcap failed: ${e.message}", e)
            notifyStopped(e.message ?: "create pcap file failed")
            stopSelf()
            return
        }
        pcapPath = file.absolutePath
        LogUtil.d("startCapture: pcap path=${file.absolutePath}")
        packetCount.set(0)
        CaptureRepository.reset()

        val builder = Builder()
            .addAddress(VPN_ADDRESS, 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .setMtu(MTU)
            .setSession("OneDroid Capture")
            .setConfigureIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, NetCaptureActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE
                )
            )
        // 指定应用抓包：仅路由该应用的流量经过 VPN
        targetPackage?.let { pkg ->
            val added = runCatching { builder.addAllowedApplication(pkg) }.isSuccess
            if (!added) {
                LogUtil.e("startCapture: addAllowedApplication failed for $pkg", Exception())
                runCatching { pcapWriter?.close() }
                pcapWriter = null
                pcapPath = null
                notifyStopped(getString(R.string.net_capture_vpn_error))
                stopSelf()
                return
            }
        }
        val fd = try {
            builder.establish()
        } catch (e: Exception) {
            LogUtil.e("startCapture: builder.establish() threw: ${e.message}", e)
            null
        }
        if (fd == null) {
            LogUtil.e("startCapture: builder.establish() returned null", Exception())
            runCatching { pcapWriter?.close() }
            pcapWriter = null
            pcapPath = null
            notifyStopped(getString(R.string.net_capture_vpn_error))
            stopSelf()
            return
        }
        LogUtil.d("startCapture: TUN established, fd=${fd.fd}")

        tunInterface = fd
        tunInput = FileInputStream(fd.fileDescriptor)
        tunOutput = FileOutputStream(fd.fileDescriptor)
        forwardExecutor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "onedroid-tcp-fwd").apply { isDaemon = true }
        }
        udpForwarder = VpnUdpForwarder(this)

        isRunning = true
        workerThread = Thread({ readLoop() }, "onedroid-capture").apply {
            start()
        }
    }

    private fun readLoop() {
        val buffer = ByteArray(65536)
        // 新版 Android 上 establish() 返回的 TUN fd 是非阻塞模式，
        // 直接 read() 无数据时立即返回 0（看似 EOF），必须先 poll 等待可读
        val pollFd = android.system.StructPollfd()
        pollFd.fd = tunInterface?.fileDescriptor
        pollFd.events =
            (android.system.OsConstants.POLLIN or android.system.OsConstants.POLLERR)
                .toShort()
        var readCount = 0
        var parseFailCount = 0
        try {
            LogUtil.d("capture readLoop start")
            while (isRunning) {
                val rc = android.system.Os.poll(arrayOf(pollFd), 500)
                if (!isRunning) {
                    break
                }
                if (rc <= 0) {
                    continue // 超时，无事件
                }
                val revents = pollFd.revents
                val pollin = android.system.OsConstants.POLLIN.toShort()
                val pollErr = (android.system.OsConstants.POLLERR or
                    android.system.OsConstants.POLLHUP or
                    android.system.OsConstants.POLLNVAL).toShort()
                if (revents.toInt() and pollErr.toInt() != 0) {
                    LogUtil.d("capture readLoop poll error events: $revents")
                    break
                }
                if (revents.toInt() and pollin.toInt() == 0) {
                    continue
                }
                val length = tunInput!!.read(buffer)
                if (length <= 0) {
                    continue // 非阻塞下偶发无数据，继续 poll
                }
                readCount++
                val now = System.currentTimeMillis()
                runCatching { pcapWriter?.writePacket(buffer, length, now) }
                val header = IpPacketUtil.parseIp(buffer, length)
                if (header == null) {
                    parseFailCount++
                    if (parseFailCount <= 10) {
                        val version = (buffer[0].toInt() shr 4) and 0xF
                        if (version == 6) {
                            LogUtil.d("capture readLoop: skip IPv6 packet len=$length (tun0 link-local control, not forwarded)")
                        } else {
                            LogUtil.d("capture readLoop: drop unparsed packet len=$length")
                        }
                    }
                    continue
                }
                if (readCount % 200 == 0) {
                    LogUtil.d("capture readLoop: readCount=$readCount parseFail=$parseFailCount")
                }
                // 分片包无法透明转发，仅记录到 pcap
                if (header.fragmentOffset != 0 || header.moreFragments) {
                    addPacket(formatPacket(now, protoName(header.protocol), header, 0, 0, length))
                    continue
                }
                when (header.protocol) {
                    IpPacketUtil.PROTO_TCP -> handleTcp(buffer, length, header, now)
                    IpPacketUtil.PROTO_UDP -> handleUdp(buffer, length, header, now)
                    else -> addPacket(
                        formatPacket(now, protoName(header.protocol), header, 0, 0, length)
                    )
                }
            }
        } catch (e: Exception) {
            // TUN 关闭等导致的读取异常，正常退出
            LogUtil.d("capture readLoop error: ${Log.getStackTraceString(e)}")
        }
        LogUtil.d("capture readLoop exit: readCount=$readCount parseFail=$parseFailCount")
        if (isRunning) {
            // 非 用户主动停止（TUN 异常关闭），通知界面
            isRunning = false
            cleanup()
            notifyStopped(null)
            stopSelf()
        }
    }

    private fun handleTcp(buffer: ByteArray, length: Int, header: IpPacketUtil.IpHeader, now: Long) {
        val tcp = IpPacketUtil.parseTcp(buffer, header) ?: run {
            LogUtil.d("handleTcp: parseTcp failed, drop len=$length")
            return
        }
        val payloadStart = header.headerLength + tcp.headerLength
        val payloadEnd = header.totalLength
        val payload = if (payloadEnd > payloadStart) {
            buffer.copyOfRange(payloadStart, payloadEnd)
        } else {
            ByteArray(0)
        }
        addPacket(formatPacket(now, "TCP", header, tcp.srcPort, tcp.dstPort, length))

        val key = "${IpPacketUtil.ipToText(header.srcIp)}:${tcp.srcPort}-" +
            "${IpPacketUtil.ipToText(header.dstIp)}:${tcp.dstPort}"
        val flagStr = VpnTcpConnection.flagsToString(tcp.flags)
        LogUtil.d("handleTcp: $key flags=$flagStr seq=${tcp.seq} ack=${tcp.ack} payloadLen=${payload.size}")
        val connection = tcpConnections[key]
        if (connection != null) {
            if (connection.isClosed()) {
                LogUtil.d("handleTcp: conn closed, remove $key")
                tcpConnections.remove(key, connection)
            } else {
                connection.handleClientSegment(tcp.flags, tcp.seq, payload)
                return
            }
        }
        if (tcp.flags and IpPacketUtil.TCP_FLAG_SYN != 0 &&
            tcp.flags and IpPacketUtil.TCP_FLAG_ACK == 0
        ) {
            LogUtil.d("handleTcp: new SYN $key seq=${tcp.seq} payload=${payload.size}")
        }
        if (tcp.flags and IpPacketUtil.TCP_FLAG_SYN != 0 &&
            tcp.flags and IpPacketUtil.TCP_FLAG_ACK == 0
        ) {
            val newConnection = VpnTcpConnection(
                this, header.srcIp, tcp.srcPort, header.dstIp, tcp.dstPort, tcp.seq
            )
            val raced = tcpConnections.putIfAbsent(key, newConnection)
            if (raced == null) {
                newConnection.handleSyn()
            } else {
                raced.handleClientSegment(tcp.flags, tcp.seq, payload)
            }
        } else {
            // 非 SYN 且无连接记录（VPN 建立前已存在的旧连接）：回复 RST 让 App 尽快重连
            val rstSeq = if (tcp.flags and IpPacketUtil.TCP_FLAG_ACK != 0) tcp.ack else 0L
            val rst = IpPacketUtil.buildTcpPacket(
                header.dstIp, header.srcIp, tcp.dstPort, tcp.srcPort,
                rstSeq, tcp.seq + payload.size,
                IpPacketUtil.TCP_FLAG_RST or IpPacketUtil.TCP_FLAG_ACK, 0, null, 0
            )
            writeToTun(rst)
        }
    }

    private fun handleUdp(buffer: ByteArray, length: Int, header: IpPacketUtil.IpHeader, now: Long) {
        val offset = header.headerLength
        if (header.totalLength < offset + 8) {
            return
        }
        val srcPort = IpPacketUtil.u16(buffer, offset)
        val dstPort = IpPacketUtil.u16(buffer, offset + 2)
        val payloadStart = offset + 8
        val payload = if (header.totalLength > payloadStart) {
            buffer.copyOfRange(payloadStart, header.totalLength)
        } else {
            ByteArray(0)
        }
        addPacket(formatPacket(now, "UDP", header, srcPort, dstPort, length))
        udpForwarder?.handle(header.srcIp, srcPort, header.dstIp, dstPort, payload)
    }

    private fun protoName(protocol: Int): String {
        return when (protocol) {
            IpPacketUtil.PROTO_ICMP -> "ICMP"
            IpPacketUtil.PROTO_TCP -> "TCP"
            IpPacketUtil.PROTO_UDP -> "UDP"
            else -> "IP($protocol)"
        }
    }

    private fun formatPacket(
        now: Long,
        proto: String,
        header: IpPacketUtil.IpHeader,
        srcPort: Int,
        dstPort: Int,
        length: Int
    ): PacketInfo {
        return PacketInfo(
            time = timeFormat.format(Date(now)),
            proto = proto,
            src = IpPacketUtil.ipToText(header.srcIp),
            srcPort = srcPort,
            dst = IpPacketUtil.ipToText(header.dstIp),
            dstPort = dstPort,
            length = length
        )
    }

    /** 回注数据包到 TUN，同时写入 pcap */
    fun writeToTun(packet: ByteArray) {
        synchronized(tunWriteLock) {
            runCatching { pcapWriter?.writePacket(packet, packet.size, System.currentTimeMillis()) }
            try {
                tunOutput?.write(packet)
            } catch (e: Exception) {
                LogUtil.d("writeToTun error: ${e.message}")
            }
        }
    }

    fun submitForwardTask(task: () -> Unit) {
        val executor = forwardExecutor
        if (executor == null) {
            runCatching { task() }
            return
        }
        // 服务停止过程中 executor 可能已关闭，吞掉拒绝异常；任务体异常也不允许击穿线程
        try {
            executor.execute { runCatching { task() } }
        } catch (_: Exception) {
        }
    }

    /**
     * protect 一个 Socket 使其流量不经过 VPN。
     * 必须在 connect 之前调用；先 bind 触发底层 fd 创建，否则 protect 可能因 fd 未就绪返回 false。
     */
    fun protectSocket(socket: java.net.Socket): Boolean {
        return try {
            if (!socket.isBound) {
                socket.bind(java.net.InetSocketAddress(0))
            }
            val ok = protect(socket)
            if (!ok) {
                LogUtil.e("protectSocket: protect returned false", Exception("protect failed"))
            }
            ok
        } catch (e: Exception) {
            LogUtil.e("protectSocket: exception ${e.message}", e)
            false
        }
    }

    fun removeTcpConnection(connection: VpnTcpConnection) {
        tcpConnections.remove(connection.key, connection)
    }

    private fun stopCapture() {
        if (!isRunning && workerThread == null) {
            LogUtil.d("stopCapture ignored: not running")
            return
        }
        LogUtil.d("stopCapture begin")
        isRunning = false
        cleanup()
    }

    private fun cleanup() {
        workerThread = null
        // 关闭 TUN 使读线程退出
        runCatching { tunInput?.close() }
        runCatching { tunOutput?.close() }
        runCatching { tunInterface?.close() }
        tunInput = null
        tunOutput = null
        tunInterface = null

        tcpConnections.values.forEach { it.closeQuietly() }
        tcpConnections.clear()
        udpForwarder?.shutdown()
        udpForwarder = null
        forwardExecutor?.shutdownNow()
        forwardExecutor = null

        runCatching { pcapWriter?.close() }
        pcapWriter = null
    }

    override fun onRevoke() {
        // 用户在系统设置中断开 VPN
        LogUtil.d("onRevoke: VPN revoked by system/user")
        isRunning = false
        cleanup()
        notifyStopped(null)
        stopSelf()
    }

    override fun onDestroy() {
        LogUtil.d("onDestroy")
        isRunning = false
        cleanup()
        notifyStopped(null)
        super.onDestroy()
    }

}
