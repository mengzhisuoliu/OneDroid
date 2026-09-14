package tech.qingge.onedroid.net

import tech.qingge.onedroid.util.LogUtil
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * HTTPS MITM 桥。
 *
 * 在 127.0.0.1 上开一个 SSLServerSocket，用指定主机名对应的叶子证书（由 CA 签发）
 * 终结来自 App 的 TLS；解密出的明文交给上游真实服务器（同样走 TLS），
 * 并把双向明文流喂给 [HttpConnectionParser] 解析出请求/响应。
 *
 * 每个桥对应一条 TCP 连接（一个 SNI 主机名），所以 server socket 只需配置一张叶子证书。
 */
class HttpsMitmBridge(
    private val host: String,
    private val dstIp: ByteArray,
    private val dstPort: Int,
    private val leaf: HttpsCaCertUtil.LeafMaterial,
    private val onTransaction: (HttpTransaction) -> Unit,
    /** 把上游 socket 排除出 VPN，避免流量回环；返回 false 表示 protect 失败 */
    private val protect: (java.net.Socket) -> Boolean
) {

    private var serverSocket: SSLServerSocket? = null
    private var acceptThread: Thread? = null
    @Volatile
    private var shutdown = false

    /** 创建 TLS 服务端并监听，返回本地端口；失败返回 -1 */
    fun start(): Int {
        LogUtil.d("HttpsMitm start: host=$host port=$dstPort")
        val sslContext = try {
            buildServerContext(leaf)
        } catch (e: Exception) {
            LogUtil.e("HttpsMitm: 构建 SSLContext 失败: ${e.message}", e)
            return -1
        }
        val ss = sslContext.serverSocketFactory
            .createServerSocket(0, 16, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        ss.needClientAuth = false
        ss.useClientMode = false
        enableModernProtocols(ss)
        // 只通告 HTTP/1.1，强制客户端使用 HTTP/1.x 而非 HTTP/2
        runCatching {
            val params = ss.sslParameters
            params.applicationProtocols = arrayOf("http/1.1")
            ss.sslParameters = params
        }
        serverSocket = ss
        LogUtil.d("HttpsMitm start: listening on 127.0.0.1:${ss.localPort}")
        acceptThread = Thread({
            try {
                if (shutdown) {
                    runCatching { ss.close() }
                    return@Thread
                }
                LogUtil.d("HttpsMitm accept: waiting for local connection")
                val client = ss.accept()
                if (shutdown) {
                    runCatching { client.close() }
                    return@Thread
                }
                LogUtil.d("HttpsMitm accept: got local connection")
                handleConnection(client)
            } catch (e: Exception) {
                LogUtil.d("HttpsMitm accept: error ${e.message}")
            } finally {
                runCatching { ss.close() }
            }
        }, "onedroid-mitm-accept").apply { isDaemon = true; start() }
        return ss.localPort
    }

    private fun handleConnection(client: Socket) {
        Thread({
            var upstream: SSLSocket? = null
            try {
                LogUtil.d("HttpsMitm handleConnection: creating upstream to $host:$dstPort")
                upstream = createUpstream(host)
                LogUtil.d("HttpsMitm handleConnection: upstream connected")
                val parser = HttpConnectionParser(
                    isSsl = true,
                    scheme = "https",
                    defaultHost = host,
                    defaultPort = dstPort,
                    onTransaction = onTransaction
                )
                val clientIn = client.getInputStream()
                val clientOut = client.getOutputStream()
                val upIn = upstream!!.getInputStream()
                val upOut = upstream!!.getOutputStream()

                // App -> 上游：明文请求
                val t1 = copyThread(clientIn, upOut) { parser.feedRequest(it) }
                // 上游 -> App：明文响应
                val t2 = copyThread(upIn, clientOut) { parser.feedResponse(it) }
                t1.join()
                t2.join()
                LogUtil.d("HttpsMitm handleConnection: both copy threads done")
            } catch (e: Exception) {
                LogUtil.d("HttpsMitm proxy 异常: ${e.javaClass.simpleName}: ${e.message}")
                LogUtil.d("HttpsMitm proxy 堆栈: ${android.util.Log.getStackTraceString(e)}")
                parserSafeMarkError(e)
            } finally {
                runCatching { client.close() }
                runCatching { upstream?.close() }
            }
        }, "onedroid-mitm-proxy").apply { isDaemon = true; start() }
    }

    private fun parserSafeMarkError(e: Exception) {
        // 仅作兜底记录，无需强引用 parser
        LogUtil.d("HttpsMitm: 上游连接失败 ${e.message}")
    }

    private fun createUpstream(host: String): SSLSocket {
        LogUtil.d("HttpsMitm createUpstream: $host:$dstPort (dstIp=${IpPacketUtil.ipToText(dstIp)})")
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(permissiveTrustManager()), SecureRandom())
        // 先创建裸 socket 并 protect，避免上游流量再次经过 VPN 造成回环
        val raw = Socket()
        if (!protect(raw)) {
            LogUtil.e("HttpsMitm: protect 上游 socket 失败，可能回环", Exception("protect failed"))
        } else {
            LogUtil.d("HttpsMitm: protect 上游 socket OK")
        }
        // 用原始目标 IP 建立 TCP 连接，避免 DNS 解析走 VPN 导致循环依赖
        val dstAddress = InetAddress.getByAddress(dstIp)
        LogUtil.d("HttpsMitm createUpstream: connecting raw to ${dstAddress.hostAddress}:$dstPort")
        raw.connect(java.net.InetSocketAddress(dstAddress, dstPort), 15_000)
        raw.tcpNoDelay = true
        LogUtil.d("HttpsMitm createUpstream: raw connected, wrapping SSL (SNI=$host)")
        // 用 SNI hostname 建立 SSL 连接，让上游服务器返回正确的证书
        val s = ctx.socketFactory.createSocket(raw, host, dstPort, true) as SSLSocket
        enableModernProtocols(s)
        LogUtil.d("HttpsMitm createUpstream: starting handshake")
        s.startHandshake()
        LogUtil.d("HttpsMitm createUpstream: handshake done")
        return s
    }

    private fun copyThread(
        input: InputStream,
        output: OutputStream,
        onData: (ByteArray) -> Unit
    ): Thread {
        return Thread({
            val buf = ByteArray(16384)
            try {
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    val chunk = buf.copyOf(n)
                    onData(chunk)
                    output.write(chunk)
                    output.flush()
                }
            } catch (_: Exception) {
            } finally {
                runCatching { output.close() }
            }
        }).apply { isDaemon = true; start() }
    }

    private fun buildServerContext(leaf: HttpsCaCertUtil.LeafMaterial): SSLContext {
        val ks = java.security.KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setCertificateEntry("ca", leaf.chain.last())
        ks.setKeyEntry("leaf", leaf.key, "onedroid".toCharArray(), leaf.chain)
        val kmf = javax.net.ssl.KeyManagerFactory.getInstance("X509")
        kmf.init(ks, "onedroid".toCharArray())
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, arrayOf(permissiveTrustManager()), SecureRandom())
        return ctx
    }

    private fun permissiveTrustManager(): X509TrustManager {
        return object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            override fun checkClientTrusted(p0: Array<out X509Certificate>?, p1: String?) {}
            override fun checkServerTrusted(p0: Array<out X509Certificate>?, p1: String?) {}
        }
    }

    private fun enableModernProtocols(s: javax.net.ssl.SSLSocket) {
        val supported = s.supportedProtocols?.toSet() ?: emptySet()
        val want = listOf("TLSv1.3", "TLSv1.2").filter { it in supported }
        if (want.isNotEmpty()) s.enabledProtocols = want.toTypedArray()
    }

    private fun enableModernProtocols(s: javax.net.ssl.SSLServerSocket) {
        val supported = s.supportedProtocols?.toSet() ?: emptySet()
        val want = listOf("TLSv1.3", "TLSv1.2").filter { it in supported }
        if (want.isNotEmpty()) s.enabledProtocols = want.toTypedArray()
    }

    fun shutdown() {
        shutdown = true
        runCatching { serverSocket?.close() }
    }
}
