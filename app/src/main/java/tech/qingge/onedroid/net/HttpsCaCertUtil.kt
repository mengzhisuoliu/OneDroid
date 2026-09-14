package tech.qingge.onedroid.net

import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Calendar
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.ConcurrentHashMap

/**
 * 生成自签名 HTTPS CA 证书（RSA-2048 + SHA256withRSA）。
 * 手工编码 X.509 DER，避免引入 BouncyCastle 等第三方依赖。
 * 证书持久化到应用私有目录，并通过系统证书安装器安装为用户 CA。
 */
object HttpsCaCertUtil {

    private const val CN = "OneDroid CA"
    private const val ORG = "OneDroid"
    private const val CERT_NAME = "OneDroid CA"

    // OID: commonName 2.5.4.3
    private val OID_CN = byteArrayOf(0x55, 0x04, 0x03)
    // OID: organizationName 2.5.4.10
    private val OID_ORG = byteArrayOf(0x55, 0x04, 0x0A)
    // OID: rsaEncryption 1.2.840.113549.1.1.1
    private val OID_RSA = byteArrayOf(
        0x2A.toByte(), 0x86.toByte(), 0x48.toByte(), 0x86.toByte(),
        0xF7.toByte(), 0x0D.toByte(), 0x01, 0x01, 0x01
    )
    // OID: sha256WithRSAEncryption 1.2.840.113549.1.1.11
    private val OID_SHA256_RSA = byteArrayOf(
        0x2A.toByte(), 0x86.toByte(), 0x48.toByte(), 0x86.toByte(),
        0xF7.toByte(), 0x0D.toByte(), 0x01, 0x01, 0x0B
    )
    // OID: subjectAltName 2.5.29.17
    private val OID_SAN = byteArrayOf(0x55, 0x1D, 0x11)
    // OID: basicConstraints 2.5.29.19
    private val OID_BC = byteArrayOf(0x55, 0x1D, 0x13)
    // OID: keyUsage 2.5.29.15
    private val OID_KU = byteArrayOf(0x55, 0x1D, 0x0F)

    class CaMaterial(val certDer: ByteArray, val certFile: File, val keyFile: File)

    /** 获取或生成 CA。生成成功后写入 ca.crt（PEM）与 ca.key（PKCS#8 PEM） */
    fun getOrCreateCa(baseDir: File): CaMaterial {
        val dir = File(baseDir, "https_ca").apply { mkdirs() }
        val certFile = File(dir, "ca.crt")
        val keyFile = File(dir, "ca.key")
        if (certFile.exists() && keyFile.exists()) {
            val der = pemToDer(certFile.readText())
            if (der != null && isValidCaCert(der)) {
                return CaMaterial(der, certFile, keyFile)
            }
            // 旧证书格式无效（如早期版本缺失 CA 扩展），删除后重新生成
            runCatching { certFile.delete() }
            runCatching { keyFile.delete() }
        }
        val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048, SecureRandom())
        }.generateKeyPair()
        val certDer = buildSelfSignedCert(keyPair)
        certFile.writeText(derToPem("CERTIFICATE", certDer))
        keyFile.writeText(derToPem("PRIVATE KEY", keyPair.private.encoded))
        return CaMaterial(certDer, certFile, keyFile)
    }

    fun certDisplayName(): String = CERT_NAME

    /** 校验存量证书是否可用的 CA（可解析、自签名且带 CA:TRUE 约束） */
    private fun isValidCaCert(der: ByteArray): Boolean {
        return runCatching {
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            cert.basicConstraints >= 0 && cert.subjectX500Principal == cert.issuerX500Principal
        }.getOrDefault(false)
    }

    // ---- 叶子证书（MITM 用，按 SNI 主机名签发） ----

    private val leafCache = ConcurrentHashMap<String, LeafMaterial>()

    /** 叶子证书 + 私钥 + 证书链（叶子 + CA），用于 MITM 时向 App 出示 */
    class LeafMaterial(
        val cert: X509Certificate,
        val key: PrivateKey,
        val chain: Array<X509Certificate>
    )

    /** 加载已有的 CA 证书与私钥；不存在返回 null */
    fun loadCa(baseDir: File): Pair<X509Certificate, PrivateKey>? {
        val dir = File(baseDir, "https_ca")
        val certFile = File(dir, "ca.crt")
        val keyFile = File(dir, "ca.key")
        if (!certFile.exists() || !keyFile.exists()) {
            return null
        }
        val certDer = pemToDer(certFile.readText()) ?: return null
        val keyDer = pemToDer(keyFile.readText()) ?: return null
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
        val key = KeyFactory.getInstance("RSA")
            .generatePrivate(PKCS8EncodedKeySpec(keyDer))
        return cert to key
    }

    /** 获取（或生成并缓存）指定主机名的叶子证书 */
    fun getLeaf(host: String, baseDir: File): LeafMaterial? {
        leafCache[host]?.let { return it }
        val ca = loadCa(baseDir) ?: return null
        val leafKey = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048, SecureRandom())
        }.generateKeyPair()
        val certDer = buildLeafCert(ca.first, ca.second, leafKey.public as RSAPublicKey, host)
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
        val mat = LeafMaterial(cert, leafKey.private, arrayOf(cert, ca.first))
        leafCache[host] = mat
        return mat
    }

    private fun buildLeafCert(
        caCert: X509Certificate,
        caKey: PrivateKey,
        pub: RSAPublicKey,
        host: String
    ): ByteArray {
        val now = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        val notBefore = (now.clone() as Calendar).apply { add(Calendar.DAY_OF_YEAR, -1) }
        val notAfter = (now.clone() as Calendar).apply { add(Calendar.YEAR, 10) }

        val algId = derSequence(oid(OID_SHA256_RSA), DER_NULL)
        val serial = derInteger(BigInteger(63, SecureRandom()))
        val version = der(0xA0, der(0x02, byteArrayOf(2)))
        val issuer = buildName(CN)
        val subject = buildName(host)
        val validity = derSequence(utcTime(notBefore), utcTime(notAfter))
        val spki = buildSpki(pub)
        val extensions = derSequence(basicConstraintsExt(), keyUsageExt(), sanExt(host))
        val extensionsEx = der(0xA3, extensions)

        val tbs = derSequence(
            version, serial, algId, issuer, validity, subject, spki, extensionsEx
        )
        val signature = Signature.getInstance("SHA256withRSA").apply {
            initSign(caKey)
            update(tbs)
        }.sign()
        return derSequence(tbs, algId, derBitString(signature))
    }

    private fun sanExt(host: String): ByteArray {
        // GeneralName dNSName [2] IMPLICIT IA5String
        val dnsName = der(0x82, host.toByteArray(Charsets.US_ASCII))
        val generalNames = derSequence(dnsName)
        return derSequence(oid(OID_SAN), der(0x04, generalNames))
    }

    private fun basicConstraintsExt(): ByteArray {
        val bc = der(0x30, der(0x01, byteArrayOf(0x00))) // SEQUENCE { BOOLEAN FALSE }
        return derSequence(oid(OID_BC), der(0x01, byteArrayOf(0xFF.toByte())), der(0x04, bc))
    }

    /** BasicConstraints: CA=TRUE（critical），CA 证书必需 */
    private fun caBasicConstraintsExt(): ByteArray {
        val bc = der(0x30, der(0x01, byteArrayOf(0xFF.toByte()))) // SEQUENCE { BOOLEAN TRUE }
        return derSequence(oid(OID_BC), der(0x01, byteArrayOf(0xFF.toByte())), der(0x04, bc))
    }

    /** keyUsage: keyCertSign(bit5) + cRLSign(bit6)；BIT STRING 位编号从 MSB 起，故字节值=0b00000110=0x06（critical），CA 证书必需 */
    private fun caKeyUsageExt(): ByteArray {
        val ku = der(0x03, byteArrayOf(0, 0x06))
        return derSequence(oid(OID_KU), der(0x01, byteArrayOf(0xFF.toByte())), der(0x04, ku))
    }

    private fun keyUsageExt(): ByteArray {
        // digitalSignature(bit0) + keyEncipherment(bit2) = 0b10100000 = 0xA0
        val ku = der(0x03, byteArrayOf(0, 0xA0.toByte()))
        return derSequence(oid(OID_KU), der(0x01, byteArrayOf(0xFF.toByte())), der(0x04, ku))
    }

    // ---- X.509 证书构造 ----

    private fun buildSelfSignedCert(keyPair: KeyPair): ByteArray {
        val now = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        val notBefore = (now.clone() as Calendar).apply { add(Calendar.DAY_OF_YEAR, -1) }
        val notAfter = (now.clone() as Calendar).apply { add(Calendar.YEAR, 10) }

        val algId = derSequence(oid(OID_SHA256_RSA), DER_NULL)
        val name = buildName()
        val validity = derSequence(utcTime(notBefore), utcTime(notAfter))
        val spki = buildSpki(keyPair.public as RSAPublicKey)

        val serial = derInteger(BigInteger(63, SecureRandom()))
        val version = der(0xA0, der(0x02, byteArrayOf(2))) // [0] EXPLICIT v3

        val extensions = derSequence(caKeyUsageExt(), caBasicConstraintsExt())
        val extensionsEx = der(0xA3, extensions) // [3] EXPLICIT Extensions
        val tbs = derSequence(version, serial, algId, name, validity, name, spki, extensionsEx)
        val signature = Signature.getInstance("SHA256withRSA").apply {
            initSign(keyPair.private)
            update(tbs)
        }.sign()
        return derSequence(tbs, algId, derBitString(signature))
    }

    private fun buildName(): ByteArray = buildName(CN)

    private fun buildName(cn: String): ByteArray {
        val c = derSequence(oid(OID_CN), derUtf8(cn))
        val org = derSequence(oid(OID_ORG), derUtf8(ORG))
        return derSequence(derSet(c), derSet(org))
    }

    private fun buildSpki(pubKey: RSAPublicKey): ByteArray {
        val rsaPub = derSequence(
            derInteger(pubKey.modulus),
            derInteger(pubKey.publicExponent)
        )
        return derSequence(
            derSequence(oid(OID_RSA), DER_NULL),
            derBitString(rsaPub)
        )
    }

    private fun utcTime(cal: Calendar): ByteArray {
        // UTCTime: yyMMddHHmmssZ（适用于 2050 年前）
        val text = java.text.SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(cal.time)
        return der(0x17, text.toByteArray(Charsets.US_ASCII))
    }

    // ---- DER 编码 ----

    private val DER_NULL = byteArrayOf(0x05, 0x00)

    /** OBJECT IDENTIFIER 编码：OID 内容必须带 0x06 tag 才能被 DER 解析 */
    private fun oid(bytes: ByteArray): ByteArray = der(0x06, bytes)

    private fun der(tag: Int, content: ByteArray): ByteArray {
        val len = content.size
        val lenBytes = when {
            len < 0x80 -> byteArrayOf(len.toByte())
            len < 0x100 -> byteArrayOf(0x81.toByte(), len.toByte())
            len < 0x10000 -> byteArrayOf(0x82.toByte(), (len shr 8).toByte(), len.toByte())
            else -> byteArrayOf(
                0x83.toByte(), (len shr 16).toByte(), (len shr 8).toByte(), len.toByte()
            )
        }
        return byteArrayOf(tag.toByte()) + lenBytes + content
    }

    private fun derSequence(vararg parts: ByteArray): ByteArray {
        val content = parts.reduce { acc, bytes -> acc + bytes }
        return der(0x30, content)
    }

    private fun derSet(content: ByteArray): ByteArray = der(0x31, content)

    private fun derInteger(value: BigInteger): ByteArray = der(0x02, value.toByteArray())

    private fun derUtf8(text: String): ByteArray =
        der(0x0C, text.toByteArray(Charsets.UTF_8))

    private fun derBitString(content: ByteArray): ByteArray =
        der(0x03, byteArrayOf(0) + content) // 高位 unused bits = 0

    // ---- PEM ----

    private fun derToPem(type: String, der: ByteArray): String {
        val base64 = Base64.encodeToString(der, Base64.NO_WRAP)
        return buildString {
            append("-----BEGIN ").append(type).append("-----\n")
            base64.chunked(64).forEach {
                append(it).append('\n')
            }
            append("-----END ").append(type).append("-----\n")
        }
    }

    private fun pemToDer(pem: String): ByteArray? {
        val body = pem.lineSequence()
            .filter { !it.startsWith("-----") }
            .joinToString("")
            .replace("\\s".toRegex(), "")
        return runCatching { Base64.decode(body, Base64.DEFAULT) }.getOrNull()
    }

}
