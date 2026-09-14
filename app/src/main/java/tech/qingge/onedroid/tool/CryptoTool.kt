package tech.qingge.onedroid.tool

import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object CryptoTool {

    enum class HashAlg(val algorithm: String) {
        MD5("MD5"), SHA1("SHA-1"), SHA256("SHA-256")
    }

    enum class HmacAlg(val algorithm: String) {
        HMAC_MD5("HmacMD5"), HMAC_SHA1("HmacSHA1"), HMAC_SHA256("HmacSHA256")
    }

    fun hash(input: String, alg: HashAlg): String =
        MessageDigest.getInstance(alg.algorithm)
            .digest(input.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    fun hmac(input: String, key: String, alg: HmacAlg): String {
        val mac = Mac.getInstance(alg.algorithm)
        mac.init(SecretKeySpec(key.toByteArray(StandardCharsets.UTF_8), alg.algorithm))
        return mac.doFinal(input.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    fun aesEncrypt(plain: String, key: String, iv: String): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            aesKey(key),
            IvParameterSpec(iv.toByteArray(StandardCharsets.UTF_8))
        )
        val result = cipher.doFinal(plain.toByteArray(StandardCharsets.UTF_8))
        return java.util.Base64.getEncoder().encodeToString(result)
    }

    fun aesDecrypt(cipherBase64: String, key: String, iv: String): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            aesKey(key),
            IvParameterSpec(iv.toByteArray(StandardCharsets.UTF_8))
        )
        val result = cipher.doFinal(java.util.Base64.getDecoder().decode(cipherBase64))
        return String(result, StandardCharsets.UTF_8)
    }

    private fun aesKey(key: String): SecretKeySpec {
        val keyBytes = key.toByteArray(StandardCharsets.UTF_8)
        val fixed = when (keyBytes.size) {
            16, 24, 32 -> keyBytes
            else -> keyBytes.copyOf(16)
        }
        return SecretKeySpec(fixed, "AES")
    }

    fun generateRsaKeyPair(keySize: Int = 2048): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(keySize) }.generateKeyPair()

    fun rsaEncrypt(plain: String, publicKeyBase64: String): String {
        val keyBytes = java.util.Base64.getDecoder().decode(publicKeyBase64)
        val pubKey = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyBytes))
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, pubKey)
        val result = cipher.doFinal(plain.toByteArray(StandardCharsets.UTF_8))
        return java.util.Base64.getEncoder().encodeToString(result)
    }

    fun rsaDecrypt(cipherBase64: String, privateKey: java.security.PrivateKey): String {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val result = cipher.doFinal(java.util.Base64.getDecoder().decode(cipherBase64))
        return String(result, StandardCharsets.UTF_8)
    }

    fun deriveKey(password: String, salt: ByteArray, keyLength: Int = 128): SecretKey {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val spec = PBEKeySpec(password.toCharArray(), salt, 1024, keyLength)
        val tmp = factory.generateSecret(spec)
        return SecretKeySpec(tmp.encoded, "AES")
    }
}