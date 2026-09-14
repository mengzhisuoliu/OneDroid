package tech.qingge.onedroid.tool

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CryptoToolTest {

    @Test
    fun md5_lengthAndHex() {
        val h = CryptoTool.hash("abc", CryptoTool.HashAlg.MD5)
        assertEquals(32, h.length)
        assertTrue(h.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun sha1_knownValue() {
        assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d", CryptoTool.hash("abc", CryptoTool.HashAlg.SHA1))
    }

    @Test
    fun sha256_lengthAndHex() {
        val h = CryptoTool.hash("abc", CryptoTool.HashAlg.SHA256)
        assertEquals(64, h.length)
        assertTrue(h.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun hmac_notEmptyAndHex() {
        val h = CryptoTool.hmac("abc", "key", CryptoTool.HmacAlg.HMAC_SHA256)
        assertEquals(64, h.length)
        assertTrue(h.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun aes_roundTrip() {
        val key = "0123456789abcdef"
        val iv = "fedcba9876543210"
        val plain = "Hello, AES 测试!"
        val enc = CryptoTool.aesEncrypt(plain, key, iv)
        assertEquals(plain, CryptoTool.aesDecrypt(enc, key, iv))
    }

    @Test
    fun rsa_roundTrip() {
        val kp = CryptoTool.generateRsaKeyPair(1024)
        val pubB64 = java.util.Base64.getEncoder().encodeToString(kp.public.encoded)
        val plain = "Hello, RSA 测试!"
        val enc = CryptoTool.rsaEncrypt(plain, pubB64)
        assertEquals(plain, CryptoTool.rsaDecrypt(enc, kp.private))
    }
}