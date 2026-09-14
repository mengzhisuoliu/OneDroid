package tech.qingge.onedroid.tool

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CodecToolTest {

    @Test
    fun base64_roundTrip() {
        val s = "Hello, 世界! @#"
        assertEquals(s, CodecTool.decode(CodecTool.encode(s, CodecTool.Format.BASE64), CodecTool.Format.BASE64))
    }

    @Test
    fun base64_knownValue() {
        assertEquals("aGVsbG8=", CodecTool.base64Encode("hello"))
        assertEquals("hello", CodecTool.base64Decode("aGVsbG8="))
    }

    @Test
    fun url_roundTrip() {
        val s = "a b&c=中文/路径"
        assertEquals(s, CodecTool.decode(CodecTool.encode(s, CodecTool.Format.URL), CodecTool.Format.URL))
    }

    @Test
    fun url_knownValue() {
        assertEquals("a+b", CodecTool.urlEncode("a b"))
        assertEquals("a b", CodecTool.urlDecode("a+b"))
    }

    @Test
    fun hex_roundTrip() {
        val s = "ABC中文"
        assertEquals(s, CodecTool.decode(CodecTool.encode(s, CodecTool.Format.HEX), CodecTool.Format.HEX))
    }

    @Test
    fun hex_knownValue() {
        assertEquals("48656c6c6f", CodecTool.hexEncode("Hello"))
        assertEquals("Hello", CodecTool.hexDecode("48656c6c6f"))
    }

    @Test
    fun unicode_roundTrip() {
        val s = "abc中文测试"
        val encoded = CodecTool.unicodeEncode(s)
        assertEquals(s, CodecTool.unicodeDecode(encoded))
    }

    @Test
    fun unicode_knownValue() {
        assertEquals("a\\u4e2d", CodecTool.unicodeEncode("a中"))
        assertEquals("a中", CodecTool.unicodeDecode("a\\u4e2d"))
    }

    @Test
    fun unicode_asciiPassthrough() {
        assertEquals("abc123", CodecTool.unicodeEncode("abc123"))
    }
}