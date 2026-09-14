package tech.qingge.onedroid.tool

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FormatToolTest {

    @Test
    fun json_pretty_success() {
        val r = FormatTool.jsonPretty("{\"a\":1,\"b\":[2,3]}")
        assertTrue(r.success)
        assertTrue(r.output.contains("\n"))
        assertTrue(r.output.contains("\"a\""))
    }

    @Test
    fun json_compress_success() {
        val r = FormatTool.jsonCompress("{\"a\":1,\"b\":[2,3]}")
        assertTrue(r.success)
        assertFalse(r.output.contains("\n"))
    }

    @Test
    fun json_validate_valid() {
        val r = FormatTool.jsonValidate("{\"a\":1}")
        assertTrue(r.success)
        assertTrue(r.output.contains("合法"))
    }

    @Test
    fun json_validate_invalid() {
        val r = FormatTool.jsonValidate("{\"a\":}")
        assertFalse(r.success)
    }

    @Test
    fun xml_pretty_success() {
        val r = FormatTool.xmlPretty("<root><a>1</a><b>2</b></root>")
        assertTrue(r.success)
        assertTrue(r.output.contains("\n"))
    }

    @Test
    fun xml_compress_success() {
        val r = FormatTool.xmlCompress("<root><a>1</a></root>")
        assertTrue(r.success)
        assertTrue(r.output.contains("<root><a>1</a></root>"))
    }

    @Test
    fun xml_validate_valid() {
        val r = FormatTool.xmlValidate("<root><a>1</a></root>")
        assertTrue(r.success)
        assertTrue(r.output.contains("合法"))
    }

    @Test
    fun xml_validate_invalid() {
        val r = FormatTool.xmlValidate("<root><a>1</root>")
        assertFalse(r.success)
    }
}