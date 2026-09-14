package tech.qingge.onedroid.tool

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import java.io.StringReader
import java.io.StringWriter
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.OutputKeys
import javax.xml.transform.TransformerFactory
import javax.xml.transform.stream.StreamResult
import javax.xml.transform.stream.StreamSource

object FormatTool {

    enum class Type { JSON, XML }

    data class Result(val success: Boolean, val output: String, val error: String? = null)

    fun pretty(input: String, type: Type): Result = when (type) {
        Type.JSON -> jsonPretty(input)
        Type.XML -> xmlPretty(input)
    }

    fun compress(input: String, type: Type): Result = when (type) {
        Type.JSON -> jsonCompress(input)
        Type.XML -> xmlCompress(input)
    }

    fun validate(input: String, type: Type): Result = when (type) {
        Type.JSON -> jsonValidate(input)
        Type.XML -> xmlValidate(input)
    }

    private val prettyGson: Gson = GsonBuilder().setPrettyPrinting().create()
    private val compactGson: Gson = Gson()

    fun jsonPretty(input: String): Result = try {
        val element = JsonParser.parseString(input)
        Result(true, prettyGson.toJson(element))
    } catch (e: Exception) {
        Result(false, "", e.message)
    }

    fun jsonCompress(input: String): Result = try {
        val element = JsonParser.parseString(input)
        Result(true, compactGson.toJson(element))
    } catch (e: Exception) {
        Result(false, "", e.message)
    }

    fun jsonValidate(input: String): Result = try {
        val element = JsonParser.parseString(input)
        val depth = computeJsonDepth(element)
        Result(true, "JSON 合法\n层级深度: $depth")
    } catch (e: Exception) {
        Result(false, "", e.message)
    }

    private fun computeJsonDepth(element: com.google.gson.JsonElement): Int {
        if (!element.isJsonObject && !element.isJsonArray) return 0
        val children = if (element.isJsonObject) {
            element.asJsonObject.entrySet().map { it.value }
        } else {
            element.asJsonArray.toList()
        }
        if (children.isEmpty()) return 1
        return 1 + (children.maxOf { computeJsonDepth(it) })
    }

    fun xmlPretty(input: String): Result = try {
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(org.xml.sax.InputSource(StringReader(input)))
        val transformer = TransformerFactory.newInstance().newTransformer().apply {
            setOutputProperty(OutputKeys.INDENT, "yes")
            setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2")
            setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no")
        }
        val writer = StringWriter()
        transformer.transform(javax.xml.transform.dom.DOMSource(doc), StreamResult(writer))
        Result(true, writer.toString())
    } catch (e: Exception) {
        Result(false, "", e.message)
    }

    fun xmlCompress(input: String): Result = try {
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(org.xml.sax.InputSource(StringReader(input)))
        val transformer = TransformerFactory.newInstance().newTransformer().apply {
            setOutputProperty(OutputKeys.INDENT, "no")
            setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no")
        }
        val writer = StringWriter()
        transformer.transform(javax.xml.transform.dom.DOMSource(doc), StreamResult(writer))
        Result(true, writer.toString().replace("\n", "").replace("\r", ""))
    } catch (e: Exception) {
        Result(false, "", e.message)
    }

    fun xmlValidate(input: String): Result = try {
        val factory = DocumentBuilderFactory.newInstance().apply {
            isValidating = false
            isNamespaceAware = false
        }
        val doc = factory.newDocumentBuilder().parse(org.xml.sax.InputSource(StringReader(input)))
        val depth = computeXmlDepth(doc.documentElement)
        Result(true, "XML 合法\n层级深度: $depth")
    } catch (e: Exception) {
        Result(false, "", e.message)
    }

    private fun computeXmlDepth(node: org.w3c.dom.Node): Int {
        var maxChild = 0
        var child = node.firstChild
        while (child != null) {
            if (child.nodeType == org.w3c.dom.Node.ELEMENT_NODE) {
                maxChild = maxOf(maxChild, computeXmlDepth(child))
            }
            child = child.nextSibling
        }
        return 1 + maxChild
    }
}