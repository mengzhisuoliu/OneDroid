package tech.qingge.onedroid.server

import com.yanzhenjie.andserver.annotation.Converter
import com.yanzhenjie.andserver.framework.MessageConverter
import com.yanzhenjie.andserver.framework.body.StringBody
import com.yanzhenjie.andserver.http.ResponseBody
import com.yanzhenjie.andserver.util.MediaType
import java.io.InputStream
import java.lang.reflect.Type
import java.nio.charset.StandardCharsets

@Converter
class FileServerMessageConverter : MessageConverter {

    override fun convert(output: Any?, mediaType: MediaType?): ResponseBody {
        return StringBody(output?.toString() ?: "", mediaType)
    }

    override fun <T> convert(stream: InputStream, mediaType: MediaType?, type: Type): T? {
        val text = stream.readBytes().toString(StandardCharsets.UTF_8)
        if (type == String::class.java) {
            @Suppress("UNCHECKED_CAST")
            return text as T
        }
        return null
    }
}
