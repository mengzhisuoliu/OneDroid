package tech.qingge.onedroid.net

import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/**
 * pcap 文件写入器。
 * 使用 LINKTYPE_RAW(101)：TUN 设备中每个包都是裸 IP 包，无需伪造以太网头。
 * 线程安全：读侧（TUN 收到的包）与写侧（转发后注入 TUN 的回包）都会调用 writePacket。
 */
class PcapWriter(file: File) {

    companion object {
        private const val LINKTYPE_RAW = 101
    }

    private val out = BufferedOutputStream(FileOutputStream(file))
    @Volatile
    var closed = false
        private set

    init {
        // 全局头 24 字节：魔数（小端 0xA1B2C3D4）、版本 2.4、时区/精度、snaplen、链路类型
        val header = byteArrayOf(
            0xD4.toByte(), 0xC3.toByte(), 0xB2.toByte(), 0xA1.toByte(), // magic (LE)
            0x02, 0x00, 0x04, 0x00,                                     // version 2.4
            0x00, 0x00, 0x00, 0x00,                                     // thiszone
            0x00, 0x00, 0x00, 0x00,                                     // sigfigs
            0xFF.toByte(), 0xFF.toByte(), 0x00, 0x00,                   // snaplen 65535
            LINKTYPE_RAW.toByte(), 0x00, 0x00, 0x00                     // linktype
        )
        out.write(header)
        out.flush()
    }

    @Synchronized
    @Throws(IOException::class)
    fun writePacket(packet: ByteArray, length: Int, timestampMillis: Long) {
        if (closed || length <= 0) {
            return
        }
        val header = ByteArray(16)
        val sec = timestampMillis / 1000
        val usec = (timestampMillis % 1000) * 1000
        putInt32LE(header, 0, sec)
        putInt32LE(header, 4, usec)
        putInt32LE(header, 8, length.toLong())
        putInt32LE(header, 12, length.toLong())
        out.write(header)
        out.write(packet, 0, length)
        out.flush()
    }

    @Synchronized
    fun close() {
        if (closed) {
            return
        }
        closed = true
        runCatching { out.close() }
    }

    private fun putInt32LE(dst: ByteArray, offset: Int, value: Long) {
        dst[offset] = (value and 0xFF).toByte()
        dst[offset + 1] = ((value shr 8) and 0xFF).toByte()
        dst[offset + 2] = ((value shr 16) and 0xFF).toByte()
        dst[offset + 3] = ((value shr 24) and 0xFF).toByte()
    }

}
