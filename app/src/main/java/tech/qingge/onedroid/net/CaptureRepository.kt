package tech.qingge.onedroid.net

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * 抓包会话内捕获到的 HTTP/HTTPS 事务仓库。
 * 由抓包线程写入（解析出请求/响应时），由界面线程定时读取快照展示，
 * 详情页按 id 读取。每次开始抓包调用 [reset] 清空。
 */
object CaptureRepository {

    private const val MAX_TRANSACTIONS = 2000

    private val lock = Any()
    private val list = ArrayList<HttpTransaction>()
    private val idGen = AtomicLong(1)
    private val seenIds = HashSet<Long>()

    fun reset() {
        synchronized(lock) {
            list.clear()
            seenIds.clear()
        }
    }

    fun nextId(): Long = idGen.getAndIncrement()

    /** 仅在首次出现该 id 时加入；之后对同一个对象的修改会直接反映到快照 */
    fun add(tx: HttpTransaction) {
        synchronized(lock) {
            if (seenIds.add(tx.id)) {
                list.add(tx)
                if (list.size > MAX_TRANSACTIONS) {
                    val removed = list.removeAt(0)
                    seenIds.remove(removed.id)
                }
            }
        }
    }

    fun snapshot(): List<HttpTransaction> = synchronized(lock) {
        ArrayList(list)
    }

    fun get(id: Long): HttpTransaction? = synchronized(lock) {
        list.firstOrNull { it.id == id }
    }

    fun size(): Int = synchronized(lock) { list.size }
}
