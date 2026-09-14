package tech.qingge.onedroid.ui.activity

import android.os.Bundle
import android.text.SpannableStringBuilder
import android.widget.TextView
import androidx.core.content.ContextCompat
import tech.qingge.onedroid.R
import tech.qingge.onedroid.base.BaseActivity
import tech.qingge.onedroid.databinding.ActivityHttpTransactionBinding
import tech.qingge.onedroid.net.CaptureRepository
import tech.qingge.onedroid.net.HttpTransaction
import tech.qingge.onedroid.net.HttpUtil
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * HTTP/HTTPS 事务详情页：分别展示请求与响应的头部与包体。
 */
class HttpTransactionActivity : BaseActivity<ActivityHttpTransactionBinding>() {

    companion object {
        const val EXTRA_TX_ID = "extra_tx_id"
    }

    private var showRequest = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val id = intent.getLongExtra(EXTRA_TX_ID, -1)
        val tx = CaptureRepository.get(id)

        binding.toolbar.setNavigationOnClickListener { finish() }
        binding.toolbar.title = tx?.host ?: getString(R.string.http_detail)

        binding.btnRequest.setOnClickListener {
            showRequest = true
            updateToggle()
            render(tx)
        }
        binding.btnResponse.setOnClickListener {
            showRequest = false
            updateToggle()
            render(tx)
        }
        updateToggle()
        render(tx)
    }

    private fun updateToggle() {
        binding.btnRequest.isEnabled = !showRequest
        binding.btnResponse.isEnabled = showRequest
    }

    private fun render(tx: HttpTransaction?) {
        if (tx == null) {
            binding.tvMeta.text = getString(R.string.http_detail_unavailable)
            binding.tvContent.text = ""
            return
        }
        val timeStr = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault()).format(Date(tx.requestTime))
        val dur = if (tx.responseTime > 0) (tx.responseTime - tx.requestTime) else 0
        binding.tvMeta.text = buildString {
            append(if (tx.isSsl) "HTTPS" else "HTTP")
            append("  ·  ")
            append(timeStr)
            if (dur > 0) append("  ·  ${dur}ms")
        }

        val sb = SpannableStringBuilder()
        if (showRequest) {
            appendRequest(sb, tx)
        } else {
            appendResponse(sb, tx)
        }
        binding.tvContent.text = sb
    }

    private fun appendRequest(sb: SpannableStringBuilder, tx: HttpTransaction) {
        sb.append("▶ ${tx.method} ${tx.path} (${tx.scheme}://${tx.host}:${tx.port})\n\n")
        sb.append(HttpUtil.headersToText(tx.requestHeaders))
        sb.append("\n\n--- BODY (${tx.requestBody.size} bytes) ---\n")
        sb.append(HttpUtil.bodyToText(tx.requestHeaders, tx.requestBody))
    }

    private fun appendResponse(sb: SpannableStringBuilder, tx: HttpTransaction) {
        when (tx.state) {
            HttpTransaction.STATE_PENDING -> {
                sb.append("（请求已发送，等待响应…）")
                return
            }
            HttpTransaction.STATE_ERROR -> {
                sb.append("（请求失败：${tx.error ?: "未知错误"}）")
                return
            }
        }
        sb.append("◀ ${tx.responseStatusCode} ${tx.responseReason}\n\n")
        sb.append(HttpUtil.headersToText(tx.responseHeaders))
        sb.append("\n\n--- BODY (${tx.responseBody.size} bytes) ---\n")
        sb.append(HttpUtil.bodyToText(tx.responseHeaders, tx.responseBody))
    }
}
