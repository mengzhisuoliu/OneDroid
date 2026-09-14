package tech.qingge.onedroid.ui.fragment

import android.graphics.Typeface
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.StyleSpan
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import dagger.hilt.android.AndroidEntryPoint
import tech.qingge.onedroid.R
import tech.qingge.onedroid.databinding.FragmentHttpTransactionDetailBinding
import tech.qingge.onedroid.net.CaptureRepository
import tech.qingge.onedroid.net.HttpTransaction
import tech.qingge.onedroid.net.HttpUtil
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject

/**
 * 点击抓包列表项后弹出的底部抽屉，展示单次 HTTP/HTTPS 事务的完整报文：
 * 请求行、请求头、请求体、响应行、响应头、响应体。
 */
@AndroidEntryPoint
class HttpTransactionDetailDialogFragment @Inject constructor() : BottomSheetDialogFragment() {

    companion object {
        private const val KEY_TX_ID = "tx_id"

        fun newInstance(txId: Long): HttpTransactionDetailDialogFragment =
            HttpTransactionDetailDialogFragment().apply {
                arguments = Bundle().apply { putLong(KEY_TX_ID, txId) }
            }
    }

    private lateinit var binding: FragmentHttpTransactionDetailBinding

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        binding = FragmentHttpTransactionDetailBinding.inflate(layoutInflater)
        (dialog as BottomSheetDialog).behavior.state = BottomSheetBehavior.STATE_EXPANDED
        render()
        return binding.root
    }

    private fun render() {
        val id = requireArguments().getLong(KEY_TX_ID, -1)
        val tx = CaptureRepository.get(id)
        if (tx == null) {
            binding.tvTitle.text = getString(R.string.http_detail)
            binding.tvContent.text = getString(R.string.http_detail_unavailable)
            return
        }
        binding.tvTitle.text = tx.url
        binding.tvContent.text = buildDetail(tx)
    }

    private fun buildDetail(tx: HttpTransaction): CharSequence {
        val sb = SpannableStringBuilder()
        val timeStr =
            SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault()).format(Date(tx.requestTime))
        val dur = if (tx.responseTime > 0) (tx.responseTime - tx.requestTime) else 0
        sb.append(if (tx.isSsl) "HTTPS" else "HTTP")
        sb.append("  ·  ")
        sb.append(timeStr)
        if (dur > 0) sb.append("  ·  ${dur}ms")
        sb.append('\n')
        sb.append('\n')

        // 请求
        section(sb, getString(R.string.http_request))
        sb.append('\n').append(tx.method).append(' ').append(tx.path)
        sb.append('\n').append(tx.scheme).append("://").append(tx.host).append(':')
            .append(tx.port.toString())
        sb.append('\n').append('\n')
        section(sb, getString(R.string.http_request_headers))
        sb.append('\n').append(HttpUtil.headersToText(tx.requestHeaders))
        sb.append('\n').append('\n')
        section(sb, getString(R.string.http_request_body))
        sb.append('\n').append(bodyText(tx.requestHeaders, tx.requestBody))
        sb.append('\n').append('\n')

        // 响应
        section(sb, getString(R.string.http_response))
        sb.append('\n')
        when (tx.state) {
            HttpTransaction.STATE_PENDING -> sb.append(getString(R.string.http_waiting_response))
            HttpTransaction.STATE_ERROR -> sb.append(
                getString(R.string.http_request_failed, tx.error ?: getString(R.string.http_unknown_error))
            )
            else -> sb.append(tx.responseStatusCode.toString()).append(' ').append(tx.responseReason)
        }
        sb.append('\n').append('\n')
        section(sb, getString(R.string.http_response_headers))
        sb.append('\n').append(HttpUtil.headersToText(tx.responseHeaders))
        sb.append('\n').append('\n')
        section(sb, getString(R.string.http_response_body))
        sb.append('\n').append(bodyText(tx.responseHeaders, tx.responseBody))

        return sb
    }

    private fun bodyText(headers: List<Pair<String, String>>, body: ByteArray): String {
        val text = HttpUtil.bodyToText(headers, body)
        return if (text.isEmpty()) getString(R.string.http_empty_body) else text
    }

    private fun section(sb: SpannableStringBuilder, title: String) {
        val start = sb.length
        sb.append(title)
        sb.setSpan(StyleSpan(Typeface.BOLD), start, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    }
}