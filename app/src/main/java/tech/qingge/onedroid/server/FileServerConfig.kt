package tech.qingge.onedroid.server

import android.content.Context
import com.yanzhenjie.andserver.annotation.Config
import com.yanzhenjie.andserver.framework.config.WebConfig
import com.yanzhenjie.andserver.framework.website.AssetsWebsite

@Config
class FileServerConfig : WebConfig {

    override fun onConfig(context: Context, delegate: WebConfig.Delegate) {
        delegate.addWebsite(AssetsWebsite(context, "/file_server"))
    }

}
