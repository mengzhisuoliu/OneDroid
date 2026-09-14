package tech.qingge.onedroid.ui.activity

import android.content.Intent
import android.location.Location
import android.location.LocationManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.widget.Toast
import tech.qingge.onedroid.R
import tech.qingge.onedroid.base.BaseActivity
import tech.qingge.onedroid.databinding.ActivityMockLocationBinding
import tech.qingge.onedroid.ui.dialog.Dialogs

class MockLocationActivity : BaseActivity<ActivityMockLocationBinding>() {

    companion object {
        private const val UPDATE_INTERVAL = 1000L
        private val PROVIDERS = listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)
    }

    private lateinit var locationManager: LocationManager

    private val handler = Handler(Looper.getMainLooper())

    private var isMocking = false
    private var latitude = 0.0
    private var longitude = 0.0

    private val mockRunnable = object : Runnable {
        override fun run() {
            if (!isMocking) {
                return
            }
            try {
                PROVIDERS.forEach { provider ->
                    if (locationManager.getProvider(provider) != null) {
                        val location = Location(provider).apply {
                            this.latitude = this@MockLocationActivity.latitude
                            this.longitude = this@MockLocationActivity.longitude
                            accuracy = 1.0f
                            time = System.currentTimeMillis()
                            elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos()
                        }
                        locationManager.setTestProviderLocation(provider, location)
                    }
                }
            } catch (_: Exception) {
            }
            handler.postDelayed(this, UPDATE_INTERVAL)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        locationManager = getSystemService(LOCATION_SERVICE) as LocationManager

        binding.toolbar.setNavigationOnClickListener { finish() }

        binding.btnToggle.setOnClickListener {
            if (isMocking) {
                stopMock()
            } else {
                startMock()
            }
        }
    }

    private fun startMock() {
        latitude = binding.etLatitude.text?.toString()?.toDoubleOrNull() ?: Double.NaN
        longitude = binding.etLongitude.text?.toString()?.toDoubleOrNull() ?: Double.NaN
        if (latitude.isNaN() || longitude.isNaN() ||
            Math.abs(latitude) > 90.0 || Math.abs(longitude) > 180.0
        ) {
            Toast.makeText(this, R.string.invalid_latitude_longitude, Toast.LENGTH_SHORT).show()
            return
        }

        if (!addTestProviders()) {
            showMockLocationDeniedTips()
            return
        }

        isMocking = true
        binding.btnToggle.setText(R.string.mock_location_stop)
        binding.tvStatus.text =
            getString(R.string.mock_location_running, "($latitude, $longitude)")
        handler.post(mockRunnable)
    }

    private fun addTestProviders(): Boolean {
        return try {
            var added = false
            PROVIDERS.forEach { provider ->
                if (locationManager.getProvider(provider) != null) {
                    locationManager.addTestProvider(
                        provider,
                        false,
                        false,
                        false,
                        false,
                        true,
                        true,
                        true,
                        android.location.Criteria.POWER_LOW,
                        android.location.Criteria.ACCURACY_FINE
                    )
                    locationManager.setTestProviderEnabled(provider, true)
                    added = true
                }
            }
            added
        } catch (_: Exception) {
            false
        }
    }

    private fun showMockLocationDeniedTips() {
        Dialogs.showTwoButtonTips(
            this,
            getString(R.string.mock_location_not_allowed),
            okListener = { _, _ ->
                runCatching {
                    startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
                }
            }
        )
    }

    private fun stopMock() {
        isMocking = false
        handler.removeCallbacks(mockRunnable)
        PROVIDERS.forEach { provider ->
            runCatching {
                locationManager.setTestProviderEnabled(provider, false)
                locationManager.removeTestProvider(provider)
            }
        }
        binding.btnToggle.setText(R.string.mock_location_start)
        binding.tvStatus.text = ""
    }

    override fun onDestroy() {
        stopMock()
        super.onDestroy()
    }

}
