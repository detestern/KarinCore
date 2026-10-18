package com.nikitahya.karincore.vpn

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import java.util.concurrent.ConcurrentHashMap

/**
 * ***************************************
 * CONNECTION SCENARIOS: NETWORK WATCHER
 * ***************************************
 * A foreground service that exists only while at least one scenario is enabled.
 * Being a foreground service keeps the process alive and, on Android 12+, is
 * what allows starting the VPN from the background. It watches the real
 * (non-VPN) networks, so Wi-Fi and mobile are visible even while the VPN is up.
 */
class ScenarioWatcherService : Service() {
    private val handler = Handler(Looper.getMainLooper())
    // Callbacks arrive on the connectivity thread, evaluation runs on the main thread.
    private val networks = ConcurrentHashMap<Network, NetworkCapabilities>()
    private var callback: ConnectivityManager.NetworkCallback? = null

    private val evaluate = Runnable {
        ScenarioEngine.onNetwork(applicationContext, computeNet())
    }
    private val repostNotification = Runnable { postOngoingNotification() }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // A foreground service must call startForeground() right after
        // startForegroundService(), even if we are about to stop again.
        val count = ScenarioStore(this).enabledCount()
        try {
            enterForeground(count)
        } catch (_: Exception) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (count == 0) {
            releaseForeground()
            stopSelf()
            return START_NOT_STICKY
        }
        register()
        scheduleEvaluate()
        return START_STICKY
    }

    override fun onDestroy() {
        releaseForeground()
        handler.removeCallbacks(evaluate)
        handler.removeCallbacks(repostNotification)
        unregister()
        if (instance === this) instance = null
        super.onDestroy()
    }

    // The notification slot is shared with the VPN: keep it when the VPN still uses it.
    private fun releaseForeground() {
        val vpnActive = KarinVpnService.running || KarinVpnService.starting || KarinVpnService.reconnecting
        stopForeground(if (vpnActive) STOP_FOREGROUND_DETACH else STOP_FOREGROUND_REMOVE)
    }

    private fun enterForeground(enabledCount: Int) {
        val serviceType = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, ScenarioNotifier.ONGOING_ID, ongoingNotification(enabledCount), serviceType)
    }

    // While the VPN is up its own notification already owns the shared slot;
    // posting ours would replace it, so we post the VPN one again unchanged.
    private fun ongoingNotification(enabledCount: Int): android.app.Notification {
        return if (KarinVpnService.running || KarinVpnService.starting || KarinVpnService.reconnecting) {
            KarinVpnService.buildOngoingNotification(this, KarinVpnService.ongoingText)
        } else {
            ScenarioNotifier.watching(this, enabledCount)
        }
    }

    private fun postOngoingNotification() {
        val count = ScenarioStore(this).enabledCount()
        if (count == 0) return
        try {
            NotificationManagerCompat.from(this).notify(ScenarioNotifier.ONGOING_ID, ongoingNotification(count))
        } catch (_: SecurityException) {
            // Notifications are blocked; the foreground service keeps running regardless.
        }
    }

    private fun register() {
        if (callback != null) return
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val created: ConnectivityManager.NetworkCallback =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) LocationAwareCallback() else PlainCallback()
        try {
            connectivity.registerNetworkCallback(request, created)
            callback = created
        } catch (_: Exception) {
            // Without the callback the watcher is useless; stop rather than pretend.
            stopSelf()
        }
    }

    private fun unregister() {
        val current = callback ?: return
        callback = null
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(current)
        } catch (_: Exception) {
            // Already unregistered.
        }
        networks.clear()
    }

    private inner class PlainCallback : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            networks[network] = networkCapabilities
            scheduleEvaluate()
        }

        override fun onLost(network: Network) {
            networks.remove(network)
            scheduleEvaluate()
        }
    }

    // FLAG_INCLUDE_LOCATION_INFO lets the callback carry the real Wi-Fi name
    // when the app holds location access.
    @RequiresApi(Build.VERSION_CODES.S)
    private inner class LocationAwareCallback :
        ConnectivityManager.NetworkCallback(ConnectivityManager.NetworkCallback.FLAG_INCLUDE_LOCATION_INFO) {
        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            networks[network] = networkCapabilities
            scheduleEvaluate()
        }

        override fun onLost(network: Network) {
            networks.remove(network)
            scheduleEvaluate()
        }
    }

    // Networks flap during handover; act only on a settled picture.
    private fun scheduleEvaluate() {
        handler.removeCallbacks(evaluate)
        handler.postDelayed(evaluate, SETTLE_MS)
    }

    private fun computeNet(): ScenarioEngine.Net {
        val wifi = networks.values.firstOrNull {
            it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        if (wifi != null) return ScenarioEngine.Net(ScenarioEngine.Net.WIFI, readSsid(wifi))

        val cellular = networks.values.firstOrNull {
            it.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) &&
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        if (cellular != null) return ScenarioEngine.Net(ScenarioEngine.Net.MOBILE, null)

        return ScenarioEngine.Net(ScenarioEngine.Net.NONE, null)
    }

    @Suppress("DEPRECATION")
    private fun readSsid(capabilities: NetworkCapabilities): String? {
        var raw: String? = null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val info = capabilities.transportInfo
            if (info is WifiInfo) raw = info.ssid
        }
        var cleaned = cleanSsid(raw)
        if (cleaned == null) {
            try {
                val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                cleaned = cleanSsid(wifiManager?.connectionInfo?.ssid)
            } catch (_: Exception) {
                // No permission or no Wi-Fi service.
            }
        }
        return cleaned
    }

    private fun cleanSsid(raw: String?): String? {
        if (raw == null) return null
        var value: String = raw
        if (value.length >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length - 1)
        }
        if (value.isEmpty() || value == "<unknown ssid>" || value == "0x") return null
        return value
    }

    companion object {
        private const val SETTLE_MS = 2500L
        private const val REPOST_DELAY_MS = 600L

        @Volatile private var instance: ScenarioWatcherService? = null

        val running: Boolean get() = instance != null

        /** Starts the watcher when at least one scenario is enabled, stops it otherwise. */
        fun startIfNeeded(context: Context) {
            val appContext = context.applicationContext
            val intent = Intent(appContext, ScenarioWatcherService::class.java)
            if (ScenarioStore(appContext).enabledCount() == 0) {
                appContext.stopService(intent)
                return
            }
            try {
                ContextCompat.startForegroundService(appContext, intent)
            } catch (_: Exception) {
                // Android refused a background start; it will be retried the next time the app opens.
            }
        }

        /** Re-reads the current network right away, e.g. after the scenario list changed. */
        fun reevaluate() {
            instance?.scheduleEvaluate()
        }

        /** VPN state changed: keep the single shared notification showing the right content. */
        fun onVpnStateChanged() {
            val service = instance ?: return
            service.handler.removeCallbacks(service.repostNotification)
            service.handler.postDelayed(service.repostNotification, REPOST_DELAY_MS)
        }
    }
}
