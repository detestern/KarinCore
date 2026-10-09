package com.nikitahya.karincore.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.util.Log
import android.text.format.DateFormat
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import go.Seq
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.Libv2ray
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors

class KarinVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var coreController: CoreController? = null
    private val worker = Executors.newSingleThreadExecutor()
    private val stateLock = Any()
    private val mainHandler = Handler(Looper.getMainLooper())
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var upstreamNetwork: Network? = null
    private var upstreamWasLost: Boolean = false
    private val handoverReload = Runnable {
        worker.execute { reloadCoreForHandover() }
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        refreshSystemVpnFlags()
    }

    private data class PersistedConnection(
        val configJson: String,
        val mtu: Int,
        val appRoutingMode: String,
        val appPackages: List<String>
    )

    private fun persistConnection(
        configJson: String,
        mtu: Int,
        appRoutingMode: String,
        appPackages: List<String>
    ) {
        val payload = JSONObject()
            .put("configJson", configJson)
            .put("mtu", mtu)
            .put("appRoutingMode", appRoutingMode)
            .put("appPackages", JSONArray(appPackages))
            .toString()
        SecureStorage(this).apply {
            put(SecureStorage.VPN_CONNECTION_KEY, payload)
            put(SecureStorage.WIDGET_CONNECTION_KEY, payload)
        }
    }

    private fun loadPersistedConnection(): PersistedConnection? {
        val payload = SecureStorage(this).get(SecureStorage.VPN_CONNECTION_KEY) ?: return null
        return try {
            val json = JSONObject(payload)
            val packages = json.optJSONArray("appPackages") ?: JSONArray()
            PersistedConnection(
                configJson = json.getString("configJson").takeIf { it.isNotBlank() } ?: return null,
                mtu = json.optInt("mtu", 1500).coerceIn(1280, 9000),
                appRoutingMode = json.optString("appRoutingMode", "all"),
                appPackages = (0 until packages.length()).mapNotNull { packages.optString(it).takeIf(String::isNotBlank) }
            )
        } catch (_: Exception) {
            SecureStorage(this).remove(SecureStorage.VPN_CONNECTION_KEY)
            null
        }
    }

    private fun clearPersistedConnection() {
        SecureStorage(this).remove(SecureStorage.VPN_CONNECTION_KEY)
    }

    private fun refreshSystemVpnFlags() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            alwaysOn = isAlwaysOn
            lockdown = isLockdownEnabled
        } else {
            alwaysOn = false
            lockdown = false
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        refreshSystemVpnFlags()

        when (intent?.action) {
            ACTION_STOP -> {
                refreshSystemVpnFlags()
                if (alwaysOn) {
                    recordLog("WARN", "Ignoring stop request while Android Always-on VPN is enabled")
                    updateNotification(getString(R.string.notification_always_on))
                } else {
                    worker.execute {
                        clearPersistedConnection()
                        stopTunnel(stopService = true)
                    }
                }
                updateHomeScreenWidget()
            }
            ACTION_START -> {
                val configJson = intent.getStringExtra(EXTRA_CONFIG_JSON).orEmpty()
                val mtu = intent.getIntExtra(EXTRA_MTU, 1500).coerceIn(1280, 9000)
                val appRoutingMode = intent.getStringExtra(EXTRA_APP_ROUTING_MODE) ?: "all"
                val appPackages = intent.getStringArrayListExtra(EXTRA_APP_PACKAGES)?.toList().orEmpty()

                // A user-requested profile change must not leave an older profile
                // behind for a future always-on restart if the new one fails.
                clearPersistedConnection()
                startInForeground(getString(R.string.notification_connecting))
                recordLog("INFO", "VPN start requested; appRouting=$appRoutingMode, selectedApps=${appPackages.size}")
                starting = true
                lastError = null
                updateHomeScreenWidget()

                worker.execute {
                    try {
                        startTunnel(configJson, mtu, appRoutingMode, appPackages)
                        persistConnection(configJson, mtu, appRoutingMode, appPackages)
                    } catch (t: Throwable) {
                        recordLog("ERROR", "VPN start failed: ${t.message ?: t.javaClass.simpleName}", t)
                        lastError = t.message ?: t.javaClass.simpleName
                        stopTunnel(stopService = true)
                    } finally {
                        starting = false
                        updateHomeScreenWidget()
                    }
                }
            }
            else -> {
                // Android starts VpnService itself when Always-on VPN is enabled,
                // including after reboot. Restore only a previously successful
                // connection; never invent or partially reconstruct a config.
                val persisted = loadPersistedConnection()
                if (persisted == null) {
                    recordLog("WARN", "System started VPN service without a persisted connection")
                    stopSelf()
                } else {
                    startInForeground(getString(R.string.notification_restoring))
                    recordLog(
                        "INFO",
                        "System VPN start; alwaysOn=$alwaysOn, lockdown=$lockdown, appRouting=${persisted.appRoutingMode}"
                    )
                    starting = true
                    lastError = null
                    updateHomeScreenWidget()

                    worker.execute {
                        try {
                            startTunnel(
                                persisted.configJson,
                                persisted.mtu,
                                persisted.appRoutingMode,
                                persisted.appPackages
                            )
                        } catch (t: Throwable) {
                            recordLog(
                                "ERROR",
                                "Always-on VPN restore failed: ${t.message ?: t.javaClass.simpleName}",
                                t
                            )
                            lastError = t.message ?: t.javaClass.simpleName
                            stopTunnel(stopService = true)
                        } finally {
                            starting = false
                            updateHomeScreenWidget()
                        }
                    }
                }
            }
        }

        return START_NOT_STICKY
    }

    private fun initCoreIfNeeded() {
        if (coreController != null) return

        // Required by gomobile so bundled assets (geoip.dat/geosite.dat) are visible.
        Seq.setContext(applicationContext)

        // initCoreEnv points Xray at a normal filesystem directory. Android assets
        // remain inside the APK, so copy the pinned databases into the private app
        // directory before the core parses subscription routing rules.
        ensureGeoDataFiles()
        Libv2ray.initCoreEnv(filesDir.absolutePath, "")
        coreVersion = Libv2ray.checkVersionX()
        recordLog("INFO", "Xray core initialized: ${coreVersion.orEmpty()}")
        coreController = Libv2ray.newCoreController(CoreCallback())
    }

    private fun ensureGeoDataFiles() {
        val required = listOf("geoip.dat", "geosite.dat")
        val marker = File(filesDir, GEO_DATA_MARKER)
        val ready = runCatching {
            marker.takeIf { it.isFile }?.readText() == GEO_DATA_REVISION &&
                required.all { name -> File(filesDir, name).let { it.isFile && it.length() > 0L } }
        }.getOrDefault(false)
        if (ready) {
            recordGeoDataReady("ready")
            return
        }

        filesDir.mkdirs()
        required.forEach { name ->
            val destination = File(filesDir, name)
            val temporary = File(filesDir, ".$name.tmp")
            temporary.delete()

            try {
                assets.open(name).use { input ->
                    temporary.outputStream().use { output -> input.copyTo(output) }
                }
                check(temporary.length() > 0L) { "Bundled $name is empty" }
                if (destination.exists() && !destination.delete()) {
                    error("Unable to replace ${destination.absolutePath}")
                }
                if (!temporary.renameTo(destination)) {
                    temporary.copyTo(destination, overwrite = true)
                    temporary.delete()
                }
            } catch (t: Throwable) {
                temporary.delete()
                throw IllegalStateException("Unable to install bundled $name: ${t.message}", t)
            }
        }

        val markerTemporary = File(filesDir, ".$GEO_DATA_MARKER.tmp")
        markerTemporary.writeText(GEO_DATA_REVISION)
        marker.delete()
        if (!markerTemporary.renameTo(marker)) {
            markerTemporary.copyTo(marker, overwrite = true)
            markerTemporary.delete()
        }
        recordGeoDataReady("installed")
    }

    private fun recordGeoDataReady(state: String) {
        recordLog(
            "INFO",
            "Xray geodata $state: geoip.dat=${File(filesDir, "geoip.dat").length()}, " +
                "geosite.dat=${File(filesDir, "geosite.dat").length()}"
        )
    }

    private fun startTunnel(
        configJson: String,
        mtu: Int,
        appRoutingMode: String,
        appPackages: List<String>
    ) {
        require(configJson.isNotBlank()) { "Xray config is empty" }

        synchronized(stateLock) {
            // Reconnect with a new profile/config cleanly.
            if (vpnInterface != null || coreController?.isRunning == true) {
                stopTunnelLocked(stopService = false)
            }

            initCoreIfNeeded()

            val builder = Builder()
                .setSession("KarinCore")
                .setMtu(mtu)
                .addAddress("172.19.0.2", 30)
                .addRoute("0.0.0.0", 0)
                .addAddress("fc00::172:19:0:2", 126)
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")

            applyAppRouting(builder, appRoutingMode, appPackages)
            recordLog("INFO", "App routing applied: mode=$appliedAppRoutingMode, packages=$appliedAppPackageCount")

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            val pfd = builder.establish()
                ?: throw IllegalStateException("Android refused to establish VPN interface")

            vpnInterface = pfd
            tunFd = pfd.fd
            lastConfigJson = configJson

            val controller = coreController
                ?: throw IllegalStateException("Xray controller was not initialized")

            // AndroidLibXrayLite sets xray.tun.fd internally from this argument.
            controller.startLoop(configJson, pfd.fd)
            if (!controller.isRunning) {
                throw IllegalStateException("Xray core returned without entering running state")
            }

            coreRunning = true
            running = true
            lastError = null
            registerNetworkMonitor()
            updateNotification(getString(R.string.notification_connected))
            updateHomeScreenWidget()
            recordLog("INFO", "VPN started, fd=${pfd.fd}, core=$coreVersion")
        }
    }

    @Suppress("DEPRECATION")
    private fun applyAppRouting(
        builder: Builder,
        mode: String,
        packages: List<String>
    ) {
        val validPackages = packages
            .asSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && it != packageName }
            .distinct()
            .filter { candidate ->
                try {
                    packageManager.getApplicationInfo(candidate, 0)
                    true
                } catch (_: PackageManager.NameNotFoundException) {
                    recordLog("WARN", "Ignoring missing package in app routing: $candidate")
                    false
                }
            }
            .toList()

        when (mode) {
            "allowlist" -> {
                require(validPackages.isNotEmpty()) {
                    "Per-app mode 'Only selected' requires at least one installed application"
                }
                validPackages.forEach { builder.addAllowedApplication(it) }
            }
            "denylist" -> {
                builder.addDisallowedApplication(packageName)
                validPackages.forEach { builder.addDisallowedApplication(it) }
            }
            else -> {
                builder.addDisallowedApplication(packageName)
            }
        }

        appliedAppRoutingMode = when (mode) {
            "allowlist", "denylist" -> mode
            else -> "all"
        }
        appliedAppPackageCount = validPackages.size
    }

    private fun registerNetworkMonitor() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P || networkCallback != null) return

        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val capabilities = connectivity.getNetworkCapabilities(network)
                if (!isUsableUnderlyingNetwork(capabilities)) return
                val previous = upstreamNetwork
                val recoveredAfterLoss = upstreamWasLost
                upstreamNetwork = network
                upstreamWasLost = false
                setUnderlyingNetworks(arrayOf(network))

                if (running && ((previous != null && previous != network) || recoveredAfterLoss)) {
                    recordLog(
                        "INFO",
                        if (recoveredAfterLoss) {
                            "Underlying network recovered after loss: $network"
                        } else {
                            "Underlying network changed: $previous -> $network"
                        }
                    )
                    mainHandler.removeCallbacks(handoverReload)
                    mainHandler.postDelayed(handoverReload, HANDOVER_DEBOUNCE_MS)
                }
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities
            ) {
                if (network == upstreamNetwork && isUsableUnderlyingNetwork(networkCapabilities)) {
                    setUnderlyingNetworks(arrayOf(network))
                } else if (network == upstreamNetwork) {
                    upstreamNetwork = null
                    upstreamWasLost = true
                    setUnderlyingNetworks(null)
                }
            }

            override fun onLost(network: Network) {
                if (network == upstreamNetwork) {
                    recordLog("WARN", "Underlying network lost: $network")
                    upstreamNetwork = null
                    upstreamWasLost = true
                    setUnderlyingNetworks(null)
                }
            }
        }

        try {
            connectivity.requestNetwork(request, callback)
            connectivityManager = connectivity
            networkCallback = callback
        } catch (t: Throwable) {
            recordLog("WARN", "Unable to register underlying network monitor: ${t.message ?: t.javaClass.simpleName}", t)
        }
    }

    private fun isUsableUnderlyingNetwork(capabilities: NetworkCapabilities?): Boolean {
        return capabilities != null &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
            !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    private fun unregisterNetworkMonitor() {
        mainHandler.removeCallbacks(handoverReload)
        val callback = networkCallback
        val connectivity = connectivityManager

        networkCallback = null
        connectivityManager = null
        upstreamNetwork = null
        upstreamWasLost = false
        setUnderlyingNetworks(null)

        if (callback != null && connectivity != null) {
            try {
                connectivity.unregisterNetworkCallback(callback)
            } catch (t: Throwable) {
                recordLog("WARN", "Unable to unregister underlying network monitor: ${t.message ?: t.javaClass.simpleName}", t)
            }
        }
    }

    private fun reloadCoreForHandover() {
        synchronized(stateLock) {
            if (!running || starting || reconnecting) return

            val controller = coreController ?: return
            val pfd = vpnInterface ?: return
            val config = lastConfigJson ?: return

            reconnecting = true
            updateNotification(getString(R.string.notification_network_change))
            var lastFailure: Throwable? = null

            try {
                for (attempt in 1..HANDOVER_RETRY_COUNT) {
                    try {
                        if (controller.isRunning) {
                            controller.stopLoop()
                        }
                        coreRunning = false

                        if (attempt > 1) {
                            Thread.sleep(HANDOVER_RETRY_DELAY_MS * attempt)
                        }

                        controller.startLoop(config, pfd.fd)
                        if (!controller.isRunning) {
                            throw IllegalStateException("Xray core did not resume after network handover")
                        }

                        coreRunning = true
                        lastError = null
                        updateNotification(getString(R.string.notification_connected))
                        recordLog("INFO", "Xray reloaded after network handover on attempt $attempt")
                        return
                    } catch (t: Throwable) {
                        lastFailure = t
                        recordLog("WARN", "Xray handover reload attempt $attempt failed: ${t.message ?: t.javaClass.simpleName}", t)
                    }
                }

                coreRunning = false
                lastError = "Network handover failed: ${lastFailure?.message ?: "unknown error"}"
                updateNotification(getString(R.string.notification_reconnect_error))
            } finally {
                reconnecting = false
            }
        }
    }

    private fun stopTunnel(stopService: Boolean) {
        synchronized(stateLock) {
            stopTunnelLocked(stopService)
        }
    }

    private fun stopTunnelLocked(stopService: Boolean) {
        unregisterNetworkMonitor()
        reconnecting = false

        try {
            if (coreController?.isRunning == true) {
                coreController?.stopLoop()
            }
        } catch (t: Throwable) {
            recordLog("WARN", "Xray shutdown failed: ${t.message ?: t.javaClass.simpleName}", t)
            if (lastError == null) lastError = "Xray stop: ${t.message ?: t.javaClass.simpleName}"
        }

        coreRunning = false
        running = false
        tunFd = -1
        lastConfigJson = null

        try {
            vpnInterface?.close()
        } catch (t: Throwable) {
            recordLog("WARN", "TUN close failed: ${t.message ?: t.javaClass.simpleName}", t)
        }
        vpnInterface = null
        updateHomeScreenWidget()

        if (stopService) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onRevoke() {
        recordLog("WARN", "Android revoked VPN permission")
        clearPersistedConnection()
        worker.execute { stopTunnel(stopService = true) }
        super.onRevoke()
    }

    override fun onDestroy() {
        synchronized(stateLock) {
            stopTunnelLocked(stopService = false)
        }
        if (instance === this) instance = null
        updateHomeScreenWidget()
        worker.shutdownNow()
        super.onDestroy()
    }

    private fun updateHomeScreenWidget() {
        KarinVpnWidgetProvider.updateAll(this)
        KarinVpnTileService.refresh()
    }

    private fun startInForeground(text: String) {
        val channelId = CHANNEL_ID
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(channelId, getString(R.string.notification_channel_name), NotificationManager.IMPORTANCE_LOW)
            )
        }

        val notification = buildNotification(text)
        val serviceType = if (Build.VERSION.SDK_INT >= 34) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, serviceType)
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): android.app.Notification {
        refreshSystemVpnFlags()

        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val launchPendingIntent = launchIntent?.let {
            PendingIntent.getActivity(
                this,
                0,
                it,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
        }

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_karincore)
            .setContentTitle("KarinCore")
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(launchPendingIntent)

        if (alwaysOn) {
            val settingsIntent = Intent(Settings.ACTION_VPN_SETTINGS)
            val settingsPendingIntent = PendingIntent.getActivity(
                this,
                2,
                settingsIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            builder.addAction(
                android.R.drawable.ic_menu_manage,
                getString(R.string.notification_vpn_settings),
                settingsPendingIntent
            )
        } else {
            val stopIntent = Intent(this, KarinVpnService::class.java).apply {
                action = ACTION_STOP
            }
            val stopPendingIntent = PendingIntent.getService(
                this,
                1,
                stopIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            builder.addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                getString(R.string.notification_disconnect),
                stopPendingIntent
            )
        }

        return builder.build()
    }

    private inner class CoreCallback : CoreCallbackHandler {
        override fun startup(): Long {
            coreRunning = true
            recordLog("INFO", "Xray startup callback")
            return 0
        }

        override fun shutdown(): Long {
            coreRunning = false
            recordLog("INFO", "Xray shutdown callback")
            return 0
        }

        override fun onEmitStatus(code: Long, message: String?): Long {
            recordLog("XRAY", "status[$code]: ${message.orEmpty()}")
            return 0
        }
    }

    companion object {
        private const val TAG = "KarinVpnService"
        private const val GEO_DATA_REVISION = "AndroidLibXrayLite-v26.9.30"
        private const val GEO_DATA_MARKER = ".karincore-geodata-revision"
        @Volatile private var instance: KarinVpnService? = null
        private const val MAX_LOG_LINES = 500
        private val logLock = Any()
        private val logLines = ArrayDeque<String>()

        private fun recordLog(level: String, message: String, throwable: Throwable? = null) {
            val timestamp = DateFormat.format("HH:mm:ss", System.currentTimeMillis()).toString()
            synchronized(logLock) {
                logLines.addLast("$timestamp [$level] $message")
                while (logLines.size > MAX_LOG_LINES) {
                    logLines.removeFirst()
                }
            }

            when (level) {
                "ERROR" -> Log.e(TAG, message, throwable)
                "WARN" -> Log.w(TAG, message, throwable)
                else -> Log.i(TAG, message)
            }
        }

        fun logsSnapshot(): String = synchronized(logLock) {
            logLines.joinToString("\n")
        }

        fun clearLogBuffer() {
            synchronized(logLock) {
                logLines.clear()
            }
            recordLog("INFO", "Log buffer cleared")
        }

        fun refreshSystemStatus() {
            instance?.refreshSystemVpnFlags()
        }

        fun widgetStartIntent(context: android.content.Context): Intent? {
            val payload = SecureStorage(context).get(SecureStorage.WIDGET_CONNECTION_KEY) ?: return null
            val persisted = try {
                val json = JSONObject(payload)
                val packages = json.optJSONArray("appPackages") ?: JSONArray()
                PersistedConnection(
                    configJson = json.getString("configJson").takeIf { it.isNotBlank() } ?: return null,
                    mtu = json.optInt("mtu", 1500).coerceIn(1280, 9000),
                    appRoutingMode = json.optString("appRoutingMode", "all"),
                    appPackages = (0 until packages.length()).mapNotNull {
                        packages.optString(it).takeIf(String::isNotBlank)
                    }
                )
            } catch (_: Exception) {
                SecureStorage(context).remove(SecureStorage.WIDGET_CONNECTION_KEY)
                return null
            }

            return Intent(context, KarinVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_CONFIG_JSON, persisted.configJson)
                putExtra(EXTRA_MTU, persisted.mtu)
                putExtra(EXTRA_APP_ROUTING_MODE, persisted.appRoutingMode)
                putStringArrayListExtra(EXTRA_APP_PACKAGES, ArrayList(persisted.appPackages))
            }
        }

        const val ACTION_START = "com.nikitahya.karincore.vpn.START"
        const val ACTION_STOP = "com.nikitahya.karincore.vpn.STOP"
        const val EXTRA_CONFIG_JSON = "config_json"
        const val EXTRA_MTU = "mtu"
        const val EXTRA_APP_ROUTING_MODE = "app_routing_mode"
        const val EXTRA_APP_PACKAGES = "app_packages"
        private const val CHANNEL_ID = "karincore_vpn"
        private const val NOTIFICATION_ID = 7301
        private const val HANDOVER_DEBOUNCE_MS = 1000L
        private const val HANDOVER_RETRY_COUNT = 3
        private const val HANDOVER_RETRY_DELAY_MS = 500L

        @Volatile var running: Boolean = false
        @Volatile var starting: Boolean = false
        @Volatile var coreRunning: Boolean = false
        @Volatile var reconnecting: Boolean = false
        @Volatile var alwaysOn: Boolean = false
        @Volatile var lockdown: Boolean = false
        @Volatile var tunFd: Int = -1
        @Volatile var coreVersion: String? = null
        @Volatile var lastError: String? = null
        @Volatile var lastConfigJson: String? = null
        @Volatile var appliedAppRoutingMode: String = "all"
        @Volatile var appliedAppPackageCount: Int = 0
    }
}
