package com.nikitahya.karincore.vpn

import android.app.Activity
import android.app.ActivityManager
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.net.URL
import java.util.concurrent.Executors
import java.util.zip.GZIPInputStream
import javax.net.ssl.SSLException
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
import androidx.core.app.NotificationManagerCompat
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class StartArgs {
    lateinit var configJson: String
    var mtu: Int = 1500
    var appRoutingMode: String = "all"
    var appPackages: Array<String> = emptyArray()
}

@InvokeArg
class SaveDocumentArgs {
    lateinit var filename: String
    lateinit var content: String
    var mimeType: String = "application/json"
}

@InvokeArg
class FetchTextArgs {
    lateinit var url: String
    var timeoutMs: Long = 20_000
    var maxBytes: Long = 8L * 1024L * 1024L
}

@InvokeArg
class SecureStateArgs {
    lateinit var content: String
}

@InvokeArg
class OpenStabilitySettingsArgs {
    lateinit var target: String
}

@TauriPlugin
class KarinVpnPlugin(private val activity: Activity) : Plugin(activity) {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val networkExecutor = Executors.newCachedThreadPool()
    private var pendingDocumentContent: String? = null

    @Command
    fun saveSecureState(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(SecureStateArgs::class.java)
            require(args.content.toByteArray(Charsets.UTF_8).size <= MAX_SECURE_STATE_BYTES) {
                "SECURE_STATE_TOO_LARGE"
            }
            SecureStorage(activity).put(SecureStorage.PROFILE_STATE_KEY, args.content)
            invoke.resolve(JSObject().apply { put("saved", true) })
        } catch (ex: Exception) {
            invoke.reject(ex.message ?: "SECURE_STATE_SAVE_FAILED")
        }
    }

    @Command
    fun loadSecureState(invoke: Invoke) {
        try {
            invoke.resolve(JSObject().apply {
                put("content", SecureStorage(activity).get(SecureStorage.PROFILE_STATE_KEY))
            })
        } catch (ex: Exception) {
            invoke.reject(ex.message ?: "SECURE_STATE_LOAD_FAILED")
        }
    }

    @Command
    fun prepare(invoke: Invoke) {
        try {
            val intent = VpnService.prepare(activity)
            if (intent == null) {
                invoke.resolve(JSObject().apply { put("prepared", true) })
            } else {
                startActivityForResult(invoke, intent, "onVpnPermissionResult")
            }
        } catch (ex: Exception) {
            invoke.reject(ex.message ?: "VPN prepare failed")
        }
    }

    @ActivityCallback
    private fun onVpnPermissionResult(invoke: Invoke, result: ActivityResult) {
        invoke.resolve(JSObject().apply {
            put("prepared", result.resultCode == Activity.RESULT_OK)
        })
    }

    @Command
    fun start(invoke: Invoke) {
        try {
            if (VpnService.prepare(activity) != null) {
                invoke.reject("VPN_PERMISSION_REQUIRED")
                return
            }

            val args = invoke.parseArgs(StartArgs::class.java)
            if (args.configJson.isBlank()) {
                invoke.reject("XRAY_CONFIG_EMPTY")
                return
            }

            // Set transitional state before Android dispatches the service intent,
            // so the polling below cannot observe a false idle state in between.
            KarinVpnService.starting = true
            KarinVpnService.lastError = null

            val intent = Intent(activity, KarinVpnService::class.java).apply {
                action = KarinVpnService.ACTION_START
                putExtra(KarinVpnService.EXTRA_CONFIG_JSON, args.configJson)
                putExtra(KarinVpnService.EXTRA_MTU, args.mtu)
                putExtra(KarinVpnService.EXTRA_APP_ROUTING_MODE, args.appRoutingMode)
                putStringArrayListExtra(
                    KarinVpnService.EXTRA_APP_PACKAGES,
                    ArrayList(args.appPackages.toList())
                )
            }
            ContextCompat.startForegroundService(activity, intent)

            waitForStart(invoke, SystemClock.elapsedRealtime() + START_TIMEOUT_MS)
        } catch (ex: Exception) {
            KarinVpnService.starting = false
            invoke.reject(ex.message ?: "VPN start failed")
        }
    }

    private fun waitForStart(invoke: Invoke, deadline: Long) {
        when {
            KarinVpnService.running && KarinVpnService.coreRunning -> {
                invoke.resolve(statusObject())
            }
            KarinVpnService.lastError != null && !KarinVpnService.starting -> {
                invoke.reject(KarinVpnService.lastError ?: "XRAY_START_FAILED")
            }
            SystemClock.elapsedRealtime() >= deadline -> {
                invoke.reject(KarinVpnService.lastError ?: "XRAY_START_TIMEOUT")
            }
            else -> mainHandler.postDelayed({ waitForStart(invoke, deadline) }, POLL_MS)
        }
    }

    @Command
    fun stop(invoke: Invoke) {
        try {
            KarinVpnService.refreshSystemStatus()
            if (KarinVpnService.alwaysOn) {
                invoke.reject("ALWAYS_ON_VPN_ENABLED")
                return
            }

            val intent = Intent(activity, KarinVpnService::class.java).apply {
                action = KarinVpnService.ACTION_STOP
            }
            activity.startService(intent)
            waitForStop(invoke, SystemClock.elapsedRealtime() + STOP_TIMEOUT_MS)
        } catch (ex: Exception) {
            invoke.reject(ex.message ?: "VPN stop failed")
        }
    }

    private fun waitForStop(invoke: Invoke, deadline: Long) {
        when {
            !KarinVpnService.running && !KarinVpnService.starting && !KarinVpnService.coreRunning -> {
                invoke.resolve(statusObject())
            }
            SystemClock.elapsedRealtime() >= deadline -> {
                invoke.reject("VPN_STOP_TIMEOUT")
            }
            else -> mainHandler.postDelayed({ waitForStop(invoke, deadline) }, POLL_MS)
        }
    }

    @Suppress("DEPRECATION")
    @Command
    fun listApps(invoke: Invoke) {
        try {
            val launcherIntent = Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_LAUNCHER)
            }

            val resolved = if (android.os.Build.VERSION.SDK_INT >= 33) {
                activity.packageManager.queryIntentActivities(
                    launcherIntent,
                    PackageManager.ResolveInfoFlags.of(0)
                )
            } else {
                activity.packageManager.queryIntentActivities(launcherIntent, 0)
            }

            val appsByPackage = linkedMapOf<String, JSObject>()
            resolved.forEach { info ->
                val packageName = info.activityInfo?.packageName ?: return@forEach
                if (packageName == activity.packageName) return@forEach
                val applicationInfo = info.activityInfo?.applicationInfo

                appsByPackage[packageName] = JSObject().apply {
                    put("label", info.loadLabel(activity.packageManager).toString())
                    put("packageName", packageName)
                    put(
                        "system",
                        applicationInfo != null &&
                            (applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                    )
                }
            }

            val rows = appsByPackage.values
                .sortedBy { it.getString("label").lowercase() }
                .toTypedArray()

            invoke.resolve(JSObject().apply {
                put("apps", JSArray.from(rows))
            })
        } catch (ex: Exception) {
            invoke.reject(ex.message ?: "Failed to list installed applications")
        }
    }

    @Command
    fun saveDocument(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(SaveDocumentArgs::class.java)
            if (args.filename.isBlank()) {
                invoke.reject("DOCUMENT_FILENAME_EMPTY")
                return
            }

            pendingDocumentContent = args.content

            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = args.mimeType.ifBlank { "application/json" }
                putExtra(Intent.EXTRA_TITLE, args.filename)
            }

            startActivityForResult(invoke, intent, "saveDocumentResult")
        } catch (ex: Exception) {
            pendingDocumentContent = null
            invoke.reject(ex.message ?: "Failed to open Android document picker")
        }
    }

    @ActivityCallback
    private fun saveDocumentResult(invoke: Invoke, result: ActivityResult) {
        val content = pendingDocumentContent
        pendingDocumentContent = null

        when (result.resultCode) {
            Activity.RESULT_OK -> {
                try {
                    val uri = result.data?.data
                        ?: throw IllegalStateException("Android document picker returned no URI")
                    val payload = content
                        ?: throw IllegalStateException("Document content is no longer available")

                    activity.contentResolver.openOutputStream(uri, "wt")?.use { stream ->
                        stream.write(payload.toByteArray(Charsets.UTF_8))
                        stream.flush()
                    } ?: throw IllegalStateException("Unable to open selected document for writing")

                    invoke.resolve(JSObject().apply {
                        put("saved", true)
                        put("uri", uri.toString())
                    })
                } catch (ex: Exception) {
                    invoke.reject(ex.message ?: "Failed to save document")
                }
            }
            Activity.RESULT_CANCELED -> invoke.reject("Отменено")
            else -> invoke.reject("Failed to save document")
        }
    }

    @Command
    fun fetchText(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(FetchTextArgs::class.java)
        } catch (ex: Exception) {
            invoke.reject(ex.message ?: "SUBSCRIPTION_NATIVE_ARGS")
            return
        }

        if (args.url.isBlank()) {
            invoke.reject("SUBSCRIPTION_NATIVE_URL_EMPTY")
            return
        }

        networkExecutor.execute {
            try {
                val result = fetchTextBlocking(
                    initialUrl = args.url,
                    timeoutMs = args.timeoutMs.coerceIn(1_000, 60_000).toInt(),
                    maxBytes = args.maxBytes.coerceIn(1_024, 16L * 1024L * 1024L)
                )

                invoke.resolve(JSObject().apply {
                    put("status", result.status)
                    put("finalUrl", result.finalUrl)
                    put("content", result.content)
                    result.routing?.let { put("routing", it) }
                })
            } catch (ex: SocketTimeoutException) {
                invoke.reject("SUBSCRIPTION_TIMEOUT: Android HTTP timeout")
            } catch (ex: SSLException) {
                invoke.reject("SUBSCRIPTION_TLS: ${ex.message ?: "TLS validation failed"}")
            } catch (ex: Exception) {
                invoke.reject("SUBSCRIPTION_NATIVE: ${ex.javaClass.simpleName}: ${ex.message ?: "request failed"}")
            }
        }
    }

    private data class NativeFetchResult(
        val status: Int,
        val finalUrl: String,
        val content: String,
        val routing: String?
    )

    private fun fetchTextBlocking(
        initialUrl: String,
        timeoutMs: Int,
        maxBytes: Long
    ): NativeFetchResult {
        var current = URL(initialUrl)
        var redirects = 0

        while (true) {
            validateSubscriptionUrl(current)
            val connection = (current.openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = false
                connectTimeout = minOf(timeoutMs, 8_000)
                readTimeout = timeoutMs
                requestMethod = "GET"
                setRequestProperty("User-Agent", "KarinCore-Android/0.1")
                setRequestProperty("Accept", "*/*")
                setRequestProperty("Accept-Encoding", "gzip")
                useCaches = false
            }

            try {
                val status = connection.responseCode

                if (status in 300..399) {
                    val location = connection.getHeaderField("Location")
                        ?: throw IllegalStateException("Redirect without Location header")
                    redirects += 1
                    if (redirects > 5) {
                        throw IllegalStateException("SUBSCRIPTION_REDIRECT_LIMIT")
                    }
                    current = URL(current, location)
                    validateSubscriptionUrl(current)
                    continue
                }

                val source: InputStream = if (status >= 400) {
                    connection.errorStream ?: connection.inputStream
                } else {
                    connection.inputStream
                }

                val contentEncoding = connection.getHeaderField("Content-Encoding").orEmpty()
                val input = if (contentEncoding.equals("gzip", ignoreCase = true)) {
                    GZIPInputStream(source)
                } else {
                    source
                }

                val body = input.use { readBounded(it, maxBytes) }
                    .toString(Charsets.UTF_8)
                val routing = connection.getHeaderField("routing")
                    ?.trim()
                    ?.takeIf { it.isNotEmpty() }
                require(routing == null || routing.length <= MAX_ROUTING_HEADER_CHARS) {
                    "SUBSCRIPTION_ROUTING_TOO_LARGE"
                }

                return NativeFetchResult(
                    status = status,
                    finalUrl = current.toString(),
                    content = body,
                    routing = routing
                )
            } finally {
                connection.disconnect()
            }
        }
    }

    private fun validateSubscriptionUrl(url: URL) {
        require(url.protocol.equals("https", ignoreCase = true)) { "SUBSCRIPTION_HTTPS_REQUIRED" }
        require(url.userInfo == null) { "SUBSCRIPTION_URL_CREDENTIALS_FORBIDDEN" }
        val host = url.host.orEmpty().lowercase()
        require(host.isNotBlank()) { "SUBSCRIPTION_HOST_MISSING" }
        require(host != "localhost" && !host.endsWith(".localhost") && !host.endsWith(".local")) {
            "SUBSCRIPTION_PRIVATE_HOST_FORBIDDEN"
        }

        val addresses = InetAddress.getAllByName(host)
        require(addresses.isNotEmpty()) { "SUBSCRIPTION_DNS_EMPTY" }
        addresses.forEach { address ->
            val bytes = address.address
            val uniqueLocalV6 = bytes.size == 16 && (bytes[0].toInt() and 0xfe) == 0xfc
            require(
                !address.isAnyLocalAddress &&
                    !address.isLoopbackAddress &&
                    !address.isLinkLocalAddress &&
                    !address.isSiteLocalAddress &&
                    !address.isMulticastAddress &&
                    !uniqueLocalV6
            ) { "SUBSCRIPTION_PRIVATE_HOST_FORBIDDEN" }
        }
    }

    private fun readBounded(input: InputStream, maxBytes: Long): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(16 * 1024)
        var total = 0L

        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > maxBytes) {
                throw IllegalStateException("SUBSCRIPTION_TOO_LARGE")
            }
            output.write(buffer, 0, count)
        }

        return output.toByteArray()
    }

    @Command
    fun openVpnSettings(invoke: Invoke) {
        try {
            val intent = Intent(Settings.ACTION_VPN_SETTINGS)
            if (intent.resolveActivity(activity.packageManager) == null) {
                invoke.reject("VPN_SETTINGS_UNAVAILABLE")
                return
            }
            activity.startActivity(intent)
            invoke.resolve(JSObject().apply { put("opened", true) })
        } catch (ex: Exception) {
            invoke.reject(ex.message ?: "Unable to open Android VPN settings")
        }
    }

    @Command
    fun stabilityDiagnostics(invoke: Invoke) {
        try {
            KarinVpnService.refreshSystemStatus()
            val connectivity = activity.getSystemService(ConnectivityManager::class.java)
            val activeNetwork = connectivity?.activeNetwork
            val capabilities = if (connectivity != null && activeNetwork != null) {
                connectivity.getNetworkCapabilities(activeNetwork)
            } else {
                null
            }
            val powerManager = activity.getSystemService(PowerManager::class.java)
            val activityManager = activity.getSystemService(ActivityManager::class.java)
            val notificationsGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                ContextCompat.checkSelfPermission(
                    activity,
                    android.Manifest.permission.POST_NOTIFICATIONS
                ) == PackageManager.PERMISSION_GRANTED
            } else {
                NotificationManagerCompat.from(activity).areNotificationsEnabled()
            }
            val dataSaverStatus = when (connectivity?.restrictBackgroundStatus) {
                ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED -> "enabled"
                ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED -> "whitelisted"
                else -> "disabled"
            }

            invoke.resolve(JSObject().apply {
                put("vpnPermissionGranted", VpnService.prepare(activity) == null)
                put("notificationsGranted", notificationsGranted)
                put("batteryOptimizationExempt", powerManager?.isIgnoringBatteryOptimizations(activity.packageName) == true)
                put("backgroundRestricted", if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) activityManager?.isBackgroundRestricted == true else false)
                put("dataSaverStatus", dataSaverStatus)
                put("networkAvailable", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true)
                put("networkValidated", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true)
                put("alwaysOn", KarinVpnService.alwaysOn)
                put("lockdown", KarinVpnService.lockdown)
                put("sdkInt", Build.VERSION.SDK_INT)
                put("manufacturer", Build.MANUFACTURER.orEmpty())
            })
        } catch (ex: Exception) {
            invoke.reject(ex.message ?: "STABILITY_DIAGNOSTICS_FAILED")
        }
    }

    @Command
    fun openStabilitySettings(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(OpenStabilitySettingsArgs::class.java)
            val packageUri = Uri.parse("package:${activity.packageName}")
            val intent = when (args.target) {
                "vpn" -> Intent(Settings.ACTION_VPN_SETTINGS)
                "notifications" -> Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
                    putExtra(Settings.EXTRA_APP_PACKAGE, activity.packageName)
                }
                "battery" -> Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                "data_saver" -> Intent(Settings.ACTION_IGNORE_BACKGROUND_DATA_RESTRICTIONS_SETTINGS, packageUri)
                "background", "app" -> Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, packageUri)
                else -> throw IllegalArgumentException("STABILITY_SETTINGS_TARGET_INVALID")
            }
            val resolvedIntent = if (intent.resolveActivity(activity.packageManager) != null) {
                intent
            } else {
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, packageUri)
            }
            activity.startActivity(resolvedIntent)
            invoke.resolve(JSObject().apply { put("opened", true) })
        } catch (ex: Exception) {
            invoke.reject(ex.message ?: "STABILITY_SETTINGS_UNAVAILABLE")
        }
    }

    @Command
    fun deviceInfo(invoke: Invoke) {
        invoke.resolve(JSObject().apply {
            put("manufacturer", android.os.Build.MANUFACTURER.orEmpty())
            put("brand", android.os.Build.BRAND.orEmpty())
            put("model", android.os.Build.MODEL.orEmpty())
            put("device", android.os.Build.DEVICE.orEmpty())
            put("androidRelease", android.os.Build.VERSION.RELEASE.orEmpty())
            put("sdkInt", android.os.Build.VERSION.SDK_INT)
        })
    }

    @Command
    fun logs(invoke: Invoke) {
        invoke.resolve(JSObject().apply {
            put("content", KarinVpnService.logsSnapshot())
        })
    }

    @Command
    fun clearLogs(invoke: Invoke) {
        KarinVpnService.clearLogBuffer()
        invoke.resolve(JSObject().apply { put("cleared", true) })
    }

    @Command
    fun status(invoke: Invoke) {
        KarinVpnService.refreshSystemStatus()
        invoke.resolve(statusObject())
    }

    private fun statusObject() = JSObject().apply {
        put("running", KarinVpnService.running)
        put("starting", KarinVpnService.starting)
        put("coreRunning", KarinVpnService.coreRunning)
        put("reconnecting", KarinVpnService.reconnecting)
        put("alwaysOn", KarinVpnService.alwaysOn)
        put("lockdown", KarinVpnService.lockdown)
        put("appRoutingMode", KarinVpnService.appliedAppRoutingMode)
        put("appPackageCount", KarinVpnService.appliedAppPackageCount)
        put("tunFd", KarinVpnService.tunFd.takeIf { it >= 0 })
        put("coreVersion", KarinVpnService.coreVersion)
        put("lastError", KarinVpnService.lastError)
    }

    companion object {
        private const val MAX_SECURE_STATE_BYTES = 8 * 1024 * 1024
        private const val MAX_ROUTING_HEADER_CHARS = 1024 * 1024
        private const val POLL_MS = 100L
        private const val START_TIMEOUT_MS = 12_000L
        private const val STOP_TIMEOUT_MS = 5_000L
    }
}
