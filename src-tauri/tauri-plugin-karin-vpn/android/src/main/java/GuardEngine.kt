package com.nikitahya.karincore.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Base64
import androidx.core.content.ContextCompat
import org.json.JSONObject
import java.net.InetSocketAddress
import java.net.Socket

/**
 * ***************************************
 * TUNNEL GUARD: ENGINE
 * ***************************************
 * While the tunnel is up, a small thread sends a request through the local ping-in
 * inbound of Xray every few seconds. A drop is several failed checks in a row (a single
 * lost packet never switches anything). Then the guard does what the user chose:
 * turn the VPN off, or move to a prepared backup server and verify it really works.
 * It lives next to the VPN service, so it keeps working while the app is closed.
 */
internal object GuardEngine {
    private const val PROXY_HOST = "127.0.0.1"
    private const val PROXY_PORT = 2082
    private const val PROBE_HOST = "cp.cloudflare.com"
    private const val PROBE_URL = "http://cp.cloudflare.com/generate_204"
    private const val CHECK_TIMEOUT_MS = 6_000
    private const val RETRY_DELAY_MS = 4_000L
    private const val START_WAIT_MS = 20_000L
    private const val SETTLE_MS = 1_500L

    private val lock = Any()
    private var thread: Thread? = null
    @Volatile private var switching = false

    @Volatile private var phase = "idle"
    @Volatile private var fails = 0
    @Volatile private var checkedAt = 0L
    @Volatile private var lastMs = 0

    /** The tunnel came up (a fresh start or a manual server change): begin watching it. */
    fun onTunnelUp(context: Context) {
        if (switching) return
        synchronized(lock) {
            stopLocked()
            val appContext = context.applicationContext
            if (!GuardStore(appContext).settings().enabled) return
            fails = 0
            phase = "ok"
            checkedAt = 0L
            val worker = Thread({ loop(appContext) }, "karin-guard").apply { isDaemon = true }
            thread = worker
            worker.start()
        }
    }

    /** The tunnel is really gone (stopped by the user, a scenario or a failed start). */
    fun onTunnelDown() {
        if (switching) return
        synchronized(lock) { stopLocked() }
        phase = "idle"
        fails = 0
    }

    /** Settings changed in the app: apply them to a running tunnel. */
    fun onSettingsChanged(context: Context) {
        val appContext = context.applicationContext
        val enabled = GuardStore(appContext).settings().enabled
        val up = KarinVpnService.running && KarinVpnService.coreRunning
        if (!enabled) {
            onTunnelDown()
        } else if (up && thread == null) {
            onTunnelUp(appContext)
        }
    }

    private fun stopLocked() {
        thread?.interrupt()
        thread = null
    }

    fun status(context: Context): JSONObject {
        val store = GuardStore(context.applicationContext)
        return JSONObject()
            .put("vpnUp", KarinVpnService.running && KarinVpnService.coreRunning)
            .put("phase", if (thread == null) "idle" else phase)
            .put("fails", fails)
            .put("checkedAt", checkedAt)
            .put("ms", lastMs)
            .put("events", store.events())
            .put("seq", store.seq())
            .put("currentUrl", store.currentUrl())
    }

    private fun loop(context: Context) {
        val me = Thread.currentThread()
        try {
            var delayMs = initialDelay(context)
            while (!me.isInterrupted) {
                Thread.sleep(delayMs)
                if (thread !== me) return
                val settings = GuardStore(context).settings()
                if (!settings.enabled) return
                delayMs = settings.interval * 1000L

                if (KarinVpnService.starting || KarinVpnService.reconnecting || !KarinVpnService.coreRunning) {
                    fails = 0
                    continue
                }
                if (!deviceHasInternet(context)) {
                    // No network at all (airplane mode, lift): that is not a dead server.
                    phase = "waiting"
                    fails = 0
                    continue
                }

                val ms = check()
                checkedAt = System.currentTimeMillis()
                if (ms >= 0) {
                    lastMs = ms
                    fails = 0
                    phase = "ok"
                    continue
                }
                fails += 1
                phase = "retry"
                if (fails < settings.confirm) {
                    delayMs = RETRY_DELAY_MS
                    continue
                }
                handleDrop(context, settings)
                fails = 0
                if (thread !== me) return
                phase = "ok"
            }
        } catch (_: InterruptedException) {
            // stopped on purpose
        } catch (_: Throwable) {
            phase = "idle"
        }
    }

    private fun initialDelay(context: Context): Long =
        (GuardStore(context).settings().interval * 1000L).coerceAtMost(15_000L)

    private fun deviceHasInternet(context: Context): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return true
        return try {
            cm.allNetworks.any { network ->
                val caps = cm.getNetworkCapabilities(network) ?: return@any false
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
        } catch (_: Exception) {
            true
        }
    }

    /**
     * Milliseconds of one round trip through the tunnel, or -1 when it did not answer.
     * A plain socket to the local proxy: no cleartext-traffic policy and no platform HTTP
     * client behaviour in the way, and nothing leaves the device except through Xray.
     */
    private fun check(): Int {
        val token = pingToken(KarinVpnService.lastConfigJson) ?: return -1
        val started = System.nanoTime()
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(PROXY_HOST, PROXY_PORT), CHECK_TIMEOUT_MS)
                socket.soTimeout = CHECK_TIMEOUT_MS
                val auth = Base64.encodeToString("karin:$token".toByteArray(), Base64.NO_WRAP)
                val request = "GET $PROBE_URL HTTP/1.1\r\nHost: $PROBE_HOST\r\n" +
                    "Proxy-Authorization: Basic $auth\r\nConnection: close\r\n\r\n"
                socket.getOutputStream().apply { write(request.toByteArray()); flush() }
                val line = socket.getInputStream().bufferedReader().readLine().orEmpty()
                val code = line.split(' ').getOrNull(1)?.toIntOrNull() ?: -1
                if (code in 200..399) ((System.nanoTime() - started) / 1_000_000L).toInt().coerceAtLeast(1) else -1
            }
        } catch (_: Exception) {
            -1
        }
    }

    private fun pingToken(configJson: String?): String? {
        if (configJson.isNullOrBlank()) return null
        return try {
            val inbounds = JSONObject(configJson).optJSONArray("inbounds") ?: return null
            for (i in 0 until inbounds.length()) {
                val inbound = inbounds.optJSONObject(i) ?: continue
                if (inbound.optString("tag") != "ping-in") continue
                val accounts = inbound.optJSONObject("settings")?.optJSONArray("accounts") ?: continue
                val pass = accounts.optJSONObject(0)?.optString("pass").orEmpty()
                if (pass.isNotBlank()) return pass
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    private fun handleDrop(context: Context, settings: GuardSettings) {
        val store = GuardStore(context)
        val fromLabel = store.currentLabel().ifBlank { "VPN" }

        if (settings.action != GuardSettings.ACTION_OFF) {
            phase = "switching"
            val current = KarinVpnService.lastConfigJson
            val scenarios = ScenarioStore(context)
            val currentUrl = store.currentUrl()
            val candidates = store.candidates().filter { it.url != currentUrl }
            switching = true
            try {
                for (candidate in candidates) {
                    val connection = scenarios.connection(candidate.id) ?: continue
                    if (connection.configJson == current) continue
                    if (!startAndVerify(context, connection)) continue
                    store.setCurrent(candidate.url, candidate.label, bumpSeq = true)
                    store.addEvent("switch", fromLabel, candidate.label)
                    announce(context, settings, context.getString(R.string.guard_note_switch, fromLabel, candidate.label))
                    return
                }
            } finally {
                switching = false
            }
            stopVpn(context, store, settings, fromLabel, "failed", R.string.guard_note_failed)
            return
        }
        stopVpn(context, store, settings, fromLabel, "off", R.string.guard_note_off)
    }

    private fun stopVpn(context: Context, store: GuardStore, settings: GuardSettings, from: String, kind: String, noteRes: Int) {
        KarinVpnService.refreshSystemStatus()
        if (KarinVpnService.alwaysOn) {
            // Android does not let an app turn Always-on VPN off; say so instead of pretending.
            store.addEvent("blocked", from, "")
            announce(context, settings, context.getString(R.string.guard_note_blocked, from))
            return
        }
        store.addEvent(kind, from, "")
        announce(context, settings, context.getString(noteRes, from))
        try {
            context.startService(Intent(context, KarinVpnService::class.java).apply { action = KarinVpnService.ACTION_STOP })
        } catch (_: Exception) {
            // the service is already ours; nothing else to do
        }
    }

    private fun startAndVerify(context: Context, connection: ScenarioConnection): Boolean {
        val intent = Intent(context, KarinVpnService::class.java).apply {
            action = KarinVpnService.ACTION_START
            putExtra(KarinVpnService.EXTRA_CONFIG_JSON, connection.configJson)
            putExtra(KarinVpnService.EXTRA_MTU, connection.mtu)
            putExtra(KarinVpnService.EXTRA_APP_ROUTING_MODE, connection.appRoutingMode)
            putStringArrayListExtra(KarinVpnService.EXTRA_APP_PACKAGES, ArrayList(connection.appPackages))
        }
        KarinVpnService.starting = true
        KarinVpnService.lastError = null
        try {
            ContextCompat.startForegroundService(context, intent)
        } catch (_: Exception) {
            KarinVpnService.starting = false
            return false
        }

        val deadline = System.currentTimeMillis() + START_WAIT_MS
        // The service flips "starting" on its worker; give the request a moment to be picked up.
        Thread.sleep(300)
        while (System.currentTimeMillis() < deadline) {
            if (!KarinVpnService.starting) break
            Thread.sleep(200)
        }
        if (!(KarinVpnService.running && KarinVpnService.coreRunning && KarinVpnService.lastConfigJson == connection.configJson)) {
            return false
        }
        Thread.sleep(SETTLE_MS)
        repeat(2) {
            if (check() >= 0) return true
            Thread.sleep(RETRY_DELAY_MS)
        }
        return false
    }

    private fun announce(context: Context, settings: GuardSettings, text: String) {
        if (!settings.notify) return
        ScenarioNotifier.fired(context, "KarinCore", text, ScenarioStore.LEVEL_QUIET, null, null)
    }
}
