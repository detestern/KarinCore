package com.nikitahya.karincore.vpn

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.provider.Settings
import androidx.core.content.ContextCompat

/**
 * ***************************************
 * CONNECTION SCENARIOS: ENGINE
 * ***************************************
 * Top-to-bottom, first enabled scenario that matches the current network wins;
 * no match means do nothing. A scenario is applied once when its network is
 * entered, so a manual connect or disconnect afterwards is never overridden.
 */
internal object ScenarioEngine {
    data class Net(val kind: String, val ssid: String?) {
        companion object {
            const val WIFI = "wifi"
            const val MOBILE = "mobile"
            const val NONE = "none"
        }
    }

    private const val ERROR_LOCATION = "location"

    @Volatile var current: Net = Net(Net.NONE, null)
        private set
    @Volatile var activeId: String? = null
        private set

    private val lock = Any()

    fun onNetwork(context: Context, net: Net) {
        net.ssid?.let { if (net.kind == Net.WIFI) ScenarioStore(context.applicationContext).rememberSsid(it) }
        synchronized(lock) {
            current = net
            evaluateLocked(context.applicationContext)
        }
    }

    /** Called after the scenario list changed or its prepared connection was refreshed. */
    fun reevaluate(context: Context) {
        synchronized(lock) { evaluateLocked(context.applicationContext) }
    }

    private fun matches(scenario: Scenario, net: Net): Boolean = when (scenario.kind) {
        Scenario.KIND_MOBILE -> net.kind == Net.MOBILE
        else -> net.kind == Net.WIFI && net.ssid != null && net.ssid == scenario.ssid
    }

    private fun evaluateLocked(context: Context) {
        val store = ScenarioStore(context)
        val net = current
        val enabled = store.scenarios().filter { it.enabled }

        // On Wi-Fi but the network name is hidden from us (no location access).
        val nameHidden = net.kind == Net.WIFI && net.ssid == null && enabled.any { it.kind == Scenario.KIND_WIFI }
        if (nameHidden) {
            if (!store.errorShown(ERROR_LOCATION)) {
                store.markError(ERROR_LOCATION)
                ScenarioNotifier.problem(
                    context,
                    context.getString(R.string.scenario_err_wifi_title),
                    context.getString(R.string.scenario_err_location),
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                        data = Uri.fromParts("package", context.packageName, null)
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                )
            }
        } else {
            store.clearError(ERROR_LOCATION)
        }

        val match = enabled.firstOrNull { matches(it, net) }
        activeId = match?.id
        if (match == null) {
            store.setApplied(null)
            return
        }

        val key = "${net.kind}:${net.ssid.orEmpty()}|${match.id}|${match.action}"
        if (store.appliedKey() == key) return
        store.setApplied(key)
        apply(context, store, match, net)
    }

    private fun conditionText(context: Context, scenario: Scenario, net: Net): String =
        if (scenario.kind == Scenario.KIND_MOBILE) {
            context.getString(R.string.scenario_condition_mobile)
        } else {
            context.getString(R.string.scenario_condition_wifi, net.ssid.orEmpty())
        }

    private fun titleOf(context: Context, scenario: Scenario): String {
        val name = scenario.name.trim()
        return when {
            name.isNotEmpty() -> name
            scenario.kind == Scenario.KIND_MOBILE -> context.getString(R.string.scenario_condition_mobile)
            else -> scenario.ssid
        }
    }

    private fun apply(context: Context, store: ScenarioStore, scenario: Scenario, net: Net) {
        val problemTitle = context.getString(R.string.scenario_err_title, titleOf(context, scenario))
        KarinVpnService.refreshSystemStatus()

        if (scenario.action == Scenario.ACTION_OFF) {
            val busy = KarinVpnService.running || KarinVpnService.starting || KarinVpnService.coreRunning
            if (!busy) return // already off: nothing changed, nothing to say
            if (KarinVpnService.alwaysOn) {
                ScenarioNotifier.problem(context, problemTitle, context.getString(R.string.scenario_err_always_on), null)
                return
            }
            try {
                context.startService(
                    Intent(context, KarinVpnService::class.java).apply { action = KarinVpnService.ACTION_STOP }
                )
            } catch (_: Exception) {
                ScenarioNotifier.problem(context, problemTitle, context.getString(R.string.scenario_err_start), null)
                return
            }
            announce(context, store, scenario, net, context.getString(R.string.scenario_result_off))
            return
        }

        val connection = store.connection(scenario.id)
        if (connection == null) {
            ScenarioNotifier.problem(context, problemTitle, context.getString(R.string.scenario_err_no_config), null)
            return
        }
        if (VpnService.prepare(context) != null) {
            ScenarioNotifier.problem(context, problemTitle, context.getString(R.string.scenario_err_vpn_permission), null)
            return
        }
        if (KarinVpnService.running && KarinVpnService.coreRunning && KarinVpnService.lastConfigJson == connection.configJson) {
            return // already connected to exactly this server
        }

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
            ScenarioNotifier.problem(context, problemTitle, context.getString(R.string.scenario_err_start), null)
            return
        }
        val server = scenario.serverLabel.ifBlank { "…" }
        announce(context, store, scenario, net, context.getString(R.string.scenario_result_connect, server))
    }

    private fun announce(context: Context, store: ScenarioStore, scenario: Scenario, net: Net, result: String) {
        val line = context.getString(R.string.scenario_line, conditionText(context, scenario, net), result)
        store.setLastText("${titleOf(context, scenario)}: $line")
        ScenarioNotifier.fired(
            context,
            titleOf(context, scenario),
            line,
            store.notifyLevel(),
            scenario.id,
            scenario.action
        )
    }

    /** "Undo" on the notification: do the opposite of what the scenario just did. */
    fun undo(context: Context, performedAction: String) {
        val appContext = context.applicationContext
        ScenarioNotifier.cancelFired(appContext)
        try {
            if (performedAction == Scenario.ACTION_CONNECT) {
                if (!KarinVpnService.alwaysOn) {
                    appContext.startService(
                        Intent(appContext, KarinVpnService::class.java).apply { action = KarinVpnService.ACTION_STOP }
                    )
                }
            } else if (VpnService.prepare(appContext) == null) {
                val start = KarinVpnService.widgetStartIntent(appContext)
                if (start != null) {
                    KarinVpnService.starting = true
                    KarinVpnService.lastError = null
                    ContextCompat.startForegroundService(appContext, start)
                }
            }
        } catch (_: Exception) {
            KarinVpnService.starting = false
        }
        ScenarioStore(appContext).setLastText("")
    }
}
