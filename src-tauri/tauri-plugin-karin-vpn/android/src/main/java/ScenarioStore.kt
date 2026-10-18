package com.nikitahya.karincore.vpn

import android.content.Context
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject

/**
 * ***************************************
 * CONNECTION SCENARIOS: STORAGE
 * ***************************************
 * Scenarios live natively so they keep working while the WebView is gone.
 * The scenario list and settings are plain preferences (no secrets). The
 * prepared Xray connection of a "connect" scenario holds server credentials,
 * so it goes into the Keystore-backed SecureStorage, like the widget connection.
 */
internal data class Scenario(
    val id: String,
    val name: String,
    val kind: String,
    val ssid: String,
    val action: String,
    val serverLabel: String,
    val enabled: Boolean
) {
    companion object {
        const val KIND_WIFI = "wifi"
        const val KIND_MOBILE = "mobile"
        const val ACTION_OFF = "off"
        const val ACTION_CONNECT = "connect"
    }
}

internal data class ScenarioConnection(
    val configJson: String,
    val mtu: Int,
    val appRoutingMode: String,
    val appPackages: List<String>
)

internal class ScenarioStore(context: Context) {
    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun scenarios(): List<Scenario> {
        val raw = prefs.getString(KEY_LIST, null) ?: return emptyList()
        return parse(raw)
    }

    fun enabledCount(): Int = scenarios().count { it.enabled }

    fun notifyLevel(): String {
        val level = prefs.getString(KEY_NOTIFY, LEVEL_QUIET) ?: LEVEL_QUIET
        return if (level == LEVEL_OFF || level == LEVEL_BUTTON) level else LEVEL_QUIET
    }

    /**
     * Replaces the list. Returns true when the rules changed (which scenarios exist,
     * what they match, what they do, whether they are on). Renaming a scenario or a
     * server label is not a rule change and must not re-apply anything.
     */
    fun replace(scenariosJson: String, notifyLevel: String): Boolean {
        val parsed = parse(scenariosJson)
        val normalized = toJson(parsed)
        val previous = prefs.getString(KEY_LIST, null)
        val changed = ruleSignature(previous?.let { parse(it) } ?: emptyList()) != ruleSignature(parsed)

        val keepIds = parsed.map { it.id }.toSet()
        val known = prefs.getStringSet(KEY_CONNECTION_IDS, emptySet()) ?: emptySet()
        val secure = SecureStorage(appContext)
        val remaining = HashSet<String>()
        for (id in known) {
            if (id in keepIds) remaining.add(id) else secure.remove(connectionKey(id))
        }

        prefs.edit()
            .putString(KEY_LIST, normalized)
            .putString(KEY_NOTIFY, notifyLevel)
            .putStringSet(KEY_CONNECTION_IDS, remaining)
            .apply()
        return changed
    }

    fun saveConnection(id: String, payload: String) {
        SecureStorage(appContext).put(connectionKey(id), payload)
        val known = HashSet(prefs.getStringSet(KEY_CONNECTION_IDS, emptySet()) ?: emptySet())
        if (known.add(id)) prefs.edit().putStringSet(KEY_CONNECTION_IDS, known).apply()
    }

    fun connection(id: String): ScenarioConnection? {
        val payload = SecureStorage(appContext).get(connectionKey(id)) ?: return null
        return try {
            val json = JSONObject(payload)
            val packages = json.optJSONArray("appPackages") ?: JSONArray()
            ScenarioConnection(
                configJson = json.getString("configJson").takeIf { it.isNotBlank() } ?: return null,
                mtu = json.optInt("mtu", 1500).coerceIn(1280, 9000),
                appRoutingMode = json.optString("appRoutingMode", "all"),
                appPackages = (0 until packages.length()).mapNotNull {
                    packages.optString(it).takeIf(String::isNotBlank)
                }
            )
        } catch (_: Exception) {
            SecureStorage(appContext).remove(connectionKey(id))
            null
        }
    }

    // "Applied once": remembers which scenario already ran for the current network
    // in the current boot, so a manual connect or disconnect afterwards stays.
    fun appliedKey(): String? {
        val key = prefs.getString(KEY_APPLIED, null) ?: return null
        return if (prefs.getInt(KEY_APPLIED_BOOT, -1) == bootCount()) key else null
    }

    fun setApplied(key: String?) {
        val editor = prefs.edit()
        if (key == null) {
            editor.remove(KEY_APPLIED).remove(KEY_APPLIED_BOOT)
        } else {
            editor.putString(KEY_APPLIED, key).putInt(KEY_APPLIED_BOOT, bootCount())
        }
        editor.apply()
    }

    /** Wi-Fi names seen by the watcher, newest first. Android cannot list saved networks. */
    fun seenSsids(): List<String> {
        val raw = prefs.getString(KEY_SEEN, null) ?: return emptyList()
        return try {
            val array = org.json.JSONArray(raw)
            (0 until array.length()).map { array.optString(it) }.filter { it.isNotBlank() }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun rememberSsid(ssid: String) {
        val list = seenSsids()
        if (list.firstOrNull() == ssid) return
        val next = (listOf(ssid) + list.filter { it != ssid }).take(MAX_SEEN)
        prefs.edit().putString(KEY_SEEN, org.json.JSONArray(next).toString()).apply()
    }

    fun lastText(): String? = prefs.getString(KEY_LAST_TEXT, null)

    fun setLastText(text: String) {
        prefs.edit().putString(KEY_LAST_TEXT, text).apply()
    }

    fun errorShown(key: String): Boolean =
        (prefs.getStringSet(KEY_ERRORS, emptySet()) ?: emptySet()).contains(key)

    fun markError(key: String) {
        val set = HashSet(prefs.getStringSet(KEY_ERRORS, emptySet()) ?: emptySet())
        if (set.add(key)) prefs.edit().putStringSet(KEY_ERRORS, set).apply()
    }

    fun clearError(key: String) {
        val set = HashSet(prefs.getStringSet(KEY_ERRORS, emptySet()) ?: emptySet())
        if (set.remove(key)) prefs.edit().putStringSet(KEY_ERRORS, set).apply()
    }

    private fun bootCount(): Int = try {
        Settings.Global.getInt(appContext.contentResolver, Settings.Global.BOOT_COUNT, 0)
    } catch (_: Exception) {
        0
    }

    private fun ruleSignature(list: List<Scenario>): String =
        list.joinToString("|") { "${it.id},${it.kind},${it.ssid},${it.action},${it.enabled}" }

    private fun connectionKey(id: String) = "scenario_conn_$id"

    private fun parse(raw: String): List<Scenario> {
        return try {
            val array = JSONArray(raw)
            val seen = HashSet<String>()
            (0 until array.length()).mapNotNull { index ->
                val item = array.optJSONObject(index) ?: return@mapNotNull null
                val id = item.optString("id").takeIf { it.isNotBlank() } ?: return@mapNotNull null
                if (!seen.add(id)) return@mapNotNull null
                val kind = if (item.optString("kind") == Scenario.KIND_MOBILE) Scenario.KIND_MOBILE else Scenario.KIND_WIFI
                val ssid = item.optString("ssid")
                if (kind == Scenario.KIND_WIFI && ssid.isBlank()) return@mapNotNull null
                Scenario(
                    id = id,
                    name = item.optString("name"),
                    kind = kind,
                    ssid = if (kind == Scenario.KIND_WIFI) ssid else "",
                    action = if (item.optString("action") == Scenario.ACTION_CONNECT) Scenario.ACTION_CONNECT else Scenario.ACTION_OFF,
                    serverLabel = item.optString("serverLabel"),
                    enabled = item.optBoolean("enabled", true)
                )
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun toJson(list: List<Scenario>): String {
        val array = JSONArray()
        for (s in list) {
            array.put(
                JSONObject()
                    .put("id", s.id)
                    .put("name", s.name)
                    .put("kind", s.kind)
                    .put("ssid", s.ssid)
                    .put("action", s.action)
                    .put("serverLabel", s.serverLabel)
                    .put("enabled", s.enabled)
            )
        }
        return array.toString()
    }

    companion object {
        private const val PREFERENCES_NAME = "karincore_scenarios_v1"
        private const val KEY_LIST = "list"
        private const val KEY_NOTIFY = "notify"
        private const val KEY_CONNECTION_IDS = "connection_ids"
        private const val KEY_APPLIED = "applied"
        private const val KEY_APPLIED_BOOT = "applied_boot"
        private const val KEY_LAST_TEXT = "last_text"
        private const val KEY_ERRORS = "errors"
        private const val KEY_SEEN = "seen_ssids"
        private const val MAX_SEEN = 30
        const val LEVEL_OFF = "off"
        const val LEVEL_QUIET = "quiet"
        const val LEVEL_BUTTON = "button"
    }
}
