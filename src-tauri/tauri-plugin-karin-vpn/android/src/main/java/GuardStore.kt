package com.nikitahya.karincore.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * ***************************************
 * TUNNEL GUARD: STORAGE
 * ***************************************
 * Settings of the "connection drop" guard, the backup servers prepared by the
 * app, the server that is currently in use and a short event log. Plain
 * preferences: server credentials of the backups live in the Keystore-backed
 * ScenarioStore (ids starting with "guard_"), never here.
 */
internal data class GuardCandidate(val id: String, val url: String, val label: String)

internal data class GuardSettings(
    val enabled: Boolean,
    val action: String,
    val interval: Int,
    val notify: Boolean,
    val confirm: Int
) {
    companion object {
        const val ACTION_OFF = "off"
        const val ACTION_PROFILE = "profile"
        const val ACTION_BEST = "best"
    }
}

internal class GuardStore(context: Context) {
    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun settings(): GuardSettings {
        val action = prefs.getString(KEY_ACTION, GuardSettings.ACTION_OFF)
        return GuardSettings(
            enabled = prefs.getBoolean(KEY_ENABLED, false),
            action = if (action == GuardSettings.ACTION_PROFILE || action == GuardSettings.ACTION_BEST) action else GuardSettings.ACTION_OFF,
            interval = prefs.getInt(KEY_INTERVAL, 30).coerceIn(10, 300),
            notify = prefs.getBoolean(KEY_NOTIFY, true),
            confirm = prefs.getInt(KEY_CONFIRM, 3).coerceIn(2, 10)
        )
    }

    fun candidates(): List<GuardCandidate> {
        val raw = prefs.getString(KEY_CANDIDATES, null) ?: return emptyList()
        return try {
            val array = JSONArray(raw)
            (0 until array.length()).mapNotNull { index ->
                val item = array.optJSONObject(index) ?: return@mapNotNull null
                val id = item.optString("id")
                val url = item.optString("url")
                if (id.isBlank() || url.isBlank()) null else GuardCandidate(id, url, item.optString("label"))
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun currentUrl(): String = prefs.getString(KEY_CURRENT_URL, "").orEmpty()

    fun currentLabel(): String = prefs.getString(KEY_CURRENT_LABEL, "").orEmpty()

    fun seq(): Int = prefs.getInt(KEY_SEQ, 0)

    /**
     * Takes the state sent by the app. The server the app shows as current wins unless the
     * guard switched the server after the app last looked (then the app is behind and will
     * adopt the native value on its next status read).
     */
    fun sync(json: String): GuardSettings {
        val root = JSONObject(json)
        val list = root.optJSONArray("candidates") ?: JSONArray()
        val keep = HashSet<String>()
        val normalized = JSONArray()
        for (i in 0 until list.length()) {
            val item = list.optJSONObject(i) ?: continue
            val id = item.optString("id")
            val url = item.optString("url")
            if (id.isBlank() || url.isBlank() || !id.startsWith(ID_PREFIX)) continue
            keep.add(id)
            normalized.put(JSONObject().put("id", id).put("url", url).put("label", item.optString("label")))
        }

        val editor = prefs.edit()
            .putBoolean(KEY_ENABLED, root.optBoolean("enabled", false))
            .putString(KEY_ACTION, root.optString("action", GuardSettings.ACTION_OFF))
            .putInt(KEY_INTERVAL, root.optInt("interval", 30))
            .putBoolean(KEY_NOTIFY, root.optBoolean("notify", true))
            .putInt(KEY_CONFIRM, root.optInt("confirm", 3))
            .putString(KEY_CANDIDATES, normalized.toString())

        val seqSeen = root.optInt("seqSeen", 0)
        val appUrl = root.optString("currentUrl")
        if (seqSeen >= seq() && appUrl.isNotBlank()) {
            editor.putString(KEY_CURRENT_URL, appUrl).putString(KEY_CURRENT_LABEL, root.optString("currentLabel"))
        }
        editor.apply()

        ScenarioStore(appContext).pruneGuardConnections(keep)
        return settings()
    }

    fun setCurrent(url: String, label: String, bumpSeq: Boolean) {
        val editor = prefs.edit().putString(KEY_CURRENT_URL, url).putString(KEY_CURRENT_LABEL, label)
        if (bumpSeq) editor.putInt(KEY_SEQ, seq() + 1)
        editor.apply()
    }

    fun events(): JSONArray {
        val raw = prefs.getString(KEY_EVENTS, null) ?: return JSONArray()
        return try { JSONArray(raw) } catch (_: Exception) { JSONArray() }
    }

    fun addEvent(kind: String, from: String, to: String) {
        val old = events()
        val next = JSONArray()
        next.put(JSONObject().put("at", System.currentTimeMillis()).put("kind", kind).put("from", from).put("to", to))
        for (i in 0 until minOf(old.length(), MAX_EVENTS - 1)) next.put(old.get(i))
        prefs.edit().putString(KEY_EVENTS, next.toString()).apply()
    }

    companion object {
        const val ID_PREFIX = "guard_"
        private const val PREFERENCES_NAME = "karincore_guard_v1"
        private const val KEY_ENABLED = "enabled"
        private const val KEY_ACTION = "action"
        private const val KEY_INTERVAL = "interval"
        private const val KEY_NOTIFY = "notify"
        private const val KEY_CONFIRM = "confirm"
        private const val KEY_CANDIDATES = "candidates"
        private const val KEY_CURRENT_URL = "current_url"
        private const val KEY_CURRENT_LABEL = "current_label"
        private const val KEY_SEQ = "seq"
        private const val KEY_EVENTS = "events"
        private const val MAX_EVENTS = 20
    }
}
