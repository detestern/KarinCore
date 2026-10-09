package com.nikitahya.karincore.vpn

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast
import androidx.core.content.ContextCompat

/**
 * ***************************************
 * QUICK SETTINGS TILE
 * ***************************************
 * One-tap connect / disconnect from the notification shade. It reuses the same
 * persisted "last working connection" and the same service intents as the
 * home-screen widget, so both always behave identically.
 */
class KarinVpnTileService : TileService() {
    override fun onStartListening() {
        instance = this
        refresh()
    }

    override fun onStopListening() {
        if (instance === this) instance = null
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        super.onDestroy()
    }

    override fun onClick() {
        // Starting a VPN from the lock screen should require the user to unlock first.
        if (isLocked) unlockAndRun { toggle() } else toggle()
    }

    private fun toggle() {
        KarinVpnService.refreshSystemStatus()
        val busy = KarinVpnService.running || KarinVpnService.starting || KarinVpnService.coreRunning

        if (busy) {
            if (KarinVpnService.alwaysOn) {
                Toast.makeText(this, R.string.widget_always_on, Toast.LENGTH_SHORT).show()
                launch(Intent(Settings.ACTION_VPN_SETTINGS))
                return
            }
            startService(
                Intent(this, KarinVpnService::class.java).apply { action = KarinVpnService.ACTION_STOP }
            )
            refresh()
            return
        }

        if (VpnService.prepare(this) != null) {
            openApp(R.string.widget_permission_required)
            return
        }

        val startIntent = KarinVpnService.widgetStartIntent(this)
        if (startIntent == null) {
            openApp(R.string.widget_profile_required)
            return
        }

        KarinVpnService.starting = true
        KarinVpnService.lastError = null
        refresh()
        try {
            ContextCompat.startForegroundService(this, startIntent)
        } catch (_: Exception) {
            KarinVpnService.starting = false
            refresh()
            openApp(R.string.widget_start_failed)
        }
    }

    private fun openApp(message: Int) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
        packageManager.getLaunchIntentForPackage(packageName)?.let { launch(it) }
    }

    private fun launch(intent: Intent) {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(
                PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun refresh() {
        val tile = qsTile ?: return
        val active = KarinVpnService.running && KarinVpnService.coreRunning
        val connecting = !active && (KarinVpnService.starting || KarinVpnService.reconnecting)

        tile.state = if (active || connecting) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.tile_label)
        tile.icon = Icon.createWithResource(
            this,
            if (active) R.drawable.ic_tile_core_on else R.drawable.ic_tile_core_off
        )
        if (Build.VERSION.SDK_INT >= 29) {
            tile.subtitle = getString(
                when {
                    active -> R.string.tile_connected
                    connecting -> R.string.tile_connecting
                    else -> R.string.tile_disconnected
                }
            )
        }
        tile.updateTile()
    }

    companion object {
        @Volatile private var instance: KarinVpnTileService? = null
        private val main = Handler(Looper.getMainLooper())

        /** Called from the VPN service on every state change; a no-op when the tile is not on screen. */
        fun refresh() {
            main.post { instance?.refresh() }
        }
    }
}
