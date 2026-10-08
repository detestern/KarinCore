package com.nikitahya.karincore.vpn

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.provider.Settings
import android.widget.RemoteViews
import android.widget.Toast
import androidx.core.content.ContextCompat

class KarinVpnWidgetProvider : AppWidgetProvider() {
    override fun onUpdate(context: Context, manager: AppWidgetManager, appWidgetIds: IntArray) {
        appWidgetIds.forEach { update(context, manager, it) }
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        if (intent.action != ACTION_TOGGLE) return

        KarinVpnService.refreshSystemStatus()
        if (KarinVpnService.running || KarinVpnService.starting || KarinVpnService.coreRunning) {
            if (KarinVpnService.alwaysOn) {
                Toast.makeText(context, R.string.widget_always_on, Toast.LENGTH_SHORT).show()
                context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                return
            }

            context.startService(
                Intent(context, KarinVpnService::class.java).apply {
                    action = KarinVpnService.ACTION_STOP
                }
            )
            updateAll(context)
            return
        }

        if (VpnService.prepare(context) != null) {
            openApp(context, R.string.widget_permission_required)
            return
        }

        val startIntent = KarinVpnService.widgetStartIntent(context)
        if (startIntent == null) {
            openApp(context, R.string.widget_profile_required)
            return
        }

        KarinVpnService.starting = true
        KarinVpnService.lastError = null
        updateAll(context)
        try {
            ContextCompat.startForegroundService(context, startIntent)
        } catch (_: Exception) {
            KarinVpnService.starting = false
            updateAll(context)
            openApp(context, R.string.widget_start_failed)
        }
    }

    private fun openApp(context: Context, message: Int) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
        context.packageManager.getLaunchIntentForPackage(context.packageName)?.let {
            it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            context.startActivity(it)
        }
    }

    companion object {
        private const val ACTION_TOGGLE = "com.nikitahya.karincore.widget.TOGGLE"

        fun updateAll(context: Context) {
            val manager = AppWidgetManager.getInstance(context)
            val component = ComponentName(context, KarinVpnWidgetProvider::class.java)
            manager.getAppWidgetIds(component).forEach { update(context, manager, it) }
        }

        private fun update(context: Context, manager: AppWidgetManager, appWidgetId: Int) {
            val active = KarinVpnService.running && KarinVpnService.coreRunning
            val connecting = KarinVpnService.starting || KarinVpnService.reconnecting
            val views = RemoteViews(context.packageName, R.layout.karin_vpn_widget)
            val icon = when {
                active -> R.drawable.ic_widget_power_on
                connecting -> R.drawable.ic_widget_power_connecting
                else -> R.drawable.ic_widget_power_off
            }
            val description = when {
                active -> R.string.widget_connected
                connecting -> R.string.widget_connecting
                else -> R.string.widget_disconnected
            }

            val toggleIntent = Intent(context, KarinVpnWidgetProvider::class.java).apply {
                action = ACTION_TOGGLE
            }
            val togglePendingIntent = PendingIntent.getBroadcast(
                context,
                7302,
                toggleIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            views.setImageViewResource(R.id.widget_power, icon)
            views.setContentDescription(R.id.widget_power, context.getString(description))
            views.setOnClickPendingIntent(R.id.widget_root, togglePendingIntent)
            manager.updateAppWidget(appWidgetId, views)
        }
    }
}
