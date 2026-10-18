package com.nikitahya.karincore.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Restores the network watcher after a reboot or an app update. */
class ScenarioBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        ScenarioWatcherService.startIfNeeded(context)
    }
}
