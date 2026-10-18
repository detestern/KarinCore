package com.nikitahya.karincore.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Handles the "Undo" button of a scenario notification. */
class ScenarioActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != ACTION_UNDO) return
        val action = intent.getStringExtra(EXTRA_ACTION).orEmpty()
        ScenarioEngine.undo(context, action)
    }

    companion object {
        const val ACTION_UNDO = "com.nikitahya.karincore.vpn.SCENARIO_UNDO"
        const val EXTRA_ID = "scenario_id"
        const val EXTRA_ACTION = "scenario_action"
    }
}
