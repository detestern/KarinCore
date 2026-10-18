package com.nikitahya.karincore.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

/**
 * ***************************************
 * CONNECTION SCENARIOS: NOTIFICATIONS
 * ***************************************
 * Three separate channels so any of them can be silenced in Android settings:
 *  - watch:  the always-present service notification (minimum importance)
 *  - events: "a scenario ran" (quiet, auto-dismissed, optional Undo button)
 *  - errors: "a scenario could not run" (shown once per cause)
 */
internal object ScenarioNotifier {
    const val CHANNEL_WATCH = "karincore_watch"
    const val CHANNEL_EVENTS = "karincore_scenarios"
    const val CHANNEL_ERRORS = "karincore_scenario_errors"

    // Shared with the VPN service: one ongoing notification while both are alive.
    const val ONGOING_ID = 7301
    private const val EVENT_ID = 7311
    private const val ERROR_ID = 7312
    private const val EVENT_TIMEOUT_MS = 10_000L

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_WATCH,
                context.getString(R.string.scenario_channel_watch),
                NotificationManager.IMPORTANCE_MIN
            ).apply { setShowBadge(false) }
        )
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_EVENTS,
                context.getString(R.string.scenario_channel_events),
                NotificationManager.IMPORTANCE_LOW
            ).apply { setShowBadge(false) }
        )
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ERRORS,
                context.getString(R.string.scenario_channel_errors),
                NotificationManager.IMPORTANCE_DEFAULT
            )
        )
    }

    fun watching(context: Context, enabledCount: Int): Notification {
        ensureChannels(context)
        return NotificationCompat.Builder(context, CHANNEL_WATCH)
            .setSmallIcon(R.drawable.ic_stat_karincore)
            .setContentTitle("KarinCore")
            .setContentText(context.getString(R.string.scenario_watching, enabledCount))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(launchIntent(context))
            .build()
    }

    /** "<title>" / "<condition> → <result>", quiet, gone after a few seconds. */
    fun fired(context: Context, title: String, text: String, level: String, undoScenarioId: String?, undoAction: String?) {
        if (level == ScenarioStore.LEVEL_OFF || !canNotify(context)) return
        ensureChannels(context)
        val builder = NotificationCompat.Builder(context, CHANNEL_EVENTS)
            .setSmallIcon(R.drawable.ic_stat_karincore)
            .setContentTitle(title)
            .setContentText(text)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(launchIntent(context))

        if (level == ScenarioStore.LEVEL_BUTTON && undoScenarioId != null && undoAction != null) {
            val undo = Intent(context, ScenarioActionReceiver::class.java).apply {
                action = ScenarioActionReceiver.ACTION_UNDO
                setPackage(context.packageName)
                putExtra(ScenarioActionReceiver.EXTRA_ID, undoScenarioId)
                putExtra(ScenarioActionReceiver.EXTRA_ACTION, undoAction)
            }
            val pending = PendingIntent.getBroadcast(
                context,
                3,
                undo,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            builder.addAction(0, context.getString(R.string.scenario_undo), pending)
        } else {
            builder.setTimeoutAfter(EVENT_TIMEOUT_MS)
        }
        notifySafely(context, EVENT_ID, builder.build())
    }

    fun cancelFired(context: Context) {
        NotificationManagerCompat.from(context).cancel(EVENT_ID)
    }

    /** Shown once per cause; tapping opens the app (or the given settings screen). */
    fun problem(context: Context, title: String, text: String, tapIntent: Intent?) {
        if (!canNotify(context)) return
        ensureChannels(context)
        val pending = if (tapIntent != null) {
            PendingIntent.getActivity(
                context,
                4,
                tapIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
        } else {
            launchIntent(context)
        }
        val notification = NotificationCompat.Builder(context, CHANNEL_ERRORS)
            .setSmallIcon(R.drawable.ic_stat_karincore)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(pending)
            .build()
        notifySafely(context, ERROR_ID, notification)
    }

    private fun canNotify(context: Context): Boolean =
        NotificationManagerCompat.from(context).areNotificationsEnabled()

    @Suppress("MissingPermission")
    private fun notifySafely(context: Context, id: Int, notification: Notification) {
        try {
            NotificationManagerCompat.from(context).notify(id, notification)
        } catch (_: SecurityException) {
            // POST_NOTIFICATIONS revoked between the check and the call.
        }
    }

    private fun launchIntent(context: Context): PendingIntent? {
        val intent = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return null
        return PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }
}
