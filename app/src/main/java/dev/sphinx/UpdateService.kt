package dev.sphinx

import android.app.Notification
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

/**
 * The update's download as a foreground service: Android throttles a plain thread's network once the app is off
 * screen (the owner, 2026-10-27: 31 MB crawled at 20 KB/s until Sphinx was reopened), a foreground service's it leaves
 * alone. Its notification carries the progress; the work itself is [Update.install], which ends with the installer
 * (app in front) or a "downloaded" notification (app off screen).
 */
class UpdateService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    /** The download's thread is running: a second start (another tap) must not spawn a worker that would end the foreground state under the first (Codex, 2026-10-27). */
    @Volatile private var working = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (working) return START_NOT_STICKY
        val r = Update.pending ?: run { stopSelf(startId); return START_NOT_STICKY }
        working = true
        val nm = getSystemService(NotificationManager::class.java)
        Update.channel(nm)
        fun note(percent: Int, indeterminate: Boolean): Notification = NotificationCompat.Builder(this, Update.CHANNEL)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle("Downloading Sphinx ${r.versionName}")
            .setContentText(if (indeterminate) "Starting…" else "$percent%")
            .setProgress(100, percent, indeterminate)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(Update.NOTE_DOWNLOAD, note(0, true), ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        else startForeground(Update.NOTE_DOWNLOAD, note(0, true))
        Thread {
            var shown = -1
            runCatching {
                Update.install(this, r) { s ->
                    if (s is UpdateState.Downloading && s.percent != shown) { shown = s.percent; runCatching { nm.notify(Update.NOTE_DOWNLOAD, note(s.percent, false)) } }
                }
            }.onFailure { Log.warn("update failed", it.javaClass.simpleName); Update.fail(r, "The update failed (${it.javaClass.simpleName}).") }
            stopForeground(STOP_FOREGROUND_REMOVE)
            working = false
            stopSelf()
        }.start()
        return START_NOT_STICKY
    }

    /** Android 15 ends a dataSync service after its allowance: the download stops as a failure before that. */
    override fun onTimeout(startId: Int, fgsType: Int) {
        Log.warn("update download timed out")
        Update.cancel()
    }
}
