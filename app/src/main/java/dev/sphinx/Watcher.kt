package dev.sphinx

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

/**
 * Optional (Settings > Notification access): Sphinx sees posted notifications only to spot an imported account's app
 * asking for a 2FA code (it offers that account's code with Copy), and, only while a laptop request is waiting, a code
 * in a text or email from the SMS and mail apps in Domains.TEXT_APPS (it offers to send it to the laptop). Nothing from
 * a notification is kept.
 */
class CodeWatcher : NotificationListenerService() {
    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val pkg = sbn.packageName
        Thread {
            runCatching {
                // Any other app's notification, and an SMS or mail app's while no laptop request waits, is never read.
                if (!Sphinx.watches(applicationContext, pkg)) return@runCatching
                val e = sbn.notification?.extras ?: return@runCatching
                val title = e.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
                val text = e.getCharSequence(Notification.EXTRA_TEXT)?.toString().orEmpty()
                Sphinx.notification(applicationContext, pkg, title, text)
            }
        }.start()
    }
}
