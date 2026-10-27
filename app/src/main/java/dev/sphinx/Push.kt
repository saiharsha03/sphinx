package dev.sphinx

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.google.android.gms.tasks.Tasks
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import java.util.concurrent.TimeUnit

/**
 * How a laptop's request reaches the phone (docs/DESIGN.md, "Wake-up"): only Firebase Cloud Messaging. There is no live
 * connection and no foreground service. The phone hands its FCM token to each pairing's relay; the relay sends every
 * laptop request at once as an FCM data message that carries the sealed blobs. Besides the wake, the inbox is fetched
 * once when the app opens or comes to the front (MainActivity) and by the 15-minute heartbeat ([SphinxBeat]). The app
 * builds without `app/google-services.json` (for tests), but then it can't pair: a release build needs it. Firebase
 * stays off until a laptop is paired (auto-init false in the manifest); nothing else of Firebase is in the app.
 */
object Push {
    /** Firebase is set up: the build had google-services.json (its values are resources, read by FirebaseInitProvider). */
    fun available(c: Context): Boolean = runCatching { FirebaseApp.getApps(c).isNotEmpty() || FirebaseApp.initializeApp(c) != null }.getOrDefault(false)

    /** This phone's FCM token, or null (no Firebase in the build, no Play services, no network). Blocking. */
    fun token(c: Context): String? {
        if (!available(c)) return null
        return runCatching {
            val m = FirebaseMessaging.getInstance()
            m.isAutoInitEnabled = true
            Tasks.await(m.token, 20, TimeUnit.SECONDS)
        }.onFailure { Log.warn("no FCM token", it.javaClass.simpleName) }.getOrNull()
    }

    /**
     * Tells each pairing's relay this phone's FCM token ([known], else asked of Firebase) and keeps what each relay
     * answered (Pairing.push: false means that relay can't wake the phone yet, which the Laptops screen says). Blocking,
     * never on the main thread.
     */
    fun register(c: Context, known: String? = null) {
        val store = SphinxStore.get(c)
        val pairings = store.pairings()
        if (pairings.isEmpty()) return
        val token = known ?: token(c) ?: return
        for (p in pairings) {
            val on = runCatching { RelayClient.push(p, token) }.onFailure { Log.warn("push not registered", it.javaClass.simpleName) }.getOrDefault(p.push)
            store.updatePairing(p.pid) { it.copy(push = on) }
            if (!on) Log.warn("the relay can't wake this phone")
        }
    }

    /** Every 15 minutes while a laptop is paired: the token again and a look at each inbox. */
    fun schedule(c: Context) {
        val work = PeriodicWorkRequestBuilder<SphinxBeat>(15, TimeUnit.MINUTES)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()).build()
        WorkManager.getInstance(c).enqueueUniquePeriodicWork("sphinx.beat", ExistingPeriodicWorkPolicy.KEEP, work)
    }
}

/**
 * The heartbeat: re-registers the FCM token (a relay restarted, a token changed), fetches anything a lost wake left in
 * the inboxes, and lets the relay see the phone (the laptop's icon says "reachable" for 30 minutes after).
 */
class SphinxBeat(c: Context, p: WorkerParameters) : Worker(c, p) {
    override fun doWork(): Result {
        if (SphinxStore.get(applicationContext).pairings().isEmpty()) return Result.success()
        runCatching { Push.register(applicationContext) }
        runCatching { Sphinx.wake(applicationContext) }.onFailure { Log.warn("beat failed", it.javaClass.simpleName) }
        return Result.success()
    }
}

/**
 * The FCM wake. Its data is exactly {"t": "sync"} plus, when the relay could fit them, "sphinx": the sealed request
 * blobs; anything else is dropped. The carried blobs go through the same checks as fetched ones (Sphinx.wake), then the
 * inboxes are fetched and acked.
 */
class SphinxMessaging : FirebaseMessagingService() {
    override fun onMessageReceived(m: RemoteMessage) {
        val d = m.data
        if (d["t"] != "sync" || !d.keys.all { it == "t" || it == "sphinx" }) return
        val t0 = System.currentTimeMillis()
        Log.info("TIMING fcm wake received", "sent ${m.sentTime} delay ${t0 - m.sentTime} ms, carried ${d["sphinx"] != null}, priority ${m.priority}/${m.originalPriority}")
        runCatching { Sphinx.wake(applicationContext, SphinxLogic.carried(d["sphinx"])) }.onFailure { Log.warn("wake failed", it.javaClass.simpleName) }
        Log.info("TIMING wake handled", "${System.currentTimeMillis() - t0} ms")
    }

    override fun onNewToken(token: String) {
        runCatching { Push.register(applicationContext, token) }
    }
}
