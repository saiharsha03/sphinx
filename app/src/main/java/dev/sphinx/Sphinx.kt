package dev.sphinx

import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.PowerManager
import android.provider.Settings
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.ConcurrentHashMap

/**
 * Sphinx: 2FA codes on the phone, behind a fingerprint every time (docs/DESIGN.md). A laptop request arrives as a
 * sealed blob carried by an FCM wake (SphinxMessaging), or fetched once when the app comes to the front or by the
 * heartbeat; the phone opens it, matches the site, and shows the question over the lock screen. Approve = fingerprint (strong biometrics only, no
 * PIN), then the code goes back sealed. Approving does not unlock the phone. The log gets "request from <site>:
 * approved / denied / expired", never a code, key or account name.
 */
object Sphinx {
    const val CHANNEL = "sphinx.ask"
    const val CHANNEL_COPY = "sphinx.copy"
    private const val NOTE_ASK = 7_900
    /** Copy notifications: NOTE_COPY + the account's slot (SphinxStore keeps slots unique), so none collide. */
    const val NOTE_COPY = 7_950

    private val pending = ConcurrentHashMap<String, Pending>()
    private val _asks = MutableStateFlow<List<Pending>>(emptyList())
    /** What the approval screen shows. */
    val asks: StateFlow<List<Pending>> = _asks

    fun pending(rid: String): Pending? = pending[rid]?.takeIf { it.expires > System.currentTimeMillis() }

    private fun publish() { _asks.value = pending.values.sortedBy { it.expires } }

    private val handling = Any()

    /**
     * An FCM wake (SphinxMessaging), the app coming to the front, or the heartbeat (SphinxBeat), the last two with nothing
     * carried. The blobs the wake carried go first, through the same checks as a fetched one ([SphinxLogic.drain]); then
     * each pairing's inbox is fetched once (no long poll) and acked. Each blob is acked only after it was handled, so one
     * lost mid-way comes back on the next fetch (its counter stops a second run). Blocking. Returns how many asked.
     */
    fun wake(c: Context, carried: List<RelayClient.Blob> = emptyList()): Int {
        val store = SphinxStore.get(c)
        var asked = 0
        synchronized(handling) {
            expire(c)
            for (p in store.pairings()) {
                val handled = ArrayList<RelayClient.Blob>()
                try {
                    SphinxLogic.drain(carried.filter { it.pid == p.pid }, { RelayClient.inbox(p) }, handled) { b -> handle(c, store, b) { asked++ } }
                } catch (e: Exception) {
                    Log.warn("fetch failed", e.javaClass.simpleName)
                } finally {
                    if (handled.isNotEmpty()) runCatching { RelayClient.ack(p, handled.map { it.rid }) }.onFailure { Log.warn("ack failed", it.javaClass.simpleName) }
                }
            }
        }
        return asked
    }

    /** One blob, carried or fetched: open, check and act. False when it was refused (unknown pairing, bad seal, replay, ...). */
    private fun handle(c: Context, store: SphinxStore, b: RelayClient.Blob, asked: () -> Unit): Boolean {
        val p = store.pairing(b.pid)
        if (p == null) { Log.warn("request from an unknown pairing"); return false }
        when (val d = SphinxLogic.decide(p, b.rid, b.blob, store.accounts(), System.currentTimeMillis(), { key -> store.lastPick(key) }, store.textSites())) {
            is Decision.Drop -> { Log.warn("refused a laptop request", d.why); return false }
            is Decision.Answer -> { seen(store, d.pairing); send(c, d.pairing.pid, d.rid, d.reply); Log.info(d.line) }
            is Decision.Handoff -> { seen(store, d.pairing); Handoff.receive(c, d.pairing, d.rid, d.item); Log.info("handoff from a laptop", d.item.type) }
            is Decision.Ask -> {
                seen(store, d.pairing)
                // Inside a pre-approval's window for this site (code.ready): the code at once, no prompt.
                if (serve(c, d.pending)) return true
                pending[d.pending.rid] = d.pending
                publish()
                // A texted-code site: nothing to approve yet; it waits for an SMS or email code ([notification]).
                if (d.pending.textOnly)
                    Log.info("request from ${d.pending.host}", "waits for a texted one")
                // Its site's pre-approval is on the screen: it waits on that answer (one prompt, not two).
                else if (SphinxLogic.rides(pending.values, d.pending, System.currentTimeMillis())) {
                    riders += d.pending.rid
                    Log.info("request from ${d.pending.host}", "waits on the pre-approval")
                } else {
                    Log.info((if (d.pending.ready) "pre-approval from " else "request from ") + d.pending.host, "${d.pending.accounts.size} account(s)")
                    ask(c, d.pending)
                    asked()
                }
            }
        }
        return true
    }

    /** The highest request counter taken, in place (never lowered by a stale copy). */
    private fun seen(store: SphinxStore, p: Pairing) { store.updatePairing(p.pid) { it.copy(recv = maxOf(it.recv, p.recv), lastUsed = p.lastUsed) } }

    /** Seals with the next reply counter inside the store's lock, then sends. */
    private fun send(c: Context, pid: String, rid: String, body: Map<String, Any?>) {
        var blob: String? = null
        val p = SphinxStore.get(c).updatePairing(pid) { p -> SphinxLogic.reply(p, body, System.currentTimeMillis()).let { (b, n) -> blob = b; n } } ?: return
        RelayClient.reply(p, rid, blob!!)
    }

    /** Runs [work] off the main thread after the approve screen has closed; a failure is logged (the laptop times out). */
    fun inBackground(c: Context, work: (Context) -> Boolean) {
        val app = c.applicationContext
        Thread { runCatching { if (!work(app)) Log.warn("approved, but nothing was sent") }.onFailure { Log.warn("send failed", it.javaClass.simpleName) } }.start()
    }

    /** Approve with an authorised cipher: the code goes back sealed (or, for a pre-approval, the window opens). Blocking. */
    fun approve(c: Context, rid: String, accountId: String, u: CipherUnwrapper): Boolean {
        val p = pending.remove(rid) ?: return false.also { Log.info("request expired before approval") }
        publish(); cancelAsk(c); dropText(c, rid)
        val a = p.accounts.firstOrNull { it.id == accountId } ?: return false
        if (p.expires <= System.currentTimeMillis()) { Log.info("request from ${p.host}: expired"); return false }
        // Remembered for next time this same choice comes up (account ids only, no names or sites).
        if (p.accounts.size > 1) SphinxStore.get(c).rememberPick(SphinxLogic.choiceKey(p.accounts), a.id)
        SphinxStore.get(c).pairing(p.pid) ?: return false
        val now = System.currentTimeMillis()
        if (p.ready) {
            // A pre-approval: the window opens (SphinxLogic.WINDOW_MS) and the laptop gets the window's codes to hold.
            val times = SphinxLogic.windowTimes(now, a.period)
            val codes = SphinxStore.get(c).codes(a, u, times)
            window.open(SphinxLogic.prime(p, a, codes, now))
            send(c, p.pid, rid, SphinxLogic.readied(rid, true, held = SphinxLogic.held(a, times, codes, now)))
            Log.info("pre-approval from ${p.host}: approved", a.issuer.take(40))
            // A code request that came while this one was on screen gets its code now; any other that waited on it, a prompt.
            pending.values.filter { !it.ready }.sortedBy { it.expires }.firstOrNull { serve(c, it) }?.let { pending.remove(it.rid); riders.remove(it.rid); publish() }
            unride(c)
            return true
        }
        val code = SphinxStore.get(c).code(a, u, now)
        send(c, p.pid, rid, SphinxLogic.code(rid, a, code, Totp.left(now, a.period)))
        Log.info("request from ${p.host}: approved", a.issuer.take(40))
        return true
    }

    fun deny(c: Context, rid: String) {
        val p = pending.remove(rid) ?: return
        publish(); cancelAsk(c); dropText(c, rid)
        runCatching { send(c, p.pid, rid, SphinxLogic.no(p, "denied")) }.onFailure { Log.warn("denial not sent", it.javaClass.simpleName) }
        Log.info((if (p.ready) "pre-approval from " else "request from ") + "${p.host}: denied")
        if (p.ready) unride(c)
    }

    /** Requests past their 60 s: dropped, logged, and the laptop told (it stops waiting). */
    fun expire(c: Context) {
        val now = System.currentTimeMillis()
        var ready = false
        for (p in pending.values.filter { it.expires <= now }) {
            pending.remove(p.rid)
            dropText(c, p.rid)
            runCatching { send(c, p.pid, p.rid, SphinxLogic.no(p, "expired")) }
            Log.info((if (p.ready) "pre-approval from " else "request from ") + "${p.host}: expired")
            ready = ready || p.ready
        }
        window.close(now)
        publish()
        if (ready) unride(c)
        if (pending.isEmpty()) cancelAsk(c)
    }

    // ---- pre-approval (code.ready) ----

    private val window = PreApproval()

    /** Answers [r] from the open window, at once and without a prompt, and spends the window. False: the usual question. */
    private fun serve(c: Context, r: Pending): Boolean {
        val (a, code) = window.take(r, System.currentTimeMillis()) ?: return false
        val now = System.currentTimeMillis()
        runCatching { send(c, r.pid, r.rid, SphinxLogic.code(r.rid, a, code, Totp.left(now, a.period))) }.onFailure { Log.warn("send failed", it.javaClass.simpleName); return false }
        Log.info("request from ${r.host}: approved in advance", a.issuer.take(40))
        return true
    }

    /** A pre-approval ended without a yes: code requests that waited on it get the usual prompt. */
    private fun unride(c: Context) {
        val now = System.currentTimeMillis()
        for (rid in riders.toList()) {
            val r = pending(rid)
            if (r == null) { riders.remove(rid); continue }
            if (SphinxLogic.rides(pending.values, r, now)) continue
            riders.remove(rid)
            ask(c, r)
        }
    }

    /** Code requests waiting on a pre-approval's answer (rids only). */
    private val riders = ConcurrentHashMap.newKeySet<String>()

    // ---- the prompt ----

    /** BiometricPrompt, strong biometrics only (no PIN), authorising exactly [u]'s cipher. */
    fun fingerprint(c: Context, title: String, subtitle: String, u: CipherUnwrapper, onOk: () -> Unit, onFail: (String) -> Unit) {
        BiometricPrompt.Builder(c).setTitle(title.take(60)).setSubtitle(subtitle)
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton("Cancel", c.mainExecutor) { _, _ -> onFail("Cancelled") }
            .build()
            .authenticate(BiometricPrompt.CryptoObject(u.cipher), CancellationSignal(), c.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onOk()
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onFail(errString.toString())
            })
    }

    /** A plain strong-biometric check (no cipher): the app's own lock, and sending a texted code. */
    fun gate(c: Context, onOk: () -> Unit, onFail: (String) -> Unit, title: String = "Open Sphinx", subtitle: String = "Your 2FA accounts are behind your fingerprint") {
        BiometricPrompt.Builder(c).setTitle(title.take(60)).setSubtitle(subtitle)
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton("Cancel", c.mainExecutor) { _, _ -> onFail("Cancelled") }
            .build()
            .authenticate(CancellationSignal(), c.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onOk()
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onFail(errString.toString())
            })
    }

    /** A cipher for one code; null (and why) when it can't be had. A new fingerprint enrolment clears the codes (SphinxStore.unwrapper). */
    fun unwrapper(c: Context): Pair<CipherUnwrapper?, String?> = try {
        (SphinxStore.get(c).unwrapper() as CipherUnwrapper) to null
    } catch (e: SphinxStore.Cleared) {
        // The Keys safe's entries were sealed to the same key: gone with it. The backups still hold both.
        runCatching { SafeStore.get(c).clear() }
        Log.warn("codes cleared by a new fingerprint")
        null to e.message
    } catch (e: Exception) {
        null to "The codes key can't be used (${e.javaClass.simpleName})."
    }

    // ---- notifications ----

    fun channels(c: Context) {
        val nm = c.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Code requests", NotificationManager.IMPORTANCE_HIGH).apply {
            description = "Your laptop asks for a 2FA code; shown over the lock screen"
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        })
        nm.createNotificationChannel(NotificationChannel(CHANNEL_COPY, "Codes on this phone", NotificationManager.IMPORTANCE_DEFAULT).apply {
            description = "An app you imported shows a 2FA screen: copy its code with your fingerprint"
        })
    }

    /** On Android 14 and later the full-screen approval needs "full screen notifications" allowed for Sphinx. */
    fun canFullScreen(c: Context): Boolean = Build.VERSION.SDK_INT < 34 || c.getSystemService(NotificationManager::class.java).canUseFullScreenIntent()

    private fun ask(c: Context, p: Pending) {
        channels(c)
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val open = PendingIntent.getActivity(c, NOTE_ASK, ApproveActivity.ask(c, p.rid), flags)
        val public = NotificationCompat.Builder(c, CHANNEL).setSmallIcon(R.drawable.ic_notify).setContentTitle("Code request").setContentText("Open Sphinx to answer").build()
        val n = NotificationCompat.Builder(c, CHANNEL)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle(SphinxLogic.question(p, names = false))
            .setContentText("From ${p.laptop}. Approve with your fingerprint.")
            .setCategory(NotificationCompat.CATEGORY_REMINDER)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(public)
            .setContentIntent(open)
            .setFullScreenIntent(open, true)
            .setTimeoutAfter(SphinxCrypto.TTL_MS)
            .setAutoCancel(true)
            // Answer from the banner itself: Approve when one account is meant, Deny always.
            .apply {
                if (p.picked != null || p.accounts.size == 1)
                    addAction(0, "Approve", PendingIntent.getActivity(c, NOTE_ASK + 1, ApproveActivity.approveNow(c, p.rid), flags))
                addAction(0, "Deny", PendingIntent.getActivity(c, NOTE_ASK + 2, ApproveActivity.deny(c, p.rid), flags))
            }
            .build()
        runCatching { c.getSystemService(NotificationManager::class.java).notify(NOTE_ASK, n) }.onFailure { Log.warn("request not shown", it.javaClass.simpleName) }
        // In use (unlocked, screen on): Android shows only a banner for a full-screen intent, so with "Display over other
        // apps" allowed the approval opens on its own, as a sign-in prompt does.
        val unlocked = c.getSystemService(KeyguardManager::class.java)?.isKeyguardLocked == false
        val awake = c.getSystemService(PowerManager::class.java)?.isInteractive == true
        if (unlocked && awake && Settings.canDrawOverlays(c))
            runCatching { c.startActivity(ApproveActivity.ask(c, p.rid)) }.onFailure { Log.warn("full screen not opened", it.javaClass.simpleName) }
    }

    private fun cancelAsk(c: Context) { runCatching { c.getSystemService(NotificationManager::class.java).cancel(NOTE_ASK) } }

    // ---- codes on the phone itself ----

    private val offered = ConcurrentHashMap<String, Long>()

    /**
     * A posted notification (CodeWatcher): an SMS or email code while a laptop waits ([offerText]), and an imported
     * account's app showing a 2FA screen (a "GitHub (work) code" notification with Copy). The notification's words are
     * only matched here, never kept.
     */
    fun notification(c: Context, pkg: String, title: String, text: String) {
        if (pkg == c.packageName) return
        if (waiting()) Domains.textCode(pkg, title, text)?.let { offerText(c, it) }
        if (!Domains.looksLike2fa(title, text)) return
        val accounts = SphinxStore.get(c).accounts().filter { pkg in it.apps }
        if (accounts.isEmpty()) return
        val now = System.currentTimeMillis()
        for (a in accounts) {
            if (now - (offered[a.id] ?: 0L) < 120_000L) continue
            offered[a.id] = now
            offer(c, a)
        }
    }

    /** A laptop request is pending and fresh: only then is a texted or mailed code looked for. */
    private fun waiting(): Boolean = SphinxLogic.forText(pending.values, System.currentTimeMillis()) != null

    /** Whether a notification from [pkg] is read at all: an SMS or mail app's while a request waits, an imported account's app's. */
    fun watches(c: Context, pkg: String): Boolean =
        pkg != c.packageName && ((pkg in Domains.TEXT_APPS && waiting()) || SphinxStore.get(c).accounts().any { pkg in it.apps })

    fun offer(c: Context, a: CodeAccount) {
        channels(c)
        val copy = PendingIntent.getActivity(c, NOTE_COPY + a.slot.coerceAtLeast(0), ApproveActivity.copy(c, a.id), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = NotificationCompat.Builder(c, CHANNEL_COPY)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle("${a.title()} code")
            .setContentText("Copy it with your fingerprint. The clipboard clears in 30 s.")
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .addAction(0, "Copy", copy)
            .setContentIntent(copy)
            .setTimeoutAfter(5 * 60_000L)
            .setAutoCancel(true)
            .build()
        runCatching { c.getSystemService(NotificationManager::class.java).notify(NOTE_COPY + a.slot.coerceAtLeast(0), n) }
        Log.info("offered a code on the phone", a.issuer.take(40))
    }

    /** Copy with an authorised cipher; the clipboard is marked sensitive and clears after 30 s (SecureClipboard). */
    fun copy(c: Context, a: CodeAccount, u: CipherUnwrapper) {
        SecureClipboard.copy(c, "code", SphinxStore.get(c).code(a, u))
        Log.info("code copied on the phone", a.issuer.take(40))
    }

    // ---- codes from an SMS or email, to the laptop that is waiting ----

    /** rid -> the texted code offered for that request. In memory only, gone with the request; never logged or sent elsewhere. */
    private val texted = ConcurrentHashMap<String, String>()
    private const val NOTE_TEXT = 7_940

    fun textedFor(rid: String): String? = texted[rid]?.takeIf { pending(rid) != null }

    /**
     * An SMS or email code ([Domains.textCode]) while a paired laptop's request is fresh: "Send 482913 to the laptop?".
     * Nothing happens without such a request, and nothing is kept once it ends.
     */
    private fun offerText(c: Context, code: String) {
        // Codes whose request ended between wake-ups (expire runs on the next one) go now.
        texted.keys.removeAll { pending(it) == null }
        val p = SphinxLogic.forText(pending.values, System.currentTimeMillis()) ?: return
        texted[p.rid] = code
        channels(c)
        val open = PendingIntent.getActivity(c, NOTE_TEXT, ApproveActivity.text(c, p.rid), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val public = NotificationCompat.Builder(c, CHANNEL).setSmallIcon(R.drawable.ic_notify).setContentTitle("Code request").setContentText("Open Sphinx to answer").build()
        val n = NotificationCompat.Builder(c, CHANNEL)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle("Send $code to the laptop?")
            .setContentText("For ${p.host} on ${p.laptop}. Your fingerprint sends it.")
            .setCategory(NotificationCompat.CATEGORY_REMINDER)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(public)
            .setContentIntent(open)
            .addAction(0, "Send", open)
            .setTimeoutAfter((p.expires - System.currentTimeMillis()).coerceAtLeast(1_000L))
            .setAutoCancel(true)
            .build()
        runCatching { c.getSystemService(NotificationManager::class.java).notify(NOTE_TEXT, n) }.onFailure { Log.warn("texted one not shown", it.javaClass.simpleName) }
        Log.info("texted one offered to the laptop")
    }

    /** After the fingerprint: the texted code goes back sealed as the answer to that request. Blocking. */
    fun sendText(c: Context, rid: String): Boolean {
        val code = texted[rid] ?: return false
        val p = pending.remove(rid) ?: return false.also { dropText(c, rid); Log.info("request expired before approval") }
        publish(); cancelAsk(c); dropText(c, rid)
        if (p.expires <= System.currentTimeMillis()) { Log.info("request from ${p.host}: expired"); return false }
        SphinxStore.get(c).pairing(p.pid) ?: return false
        send(c, p.pid, rid, SphinxLogic.texted(rid, code))
        Log.info("request from ${p.host}: texted one sent")
        return true
    }

    private fun dropText(c: Context, rid: String) {
        if (texted.remove(rid) != null) runCatching { c.getSystemService(NotificationManager::class.java).cancel(NOTE_TEXT) }
    }

    // ---- pairing ----

    /**
     * Scanned the laptop's QR: derive, register with the relay, hand it this phone's FCM token, keep the pairing sealed.
     * Requests reach the phone only through FCM, so without a token it says so and pairs nothing. Blocking.
     */
    fun pair(c: Context, qr: String): Pairing {
        val o = SphinxCrypto.offer(qr) ?: error("That isn't a Sphinx pairing QR")
        val token = Push.token(c) ?: error(if (Push.available(c)) "No Firebase token yet (Google Play services, or the network). Try again in a moment."
            else "This build has no Firebase (google-services.json), so laptop requests could never reach the phone.")
        val (p, hello) = SphinxCrypto.accept(o, System.currentTimeMillis()) ?: error("The laptop's key isn't valid")
        RelayClient.pair(p, hello, o.token.ifBlank { c.getString(R.string.sphinx_relay_token) })
        SphinxStore.get(c).putPairing(p)
        o.secret.fill(0)
        val push = runCatching { RelayClient.push(p, token) }.getOrDefault(false)
        val saved = SphinxStore.get(c).updatePairing(p.pid) { it.copy(push = push) } ?: p
        Log.info(if (push) "paired a laptop" else "paired a laptop; its relay can't wake this phone yet")
        Push.schedule(c)
        return saved
    }

    fun unpair(c: Context, pid: String) {
        val store = SphinxStore.get(c)
        store.pairing(pid)?.let { p -> runCatching { RelayClient.unpair(p) }.onFailure { Log.warn("relay unpair failed", it.javaClass.simpleName) } }
        store.unpair(pid)
        Log.info("unpaired a laptop")
    }
}
