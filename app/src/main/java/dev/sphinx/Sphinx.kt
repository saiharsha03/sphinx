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

    /** By [Pending.waitId] (pairing and rid): another pairing's request can't take the place of one on screen. */
    private val pending = Waiting<Pending> { it.waitId }
    private val _asks = MutableStateFlow<List<Pending>>(emptyList())
    /** What the approval screen shows. */
    val asks: StateFlow<List<Pending>> = _asks

    fun pending(id: String): Pending? = pending[id]?.takeIf { it.expires > System.currentTimeMillis() }

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
        val enrolled = p.signer && UnlockStore.get(c).enrolled()
        when (val d = SphinxLogic.decide(p, b.rid, b.blob, store.accounts(), System.currentTimeMillis(), { key -> store.lastPick(key) }, store.textSites(), enrolled)) {
            is Decision.Drop -> { Log.warn("refused a laptop request", d.why); return false }
            is Decision.Answer -> { seen(store, d.pairing); send(c, d.pairing.pid, d.rid, d.reply); Log.info(d.line) }
            is Decision.Handoff -> { seen(store, d.pairing); Handoff.receive(c, d.pairing, d.rid, d.item); Log.info("handoff from a laptop", d.item.type) }
            is Decision.Sign -> {
                seen(store, d.pairing)
                if (!signs.add(d.ask)) { Log.warn("refused a sign request reusing a waiting id"); return false }
                publishSigns()
                Log.info("sign request", d.ask.key)
                askSign(c, d.ask)
                asked()
            }
            is Decision.Ask -> {
                seen(store, d.pairing)
                // Inside a pre-approval's window for this site (code.ready): the code at once, no prompt.
                if (serve(c, d.pending)) return true
                if (!pending.add(d.pending)) { Log.warn("refused a request reusing a waiting id"); return false }
                publish()
                // A texted-code site: nothing to approve yet; it waits for an SMS or email code ([notification]).
                if (d.pending.textOnly)
                    Log.info("request from ${d.pending.host}", "waits for a texted one")
                else {
                    // Its site's pre-approval is still on the screen, unanswered: this code request takes its place
                    // (that prompt goes, its laptop told "superseded") and asks at once. Until 2026-10-27 it waited
                    // behind the pre-approval until that ran out, up to 60 s: the delay the owner saw.
                    supersede(c, d.pending)
                    Log.info((if (d.pending.ready) "pre-approval from " else "request from ") + d.pending.host, "${d.pending.accounts.size} account(s)")
                    ask(c, d.pending)
                    asked()
                }
            }
        }
        return true
    }

    /** The request counters taken (the highest and the window's gaps), in place; never from a stale copy (handling runs one at a time). */
    private fun seen(store: SphinxStore, p: Pairing) { store.updatePairing(p.pid) { if (p.recv >= it.recv) it.copy(recv = p.recv, gaps = p.gaps, lastUsed = p.lastUsed) else it } }

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

    /**
     * Approve with an authorised cipher: the code goes back sealed (or, for a pre-approval, the window opens). [shown] is
     * the very request the screen and the prompt showed; anything else under its id answers nothing. Blocking.
     */
    fun approve(c: Context, shown: Pending, accountId: String, u: CipherUnwrapper): Boolean {
        if (!pending.take(shown)) return false.also { Log.info("request expired before approval") }
        val p = shown
        val rid = p.rid
        publish(); cancelAsk(c); dropText(c, p.waitId)
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
            send(c, p.pid, rid, SphinxLogic.readied(rid, true, held = SphinxLogic.held(a, times, codes, now, only = p.accounts.size == 1)))
            Log.info("pre-approval from ${p.host}: approved", a.issuer.take(40))
            // A code request for this site still waiting gets its code now.
            pending.values.filter { !it.ready }.sortedBy { it.expires }.firstOrNull { serve(c, it) }?.let { pending.remove(it.waitId); publish() }
            return true
        }
        val code = SphinxStore.get(c).code(a, u, now)
        send(c, p.pid, rid, SphinxLogic.code(rid, a, code, now))
        Log.info("request from ${p.host}: approved", a.issuer.take(40))
        return true
    }

    /** [id]: the [Pending.waitId] or [SignAsk.waitId] the screen or the banner holds. */
    fun deny(c: Context, id: String) {
        signs.remove(id)?.let { a ->
            publishSigns(); cancelSign(c)
            runCatching { send(c, a.pid, a.rid, SigningRules.no(a.rid, "denied")) }.onFailure { Log.warn("denial not sent", it.javaClass.simpleName) }
            Log.info("sign request: denied", a.key)
            return
        }
        val p = pending.remove(id) ?: return
        publish(); cancelAsk(c); dropText(c, id)
        runCatching { send(c, p.pid, p.rid, SphinxLogic.no(p, "denied")) }.onFailure { Log.warn("denial not sent", it.javaClass.simpleName) }
        Log.info((if (p.ready) "pre-approval from " else "request from ") + "${p.host}: denied")
    }

    /** Requests past their 60 s: dropped, logged, and the laptop told (it stops waiting). */
    fun expire(c: Context) {
        val now = System.currentTimeMillis()
        for (p in pending.values.filter { it.expires <= now }) {
            pending.remove(p.waitId)
            dropText(c, p.waitId)
            runCatching { send(c, p.pid, p.rid, SphinxLogic.no(p, "expired")) }
            Log.info((if (p.ready) "pre-approval from " else "request from ") + "${p.host}: expired")
        }
        for (a in signs.values.filter { it.expires <= now }) {
            signs.remove(a.waitId)
            runCatching { send(c, a.pid, a.rid, SigningRules.no(a.rid, "expired")) }
            Log.info("sign request: expired", a.key)
        }
        publishSigns()
        if (signs.isEmpty()) cancelSign(c)
        window.close(now)
        publish()
        if (pending.isEmpty()) cancelAsk(c)
    }

    // ---- pre-approval (code.ready) ----

    private val window = PreApproval()

    /** Answers [r] from the open window, at once and without a prompt, and spends the window. False: the usual question. */
    private fun serve(c: Context, r: Pending): Boolean {
        val (a, code) = window.take(r, System.currentTimeMillis()) ?: return false
        val now = System.currentTimeMillis()
        runCatching { send(c, r.pid, r.rid, SphinxLogic.code(r.rid, a, code, now)) }.onFailure { Log.warn("send failed", it.javaClass.simpleName); return false }
        Log.info("request from ${r.host}: approved in advance", a.issuer.take(40))
        return true
    }

    /** The site's pre-approvals still unanswered when code request [r] arrives go, each laptop told "superseded". */
    private fun supersede(c: Context, r: Pending) {
        val gone = SphinxLogic.supersedes(pending.values, r, System.currentTimeMillis())
        for (p in gone) {
            pending.remove(p.waitId)
            runCatching { send(c, p.pid, p.rid, SphinxLogic.no(p, "superseded")) }
            Log.info("pre-approval from ${p.host}: superseded by the code request")
        }
        if (gone.isNotEmpty()) publish()
    }

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

    /**
     * A fingerprint bound to the codes key, proved by opening a fresh challenge with the cipher it authorised ([Proof]):
     * before the relay backup is turned on or moved, its passcode changed, the phrase turned on, or a Google backup
     * opened (review 2026-10-27: the app's own unlock was enough for these).
     */
    fun confirm(c: Context, title: String, subtitle: String, onOk: () -> Unit, onFail: (String) -> Unit) {
        val (u, why) = unwrapper(c)
        if (u == null) { onFail(why ?: "The codes key can't be used."); return }
        val ch = runCatching { Proof.challenge(KeystoreBoxKeys(SphinxStore.KEY_ALIAS)) }.getOrElse { onFail("The codes key can't be used (${it.javaClass.simpleName})."); return }
        fingerprint(c, title, subtitle, u, onOk = { if (Proof.check(u, ch)) onOk() else onFail("The fingerprint didn't open the codes key.") }, onFail = onFail)
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
        // So was the signing unlock secret: enrol it again from the passkey (Settings, Signing).
        runCatching { UnlockStore.get(c).remove() }
        // The local backup holds every secret under a key on disk: set aside, reopened only with its passcode or phrase.
        // Its marker was written before the key went; a failure here is said, and the next start finishes it.
        val retired = runCatching { Backups.retire(c) }
        Log.warn("codes cleared by a new fingerprint")
        null to (e.message + if (retired.isFailure) " This phone's backup couldn't be set aside yet: restart Sphinx." else "")
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
        val open = PendingIntent.getActivity(c, NOTE_ASK, ApproveActivity.ask(c, p.waitId), flags)
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
                    addAction(0, "Approve", PendingIntent.getActivity(c, NOTE_ASK + 1, ApproveActivity.approveNow(c, p.waitId), flags))
                addAction(0, "Deny", PendingIntent.getActivity(c, NOTE_ASK + 2, ApproveActivity.deny(c, p.waitId), flags))
            }
            .build()
        runCatching { c.getSystemService(NotificationManager::class.java).notify(NOTE_ASK, n) }.onFailure { Log.warn("request not shown", it.javaClass.simpleName) }
        // In use (unlocked, screen on): Android shows only a banner for a full-screen intent, so with "Display over other
        // apps" allowed the approval opens on its own, as a sign-in prompt does.
        val unlocked = c.getSystemService(KeyguardManager::class.java)?.isKeyguardLocked == false
        val awake = c.getSystemService(PowerManager::class.java)?.isInteractive == true
        if (unlocked && awake && Settings.canDrawOverlays(c))
            runCatching { c.startActivity(ApproveActivity.ask(c, p.waitId)) }.onFailure { Log.warn("full screen not opened", it.javaClass.simpleName) }
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

    /** waitId -> the texted code offered for that request. In memory only, gone with the request; never logged or sent elsewhere. */
    private val texted = TextOffers()
    private const val NOTE_TEXT = 7_940

    fun textedFor(id: String): TextOffer? = texted[id]?.takeIf { pending(id) != null }

    /**
     * An SMS or email code ([Domains.textCode]) while a paired laptop's request is fresh: "Send 482913 to the laptop?".
     * Nothing happens without such a request, and nothing is kept once it ends.
     */
    private fun offerText(c: Context, code: String) {
        // Codes whose request ended between wake-ups (expire runs on the next one) go now.
        texted.keep { pending(it) != null }
        val p = SphinxLogic.forText(pending.values, System.currentTimeMillis()) ?: return
        texted.offer(p.waitId, code)
        channels(c)
        val open = PendingIntent.getActivity(c, NOTE_TEXT, ApproveActivity.text(c, p.waitId), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
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
    fun sendText(c: Context, shown: TextOffer): Boolean {
        // Exactly the code his prompt showed: a newer text that came meanwhile replaced the offer, and this answers nothing.
        if (!texted.take(shown)) return false.also { Log.info("the texted one changed before approval") }
        val id = shown.id
        val code = shown.code
        val p = pending.remove(id) ?: return false.also { dropText(c, id); Log.info("request expired before approval") }
        publish(); cancelAsk(c); dropText(c, id)
        if (p.expires <= System.currentTimeMillis()) { Log.info("request from ${p.host}: expired"); return false }
        SphinxStore.get(c).pairing(p.pid) ?: return false
        send(c, p.pid, p.rid, SphinxLogic.texted(p.rid, code))
        Log.info("request from ${p.host}: texted one sent")
        return true
    }

    private fun dropText(c: Context, id: String) {
        if (texted.drop(id) != null) runCatching { c.getSystemService(NotificationManager::class.java).cancel(NOTE_TEXT) }
    }

    // ---- release signing (sign.approve from the release signer's pairing, docs/DESIGN.md, Release signing) ----

    private const val NOTE_SIGN = 7_960
    private val signs = Waiting<SignAsk> { it.waitId }
    private val _signAsks = MutableStateFlow<List<SignAsk>>(emptyList())
    /** What the signing screen shows. */
    val signAsks: StateFlow<List<SignAsk>> = _signAsks

    private fun publishSigns() { _signAsks.value = signs.values.sortedBy { it.expires } }

    /**
     * After his fingerprint authorised [u]: the secret of the one key file [shown] names, derived from the unlock secret
     * here, goes back sealed to the signer, which opens that key for this one sign. U never leaves the phone. Blocking.
     */
    fun approveSign(c: Context, shown: SignAsk, u: CipherUnwrapper): Boolean {
        if (!signs.take(shown)) return false.also { Log.info("sign request expired before approval") }
        val a = shown
        publishSigns(); cancelSign(c)
        if (a.expires <= System.currentTimeMillis()) { Log.info("sign request: expired", a.key); return false }
        SphinxStore.get(c).pairing(a.pid) ?: return false
        val store = UnlockStore.get(c)
        val pins = store.pins()
        pins.refusal(a)?.let { why ->
            send(c, a.pid, a.rid, SigningRules.no(a.rid, why))
            Log.warn("sign request refused: legacy key file", a.key)
            return false
        }
        val unlock = store.open(u)
        try {
            if (a.unlock.isNotEmpty() && a.unlock != SigningRules.unlockId(unlock)) {
                send(c, a.pid, a.rid, SigningRules.no(a.rid, "sealed with another unlock secret"))
                Log.warn("sign request refused: another unlock id", a.key)
                return false
            }
            // Pinned before the secret goes: a send that dies half way can't leave the file unpinned.
            store.savePins(pins.after(a))
            val k = SigningRules.keySecret(unlock, a)
            try { send(c, a.pid, a.rid, SigningRules.approved(a.rid, k)) } finally { k.fill(0) }
        } finally { unlock.fill(0) }
        Log.info("sign request: approved", a.key)
        return true
    }

    private fun askSign(c: Context, a: SignAsk) {
        channels(c)
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val open = PendingIntent.getActivity(c, NOTE_SIGN, ApproveActivity.sign(c, a.waitId), flags)
        // Over the keyguard only "Release signing request"; the label, key and hash after unlocking (review 2026-10-27).
        val public = NotificationCompat.Builder(c, CHANNEL).setSmallIcon(R.drawable.ic_notify).setContentTitle("Release signing request").setContentText("Open Sphinx to answer").build()
        // No Approve on the banner: a sign is approved only with a tap on the screen that shows the whole hash.
        val n = NotificationCompat.Builder(c, CHANNEL)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle(SigningRules.question(a))
            .setContentText("${SigningRules.detail(a)}. Check the hash on the screen, then approve.")
            .setCategory(NotificationCompat.CATEGORY_REMINDER)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(public)
            .setContentIntent(open)
            .setFullScreenIntent(open, true)
            .setTimeoutAfter((a.expires - System.currentTimeMillis()).coerceAtLeast(1_000L))
            .setAutoCancel(true)
            .addAction(0, "Deny", PendingIntent.getActivity(c, NOTE_SIGN + 2, ApproveActivity.deny(c, a.waitId), flags))
            .build()
        runCatching { c.getSystemService(NotificationManager::class.java).notify(NOTE_SIGN, n) }.onFailure { Log.warn("sign request not shown", it.javaClass.simpleName) }
        val unlocked = c.getSystemService(KeyguardManager::class.java)?.isKeyguardLocked == false
        val awake = c.getSystemService(PowerManager::class.java)?.isInteractive == true
        if (unlocked && awake && Settings.canDrawOverlays(c))
            runCatching { c.startActivity(ApproveActivity.sign(c, a.waitId)) }.onFailure { Log.warn("full screen not opened", it.javaClass.simpleName) }
    }

    private fun cancelSign(c: Context) { runCatching { c.getSystemService(NotificationManager::class.java).cancel(NOTE_SIGN) } }

    // ---- pairing ----

    /**
     * Scanned the laptop's QR: derive, register with the relay, hand it this phone's FCM token, keep the pairing sealed.
     * Requests reach the phone only through FCM, so without a token it says so and pairs nothing. Blocking.
     */
    fun pair(c: Context, qr: String): Pairing {
        val o = SphinxCrypto.offer(qr) ?: error("That isn't a Sphinx pairing QR")
        // One release signer: a second Signer QR is refused until the first is unpaired on purpose (review 2026-10-27).
        if (!SigningRules.mayPair(o.signer, SphinxStore.get(c).pairings())) error("A Signer is already paired. Unpair it first (Settings, Signing).")
        val token = Push.token(c) ?: error(if (Push.available(c)) "No Firebase token yet (Google Play services, or the network). Try again in a moment."
            else "This build has no Firebase (google-services.json), so laptop requests could never reach the phone.")
        val (p, hello) = SphinxCrypto.accept(o, System.currentTimeMillis()) ?: error("The laptop's key isn't valid")
        RelayClient.pair(p, hello, RelayClient.tokenFor(o.relay, o.token, c.getString(R.string.sphinx_relay), c.getString(R.string.sphinx_relay_token)))
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
