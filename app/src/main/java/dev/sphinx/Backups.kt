package dev.sphinx

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/**
 * The backup on Android (docs/DESIGN.md, "Backup"): the local sealed state that Google's backup carries, the relay
 * copy kept up to date after each change, the recovery phrase, and the restores. Blocking calls: run them on IO.
 * Turning the relay backup on, changing its passcode or relay, and turning the phrase on need a fresh fingerprint on
 * the codes key first (Sphinx.confirm, in the Backup pane): they send every secret somewhere (review 2026-10-27).
 */
object Backups {
    /** Set in the sealed prefs once this phone has its own backup; the prefs never travel, so a restored state.bin without it came from another phone. */
    private const val HOME = "backup.home"

    /** The one LocalBackup of this phone: the stores and this code share its lock. */
    fun local(c: Context) = LocalBackup.at(File(c.applicationContext.filesDir, "backup"))

    /**
     * On every start, before anything changes. A first run makes an empty backup with a fresh key. A state that Android
     * restored from Google (the files are here but this phone never made them) is set aside unopened and this phone
     * starts its own: nothing of it is sealed here until he opens it under Codes ([adopt]; review 2026-10-27). Returns
     * what to tell him, or null.
     */
    fun start(c: Context): String? {
        val prefs = SealedPrefs(c.applicationContext)
        val l = local(c)
        // A stash a stop interrupted is finished first: nothing may write a new key over the set-aside one. Then a retire
        // a new fingerprint left pending, before anything can upload or confirm.
        l.finishStash()
        ready(l)
        if (prefs.read(HOME) != null) { if (!l.exists()) l.start(); return null }
        val found = l.read()?.let { it.accounts.isNotEmpty() || it.safe.isNotEmpty() } == true && l.stash()
        l.start()
        prefs.write(HOME, "1")
        if (found) Log.info("a Google backup is waiting to be opened")
        return if (found) "A Google backup came with this phone. Open it under Codes." else null
    }

    /** A set-aside backup: its accounts and Keys safe entries, and whether a new fingerprint (not Google) put it there. */
    data class SetAside(val accounts: Int, val safe: Int, val cleared: Boolean, val reopenable: Boolean = true, val id: String = "")

    fun waiting(c: Context): SetAside? {
        val a = local(c).aside() ?: return null
        val cleared = a.why == LocalBackup.CLEARED
        // A cleared one opens only with its relay passcode or phrase; with no relay backup it had neither.
        return SetAside(a.state.accounts.size, a.state.safe.size, cleared, reopenable = !cleared || a.state.relay != null, id = a.id)
    }

    /**
     * A new fingerprint enrolment cleared the codes (SphinxStore.Cleared): the local backup, which holds every secret
     * under a key on disk, is set aside like a foreign one and this phone starts an empty one (review 2026-10-27: the
     * codes key comes back under the new finger, so a fingerprint must not be what reopens it). It reopens only with
     * its backup passcode or recovery phrase ([adoptWith]).
     */
    fun retire(c: Context) {
        // SphinxStore wrote the marker before the key went; this finishes it (and fails loudly if it can't).
        ready(local(c))
        Log.warn("the local backup was set aside after a new fingerprint")
    }

    /**
     * Fail closed: a retire left pending is finished first, and if it can't be, nothing that sends or merges the backup
     * runs (setUp, phraseOn, restore, upload, opening a set-aside copy; review 2026-10-27).
     */
    internal fun ready(l: LocalBackup) {
        if (!runCatching { l.retire() }.getOrDefault(false))
            error("A new fingerprint cleared the codes and this phone's backup couldn't be set aside yet. Restart Sphinx and try again.")
    }

    /** Opens the set-aside Google backup, after his fingerprint (Sphinx.confirm). Not one a new fingerprint set aside. */
    fun adopt(c: Context, id: String): String {
        val l = local(c)
        ready(l)
        val a = l.aside(id) ?: error("That copy is no longer here.")
        if (a.why == LocalBackup.CLEARED) error("This backup opens with your backup passcode or recovery phrase.")
        return adopted(c, l, a)
    }

    /** Opens the backup a new fingerprint set aside ([id]), with its passcode or its 24 words ([secret]). */
    fun adoptWith(c: Context, id: String, secret: String): String {
        val l = local(c)
        ready(l)
        val a = l.aside(id) ?: error("That copy is no longer here.")
        val words = Bip39.check(secret)
        if (!BackupCrypto.opens(a.state, secret.takeIf { words == null }, words)) error("That isn't this backup's passcode or recovery phrase.")
        return adopted(c, l, a)
    }

    /**
     * Its accounts and Keys safe sealed with this phone's keys, and its state joined to this phone's own backup; then
     * exactly that copy is deleted, by its id: never whichever happens to be first by then (review 2026-10-27).
     */
    private fun adopted(c: Context, l: LocalBackup, a: LocalBackup.Aside): String {
        val s = a.state
        val n = SphinxStore.get(c).restore(s)
        val k = SafeStore.get(c).restore(s.safe)
        l.update { BackupCrypto.merged(s, it) }
        l.dropAside(a.id)
        Log.info("restored a set-aside backup", "$n account(s)")
        changed(c)
        return "Restored: $n account(s)" + (if (k > 0) " and $k Keys safe entr${if (k == 1) "y" else "ies"}" else "") + ". Pair your laptops again."
    }

    /** Deletes exactly the copy [id]; nothing when it is already gone. */
    fun dropForeign(c: Context, id: String) { if (local(c).dropAside(id)) Log.info("a set-aside backup was left closed") }

    /** After each change: the relay copy is uploaded a few seconds later (several changes, one upload), when online. */
    fun changed(c: Context) {
        if (local(c).read()?.relay == null) return
        val work = OneTimeWorkRequestBuilder<BackupUpload>().setInitialDelay(5, TimeUnit.SECONDS)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()).build()
        runCatching { WorkManager.getInstance(c).enqueueUniqueWork("sphinx.backup", ExistingWorkPolicy.REPLACE, work) }
    }

    /** The relay's answers, in words. */
    fun why(e: Throwable): String = when ((e as? RelayClient.Failed)?.status) {
        401 -> "Wrong passcode or phrase."
        403 -> "The relay wants its registration token."
        404 -> "No backup on that relay."
        409 -> "The relay already holds another recovery phrase: turn the old one off first."
        413 -> "The backup is too big for the relay."
        423 -> "The relay's backup is locked after too many wrong tries. It has to be unlocked on the VPS."
        429 -> "Too many wrong tries. Wait a while and try again."
        null -> e.message ?: e.javaClass.simpleName
        else -> "The relay said ${(e as RelayClient.Failed).status}."
    }

    /**
     * The registration value for [relay]: the one typed (never stored when it is the built-in one), else the built-in
     * one, and that only for the built-in relay's origin (review 2026-10-27).
     */
    private fun token(c: Context, relay: String, typed: String = ""): String =
        RelayClient.tokenFor(relay, typed, c.getString(R.string.sphinx_relay), c.getString(R.string.sphinx_relay_token))

    private fun headers(token: String) = if (token.isNotBlank()) mapOf("x-sphinx-token" to token) else emptyMap()

    private fun put(c: Context, r: RelayBackup, slot: String, body: Map<String, Any?>) {
        RelayClient.plain(r.relay, "PUT", "/v1/backup/$slot", body, headers(token(c, r.relay, r.token)))
    }

    private fun delete(c: Context, r: RelayBackup, slot: String, auth: String) {
        RelayClient.plain(r.relay, "POST", "/v1/backup/$slot/delete", mapOf("auth" to auth), headers(token(c, r.relay, r.token)))
    }

    /** Uploads the current state to the relay: the passcode's slot, and the phrase's when it is on. */
    fun upload(c: Context) = upload(local(c)) { r, slot, body -> put(c, r, slot, body) }

    /**
     * The upload itself. Each slot is updated, never created (`create: false`): a slot removed on the relay, or a
     * phrase turned off, isn't brought back by a stale copy of the settings (review 2026-10-27). A phrase slot the relay
     * no longer has is turned off here too, and the passcode's copy sent again without it.
     */
    internal fun upload(l: LocalBackup, put: (RelayBackup, String, Map<String, Any?>) -> Unit) {
        ready(l)
        val (bk, st, sealed) = l.snapshot() ?: return
        val r = st.relay ?: return
        put(r, "pass", mapOf("auth" to r.passAuth, "salt" to r.salt, "kdf" to r.kdf, "blob" to BackupCrypto.record("pass", SphinxCrypto.dec(r.passKey)!!, bk, sealed), "create" to false))
        if (r.phraseId.isNotEmpty()) try {
            put(r, r.phraseId, mapOf("auth" to r.phraseAuth, "blob" to BackupCrypto.record(r.phraseId, SphinxCrypto.dec(r.phraseKey)!!, bk, sealed), "create" to false))
        } catch (e: RelayClient.Failed) {
            if (e.status != 404) throw e
            l.update { st -> st.copy(relay = st.relay?.let { if (it.phraseId == r.phraseId) it.copy(phraseId = "", phraseKey = "", phraseAuth = "") else it }) }
            Log.info("the recovery phrase's slot is gone from the relay: the phrase is off here too")
            return upload(l, put)
        }
        Log.info("backup uploaded to the relay")
    }

    /**
     * Turns the relay backup on, or changes its passcode or relay: a new salt and Argon2id keys, the slot updated with the
     * old auth (when there was one) and set to the new one, then the state uploaded. Once a relay backup exists, the
     * [current] passcode must be given and right. Blocking (Argon2id takes a moment).
     */
    fun setUp(c: Context, relay: String, typed: String, passcode: String, current: String? = null) {
        Passcode.problem(passcode)?.let { error(it) }
        val l = local(c)
        ready(l)
        val (bk, now, sealed) = l.snapshot() ?: error("No backup on this phone yet")
        val had = now.relay
        // Kept only when he typed it for this relay: never the built-in value, never the old relay's token on a move.
        val token = RelayClient.keepToken(typed, relay, c.getString(R.string.sphinx_relay_token), had?.relay, had?.token)
        if (had != null && (current == null || !BackupCrypto.proves(current, had))) error("That isn't your current backup passcode.")
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val kdf = Kdf()
        val k = BackupCrypto.passKeys(passcode, salt, kdf)
        val old = had?.takeIf { it.relay == relay }
        val r = RelayBackup(relay, token, SphinxCrypto.enc(salt), kdf, SphinxCrypto.enc(k.key), k.auth,
            old?.phraseId.orEmpty(), old?.phraseKey.orEmpty(), old?.phraseAuth.orEmpty())
        put(c, r, "pass", mapOf("auth" to (old?.passAuth ?: k.auth), "new_auth" to k.auth, "salt" to r.salt, "kdf" to kdf,
            "blob" to BackupCrypto.record("pass", k.key, bk, sealed), "create" to (old == null)))
        l.update { it.copy(relay = r) }
        upload(c)
        Log.info(if (had == null) "relay backup on" else if (old == null) "backup moved to another relay" else "backup passcode changed")
        // Moved: the full copy on the old relay goes too (review 2026-10-27); a delete it didn't take is said.
        if (had != null && old == null) dropSlots(had) { o, slot, auth -> delete(c, o, slot, auth) }?.let {
            error("Your backup now goes to ${relay.removePrefix("https://")}, but its copy on ${had.relay.removePrefix("https://")} couldn't be deleted (${why(it)}).")
        }
    }

    /** Deletes [r]'s passcode slot and phrase slot on its relay; the first failure, or null when both went. */
    internal fun dropSlots(r: RelayBackup, delete: (RelayBackup, String, String) -> Unit): Throwable? =
        listOfNotNull(runCatching { delete(r, "pass", r.passAuth) }.exceptionOrNull(),
            r.phraseId.takeIf { it.isNotEmpty() }?.let { runCatching { delete(r, it, r.phraseAuth) }.exceptionOrNull() }).firstOrNull()

    fun turnOff(c: Context) = turnOff(local(c)) { r, slot, auth -> delete(c, r, slot, auth) }

    /**
     * Off here, and both slots deleted on the relay. A delete the relay didn't take is said, not hidden: the copy is
     * still there (review 2026-10-27).
     */
    internal fun turnOff(l: LocalBackup, delete: (RelayBackup, String, String) -> Unit) {
        val r = l.read()?.relay ?: return
        val failed = dropSlots(r, delete)
        l.update { it.copy(relay = null) }
        Log.info("relay backup off")
        if (failed != null) error("The relay backup is off on this phone, but its copy on the relay couldn't be deleted (${why(failed)}).")
    }

    /** The recovery phrase on: its slot on the relay (the relay backup must be on). The words are shown once, never kept. */
    fun phraseOn(c: Context, words: List<String>) {
        val l = local(c)
        ready(l)
        val r = l.read()?.relay ?: error("Turn the relay backup on first: the phrase opens the same copy, without the passcode.")
        val k = BackupCrypto.phraseKeys(Bip39.seed(words))
        if (r.phraseId.isNotEmpty() && r.phraseId != k.id) runCatching { delete(c, r, r.phraseId, r.phraseAuth) }
        val on = r.copy(phraseId = k.id, phraseKey = SphinxCrypto.enc(k.key), phraseAuth = k.auth)
        val (bk, _, sealed) = l.snapshot() ?: error("No backup on this phone yet")
        put(c, on, k.id, mapOf("auth" to k.auth, "blob" to BackupCrypto.record(k.id, k.key, bk, sealed), "create" to true))
        l.update { it.copy(relay = on) }
        // The passcode's copy carries the settings too: sent again, so it never holds a phrase state that is out of date.
        changed(c)
        Log.info("recovery phrase on")
    }

    fun phraseOff(c: Context) {
        val l = local(c)
        val r = l.read()?.relay?.takeIf { it.phraseId.isNotEmpty() } ?: return
        delete(c, r, r.phraseId, r.phraseAuth)
        l.update { it.copy(relay = r.copy(phraseId = "", phraseKey = "", phraseAuth = "")) }
        // Without this the passcode's copy kept the phrase's settings, and a restore from it brought the phrase back.
        changed(c)
        Log.info("recovery phrase off")
    }

    /**
     * A new phone, from the relay: with the passcode (its salt fetched first), or with the 24 words. The state opens on
     * the phone; the accounts and the Keys safe are sealed again with this phone's keys, and the same backup key carries
     * on here (so the relay copy and Google's stay one), joined with what this phone already held. Returns how many
     * accounts came in.
     */
    fun restore(c: Context, relay: String, passcode: String? = null, words: List<String>? = null, typed: String = ""): Int {
        ready(local(c))
        val h = headers(token(c, relay, typed))
        val (slot, k) = if (words != null) BackupCrypto.phraseKeys(Bip39.seed(words)).let { it.id to it }
        else {
            val s = json.readTree(RelayClient.plain(relay, "GET", "/v1/backup/pass/salt", null, h)!!)
            val kdf = runCatching { json.treeToValue(s.path("kdf"), Kdf::class.java) }.getOrNull()
            val salt = SphinxCrypto.dec(s.path("salt").asText())
            require(BackupCrypto.trusted(kdf, salt)) { "The relay's Argon2id settings are weaker than Sphinx's own: not used." }
            "pass" to BackupCrypto.passKeys(passcode!!, salt!!, kdf!!)
        }
        val blob = json.readTree(RelayClient.plain(relay, "POST", "/v1/backup/$slot/open", mapOf("auth" to k.auth), h)!!).path("blob").asText()
        val (bk, sealed) = BackupCrypto.openRecord(slot, k.key, blob) ?: error("That backup doesn't open with this passcode or phrase")
        val state = BackupCrypto.openState(bk, sealed) ?: error("That backup doesn't open")
        val here = local(c).read()
        val n = SphinxStore.get(c).restore(state)
        SafeStore.get(c).restore(state.safe)
        local(c).start(BackupCrypto.merged(state, here), bk)
        SealedPrefs(c.applicationContext).write(HOME, "1")
        Log.info("restored from the relay", "$n account(s)")
        // The relay's copy (and Google's) now hold what this phone added to it too.
        changed(c)
        return n
    }
}

/** The debounced relay upload (Backups.changed). */
class BackupUpload(c: Context, p: WorkerParameters) : Worker(c, p) {
    override fun doWork(): Result = runCatching { Backups.upload(applicationContext) }.fold(
        { Result.success() },
        { e -> Log.warn("backup upload failed", e.javaClass.simpleName); if ((e as? RelayClient.Failed)?.status in setOf(401, 423)) Result.failure() else Result.retry() },
    )
}
