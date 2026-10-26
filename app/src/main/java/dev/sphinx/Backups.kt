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
 */
object Backups {
    /** Set in the sealed prefs once this phone has its own backup; the prefs never travel, so a restored state.bin without it came from another phone. */
    private const val HOME = "backup.home"

    fun local(c: Context) = LocalBackup(File(c.applicationContext.filesDir, "backup"))

    /**
     * On every start, before anything changes. A first run makes an empty backup with a fresh key. A state that Android
     * restored from Google (the files are here but this phone never made them) is opened, its accounts and Keys safe
     * sealed again with this phone's keys, and its key retired for a new one. Returns what to tell him, or null.
     */
    fun start(c: Context): String? {
        val prefs = SealedPrefs(c.applicationContext)
        val l = local(c)
        if (prefs.read(HOME) != null) { if (!l.exists()) l.start(); return null }
        val restored = if (l.exists()) l.read() else null
        if (restored != null && (restored.accounts.isNotEmpty() || restored.safe.isNotEmpty())) {
            val n = SphinxStore.get(c).restore(restored)
            val k = SafeStore.get(c).restore(restored.safe)
            l.rotate()
            prefs.write(HOME, "1")
            Log.info("restored from the Google backup", "$n account(s)")
            changed(c)
            return "Restored from your Google backup: $n account(s)" + (if (k > 0) " and $k Keys safe entr${if (k == 1) "y" else "ies"}" else "") + ". Pair your laptops again."
        }
        if (restored == null) l.start()
        prefs.write(HOME, "1")
        return null
    }

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

    private fun put(r: RelayBackup, slot: String, body: Map<String, Any?>) {
        RelayClient.plain(r.relay, "PUT", "/v1/backup/$slot", body, if (r.token.isNotBlank()) mapOf("x-sphinx-token" to r.token) else emptyMap())
    }

    /** Uploads the current state to the relay: the passcode's slot, and the phrase's when it is on. */
    fun upload(c: Context) {
        val l = local(c)
        val bk = l.key() ?: return
        val r = l.read()?.relay ?: return
        val sealed = l.stateFile.readBytes()
        put(r, "pass", mapOf("auth" to r.passAuth, "salt" to r.salt, "kdf" to r.kdf, "blob" to BackupCrypto.record("pass", SphinxCrypto.dec(r.passKey)!!, bk, sealed)))
        if (r.phraseId.isNotEmpty())
            put(r, r.phraseId, mapOf("auth" to r.phraseAuth, "blob" to BackupCrypto.record(r.phraseId, SphinxCrypto.dec(r.phraseKey)!!, bk, sealed)))
        Log.info("backup uploaded to the relay")
    }

    /**
     * Turns the relay backup on, or changes its passcode: a new salt and Argon2id keys, the slot updated with the old
     * auth (when there was one) and set to the new one, then the state uploaded. Blocking (Argon2id takes a moment).
     */
    fun setUp(c: Context, relay: String, typed: String, passcode: String) {
        val token = typed.ifBlank { c.getString(R.string.sphinx_relay_token) }
        Passcode.problem(passcode)?.let { error(it) }
        val l = local(c)
        val bk = l.key() ?: error("No backup on this phone yet")
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val kdf = Kdf()
        val k = BackupCrypto.passKeys(passcode, salt, kdf)
        val old = l.read()?.relay?.takeIf { it.relay == relay }
        val r = RelayBackup(relay, token, SphinxCrypto.enc(salt), kdf, SphinxCrypto.enc(k.key), k.auth,
            old?.phraseId.orEmpty(), old?.phraseKey.orEmpty(), old?.phraseAuth.orEmpty())
        put(r.copy(token = token), "pass", mapOf("auth" to (old?.passAuth ?: k.auth), "new_auth" to k.auth, "salt" to r.salt, "kdf" to kdf,
            "blob" to BackupCrypto.record("pass", k.key, bk, l.stateFile.readBytes())))
        l.update { it.copy(relay = r) }
        upload(c)
        Log.info(if (old == null) "relay backup on" else "backup passcode changed")
    }

    fun turnOff(c: Context) {
        val l = local(c)
        val r = l.read()?.relay ?: return
        runCatching { RelayClient.plain(r.relay, "POST", "/v1/backup/pass/delete", mapOf("auth" to r.passAuth)) }
        if (r.phraseId.isNotEmpty()) runCatching { RelayClient.plain(r.relay, "POST", "/v1/backup/${r.phraseId}/delete", mapOf("auth" to r.phraseAuth)) }
        l.update { it.copy(relay = null) }
        Log.info("relay backup off")
    }

    /** The recovery phrase on: its slot on the relay (the relay backup must be on). The words are shown once, never kept. */
    fun phraseOn(c: Context, words: List<String>) {
        val l = local(c)
        val r = l.read()?.relay ?: error("Turn the relay backup on first: the phrase opens the same copy, without the passcode.")
        val k = BackupCrypto.phraseKeys(Bip39.seed(words))
        if (r.phraseId.isNotEmpty() && r.phraseId != k.id) runCatching { RelayClient.plain(r.relay, "POST", "/v1/backup/${r.phraseId}/delete", mapOf("auth" to r.phraseAuth)) }
        val on = r.copy(phraseId = k.id, phraseKey = SphinxCrypto.enc(k.key), phraseAuth = k.auth)
        put(on, k.id, mapOf("auth" to k.auth, "blob" to BackupCrypto.record(k.id, k.key, l.key()!!, l.stateFile.readBytes())))
        l.update { it.copy(relay = on) }
        Log.info("recovery phrase on")
    }

    fun phraseOff(c: Context) {
        val l = local(c)
        val r = l.read()?.relay?.takeIf { it.phraseId.isNotEmpty() } ?: return
        RelayClient.plain(r.relay, "POST", "/v1/backup/${r.phraseId}/delete", mapOf("auth" to r.phraseAuth))
        l.update { it.copy(relay = r.copy(phraseId = "", phraseKey = "", phraseAuth = "")) }
        Log.info("recovery phrase off")
    }

    /**
     * A new phone, from the relay: with the passcode (its salt fetched first), or with the 24 words. The state opens on
     * the phone; the accounts and the Keys safe are sealed again with this phone's keys, and the same backup key carries
     * on here (so the relay copy and Google's stay one). Returns how many accounts came in.
     */
    fun restore(c: Context, relay: String, passcode: String? = null, words: List<String>? = null): Int {
        val (slot, k) = if (words != null) BackupCrypto.phraseKeys(Bip39.seed(words)).let { it.id to it }
        else {
            val s = json.readTree(RelayClient.plain(relay, "GET", "/v1/backup/pass/salt", null)!!)
            val kdf = json.treeToValue(s.path("kdf"), Kdf::class.java) ?: Kdf()
            require(kdf.m in 8_192..1_048_576 && kdf.t in 1..10 && kdf.p in 1..4) { "The relay's Argon2id settings look wrong" }
            "pass" to BackupCrypto.passKeys(passcode!!, SphinxCrypto.dec(s.path("salt").asText())!!, kdf)
        }
        val blob = json.readTree(RelayClient.plain(relay, "POST", "/v1/backup/$slot/open", mapOf("auth" to k.auth))!!).path("blob").asText()
        val (bk, sealed) = BackupCrypto.openRecord(slot, k.key, blob) ?: error("That backup doesn't open with this passcode or phrase")
        val state = BackupCrypto.openState(bk, sealed) ?: error("That backup doesn't open")
        val n = SphinxStore.get(c).restore(state)
        SafeStore.get(c).restore(state.safe)
        local(c).start(state, bk)
        SealedPrefs(c.applicationContext).write(HOME, "1")
        Log.info("restored from the relay", "$n account(s)")
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
