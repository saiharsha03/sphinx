package dev.sphinx

import android.content.Context
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

val json: ObjectMapper = ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

/**
 * One account as Sphinx keeps it. Everything but the secret is sealed with the prefs key (no prompt, so a laptop
 * request can be matched in the background); the secret is sealed again to the codes key pair, whose private half
 * needs a fresh strong fingerprint for every single use (no PIN). So every code is one fingerprint.
 */
data class CodeAccount(
    val id: String = "",
    val issuer: String = "",
    val name: String = "",
    /** The sites it may fill on (Domains.matches); editable under Sites. */
    val domains: List<String> = emptyList(),
    /** Its apps on the phone, for the "code" notification. */
    val apps: List<String> = emptyList(),
    val algo: Algo = Algo.SHA1,
    val digits: Int = 6,
    val period: Int = Totp.PERIOD,
    val added: Long = 0,
    /** The secret: AES-256-GCM under a fresh key, the key RSA-OAEP wrapped to the codes public key. */
    val wk: ByteArray = ByteArray(0),
    val iv: ByteArray = ByteArray(0),
    val ct: ByteArray = ByteArray(0),
    /** A small index, unique among the accounts and kept across restarts: its notification's id and request code. */
    val slot: Int = -1,
) {
    /** "GitHub (work)". */
    fun title(): String = when {
        issuer.isNotBlank() && name.isNotBlank() -> "$issuer ($name)"
        else -> issuer.ifBlank { name.ifBlank { "Account" } }
    }
}

/**
 * The accounts, pairings and what laptops sent, each in a sealed slot of Sphinx's prefs (SealedPrefs). The codes key is
 * `sphinx.codes` in Keystore. Nothing here is ever written to the log or the relay. Call on IO.
 */
class SphinxStore(
    private val read: (String) -> String?,
    private val write: (String, String?) -> Unit,
    private val keys: BoxKeys,
    private val clock: () -> Long = System::currentTimeMillis,
    /** Deletes the codes key (after a new fingerprint enrolment made it unusable); the next use makes a new one. */
    private val dropKey: () -> Unit = {},
    /** True for the exception Keystore throws once a new enrolment invalidated the key. */
    private val invalidated: (Throwable) -> Boolean = { it is android.security.keystore.KeyPermanentlyInvalidatedException },
    /** Where every change also goes, sealed with the backup key (docs/DESIGN.md, "Backup"). Null: no backup (tests). */
    private val backup: LocalBackup? = null,
    /** After each change: the relay backup's upload is scheduled (Backups.changed). */
    private val changed: () -> Unit = {},
    /**
     * Before anything of an invalidated key is dropped: the backup's retire marker, written durably (LocalBackup.markRetire).
     * If it can't be written, nothing is dropped (review 2026-10-27: a stop between the two left the old backup live).
     */
    private val retiring: () -> Unit = {},
) {
    private val random = SecureRandom()
    // Every read-modify-write of either slot holds this, so two callers (the listener and the screen, or two
    // replies) can't lose each other's counter or account.
    private val lock = Any()

    fun accounts(): List<CodeAccount> = read(ACCOUNTS)?.let { runCatching { json.readValue(it, object : TypeReference<List<CodeAccount>>() {}) }.getOrNull() }.orEmpty()

    private fun saveAccounts(l: List<CodeAccount>) = write(ACCOUNTS, if (l.isEmpty()) null else json.writeValueAsString(l))

    fun pairings(): List<Pairing> = read(PAIRINGS)?.let { runCatching { json.readValue(it, object : TypeReference<List<Pairing>>() {}) }.getOrNull() }.orEmpty()

    private fun savePairings(l: List<Pairing>) = write(PAIRINGS, if (l.isEmpty()) null else json.writeValueAsString(l))

    fun pairing(pid: String): Pairing? = pairings().firstOrNull { it.pid == pid }

    fun putPairing(p: Pairing) = synchronized(lock) { savePairings(pairings().filter { it.pid != p.pid } + p) }

    /** Changes one pairing in place under the lock; returns what was saved, or null when it is gone. */
    fun updatePairing(pid: String, f: (Pairing) -> Pairing): Pairing? = synchronized(lock) {
        val all = pairings()
        val p = all.firstOrNull { it.pid == pid } ?: return null
        val n = f(p)
        savePairings(all.map { if (it.pid == pid) n else it })
        n
    }

    fun unpair(pid: String) = synchronized(lock) { savePairings(pairings().filter { it.pid != pid }) }

    /** The last pick between the same accounts (choice key -> account id), sealed like the rest. */
    private fun lastPicks(): Map<String, String> = read(LAST)?.let { runCatching { json.readValue(it, object : TypeReference<Map<String, String>>() {}) }.getOrNull() }.orEmpty()

    fun lastPick(key: String): String? = lastPicks()[key]

    fun rememberPick(key: String, id: String) = synchronized(lock) { write(LAST, json.writeValueAsString(lastPicks() + (key to id))) }

    /**
     * Sites with no account here that send their code by text or email: the laptop may ask on them too, and the phone
     * offers a code from an SMS or email while that request waits. Same rules as an account's sites.
     */
    fun textSites(): List<String> = read(TEXT_SITES)?.let { runCatching { json.readValue(it, object : TypeReference<List<String>>() {}) }.getOrNull() }.orEmpty()

    fun saveTextSites(l: List<String>) {
        val clean = l.mapNotNull { Domains.savable(it) }.distinct()
        synchronized(lock) { write(TEXT_SITES, if (clean.isEmpty()) null else json.writeValueAsString(clean)) }
        backup?.update { it.copy(textSites = clean) }
        changed()
    }

    /** What laptops sent (SentItem), newest first; its own sealed slot, outside the backup. */

    private fun aad(id: String) = "sphinx/v1\n$id".toByteArray()

    /** One account's secret sealed: AES-256-GCM under a fresh key, the key RSA-OAEP wrapped to the codes public key. */
    private fun seal(id: String, secret: ByteArray, a: CodeAccount): CodeAccount {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey().encoded
        try {
            val iv = ByteArray(12).also { random.nextBytes(it) }
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            c.updateAAD(aad(id))
            val ct = c.doFinal(secret)
            val r = Cipher.getInstance(Rsa.TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, keys.publicKey(), Rsa.OAEP) }
            return a.copy(id = id, wk = r.doFinal(key), iv = iv, ct = ct)
        } finally { key.fill(0) }
    }

    /** Saves new accounts, each with a small slot unique among them. */
    private fun place(made: List<CodeAccount>): List<CodeAccount> = synchronized(lock) {
        val old = accounts()
        val fresh = made.filter { m -> old.none { it.id == m.id } }
        val used = old.map { it.slot }.toMutableSet()
        val slotted = fresh.map { a -> val free = generateSequence(0) { it + 1 }.first { it !in used }; used += free; a.copy(slot = free) }
        saveAccounts(old + slotted)
        slotted
    }

    /**
     * Seals the ticked accounts. Needs no fingerprint (the public key seals). The secret is in clear only here, so this
     * is also when it goes into the sealed backup (a fingerprint opens one code, never a whole backup). The secret
     * bytes are wiped.
     */
    fun add(picked: List<Imported>): List<CodeAccount> {
        val made = picked.map { im ->
            try {
                val domains = Domains.forIssuer(im.issuer)
                seal(SphinxCrypto.newId(12), im.secret, CodeAccount(issuer = im.issuer.take(60), name = im.name.take(80), domains = domains,
                    apps = Domains.appsFor(domains), algo = im.algo, digits = im.digits, period = im.period, added = clock())) to SphinxCrypto.enc(im.secret)
            } finally { im.secret.fill(0) }
        }
        val slotted = place(made.map { it.first })
        val secrets = made.associate { (a, s) -> a.id to s }
        backup?.update { st -> st.copy(accounts = st.accounts + slotted.map { it.toBackup(secrets.getValue(it.id)) }) }
        changed()
        return slotted
    }

    /**
     * A restore: the backup's accounts sealed again with this phone's keys (their ids kept, so the backup and the store
     * stay one), and its text-only sites. Accounts already here are left alone. Returns how many came in.
     */
    fun restore(s: BackupState): Int {
        val made = s.accounts.mapNotNull { b ->
            val secret = SphinxCrypto.dec(b.secret) ?: return@mapNotNull null
            try {
                seal(b.id, secret, CodeAccount(issuer = b.issuer, name = b.name, domains = b.domains.mapNotNull { Domains.savable(it) },
                    apps = b.apps, algo = b.algo, digits = b.digits, period = b.period, added = b.added))
            } finally { secret.fill(0) }
        }
        val placed = place(made)
        val sites = s.textSites.mapNotNull { Domains.savable(it) }.distinct()
        if (sites.isNotEmpty()) synchronized(lock) { write(TEXT_SITES, json.writeValueAsString((textSites() + sites).distinct())) }
        return placed.size
    }

    fun update(a: CodeAccount) {
        synchronized(lock) { saveAccounts(accounts().map { if (it.id == a.id) a.copy(wk = it.wk, iv = it.iv, ct = it.ct, slot = it.slot) else it }) }
        backup?.update { st -> st.copy(accounts = st.accounts.map { if (it.id == a.id) it.copy(issuer = a.issuer, name = a.name, domains = a.domains, apps = a.apps) else it }) }
        changed()
    }

    fun delete(id: String) {
        synchronized(lock) { saveAccounts(accounts().filter { it.id != id }) }
        backup?.update { st -> st.copy(accounts = st.accounts.filter { it.id != id }) }
        changed()
    }

    /** Whether this account's secret is in the backup (accounts imported before the backup existed aren't). */
    fun backedUp(id: String): Boolean = backup?.read()?.accounts?.any { it.id == id } ?: false

    /** Thrown by [unwrapper] when a new fingerprint enrolment invalidated the codes key; the accounts are already gone. */
    class Cleared : Exception("Codes cleared by a new fingerprint: restore them from your backup (Accounts, Restore), or import again")

    /**
     * The cipher BiometricPrompt must authorise for one code. When Keystore says a new enrolment invalidated the key,
     * its secrets can never open again: the key entry is deleted, the accounts wiped (pairings stay), and [Cleared] says so.
     */
    fun unwrapper(): Unwrapper = try {
        keys.unwrapper()
    } catch (e: Exception) {
        if (!invalidated(e)) throw e
        retiring()
        synchronized(lock) { saveAccounts(emptyList()) }
        runCatching { dropKey() }
        throw Cleared()
    }

    /** One code, with an authorised [u]. The secret lives only inside this call. */
    fun code(a: CodeAccount, u: Unwrapper, at: Long = clock()): String = codes(a, u, listOf(at)).single()

    /** The codes at several times from one unwrap (one fingerprint authorises one use of the key): a pre-approval's window. */
    fun codes(a: CodeAccount, u: Unwrapper, at: List<Long>): List<String> {
        val key = u.unwrap(a.wk)
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, a.iv))
            c.updateAAD(aad(a.id))
            val secret = c.doFinal(a.ct)
            try { return at.map { Totp.code(secret, it, a.algo, a.digits, a.period) } } finally { secret.fill(0) }
        } finally { key.fill(0) }
    }

    companion object {
        const val ACCOUNTS = "accounts"
        const val PAIRINGS = "pairings"
        const val LAST = "last"
        const val TEXT_SITES = "textsites"
        const val KEY_ALIAS = "sphinx.codes"

        @Volatile private var instance: SphinxStore? = null

        fun get(c: Context): SphinxStore = instance ?: synchronized(this) {
            instance ?: c.applicationContext.let { app ->
                val prefs = SealedPrefs(app)
                val keys = KeystoreBoxKeys(KEY_ALIAS)
                SphinxStore(prefs::read, prefs::write, keys, dropKey = keys::delete, backup = Backups.local(app), changed = { Backups.changed(app) },
                    retiring = { Backups.local(app).markRetire() })
            }.also { instance = it }
        }
    }
}


fun CodeAccount.toBackup(secret: String) = BackupAccount(id, issuer, name, domains, apps, algo, digits, period, added, secret)
