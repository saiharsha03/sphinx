package dev.sphinx

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.Normalizer
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * The backup (docs/DESIGN.md, "Backup"). One random backup key (BK) seals the whole state: the accounts with their
 * secrets, their sites, the text-only sites, the Keys safe, and the relay backup's settings; never the laptop pairings,
 * which always pair again. Three ways back, in this order:
 *  1. Google: Android's own backup carries `backup/state.bin` and `backup/key.bin` (BK), end-to-end encrypted with the
 *     old phone's screen lock, and nothing else of the app (res/xml/data_extraction_rules.xml).
 *  2. The relay: the same state, with BK wrapped under a key from the backup passcode (Argon2id). The relay keeps only
 *     ciphertext and a verifier, and limits wrong tries (relay/sphinx_relay.py, Backup).
 *  3. A 24-word recovery phrase (BIP39), off by default: a second relay slot whose id, key and auth come from it.
 * Keystore keys can't move between phones, so on a restore every secret is sealed again with the new phone's keys.
 */
data class BackupAccount(
    val id: String = "", val issuer: String = "", val name: String = "", val domains: List<String> = emptyList(),
    val apps: List<String> = emptyList(), val algo: Algo = Algo.SHA1, val digits: Int = 6, val period: Int = Totp.PERIOD,
    val added: Long = 0, val secret: String = "",
)

/** A Keys safe entry, opened (inside the sealed backup state only). */
data class BackupSafe(val id: String = "", val title: String = "", val kind: String = "text", val name: String = "", val mime: String = "",
                      val added: Long = 0, val data: String = "")

/**
 * The relay backup's settings, kept inside the sealed state so they survive a Google restore: where, and the keys and
 * auth values derived from the passcode (and the phrase, when it is on). Anyone holding BK holds the state anyway.
 */
data class RelayBackup(
    val relay: String = "", val token: String = "", val salt: String = "", val kdf: Kdf = Kdf(),
    val passKey: String = "", val passAuth: String = "",
    val phraseId: String = "", val phraseKey: String = "", val phraseAuth: String = "",
)

data class BackupState(
    val v: Int = 1,
    val accounts: List<BackupAccount> = emptyList(),
    val textSites: List<String> = emptyList(),
    val safe: List<BackupSafe> = emptyList(),
    val relay: RelayBackup? = null,
    val at: Long = 0,
)

/** Argon2id's cost: 64 MiB, 3 passes, 1 lane. Memory-hard, so each offline guess costs real memory and time. */
data class Kdf(val m: Int = 65536, val t: Int = 3, val p: Int = 1)

/** The keys one secret (the passcode, or the phrase) gives: [key] wraps BK, [auth] proves it to the relay, [id] is the phrase's slot. */
class SecretKeys(val key: ByteArray, val auth: String, val id: String = "pass")

object BackupCrypto {
    private val random = SecureRandom()

    fun newKey(): ByteArray = ByteArray(32).also { random.nextBytes(it) }

    /** AES-256-GCM: iv (12) | ciphertext and tag, bound to [aad]. */
    fun seal(key: ByteArray, plain: ByteArray, aad: String): ByteArray {
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv)); updateAAD(aad.toByteArray()) }
        return iv + c.doFinal(plain)
    }

    /** The plaintext, or null (another key, another [aad], or tampered). */
    fun open(key: ByteArray, sealed: ByteArray, aad: String): ByteArray? = runCatching {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, sealed, 0, 12)); updateAAD(aad.toByteArray()) }
        c.doFinal(sealed, 12, sealed.size - 12)
    }.getOrNull()

    fun argon2id(secret: ByteArray, salt: ByteArray, k: Kdf, len: Int = 32): ByteArray {
        val g = Argon2BytesGenerator()
        g.init(Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt).withIterations(k.t).withMemoryAsKB(k.m).withParallelism(k.p).build())
        return ByteArray(len).also { g.generateBytes(secret, it) }
    }

    /** The passcode's keys: Argon2id(passcode, salt), then HKDF into a wrapping key and the relay auth value. */
    fun passKeys(passcode: String, salt: ByteArray, k: Kdf): SecretKeys {
        val pw = Normalizer.normalize(passcode, Normalizer.Form.NFKC).toByteArray()
        val root = argon2id(pw, salt, k)
        pw.fill(0)
        try { return SecretKeys(Hkdf.derive(root, salt, "sphinx backup key v1"), SphinxCrypto.enc(Hkdf.derive(root, salt, "sphinx backup auth v1"))) } finally { root.fill(0) }
    }

    /** The phrase's keys, from its BIP39 seed: its own slot id, a wrapping key and an auth value. */
    fun phraseKeys(seed: ByteArray): SecretKeys {
        val salt = "sphinx phrase v1".toByteArray()
        return SecretKeys(Hkdf.derive(seed, salt, "sphinx phrase key v1"), SphinxCrypto.enc(Hkdf.derive(seed, salt, "sphinx phrase auth v1")),
            SphinxCrypto.enc(Hkdf.derive(seed, salt, "sphinx phrase id v1")))
    }

    /**
     * What the relay stores in a slot: BK wrapped for that slot, and the state sealed with BK, as JSON. v2 is that JSON
     * as it is; v1 base64'd it once more, which put a full 4 MB Keys safe over the relay's 8,000,000 characters
     * (review 2026-10-27). [openRecord] reads both.
     */
    fun record(slot: String, wrapKey: ByteArray, bk: ByteArray, state: ByteArray): String =
        json.writeValueAsString(mapOf("v" to 2, "wrapped" to SphinxCrypto.enc(seal(wrapKey, bk, "sphinx backup key v1|$slot")), "state" to SphinxCrypto.enc(state)))

    /** A slot's record opened with its wrapping key: BK and the sealed state, or null (wrong key, or not a record). */
    fun openRecord(slot: String, wrapKey: ByteArray, record: String): Pair<ByteArray, ByteArray>? = runCatching {
        val n = json.readTree(if (record.startsWith("{")) record.toByteArray() else SphinxCrypto.dec(record)!!)
        val bk = open(wrapKey, SphinxCrypto.dec(n.path("wrapped").asText())!!, "sphinx backup key v1|$slot")!!
        bk to SphinxCrypto.dec(n.path("state").asText())!!
    }.getOrNull()

    fun sealState(bk: ByteArray, s: BackupState): ByteArray = seal(bk, json.writeValueAsBytes(s), "sphinx backup state v1")

    /**
     * The relay's Argon2id salt and cost, taken only when they are at least the phone's own ([Kdf]): a relay (or a
     * lookalike typed in) can't make offline guesses at the passcode cheaper by asking for less (review 2026-10-27).
     */
    fun trusted(kdf: Kdf?, salt: ByteArray?): Boolean {
        val d = Kdf()
        return kdf != null && salt != null && salt.size >= 16 && kdf.m in d.m..1_048_576 && kdf.t in d.t..10 && kdf.p in 1..4
    }

    /**
     * Whether a set-aside backup [s] opens with what he typed: its relay passcode, or its recovery phrase. A backup with
     * neither (no relay backup was on) opens with nothing typed here.
     */
    fun opens(s: BackupState, passcode: String?, words: List<String>?): Boolean {
        val r = s.relay ?: return false
        if (words != null) return r.phraseId.isNotEmpty() && java.security.MessageDigest.isEqual(phraseKeys(Bip39.seed(words)).auth.toByteArray(), r.phraseAuth.toByteArray())
        return passcode != null && proves(passcode, r)
    }

    /** Whether [passcode] is the backup's current one: its keys, from the stored salt and cost, give the stored auth. */
    fun proves(passcode: String, r: RelayBackup): Boolean {
        val salt = SphinxCrypto.dec(r.salt) ?: return false
        return java.security.MessageDigest.isEqual(passKeys(passcode, salt, r.kdf).auth.toByteArray(), r.passAuth.toByteArray())
    }

    /**
     * A restore onto a phone that already holds accounts or Keys safe entries: what was here plus what the restore
     * brought, so nothing already on the phone drops out of its later backups (review 2026-10-27). On a duplicate id the
     * entry already here wins, as the stores keep it (SphinxStore.restore, SafeStore.restore). The restored relay
     * settings win.
     */
    fun merged(restored: BackupState, here: BackupState?): BackupState {
        if (here == null) return restored
        val ids = here.accounts.map { it.id }.toSet()
        val safeIds = here.safe.map { it.id }.toSet()
        return restored.copy(accounts = here.accounts + restored.accounts.filter { it.id !in ids }, safe = here.safe + restored.safe.filter { it.id !in safeIds },
            textSites = (here.textSites + restored.textSites).distinct())
    }

    fun openState(bk: ByteArray, sealed: ByteArray): BackupState? =
        open(bk, sealed, "sphinx backup state v1")?.let { runCatching { json.readValue(it, BackupState::class.java) }.getOrNull() }
}

/** The 24-word recovery phrase: BIP39 (English list, 256 bits of entropy and an 8-bit checksum, PBKDF2-HMAC-SHA512 seed). */
object Bip39 {
    val WORDS: List<String> by lazy {
        Bip39::class.java.getResourceAsStream("/sphinx/bip39-english.txt")!!.use { it.readBytes().toString(Charsets.UTF_8) }.split('\n').map { it.trim() }.filter { it.isNotEmpty() }
    }

    fun phrase(entropy: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }): List<String> {
        require(entropy.size == 32)
        val sum = MessageDigest.getInstance("SHA-256").digest(entropy)[0]
        val bits = (entropy + sum).joinToString("") { (it.toInt() and 0xff).toString(2).padStart(8, '0') }
        return (0 until 24).map { WORDS[bits.substring(it * 11, it * 11 + 11).toInt(2)] }
    }

    /** The words as typed: lower case, single spaces; null unless they are 24 list words with the right checksum. */
    fun check(typed: String): List<String>? {
        val w = typed.trim().lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (w.size != 24 || w.any { it !in WORDS }) return null
        val bits = w.joinToString("") { WORDS.indexOf(it).toString(2).padStart(11, '0') }
        val entropy = ByteArray(32) { bits.substring(it * 8, it * 8 + 8).toInt(2).toByte() }
        return w.takeIf { phrase(entropy) == it }
    }

    /** The 32 bytes a checked phrase ([check]) stands for: the signer's passkey is U written this way. */
    fun entropy(words: List<String>): ByteArray {
        val bits = words.joinToString("") { WORDS.indexOf(it).toString(2).padStart(11, '0') }
        return ByteArray(32) { bits.substring(it * 8, it * 8 + 8).toInt(2).toByte() }
    }

    fun seed(words: List<String>, passphrase: String = ""): ByteArray {
        val spec = PBEKeySpec(Normalizer.normalize(words.joinToString(" "), Normalizer.Form.NFKD).toCharArray(),
            Normalizer.normalize("mnemonic$passphrase", Normalizer.Form.NFKD).toByteArray(), 2048, 512)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(spec).encoded
    }
}

/** The backup passcode: at least 12 characters, and a hint that steers toward a long phrase. */
object Passcode {
    const val MIN = 12

    fun problem(p: String): String? = when {
        p.length < MIN -> "At least $MIN characters"
        p.isBlank() || p.toSet().size < 5 -> "Too repetitive"
        else -> null
    }

    /** A plain-words strength hint. A phrase of four or more words is what it pushes for. */
    fun hint(p: String): String {
        val words = p.trim().split(Regex("[\\s\\-_.]+")).count { it.length >= 3 }
        return when {
            p.length < MIN -> "Too short: use a phrase of four or more words"
            words >= 5 || p.length >= 28 -> "Strong"
            words >= 4 || p.length >= 20 -> "Good. Longer is stronger: anyone with the relay's copy can guess offline"
            else -> "Weak: try four or more unrelated words, like \"copper lantern orbit meadow\""
        }
    }
}

/**
 * The backup on this phone: `state.bin` (the state sealed with BK) and `key.bin` (BK) in [dir], the only files Android
 * backs up. Every change goes through [update]. key.bin is plain on disk (inside the app's private storage), so code
 * running as Sphinx could read the state without a fingerprint: the price of a backup that works without one.
 * One instance per folder ([at]): the stores and the backup code share its lock (review 2026-10-27: each had its own,
 * so two changes at once could lose one).
 */
class LocalBackup(private val dir: File, private val clock: () -> Long = System::currentTimeMillis) {
    private val lock = Any()
    val stateFile get() = File(dir, "state.bin")
    val keyFile get() = File(dir, "key.bin")
    /** A new BK on its way in: written before the state sealed with it, moved onto key.bin after, so a stop between never leaves a pair that can't open. */
    private val nextKeyFile get() = File(dir, "key.next")
    /** A backup Android restored from another phone, set aside until he says to open it ([stash]). */
    /** Set-aside folders: restored, restored-2, restored-3, ... Each holds one backup; none is ever overwritten. */
    private fun asideDirs(): List<File> =
        (dir.listFiles { f -> f.isDirectory && ASIDE.matches(f.name) }?.toList() ?: emptyList()).sortedBy { it.name.substringAfter('-', "1").toIntOrNull() ?: 1 }
    private fun holds(d: File) = File(d, "state.bin").exists() || File(d, MOVING).exists()
    /** The set-aside backup shown first (the oldest), or where the first one would go. */
    private val foreignDir get() = asideDirs().firstOrNull(::holds) ?: File(dir, "restored")
    /** The first free set-aside folder. */
    private fun freeAside(): File = generateSequence(1) { it + 1 }.map { File(dir, if (it == 1) "restored" else "restored-$it") }.first { !holds(it) }
        .also { it.deleteRecursively() }

    fun exists(): Boolean = stateFile.exists() && (keyFile.exists() || nextKeyFile.exists())

    private fun bytes(f: File): ByteArray? = f.takeIf { it.exists() }?.readBytes()?.takeIf { it.size == 32 }

    /** BK and the state it opens: key.bin, or a key.next a stop left behind (then it is finished here). */
    private fun current(): Pair<ByteArray, BackupState>? {
        if (!stateFile.exists()) return null
        val sealed = stateFile.readBytes()
        bytes(keyFile)?.let { k -> BackupCrypto.openState(k, sealed)?.let { return k to it } }
        val next = bytes(nextKeyFile) ?: return null
        val s = BackupCrypto.openState(next, sealed) ?: return null
        Files.move(nextKeyFile.toPath(), keyFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        return next to s
    }

    fun key(): ByteArray? = synchronized(lock) { current()?.first }

    /**
     * BK, the state and the sealed bytes, read together under the lock: an upload sends a pair that opens, even while a
     * rotation runs (review 2026-10-27: read one by one, a rotation between could send BK with another key's state).
     */
    fun snapshot(): Triple<ByteArray, BackupState, ByteArray>? = synchronized(lock) { current()?.let { (k, s) -> Triple(k, s, stateFile.readBytes()) } }

    fun read(): BackupState? = synchronized(lock) { current()?.second }

    /** Starts an empty backup with a fresh key (first run, or after a restore that has its own [bk]). */
    fun start(state: BackupState = BackupState(), bk: ByteArray = BackupCrypto.newKey()) = synchronized(lock) {
        dir.mkdirs()
        write(bk, state)
    }

    private fun put(f: File, b: ByteArray) {
        val tmp = File(dir, f.name + ".tmp").apply { writeBytes(b) }
        Files.move(tmp.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    }

    /** Each file written whole, then moved into place. A new key goes to key.next first, the state sealed with it, then key.bin. */
    private fun write(bk: ByteArray, s: BackupState) {
        val newKey = !bk.contentEquals(bytes(keyFile) ?: ByteArray(0))
        if (newKey) put(nextKeyFile, bk)
        put(stateFile, BackupCrypto.sealState(bk, s.copy(at = clock())))
        if (newKey) Files.move(nextKeyFile.toPath(), keyFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    }

    /** One change to the state, under the lock. Null when there is no backup here (yet). */
    fun update(f: (BackupState) -> BackupState): BackupState? = synchronized(lock) {
        val (k, s) = current() ?: return null
        f(s).also { write(k, it) }
    }

    /** A new BK for the same state (after a restore: the copy of BK that came with it is retired). */
    fun rotate() = synchronized(lock) { current()?.let { write(BackupCrypto.newKey(), it.second) } }

    /**
     * A backup this phone didn't make (Android restored it from Google) is moved aside, unopened, and this phone starts
     * its own. Nothing of it is sealed to this phone until he says so ([aside], [dropAside]; review 2026-10-27).
     * False when there was none to move.
     */
    fun stash(why: String = GOOGLE): Boolean = synchronized(lock) {
        if (finishStash()) return true
        if (!stateFile.exists() || (!keyFile.exists() && !nextKeyFile.exists())) return false
        // Its own folder: one set aside before (an unopened Google backup) stays as it is (review 2026-10-27).
        val to = freeAside().apply { mkdirs() }
        // A stable id of its own: every later open or delete names exactly this copy (review 2026-10-27).
        File(to, "id").writeText(java.util.UUID.randomUUID().toString())
        File(to, "why").writeText(why)
        // Marked first, so a stop between the moves is finished on the next start, before anything new is written here.
        File(to, MOVING).writeText(why)
        finishStash()
    }

    /**
     * Finishes a stash a stop interrupted: moves what is still here (the state, key.bin, key.next) into the set-aside
     * folder (review 2026-10-27: a split stash let the next start write a new key over the old one). True when one was
     * in progress. Called before anything else on every start.
     */
    fun finishStash(): Boolean = synchronized(lock) {
        val to = asideDirs().firstOrNull { File(it, MOVING).exists() } ?: return false
        for (f in listOf(stateFile, keyFile, nextKeyFile)) if (f.exists())
            Files.move(f.toPath(), File(to, f.name).toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        File(to, MOVING).delete()
        true
    }

    private val retireFile get() = File(dir, "retire.pending")

    /**
     * The retire marker, durably: written whole and synced to a temporary file, renamed into place, then the folder
     * itself synced so the rename survives a power cut (review 2026-10-27).
     */
    private fun marker(text: String) {
        dir.mkdirs()
        val tmp = File(dir, retireFile.name + ".tmp")
        java.io.FileOutputStream(tmp).use { it.write(text.toByteArray()); it.fd.sync() }
        Files.move(tmp.toPath(), retireFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        syncDir()
    }

    /** fsync on the backup folder: FileChannel where the platform allows a directory, else Os.fsync on its descriptor. */
    private fun syncDir() {
        val viaChannel = runCatching { java.nio.channels.FileChannel.open(dir.toPath(), java.nio.file.StandardOpenOption.READ).use { it.force(true) } }.isSuccess
        if (!viaChannel) runCatching {
            val fd = android.system.Os.open(dir.path, android.system.OsConstants.O_RDONLY, 0)
            try { android.system.Os.fsync(fd) } finally { android.system.Os.close(fd) }
        }
    }

    /** Written (and synced) before an invalidated codes key is dropped: the retire must happen, even after a stop. */
    fun markRetire() = synchronized(lock) { marker(PENDING) }

    fun retirePending(): Boolean = retireFile.exists()

    /**
     * Finishes a pending retire (after a new fingerprint enrolment): the backup that held the old secrets is set aside as
     * [CLEARED] (unless it held nothing), then an empty one starts, then the marker goes. Each step is marked, so a stop
     * anywhere is finished on the next call without stashing the new empty backup. True when none is pending.
     */
    fun retire(): Boolean = synchronized(lock) {
        if (!retireFile.exists()) return true
        finishStash()
        if (retireFile.readText() != STASHED) {
            if (stateFile.exists() && !keyFile.exists() && !nextKeyFile.exists()) {
                // A state with no key that opens it can never be opened: moved out of the way, so the retire can finish
                // (it would otherwise fail on every start, for good; review 2026-10-27).
                Files.move(stateFile.toPath(), File(dir, UNOPENABLE).toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
            val s = if (stateFile.exists()) read() else null
            val empty = s != null && s.accounts.isEmpty() && s.safe.isEmpty() && s.relay == null
            if (stateFile.exists() && !empty) check(stash(CLEARED)) { "the old backup couldn't be set aside" }
            marker(STASHED)
        }
        if (!exists()) start()
        retireFile.delete()
        true
    }

    /** Why the set-aside backup is there: [GOOGLE] (Android restored it) or [CLEARED] (a new fingerprint cleared the codes). */
    fun foreignWhy(): String? = synchronized(lock) {
        if (!File(foreignDir, "state.bin").exists()) null else File(foreignDir, "why").takeIf { it.exists() }?.readText()?.trim() ?: GOOGLE
    }

    /** One set-aside copy: its stable [id], its key and state, and why it was set aside ([GOOGLE] or [CLEARED]). */
    class Aside(val id: String, val key: ByteArray, val state: BackupState, val why: String)

    private fun idOf(d: File): String = File(d, "id").takeIf { it.exists() }?.readText()?.trim()?.ifEmpty { null } ?: d.name

    private fun open(d: File): Aside? {
        if (File(d, MOVING).exists()) return null
        val sealed = File(d, "state.bin").takeIf { it.exists() }?.readBytes() ?: return null
        val why = File(d, "why").takeIf { it.exists() }?.readText()?.trim() ?: GOOGLE
        // key.bin, or the key.next a stopped rotation left, whichever opens it.
        for (k in listOfNotNull(bytes(File(d, "key.bin")), bytes(File(d, nextKeyFile.name))))
            BackupCrypto.openState(k, sealed)?.let { return Aside(idOf(d), k, it, why) }
        return null
    }

    /** The set-aside copy shown first (the oldest), or null. */
    fun aside(): Aside? = synchronized(lock) { asideDirs().firstOrNull(::holds)?.let(::open) }

    /** The copy with [id], or null when it is gone. */
    fun aside(id: String): Aside? = synchronized(lock) { asideDirs().firstOrNull { holds(it) && idOf(it) == id }?.let(::open) }

    /** Deletes exactly the copy with [id]; false (and nothing deleted) when it is already gone. */
    fun dropAside(id: String): Boolean = synchronized(lock) { asideDirs().firstOrNull { holds(it) && idOf(it) == id }?.deleteRecursively() ?: false }

    /** The oldest set-aside backup and its key, or null. */
    fun foreign(): Pair<ByteArray, BackupState>? = aside()?.let { it.key to it.state }

    companion object {
        const val GOOGLE = "google"
        private const val MOVING = "moving"
        private const val PENDING = "pending"
        private const val STASHED = "stashed"
        private const val UNOPENABLE = "state.unopenable.bin"
        private val ASIDE = Regex("^restored(-[0-9]+)?$")
        const val CLEARED = "cleared"
        private val shared = java.util.concurrent.ConcurrentHashMap<String, LocalBackup>()

        /** The one instance for [dir]: every user of a folder shares its lock. */
        fun at(dir: File): LocalBackup = shared.getOrPut(dir.absolutePath) { LocalBackup(dir) }
    }
}
