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

    /** What the relay stores in a slot: BK wrapped for that slot, and the state sealed with BK. */
    fun record(slot: String, wrapKey: ByteArray, bk: ByteArray, state: ByteArray): String =
        SphinxCrypto.enc(json.writeValueAsBytes(mapOf("v" to 1, "wrapped" to SphinxCrypto.enc(seal(wrapKey, bk, "sphinx backup key v1|$slot")), "state" to SphinxCrypto.enc(state))))

    /** A slot's record opened with its wrapping key: BK and the sealed state, or null (wrong key, or not a record). */
    fun openRecord(slot: String, wrapKey: ByteArray, record: String): Pair<ByteArray, ByteArray>? = runCatching {
        val n = json.readTree(SphinxCrypto.dec(record)!!)
        val bk = open(wrapKey, SphinxCrypto.dec(n.path("wrapped").asText())!!, "sphinx backup key v1|$slot")!!
        bk to SphinxCrypto.dec(n.path("state").asText())!!
    }.getOrNull()

    fun sealState(bk: ByteArray, s: BackupState): ByteArray = seal(bk, json.writeValueAsBytes(s), "sphinx backup state v1")

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
 */
class LocalBackup(private val dir: File, private val clock: () -> Long = System::currentTimeMillis) {
    private val lock = Any()
    val stateFile get() = File(dir, "state.bin")
    val keyFile get() = File(dir, "key.bin")

    fun exists(): Boolean = stateFile.exists() && keyFile.exists()

    fun key(): ByteArray? = keyFile.takeIf { it.exists() }?.readBytes()?.takeIf { it.size == 32 }

    fun read(): BackupState? = synchronized(lock) { key()?.let { k -> BackupCrypto.openState(k, stateFile.readBytes()) } }

    /** Starts an empty backup with a fresh key (first run, or after a restore that has its own [bk]). */
    fun start(state: BackupState = BackupState(), bk: ByteArray = BackupCrypto.newKey()) = synchronized(lock) {
        dir.mkdirs()
        write(bk, state)
    }

    /** Each file written whole, then moved into place; key.bin only when the key itself changes (a start or a rotate). */
    private fun write(bk: ByteArray, s: BackupState) {
        fun put(f: File, b: ByteArray) {
            val tmp = File(dir, f.name + ".tmp").apply { writeBytes(b) }
            Files.move(tmp.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        }
        if (!bk.contentEquals(key() ?: ByteArray(0))) put(keyFile, bk)
        put(stateFile, BackupCrypto.sealState(bk, s.copy(at = clock())))
    }

    /** One change to the state, under the lock. Null when there is no backup here (yet). */
    fun update(f: (BackupState) -> BackupState): BackupState? = synchronized(lock) {
        val k = key() ?: return null
        val s = BackupCrypto.openState(k, stateFile.readBytes()) ?: return null
        f(s).also { write(k, it) }
    }

    /** A new BK for the same state (after a restore: the copy of BK that came with it is retired). */
    fun rotate() = synchronized(lock) { read()?.let { write(BackupCrypto.newKey(), it) } }
}
