package dev.sphinx

import android.content.Context
import com.fasterxml.jackson.core.type.TypeReference
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * One entry of the Keys safe: recovery material (a phrase, backup codes) as text, or a small file (a keystore, a JSON
 * key). What it is lives in the sealed prefs; its content is sealed like a code's secret (AES-256-GCM under a fresh key,
 * RSA-OAEP wrapped to the codes key, which needs a strong fingerprint for every use) in `safe/<id>.bin`.
 */
data class SafeEntry(
    val id: String = "", val title: String = "", val kind: String = "text", val name: String = "", val mime: String = "",
    val size: Int = 0, val added: Long = 0, val wk: ByteArray = ByteArray(0), val iv: ByteArray = ByteArray(0),
)

/**
 * The Keys safe. Opening an entry needs a fingerprint; it never leaves the phone except inside the sealed backup, and
 * export writes it only where you pick (the system's file picker). Call on IO.
 */
class SafeStore(
    private val read: (String) -> String?,
    private val write: (String, String?) -> Unit,
    private val keys: BoxKeys,
    private val dir: File,
    private val clock: () -> Long = System::currentTimeMillis,
    private val backup: LocalBackup? = null,
    private val changed: () -> Unit = {},
) {
    private val random = SecureRandom()
    private val lock = Any()

    fun entries(): List<SafeEntry> = read(SLOT)?.let { runCatching { json.readValue(it, object : TypeReference<List<SafeEntry>>() {}) }.getOrNull() }.orEmpty()

    private fun save(l: List<SafeEntry>) = write(SLOT, if (l.isEmpty()) null else json.writeValueAsString(l))

    private fun aad(id: String) = "sphinx/safe/v1\n$id".toByteArray()

    /** Why [data] can't go in, or null. The caps keep the sealed state (and so every backup copy) small. */
    fun problem(kind: String, data: ByteArray, now: List<SafeEntry> = entries()): String? = when {
        data.isEmpty() -> "It's empty."
        kind == "text" && data.size > MAX_TEXT -> "Text is ${MAX_TEXT / 1024} KB at most."
        data.size > MAX_ENTRY -> "A file is ${MAX_ENTRY / 1024} KB at most."
        now.size >= MAX_ENTRIES -> "The safe holds $MAX_ENTRIES entries at most."
        now.sumOf { it.size } + data.size > MAX_TOTAL -> "The safe holds ${MAX_TOTAL / 1024 / 1024} MB at most."
        else -> null
    }

    private fun seal(e: SafeEntry, data: ByteArray): SafeEntry {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey().encoded
        try {
            val iv = ByteArray(12).also { random.nextBytes(it) }
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv)); updateAAD(aad(e.id)) }
            dir.mkdirs()
            File(dir, "${e.id}.bin").writeBytes(c.doFinal(data))
            val r = Cipher.getInstance(Rsa.TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, keys.publicKey(), Rsa.OAEP) }
            return e.copy(wk = r.doFinal(key), iv = iv, size = data.size)
        } finally { key.fill(0) }
    }

    /** Seals a new entry (no fingerprint: the public key seals), and puts it in the sealed backup. [data] is wiped. */
    fun add(title: String, kind: String, name: String, mime: String, data: ByteArray): SafeEntry {
        try {
            synchronized(lock) {
                problem(kind, data)?.let { throw IllegalArgumentException(it) }
                val e = seal(SafeEntry(SphinxCrypto.newId(12), title.trim().take(80).ifEmpty { if (kind == "file") name else "Untitled" }, kind,
                    HandoffRules.safeName(name).takeIf { kind == "file" }.orEmpty(), mime.take(100), added = clock()), data)
                save(entries() + e)
                backup?.update { st -> st.copy(safe = st.safe + BackupSafe(e.id, e.title, e.kind, e.name, e.mime, e.added, SphinxCrypto.enc(data))) }
                changed()
                return e
            }
        } finally { data.fill(0) }
    }

    /** An entry's content, with a cipher the fingerprint authorised for this one use. */
    fun open(e: SafeEntry, u: Unwrapper): ByteArray {
        val key = u.unwrap(e.wk)
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, e.iv)); updateAAD(aad(e.id)) }
            return c.doFinal(File(dir, "${e.id}.bin").readBytes())
        } finally { key.fill(0) }
    }

    fun delete(id: String) {
        synchronized(lock) {
            save(entries().filter { it.id != id })
            File(dir, "$id.bin").delete()
        }
        backup?.update { st -> st.copy(safe = st.safe.filter { it.id != id }) }
        changed()
    }

    /** A restore: the backup's entries sealed again with this phone's keys (their ids kept). Returns how many came in. */
    fun restore(list: List<BackupSafe>): Int = synchronized(lock) {
        val have = entries()
        val made = list.filter { b -> have.none { it.id == b.id } }.mapNotNull { b ->
            val data = SphinxCrypto.dec(b.data) ?: return@mapNotNull null
            try { seal(SafeEntry(b.id, b.title, b.kind, b.name, b.mime, added = b.added), data) } finally { data.fill(0) }
        }
        save(have + made)
        made.size
    }

    /** After a new fingerprint enrolment the codes key is gone, and with it every entry's key (SphinxStore.Cleared). */
    fun clear() = synchronized(lock) {
        entries().forEach { File(dir, "${it.id}.bin").delete() }
        save(emptyList())
    }

    companion object {
        const val SLOT = "safe"
        /** Text up to 16 KB, a file up to 256 KB, 64 entries and 4 MB in all: recovery material, not a file store. */
        const val MAX_TEXT = 16 * 1024
        const val MAX_ENTRY = 256 * 1024
        const val MAX_ENTRIES = 64
        const val MAX_TOTAL = 4 * 1024 * 1024

        @Volatile private var instance: SafeStore? = null

        fun get(c: Context): SafeStore = instance ?: synchronized(this) {
            instance ?: c.applicationContext.let { app ->
                val prefs = SealedPrefs(app)
                SafeStore(prefs::read, prefs::write, KeystoreBoxKeys(SphinxStore.KEY_ALIAS), File(app.filesDir, "safe"),
                    backup = Backups.local(app), changed = { Backups.changed(app) })
            }.also { instance = it }
        }
    }
}
