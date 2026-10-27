package dev.sphinx

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.fasterxml.jackson.databind.JsonNode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.DateFormat
import java.util.Date
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A release-signing request from the release signer (docs/DESIGN.md, Release signing), opened and checked: "Sign Sphinx 1.2.0?". In memory
 * only, gone after [expires]. [label] is what the signer was told; [sha256] is what it computed from the APK it holds.
 * [key], [alias], [cert], [salt] and [fv] name the one key file the answer opens ([SigningRules.keySecret]); [unlock] is
 * the id of the U it was sealed with; [tag] is the asking pairing's tag, shown so a second signer can't pass for it.
 */
data class SignAsk(
    val rid: String, val pid: String, val from: String, val label: String, val key: String, val sha256: String, val size: Long, val expires: Long,
    val alias: String = "", val cert: String = "", val salt: String = "", val unlock: String = "", val fv: Int = 2, val tag: String = "",
) {
    /** Its id among the waiting asks (pairing and rid), as [Pending.waitId]. */
    val waitId: String get() = "$pid/$rid"
}

/**
 * The pure rules of signing approval. Only a pairing made with the Signer's QR (`x=sign`, [Pairing.signer]) may send
 * `sign.approve {label, key, sha256, size, alias, cert_sha256, salt, unlock, fv}`, and it may send nothing else. His yes
 * (a strong fingerprint that unwraps the sealed unlock secret U) answers `sign.approve.reply {ok: true, k}`: the secret
 * of the one key file he was shown, derived from U here. U itself never leaves the phone (review 2026-10-27: it opens
 * every key). Anything else is `{ok: false, why}`.
 */
object SigningRules {
    const val KIND = "sign.approve"
    const val REPLY = "sign.approve.reply"
    const val MAX_APK = 200L * 1024 * 1024
    private val KEY = Regex("^[a-z0-9][a-z0-9-]{0,31}$")
    private val SHA = Regex("^[0-9a-f]{64}$")
    private val LABEL = Regex("^[^\\p{Cntrl}]{1,80}$")
    private val ALIAS = Regex("^[^\\p{Cntrl}|]{1,64}$")
    private val UNLOCK = Regex("^[0-9a-f]{6}$")
    private val SALT = Regex("^[A-Za-z0-9_-]{22}$")
    private const val UNLOCK_QR = "sphinx-unlock:1?u="

    fun ask(rid: String, p: Pairing, body: JsonNode, expires: Long): SignAsk? {
        fun text(f: String, r: Regex) = body.path(f).takeIf { it.isTextual }?.asText()?.takeIf { r.matches(it) }
        val label = text("label", LABEL) ?: return null
        val key = text("key", KEY) ?: return null
        val sha = text("sha256", SHA) ?: return null
        val size = body.path("size").takeIf { it.isIntegralNumber }?.asLong()?.takeIf { it in 1..MAX_APK } ?: return null
        val alias = text("alias", ALIAS) ?: return null
        val cert = text("cert_sha256", SHA) ?: return null
        // Exactly the canonical spelling of 16 bytes: base64url decoding also takes a padded form and one with non-zero
        // trailing bits for the same bytes, which would pass a pin compared as text (review 2026-10-27).
        val salt = body.path("salt").takeIf { it.isTextual }?.asText()?.takeIf { SALT.matches(it) && SphinxCrypto.dec(it)?.let { b -> b.size == 16 && SphinxCrypto.enc(b) == it } == true } ?: return null
        val unlock = body.path("unlock").takeIf { it.isTextual }?.asText()?.takeIf { it.isEmpty() || UNLOCK.matches(it) } ?: return null
        val fv = body.path("fv").takeIf { it.isIntegralNumber }?.asInt()?.takeIf { it == 1 || it == 2 } ?: return null
        return SignAsk(rid, p.pid, p.name, label, key, sha, size, expires, alias, cert, salt, unlock, fv, SphinxCrypto.tag(p))
    }

    /**
     * The secret of the one key file [a] names, from U: v2 binds the name, alias and certificate he was shown into it, so
     * it opens that key and no other; v1 (files sealed before 2026-10-27) is that file's salt only. The signer's
     * key_secret is the same.
     */
    fun keySecret(u: ByteArray, a: SignAsk): ByteArray {
        val salt = SphinxCrypto.dec(a.salt)!!
        return if (a.fv >= 2) Hkdf.derive(u, salt, "sphinx signer key v2|${a.key}|${a.alias}|${a.cert}") else Hkdf.derive(u, salt, "sphinx signer key v1")
    }

    fun question(a: SignAsk) = "Sign ${a.label}?"
    fun short(sha: String) = "${sha.take(4)}…${sha.takeLast(4)}"
    fun detail(a: SignAsk) = "sha256 ${short(a.sha256)} · key ${a.key} · ${size(a.size)}"
    /** The whole hash in groups of 8, to compare with what the build printed. */
    fun grouped(sha: String) = sha.chunked(8).chunked(4).joinToString("\n") { it.joinToString(" ") }
    fun size(n: Long) = if (n >= 1024 * 1024) "%.1f MB".format(n / 1048576.0) else "${maxOf(1, n / 1024)} KB"

    /** One release signer at a time: a second Signer QR is refused until the first is unpaired on purpose. */
    fun mayPair(signer: Boolean, pairings: List<Pairing>): Boolean = !signer || pairings.none { it.signer }

    /** His yes: [k] is [keySecret] for the key he was shown, never U. */
    fun approved(rid: String, k: ByteArray): Map<String, Any?> = SphinxLogic.envelope(REPLY, rid, mapOf("ok" to true, "k" to SphinxCrypto.enc(k)))
    fun no(rid: String, why: String): Map<String, Any?> = SphinxLogic.envelope(REPLY, rid, mapOf("ok" to false, "why" to why))

    /** U from the enrolment QR the laptop made ("sphinx-unlock:1?u=<b64url>"), or null. */
    fun unlockQr(raw: String): ByteArray? = raw.trim().takeIf { it.startsWith(UNLOCK_QR) }?.removePrefix(UNLOCK_QR)?.let(SphinxCrypto::dec)?.takeIf { it.size == 32 }

    /** U from the typed 24-word passkey (BIP39 of U), or null. */
    fun fromPasskey(typed: String): ByteArray? = Bip39.check(typed)?.let(Bip39::entropy)

    /** Six hex characters naming U (the same as the signer's unlock_id and the passkey file's "unlock id"). */
    fun unlockId(u: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest("sphinx signer id v1|".toByteArray() + Hkdf.derive(u, ByteArray(0), "sphinx signer id v1"))
            .take(3).joinToString("") { "%02x".format(it) }
}

/**
 * What the phone has seen of the signer's key files: each legacy (v1) name's salt from its first approval, and the names
 * seen as v2. A v1 file's secret doesn't bind its name, so a signer could otherwise put another v1 file's salt under a
 * decoy name and release that key with one approval (review 2026-10-27). Re-sealing to v2 ends it (docs/DESIGN.md, Release signing).
 */
data class SignPins(val v1: Map<String, String> = emptyMap(), val v2: Set<String> = emptySet(), val owners: Map<String, String> = emptyMap()) {
    /**
     * Why [a] is refused, or null. Salts are compared as their bytes, in one canonical spelling. [owners] is every salt
     * ever approved and the name it belongs to, kept for good (never dropped when a name moves to v2: an old v1 file
     * kept by a signer could otherwise come back under a decoy name; review 2026-10-27); a salt is refused under any
     * other name, in any version.
     */
    fun refusal(a: SignAsk): String? {
        val salt = canonical(a.salt) ?: return "this key file's salt is malformed"
        val owner = owners[salt] ?: v1.entries.firstOrNull { canonical(it.value) == salt }?.key
        if (owner != null && owner != a.key) return "this key file is another key's"
        if (a.fv != 1) return null
        return when {
            a.key in v2 -> "this key is v2 now: a legacy file under its name is refused"
            v1[a.key]?.let { canonical(it) != salt } == true -> "this legacy key file changed"
            else -> null
        }
    }

    /** After his yes on [a]. */
    fun after(a: SignAsk): SignPins {
        val salt = canonical(a.salt) ?: a.salt
        val kept = owners + (salt to a.key)
        return if (a.fv == 1) copy(v1 = v1 + (a.key to salt), owners = kept) else copy(v1 = v1 - a.key, v2 = v2 + a.key, owners = kept + v1.filterKeys { it == a.key }.mapKeys { canonical(it.value) ?: it.value }.mapValues { a.key })
    }

    private fun canonical(s: String): String? = SphinxCrypto.dec(s)?.let(SphinxCrypto::enc)
}

/** The unlock secret, sealed like a code's secret: AES-256-GCM under a fresh key, that key RSA-OAEP wrapped to the codes key. */
data class SealedUnlock(val id: String = "", val added: Long = 0, val wk: ByteArray = ByteArray(0), val iv: ByteArray = ByteArray(0), val ct: ByteArray = ByteArray(0))

/**
 * U on the phone (Settings, Signing). Enrolling needs no fingerprint (the public key seals); opening it needs a fresh
 * strong fingerprint, once per sign. Not in any backup: the passkey is its way back. A new fingerprint enrolment makes it
 * unopenable (Sphinx.unwrapper removes it): enrol again from the passkey. Call on IO.
 */
class UnlockStore(private val read: (String) -> String?, private val write: (String, String?) -> Unit, private val keys: BoxKeys,
                  private val clock: () -> Long = System::currentTimeMillis) {
    private val random = SecureRandom()

    fun get(): SealedUnlock? = read(SLOT)?.let { runCatching { json.readValue(it, SealedUnlock::class.java) }.getOrNull() }

    fun enrolled(): Boolean = get() != null

    /** Seals [u] (wiped here) and returns its unlock id. */
    fun enroll(u: ByteArray): String {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey().encoded
        try {
            require(u.size == 32) { "The unlock secret is 32 bytes" }
            val iv = ByteArray(12).also { random.nextBytes(it) }
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv)); updateAAD(AAD) }
            val r = Cipher.getInstance(Rsa.TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, keys.publicKey(), Rsa.OAEP) }
            val e = SealedUnlock(SigningRules.unlockId(u), clock(), r.doFinal(key), iv, c.doFinal(u))
            write(SLOT, json.writeValueAsString(e))
            return e.id
        } finally { key.fill(0); u.fill(0) }
    }

    /** U, with a cipher his fingerprint authorised for this one use. The caller wipes it. */
    fun open(un: Unwrapper): ByteArray {
        val e = get() ?: error("No unlock secret on this phone")
        val key = un.unwrap(e.wk)
        try {
            return Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, e.iv)); updateAAD(AAD) }.doFinal(e.ct)
        } finally { key.fill(0) }
    }

    fun remove() = write(SLOT, null)

    /** The key files seen ([SignPins]); kept beside U, in the sealed prefs. Not removed with U: they name files, not secrets. */
    fun pins(): SignPins = read(PINS)?.let { runCatching { json.readValue(it, SignPins::class.java) }.getOrNull() } ?: SignPins()
    fun savePins(p: SignPins) = write(PINS, json.writeValueAsString(p))

    companion object {
        const val SLOT = "signer"
        const val PINS = "signer.pins"
        private val AAD = "sphinx/signer/v1".toByteArray()

        @Volatile private var instance: UnlockStore? = null

        fun get(c: Context): UnlockStore = instance ?: synchronized(this) {
            instance ?: c.applicationContext.let { app -> val prefs = SealedPrefs(app); UnlockStore(prefs::read, prefs::write, KeystoreBoxKeys(SphinxStore.KEY_ALIAS)) }.also { instance = it }
        }
    }
}

/** Settings, Signing: the unlock secret on this phone, shared by its section and the danger zone (Remove). */
@Stable
class SigningModel(private val app: Context, private val scope: CoroutineScope) {
    var current by mutableStateOf<SealedUnlock?>(null)
    var bump by mutableIntStateOf(0)
    var note by mutableStateOf<String?>(null)
    var typing by mutableStateOf(false)
    var typed by mutableStateOf("")

    fun enroll(u: ByteArray?, what: String) {
        if (u == null) { note = "That isn't $what."; return }
        scope.launch {
            val r = withContext(Dispatchers.IO) { runCatching { UnlockStore.get(app).enroll(u) } }
            note = r.exceptionOrNull()?.let { "It couldn't be saved (${it.javaClass.simpleName})." }
                ?: "Saved, unlock id ${r.getOrNull()}. It should match the id in the passkey file."
            if (r.isSuccess) Log.info("signing unlock enrolled")
            typed = ""; typing = false; bump++
        }
    }

    fun remove() {
        scope.launch { withContext(Dispatchers.IO) { UnlockStore.get(app).remove() }; Log.info("signing unlock removed"); note = "Removed: signing now needs the passkey."; bump++ }
    }
}

@Composable
fun rememberSigningModel(samples: Samples?): SigningModel {
    val app = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    val m = remember { SigningModel(app, scope) }
    LaunchedEffect(m.bump) { m.current = if (samples != null) samples.unlock else withContext(Dispatchers.IO) { UnlockStore.get(app).get() } }
    return m
}

/**
 * Settings, Signing: the unlock secret on this phone (scan the laptop's QR or type the passkey), and the Signer's pairing.
 * Removing the unlock is in the danger zone.
 */
@Composable
fun SigningPane(m: SigningModel, scan: ((String) -> Unit) -> Unit, signers: List<Pairing>, calls: Calls) {
    val c = Sx.p
    Group {
        ListRow("Unlock", m.current?.let { "On this phone · id ${it.id} · since ${DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(it.added))}" } ?: "Not on this phone") {
            Value(if (m.current != null) "On" else "Off", ok = m.current != null)
        }
        // The VPS signer pairs like a laptop but only asks to sign releases: it lives here, not under Laptops.
        signers.forEach { Hairline(); PairingRow(it, calls) }
        Hairline()
        GroupText("The release signer on your VPS asks here before every sign. Your fingerprint sends it the secret of the one key it shows, made here from this unlock secret, which opens that key for that one sign; the unlock secret never leaves the phone. Only a pairing made with the signer's own QR can ask.")
        Hairline()
        if (m.typing) Column(Modifier.padding(16.dp)) {
            OutlinedTextField(m.typed, { m.typed = it }, Modifier.fillMaxWidth(), label = { Text("The 24-word passkey") }, minLines = 3,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false), colors = fieldColors())
            Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SxButton("Save", { m.enroll(SigningRules.fromPasskey(m.typed), "the 24-word passkey (check the words and their order)") }, enabled = m.typed.isNotBlank(), small = true)
                SxButton("Cancel", { m.typing = false; m.typed = "" }, kind = Kind.SECONDARY, small = true)
            }
        } else {
            ListRow("Scan the unlock QR", titleColor = c.primary, onClick = { scan { raw -> m.enroll(SigningRules.unlockQr(raw), "the signer's unlock QR") } }) { Chevron() }
            ListRow("Type the passkey", titleColor = c.primary, rule = true, onClick = { m.typing = true }) { Chevron() }
        }
    }
    Note(m.note)
}

/** The signing question over the lock screen: the label, the key, the whole sha256, Approve (fingerprint) and Deny. */
@Composable
fun SignContent(a: SignAsk?, secondsLeft: Int, note: String?, onApprove: () -> Unit, onDeny: () -> Unit) {
    val c = Sx.p
    AskScreen(body = {
        if (a == null) {
            Text(note ?: "", style = Type.headlineMd, color = c.text, textAlign = TextAlign.Center)
            return@AskScreen
        }
        Eyebrow("The signer asks")
        QuestionCartouche(SigningRules.question(a))
        Group {
            Fact("Key", a.key, rule = false)
            Fact("Size", SigningRules.size(a.size))
            Fact("From", a.from)
            // The asking pairing's tag (Laptops and Settings, Signing show the same): a second signer can't pass for it.
            Fact("Pairing tag", a.tag)
            Fact("Certificate", SigningRules.short(a.cert))
            if (a.fv == 1) Fact("Key file", "legacy (v1): re-seal it to v2")
            Hairline()
            Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 11.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("sha256", style = Type.bodySm.copy(fontSize = 13.sp), color = c.text2)
                Text(SigningRules.grouped(a.sha256), Modifier.weight(1f), style = Type.codeSm.copy(fontSize = 11.sp, lineHeight = 17.sp), color = c.text, textAlign = TextAlign.End)
            }
        }
        NoteLine("Approve only if this is the build you expect: compare the hash with the one the build printed.")
        note?.let { Text(it, style = Type.bodySm, color = c.danger, textAlign = TextAlign.Center) }
    }, footer = {
        if (a != null) Timer(secondsLeft)
    }, actions = {
        if (a == null) SxButton("Close", onDeny, Modifier.fillMaxWidth(), kind = Kind.SECONDARY)
        else AnswerPair(onDeny, onApprove)
    })
}
