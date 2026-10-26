package dev.sphinx

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * The one way to open a wrapped key. On the phone it is a Keystore cipher that only works after BiometricPrompt
 * authorised it (CryptoObject); in tests, a fake that refuses until the fake prompt says yes.
 */
interface Unwrapper {
    fun unwrap(wrapped: ByteArray): ByteArray
}

/** The codes key pair: the public half for sealing, an [Unwrapper] (needing a fingerprint) for opening. */
interface BoxKeys {
    fun publicKey(): PublicKey
    fun unwrapper(): Unwrapper
}

/** RSA-OAEP with SHA-256 and MGF1 SHA-1: the padding Android Keystore takes. */
object Rsa {
    const val TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    val OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
}

/** The Keystore cipher behind one code. BiometricPrompt authorises exactly this object. */
class CipherUnwrapper(val cipher: Cipher) : Unwrapper {
    override fun unwrap(wrapped: ByteArray): ByteArray = cipher.doFinal(wrapped)
}

/**
 * The codes key pair in Android Keystore (StrongBox when the phone has it). The private key needs a fresh strong
 * fingerprint for every single use (auth timeout 0, biometrics only, never the PIN, so only a CryptoObject-bound
 * prompt opens it), and a new fingerprint enrolment invalidates it for good.
 */
class KeystoreBoxKeys(private val alias: String) : BoxKeys {
    private fun ks() = KeyStore.getInstance(STORE).apply { load(null) }

    private fun ensure(): KeyStore {
        val ks = ks()
        if (ks.containsAlias(alias)) return ks
        fun make(strongBox: Boolean) = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, STORE).apply {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
                    // StrongBox only does RSA-2048.
                    .setKeySize(if (strongBox) 2048 else 3072)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    .setInvalidatedByBiometricEnrollment(true)
                    .setIsStrongBoxBacked(strongBox)
                    .build(),
            )
        }.generateKeyPair()
        try { make(true) } catch (_: Exception) { make(false) }
        return ks
    }

    /** A plain copy of the public key: sealing never touches Keystore. */
    override fun publicKey(): PublicKey =
        KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(ensure().getCertificate(alias).publicKey.encoded))

    override fun unwrapper(): Unwrapper {
        val c = Cipher.getInstance(Rsa.TRANSFORM)
        c.init(Cipher.DECRYPT_MODE, ensure().getKey(alias, null) as PrivateKey, Rsa.OAEP)
        return CipherUnwrapper(c)
    }

    fun delete() = ks().deleteEntry(alias)

    private companion object { const val STORE = "AndroidKeyStore" }
}

/**
 * One sealed slot in Sphinx's own prefs ("sphinx"), AES-256-GCM under a Keystore key that needs no prompt, so a
 * laptop's request can be matched in the background. Only ciphertext is stored; the prefs are excluded from backup.
 * Call on IO.
 */
class SealedPrefs(context: Context) {
    private val sp = context.getSharedPreferences("sphinx", Context.MODE_PRIVATE)

    fun read(slot: String): String? {
        val ct = sp.getString("$slot.ct", null) ?: return null
        val iv = sp.getString("$slot.iv", null) ?: return null
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)))
            String(c.doFinal(Base64.decode(ct, Base64.NO_WRAP)), Charsets.UTF_8)
        } catch (_: Exception) { null }
    }

    fun write(slot: String, value: String?) {
        if (value == null) { sp.edit().remove("$slot.ct").remove("$slot.iv").commit(); return }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        val ct = c.doFinal(value.toByteArray(Charsets.UTF_8))
        sp.edit().putString("$slot.ct", Base64.encodeToString(ct, Base64.NO_WRAP)).putString("$slot.iv", Base64.encodeToString(c.iv, Base64.NO_WRAP)).commit()
    }

    private companion object {
        const val ALIAS = "sphinx.prefs"

        /** Made on first use (StrongBox when the phone has it). */
        fun key(): SecretKey {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
            fun make(strongBox: Boolean): SecretKey = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(
                    KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .setIsStrongBoxBacked(strongBox)
                        .build(),
                )
            }.generateKey()
            return try { make(true) } catch (_: Exception) { make(false) }
        }
    }
}

/**
 * A code on the clipboard: marked sensitive (keyboards and the clipboard preview hide it), cleared after 30 s by a
 * timer and again by WorkManager in case the process goes away first. Only the newest copy is cleared.
 */
object SecureClipboard {
    const val CLEAR_MS = 30_000L
    private const val WORK = "sphinx-clipboard-clear"
    private fun prefs(c: Context) = c.getSharedPreferences("sphinx_clip", Context.MODE_PRIVATE)

    fun copy(context: Context, label: String, text: String, clearMs: Long = CLEAR_MS) {
        val app = context.applicationContext
        val cm = app.getSystemService(ClipboardManager::class.java) ?: return
        cm.setPrimaryClip(ClipData.newPlainText("Sphinx: $label", text).apply {
            description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        })
        val nonce = java.util.UUID.randomUUID().toString()
        prefs(app).edit().putString("pending", nonce).commit()
        Handler(Looper.getMainLooper()).postDelayed({ clear(app, nonce) }, clearMs)
        runCatching {
            WorkManager.getInstance(app).enqueueUniqueWork(WORK, ExistingWorkPolicy.REPLACE,
                OneTimeWorkRequestBuilder<ClipClearWorker>().setInitialDelay(clearMs, TimeUnit.MILLISECONDS).setInputData(workDataOf("nonce" to nonce)).build())
        }.onFailure { Log.warn("clipboard clear not scheduled", it.javaClass.simpleName) }
    }

    /** Clears if [nonce] is still the newest copy. False when Android refused the clear. */
    fun clear(c: Context, nonce: String): Boolean {
        val p = prefs(c)
        if (p.getString("pending", null) != nonce) return true
        val ok = runCatching { c.getSystemService(ClipboardManager::class.java)!!.clearPrimaryClip() }.isSuccess
        p.edit().remove("pending").putBoolean("blocked", !ok).apply()
        if (!ok) Log.warn("clipboard clear refused")
        return ok
    }

    /** What the copy UI may promise: 30 s, unless Android refused the last clear. */
    fun promise(c: Context): String =
        if (prefs(c).getBoolean("blocked", false)) "Android blocked the last clipboard clear. Clear it yourself after pasting."
        else "The clipboard clears in 30 s."
}

class ClipClearWorker(c: Context, p: WorkerParameters) : Worker(c, p) {
    override fun doWork(): Result {
        val nonce = inputData.getString("nonce") ?: return Result.success()
        SecureClipboard.clear(applicationContext, nonce)
        return Result.success()
    }
}

/** Sphinx's log: Logcat only, on this phone. Site and outcome, never a code, a key, an account name or a user name. */
object Log {
    private const val TAG = "Sphinx"
    fun info(line: String, detail: String = "") { runCatching { android.util.Log.i(TAG, if (detail.isEmpty()) line else "$line ($detail)") } }
    fun warn(line: String, detail: String = "") { runCatching { android.util.Log.w(TAG, if (detail.isEmpty()) line else "$line ($detail)") } }
}
