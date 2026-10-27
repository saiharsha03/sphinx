package dev.sphinx

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.compose.runtime.Composable
import androidx.core.app.NotificationCompat
import androidx.core.content.FileProvider
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.security.MessageDigest

/** A release the relay serves (GET /v1/app, relay/sphinx_relay.py AppRelease): the same fields and the same limits. */
data class AppRelease(val versionCode: Long, val versionName: String, val sha256: String, val size: Int, val file: String, val notes: String?)

/** What the Settings row shows: nothing, a newer release, its download, Android's installer open, or why it stopped. */
sealed class UpdateState {
    object None : UpdateState()
    class Available(val release: AppRelease) : UpdateState()
    class Downloading(val release: AppRelease) : UpdateState()
    class Ready(val release: AppRelease, val path: String) : UpdateState()
    class Failed(val release: AppRelease?, val why: String) : UpdateState()
}

/** What an APK says about itself, read by the package manager: the installed app's, and the downloaded file's. */
data class Archive(val packageName: String, val versionCode: Long, val signers: List<ByteArray>)

/** The pure part of the updater: what a release may look like, when it is newer, and when a downloaded file is the one promised. */
object UpdateRules {
    const val MAX_SIZE = 100_000_000
    private val SHA = Regex("^[0-9a-f]{64}$")
    private val APK = Regex("^[A-Za-z0-9._-]{1,100}\\.apk$")

    /** The relay's JSON as an [AppRelease], or null when any field is missing or out of the relay's own bounds. */
    fun parse(text: String): AppRelease? {
        val n = runCatching { json.readTree(text) }.getOrNull() ?: return null
        if (!n.isObject) return null
        val code = n.path("versionCode").takeIf { it.isIntegralNumber && it.canConvertToLong() }?.asLong() ?: return null
        val name = n.path("versionName").takeIf { it.isTextual }?.asText() ?: return null
        val sha = n.path("sha256").takeIf { it.isTextual }?.asText() ?: return null
        val size = n.path("size").takeIf { it.isIntegralNumber && it.canConvertToInt() }?.asInt() ?: return null
        val file = n.path("file").takeIf { it.isTextual }?.asText() ?: return null
        val notes = n.path("notes").takeIf { it.isTextual }?.asText()?.takeIf { it.isNotBlank() }
        if (code <= 0 || name.length !in 1..40 || !SHA.matches(sha) || size !in 1..MAX_SIZE || !APK.matches(file)) return null
        if (notes != null && notes.length > 2000) return null
        return AppRelease(code, name, sha, size, file, notes)
    }

    fun newer(r: AppRelease, own: Long): Boolean = r.versionCode > own

    /** The same certificates, in any order, none missing on either side. */
    fun sameSigners(a: List<ByteArray>, b: List<ByteArray>): Boolean {
        if (a.isEmpty() || a.size != b.size) return false
        val left = a.map { it.toList() }.toSet()
        val right = b.map { it.toList() }.toSet()
        return left.size == a.size && left == right
    }

    /**
     * Why the downloaded file must not be installed, or null when it is exactly the release promised: the size, then the
     * sha256, then what the package manager read from it ([apk], null when it couldn't be read) against this app ([own]).
     */
    fun verified(r: AppRelease, own: Archive, size: Long, sha256: String, apk: Archive?): String? = when {
        size != r.size.toLong() -> "The download isn't the size the release says."
        sha256 != r.sha256 -> "The download doesn't match the release's hash."
        apk == null -> "The download isn't an APK Android can read."
        apk.packageName != own.packageName -> "The download isn't Sphinx."
        apk.versionCode != r.versionCode -> "The download isn't the version the release says."
        apk.versionCode <= own.versionCode -> "The download isn't newer than this app."
        !sameSigners(apk.signers, own.signers) -> "The download isn't signed with this app's key."
        else -> null
    }

    /** The state after a check found [found] (null: no release) while [current] stood: a download under way is left alone. */
    fun afterCheck(current: UpdateState, found: AppRelease?, own: Long): UpdateState = when {
        current is UpdateState.Downloading -> current
        found != null && newer(found, own) -> UpdateState.Available(found)
        else -> UpdateState.None
    }

    fun sha256Hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}

/**
 * The app updating itself from the relay (docs/DESIGN.md): the heartbeat and the app's start ask one paired relay for
 * its release; a newer one is one notification and a row in Settings. Update downloads the APK through the signed
 * route, keeps it only in the cache, and hands it to Android's installer only when its size, hash, package, version
 * and signing certificates all match: a relay can offer a release, never a different app or key. Nothing installs
 * without Android's own prompt.
 */
object Update {
    const val CHANNEL = "sphinx.update"
    /** The notification's tap opens MainActivity with this extra true: it shows Settings' update row. */
    const val EXTRA = "sphinx.update"
    private const val NOTE = 8_100
    private const val PREFS = "sphinx_update"
    private const val NOTIFIED = "notified"
    private const val FOLDER = "update"

    private val _state = MutableStateFlow<UpdateState>(UpdateState.None)
    /** What the Settings row shows. */
    val state: StateFlow<UpdateState> = _state

    /** The pairing whose relay served the release (its pid): the download goes through the same one. */
    @Volatile private var from: String? = null

    private fun own(c: Context): Long = c.packageManager.getPackageInfo(c.packageName, 0).longVersionCode

    /** Asks the first paired relay (the Signer's excepted) that has a release. Blocking, never on the main thread. */
    fun check(c: Context) {
        val app = c.applicationContext
        var found: AppRelease? = null
        for (p in SphinxStore.get(app).pairings().filter { !it.signer }) {
            val text = runCatching { RelayClient.app(p) }.onFailure { Log.warn("update check failed", it.javaClass.simpleName) }.getOrNull() ?: continue
            val r = UpdateRules.parse(text)
            if (r == null) { Log.warn("update refused: malformed release"); continue }
            found = r
            from = p.pid
            break
        }
        val own = own(app)
        val next = UpdateRules.afterCheck(_state.value, found, own)
        _state.value = next
        if (next is UpdateState.Available) {
            Log.info("update available", next.release.versionName)
            notify(app, next.release)
        }
    }

    fun checkInBackground(c: Context) {
        val app = c.applicationContext
        Thread { runCatching { check(app) }.onFailure { Log.warn("update check failed", it.javaClass.simpleName) } }.start()
    }

    /** One notification per release: the version last announced is kept (nothing secret: a number). */
    private fun notify(c: Context, r: AppRelease) {
        val prefs = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getLong(NOTIFIED, 0L) == r.versionCode) return
        prefs.edit().putLong(NOTIFIED, r.versionCode).apply()
        val nm = c.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Sphinx updates", NotificationManager.IMPORTANCE_DEFAULT).apply {
            description = "A newer Sphinx is on your relay"
        })
        val open = PendingIntent.getActivity(c, NOTE, Intent(c, MainActivity::class.java).putExtra(EXTRA, true), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = NotificationCompat.Builder(c, CHANNEL)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle("Sphinx ${r.versionName} is ready")
            .setContentText("Tap to update. Checked against your relay and this app's signing key.")
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        runCatching { nm.notify(NOTE, n) }.onFailure { Log.warn("update not shown", it.javaClass.simpleName) }
    }

    /**
     * Downloads [r] into the cache, checks it ([UpdateRules.verified]) and opens Android's installer. A failure leaves
     * no file behind and says why ([UpdateState.Failed]). Blocking, never on the main thread.
     */
    fun install(c: Context, r: AppRelease, onState: (UpdateState) -> Unit = {}) {
        val app = c.applicationContext
        fun set(s: UpdateState) { _state.value = s; onState(s) }
        // Asked before the download, not after it: the setting is one tap away and the APK may be large.
        if (!app.packageManager.canRequestPackageInstalls()) {
            runCatching { app.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${app.packageName}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
            set(UpdateState.Failed(r, "Allow Sphinx to install updates (Android settings), then tap Update again."))
            return
        }
        set(UpdateState.Downloading(r))
        val dir = File(app.cacheDir, FOLDER).apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }
        val file = File(dir, r.file)
        val store = SphinxStore.get(app)
        val pairings = store.pairings().filter { !it.signer }.sortedBy { if (it.pid == from) 0 else 1 }
        val p = pairings.firstOrNull() ?: return set(UpdateState.Failed(r, "No laptop paired: nowhere to fetch it from."))
        try {
            file.outputStream().use { out -> RelayClient.appFile(p, Capped(out, r.size.toLong())) }
        } catch (e: Exception) {
            file.delete()
            Log.warn("update download failed", e.javaClass.simpleName)
            set(UpdateState.Failed(r, if (e is Capped.TooBig) "The download is bigger than the release says." else "The download failed (${e.javaClass.simpleName}). Try again."))
            return
        }
        val why = runCatching { UpdateRules.verified(r, archive(app), file.length(), sha256(file), read(app, file)) }
            .getOrElse { "The download couldn't be checked (${it.javaClass.simpleName})." }
        if (why != null) {
            file.delete()
            Log.warn("update refused", why)
            set(UpdateState.Failed(r, why))
            return
        }
        set(UpdateState.Ready(r, file.path))
        Log.info("update ready", r.versionName)
        val uri = FileProvider.getUriForFile(app, "${app.packageName}.files", file)
        val i = Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { app.startActivity(i) }.onFailure {
            file.delete()
            Log.warn("installer not opened", it.javaClass.simpleName)
            set(UpdateState.Failed(r, "Android's installer didn't open (${it.javaClass.simpleName})."))
        }
    }

    fun installInBackground(c: Context, r: AppRelease) {
        val app = c.applicationContext
        Thread { runCatching { install(app, r) }.onFailure { Log.warn("update failed", it.javaClass.simpleName); _state.value = UpdateState.Failed(r, "The update failed (${it.javaClass.simpleName}).") } }.start()
    }

    /** This app, as installed. */
    private fun archive(c: Context): Archive {
        val info = c.packageManager.getPackageInfo(c.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        return Archive(info.packageName, info.longVersionCode, info.signingInfo?.apkContentsSigners?.map { it.toByteArray() }.orEmpty())
    }

    /** The downloaded file, as the package manager reads it; null when it isn't an APK it can read. */
    private fun read(c: Context, f: File): Archive? {
        val info = c.packageManager.getPackageArchiveInfo(f.path, PackageManager.GET_SIGNING_CERTIFICATES) ?: return null
        return Archive(info.packageName ?: return null, info.longVersionCode, info.signingInfo?.apkContentsSigners?.map { it.toByteArray() }.orEmpty())
    }

    private fun sha256(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { s -> val buf = ByteArray(64 * 1024); while (true) { val n = s.read(buf); if (n < 0) break; md.update(buf, 0, n) } }
        return UpdateRules.sha256Hex(md.digest())
    }

    /** Writes through up to [max] bytes and refuses the next: a body longer than the release says stops at once. */
    private class Capped(private val out: OutputStream, private val max: Long) : OutputStream() {
        class TooBig : IOException("too big")
        private var n = 0L
        override fun write(b: Int) { if (++n > max) throw TooBig(); out.write(b) }
        override fun write(b: ByteArray, off: Int, len: Int) { n += len; if (n > max) throw TooBig(); out.write(b, off, len) }
        override fun flush() = out.flush()
        override fun close() = out.close()
    }
}

/** Settings, "Update": this version with Check now; a newer release with its notes and Update; then what the update is doing. */
@Composable
fun UpdatePane(state: UpdateState, version: String, onCheck: () -> Unit, onUpdate: (AppRelease) -> Unit) {
    val busy = state is UpdateState.Downloading
    Group {
        ListRow("Sphinx $version", "From your relay, checked against this app's signing key.") {
            SxButton("Check now", onCheck, kind = Kind.SECONDARY, enabled = !busy, small = true)
        }
        when (state) {
            UpdateState.None -> {}
            is UpdateState.Available -> ListRow("Update to ${state.release.versionName}", state.release.notes, rule = true) {
                SxButton("Update", { onUpdate(state.release) }, small = true)
            }
            is UpdateState.Downloading -> ListRow("Update to ${state.release.versionName}", "Downloading…", rule = true) {
                SxButton("Update", {}, enabled = false, small = true)
            }
            is UpdateState.Ready -> ListRow("Update to ${state.release.versionName}", "Android is asking to install it.", rule = true)
            is UpdateState.Failed -> {
                state.release?.let { r ->
                    ListRow("Update to ${r.versionName}", r.notes, rule = true) { SxButton("Update", { onUpdate(r) }, small = true) }
                }
                Hairline()
                GroupText(state.why, color = Sx.p.danger)
            }
        }
    }
}
