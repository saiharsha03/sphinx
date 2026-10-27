package dev.sphinx

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.updateAndGet
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
    /** [done] bytes of the release's size so far. */
    class Downloading(val release: AppRelease, val done: Long = 0L) : UpdateState() {
        val percent: Int get() = if (release.size <= 0) 0 else (done * 100 / release.size).toInt().coerceIn(0, 100)
    }
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

    /**
     * The count of passes that brought nothing, after a pass that went from [before] to [after] bytes: bytes kept
     * reset it, however the pass ended (Codex, 2026-10-27: a transfer cut at 300 s still brings its bytes).
     */
    fun triesAfter(tries: Int, before: Long, after: Long): Int = if (after > before) 0 else tries
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
    const val NOTE_READY = 8_101
    const val NOTE_DOWNLOAD = 8_102
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
        // Atomic: a check landing mid-download must not turn Downloading back into Available (Fable, 2026-10-27).
        val next = _state.updateAndGet { UpdateRules.afterCheck(it, found, own) }
        if (next is UpdateState.Available) {
            Log.info("update available", next.release.versionCode.toString())
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
        channel(nm)
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
        // One at a time: a second tap mid-download would wipe the folder under the first (Codex, 2026-10-27).
        if (!installing.compareAndSet(false, true)) return
        try { installNow(c, r, onState) } finally { installing.set(false) }
    }

    private val installing = java.util.concurrent.atomic.AtomicBoolean(false)

    private fun installNow(c: Context, r: AppRelease, onState: (UpdateState) -> Unit) {
        val app = c.applicationContext
        fun set(s: UpdateState) { _state.value = s; onState(s) }
        // Asked before the download, not after it: the setting is one tap away and the APK may be large.
        if (!app.packageManager.canRequestPackageInstalls()) {
            runCatching { app.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${app.packageName}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
            set(UpdateState.Failed(r, "Allow Sphinx to install updates (Android settings), then tap Update again."))
            return
        }
        val dir = File(app.cacheDir, FOLDER).apply { mkdirs() }
        val file = File(dir, r.file)
        // A file from an earlier try that still checks out is not fetched again (the owner, 2026-10-27: the installer
        // never showed, the next tap downloaded all 31 MB a second time).
        val kept = checks(app, r, file)
        if (!kept) {
            // The bytes so far live in a part file (this release's: another release's part goes), and the download
            // goes on from its end with a Range request, retrying by itself: Caddy cuts a response at 300 s and a
            // lossy Wi-Fi link gave 45 KB/s, so one 31 MB transfer never finished (the owner, 2026-10-27).
            val part = File(dir, r.file + ".part")
            dir.listFiles()?.filter { it != part }?.forEach { it.delete() }
            set(UpdateState.Downloading(r, part.length()))
            val store = SphinxStore.get(app)
            val pairings = store.pairings().filter { !it.signer }.sortedBy { if (it.pid == from) 0 else 1 }
            val p = pairings.firstOrNull() ?: return set(UpdateState.Failed(r, "No laptop paired: nowhere to fetch it from."))
            cancelled = false
            val started = System.currentTimeMillis()
            var tries = 0
            fun stop(e: Exception, why: String) { Log.warn("update download failed", e.javaClass.simpleName); set(UpdateState.Failed(r, why)) }
            while (part.length() < r.size) {
                // Every pass is bounded (Codex, 2026-10-27): the cancel and the deadline are checked here too, and a
                // pass that added nothing, a restart or a retried relay error all count against the dozen.
                if (cancelled || System.currentTimeMillis() - started > DEADLINE_MS) return stop(Stopped(), "The download took too long and was stopped. Try again: it goes on from where it stopped.")
                if (++tries > TRIES) return stop(IOException("tries"), "The download kept failing. Try again: it goes on from where it stopped.")
                val at = part.length()
                try {
                    var last = at
                    java.io.FileOutputStream(part, at > 0).use { out ->
                        RelayClient.appFile(p, Capped(out, r.size - at) { n ->
                            if (cancelled || System.currentTimeMillis() - started > DEADLINE_MS) throw Stopped()
                            if (at + n - last >= STEP || at + n == r.size.toLong()) { last = at + n; set(UpdateState.Downloading(r, at + n)) }
                        }, from = at, onOpen = { c ->
                            live = c
                            if (cancelled) c.disconnect()
                            // The whole file instead of the range asked: what is there is stale; start over.
                            if (at > 0 && c.responseCode != 206) throw Restart()
                        })
                    }
                } catch (e: Exception) {
                    when {
                        e is Capped.TooBig -> { part.delete(); return stop(e, "The download is bigger than the release says.") }
                        e is Stopped || cancelled -> return stop(e, "The download took too long and was stopped. Try again: it goes on from where it stopped.")
                        e is Restart -> part.delete()
                        // The relay refused the offset (416: the file there changed) -> the part goes; a 5xx is tried again; any other status is final.
                        e is RelayClient.Failed && e.status == 416 -> part.delete()
                        e is RelayClient.Failed && e.status < 500 -> return stop(e, "The relay refused the download (${e.status}). Try again later.")
                    }
                    Log.warn("update download retried", e.javaClass.simpleName)
                    Thread.sleep(RETRY_MS)
                } finally {
                    live = null
                    tries = UpdateRules.triesAfter(tries, at, part.length())   // bytes kept reset the count, however the pass ended
                }
            }
            if (!part.renameTo(file)) { part.delete(); return set(UpdateState.Failed(r, "The downloaded file couldn't be kept.")) }
            val why = runCatching { UpdateRules.verified(r, archive(app), file.length(), sha256(file), read(app, file)) }
                .getOrElse { "The download couldn't be checked (${it.javaClass.simpleName})." }
            if (why != null) {
                file.delete()
                Log.warn("update refused", why)
                set(UpdateState.Failed(r, why))
                return
            }
        }
        set(UpdateState.Ready(r, file.path))
        Log.info("update ready", r.versionCode.toString())
        if (front) openInstaller(app, r, file, ::set) else announce(app, r)
    }

    /** Whether [file] is [r] as checked ([UpdateRules.verified]); a check that throws is a no (fail closed). */
    private fun checks(app: Context, r: AppRelease, file: File): Boolean = file.isFile && file.length() == r.size.toLong() &&
        runCatching { UpdateRules.verified(r, archive(app), file.length(), sha256(file), read(app, file)) }.getOrElse { "unverifiable" } == null

    /** Set by [cancel]: the next bytes written throw, the download fails and its thread ends. */
    @Volatile private var cancelled = false
    /** The download's connection while it is open: [cancel] disconnects it, so a blocked read ends at once (Codex, 2026-10-27). */
    @Volatile private var live: java.net.HttpURLConnection? = null
    /** A download longer than this is given up (Android 15 ends a dataSync service at 6 h anyway). */
    private const val DEADLINE_MS = 30L * 60 * 1000

    /** Stops a download under way (the service's timeout, Codex 2026-10-27): it ends as a failure that says why. */
    fun cancel() { cancelled = true; runCatching { live?.disconnect() } }

    /** Whether a download or install is running. */
    fun busy(): Boolean = installing.get()

    /** Reported every so many bytes of a download. */
    private const val STEP = 256L * 1024

    /** Whether MainActivity is on screen (set by its start and stop): Android lets only an app in front open the installer. */
    @Volatile var front = false

    /** The release whose installer opened by itself: once per download, or a cancelled install would reopen it on every return. */
    private val opened = java.util.concurrent.atomic.AtomicLong(0L)

    /** The app back in front with a checked file waiting: the installer opens now (the tap on the notification lands here). */
    fun resume(c: Context) {
        val app = c.applicationContext
        val s = _state.value as? UpdateState.Ready ?: return
        if (opened.get() == s.release.versionCode) return
        val file = File(s.path)
        // Checked again (hash and parse, off the main thread: Codex, 2026-10-27) before it goes to the installer: the
        // cache sat there while the app was off screen. Only if the app is still in front with that file waiting.
        Thread {
            if (!checks(app, s.release, file)) { file.delete(); _state.compareAndSet(s, UpdateState.Available(s.release)); return@Thread }
            // The claim is atomic: two returns at once (Codex, 2026-10-27) open one installer, not two.
            if (front && _state.value === s && opened.getAndSet(s.release.versionCode) != s.release.versionCode) openInstaller(app, s.release, file) { _state.value = it }
        }.start()
    }

    private fun openInstaller(app: Context, r: AppRelease, file: File, set: (UpdateState) -> Unit) {
        opened.set(r.versionCode)
        app.getSystemService(NotificationManager::class.java)?.cancel(NOTE_READY)
        val uri = FileProvider.getUriForFile(app, "${app.packageName}.files", file)
        val i = Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { app.startActivity(i) }.onFailure {
            file.delete()
            Log.warn("installer not opened", it.javaClass.simpleName)
            set(UpdateState.Failed(r, "Android's installer didn't open (${it.javaClass.simpleName})."))
        }
    }

    /** The file is checked and waiting while the app is off screen: one tap brings Sphinx back and opens the installer. */
    private fun announce(c: Context, r: AppRelease) {
        val nm = c.getSystemService(NotificationManager::class.java) ?: return
        channel(nm)
        val open = PendingIntent.getActivity(c, NOTE_READY, Intent(c, MainActivity::class.java).putExtra(EXTRA, true), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = NotificationCompat.Builder(c, CHANNEL)
            .setSmallIcon(R.drawable.ic_notify)
            .setContentTitle("Sphinx ${r.versionName} is downloaded")
            .setContentText("Tap to install it.")
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        runCatching { nm.notify(NOTE_READY, n) }.onFailure { Log.warn("update not shown", it.javaClass.simpleName) }
    }

    fun channel(nm: NotificationManager) {
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Sphinx updates", NotificationManager.IMPORTANCE_DEFAULT).apply {
            description = "A newer Sphinx is on your relay"
        })
    }

    /** The service's thread died: the row and the card say so. */
    fun fail(r: AppRelease, why: String) { _state.value = UpdateState.Failed(r, why) }

    /** The release the service is to fetch (same process: no need to carry it in the intent). */
    @Volatile var pending: AppRelease? = null

    /** Starts the download in [UpdateService] (a foreground service: off screen, a plain thread's network is throttled). */
    fun installInBackground(c: Context, r: AppRelease) {
        val app = c.applicationContext
        pending = r
        runCatching { ContextCompat.startForegroundService(app, Intent(app, UpdateService::class.java)) }.onFailure {
            Log.warn("update service not started", it.javaClass.simpleName)
            Thread { runCatching { install(app, r) }.onFailure { e -> Log.warn("update failed", e.javaClass.simpleName); _state.value = UpdateState.Failed(r, "The update failed (${e.javaClass.simpleName}).") } }.start()
        }
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

    /** The download was cancelled or ran past its deadline. */
    private class Stopped : IOException("stopped")
    /** The relay sent the whole file where a range was asked: the part file is dropped and the download starts over. */
    private class Restart : IOException("restart")
    /** How many passes in a row that bring no bytes (a broken transfer, a restart, a retried relay error) are made, and the pause between. */
    private const val TRIES = 12
    private const val RETRY_MS = 3_000L

    /** Writes through up to [max] bytes and refuses the next: a body longer than the release says stops at once. */
    private class Capped(private val out: OutputStream, private val max: Long, private val onCount: (Long) -> Unit = {}) : OutputStream() {
        class TooBig : IOException("too big")
        private var n = 0L
        override fun write(b: Int) { if (++n > max) throw TooBig(); out.write(b); onCount(n) }
        override fun write(b: ByteArray, off: Int, len: Int) { n += len; if (n > max) throw TooBig(); out.write(b, off, len); onCount(n) }
        override fun flush() = out.flush()
        override fun close() = out.close()
    }
}

/**
 * The popup over the home screen when the relay holds a newer Sphinx (the owner, 2026-10-27: not hidden away in Settings).
 * "Later" puts it away for that release until the app is next opened; it follows the download and the install the
 * same way the Settings row does, so a tap on Update needs no trip to Settings. Nothing here fetches: [state] is
 * whatever the last check found.
 */
@Composable
fun UpdateDialog(state: UpdateState, onUpdate: (AppRelease) -> Unit) {
    val release = when (state) {
        is UpdateState.Available -> state.release
        is UpdateState.Downloading -> state.release
        is UpdateState.Ready -> state.release
        is UpdateState.Failed -> state.release
        UpdateState.None -> null
    } ?: return
    var dismissed by rememberSaveable { mutableLongStateOf(0L) }
    if (dismissed == release.versionCode) return
    // Busy only while the bytes come: once Android's installer is up, a cancelled install must leave the card
    // dismissable (Codex, 2026-10-27: nothing clears Ready, and the installer returns without an ON_START).
    val busy = state is UpdateState.Downloading
    Dialog(onDismissRequest = { if (!busy) dismissed = release.versionCode }, properties = DialogProperties(dismissOnBackPress = !busy, dismissOnClickOutside = !busy)) {
        UpdateCard(state, release, onLater = { dismissed = release.versionCode }, onUpdate = onUpdate)
    }
}

/** What the popup shows: the release, where the update stands, Later and Update. */
@Composable
fun UpdateCard(state: UpdateState, release: AppRelease, onLater: () -> Unit, onUpdate: (AppRelease) -> Unit) {
    val busy = state is UpdateState.Downloading
    Group {
        // The notes scroll past a height, so Later and Update stay in view (Codex, 2026-10-27: notes run to 2000 chars).
        Column(Modifier.heightIn(max = 300.dp).verticalScroll(rememberScrollState()).padding(horizontal = 18.dp, vertical = 16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Kicker("Update")
            Text("Sphinx ${release.versionName} is ready", style = Type.bodyLg.copy(fontWeight = FontWeight.SemiBold), color = Sx.p.text)
            release.notes?.takeIf { it.isNotBlank() }?.let { Text(it, style = Type.bodySm, color = Sx.p.text2) }
            when (state) {
                is UpdateState.Downloading -> Text("Downloading… ${state.percent}%", style = Type.bodySm, color = Sx.p.text2)
                is UpdateState.Ready -> Text("Android is asking to install it. If you cancelled, tap Update again.", style = Type.bodySm, color = Sx.p.text2)
                is UpdateState.Failed -> Text(state.why, style = Type.bodySm, color = Sx.p.danger)
                else -> {}
            }
        }
        Hairline()
        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End), verticalAlignment = Alignment.CenterVertically) {
            SxButton("Later", onLater, kind = Kind.SECONDARY, enabled = !busy, small = true)
            SxButton("Update", { onUpdate(release) }, enabled = !busy, small = true)
        }
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
            is UpdateState.Downloading -> ListRow("Update to ${state.release.versionName}", "Downloading… ${state.percent}%", rule = true) {
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
