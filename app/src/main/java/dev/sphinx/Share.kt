package dev.sphinx

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.app.NotificationCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Handoff on the phone (docs/DESIGN.md, "Handoff"). From a laptop: a link or text shows as a notification with Open /
 * Copy; a file is saved to Download/Sphinx (MediaStore, no storage permission) and its notification opens it. Nothing
 * opens by itself. To a laptop: the share sheet's "Send to laptop" ([ShareActivity]), sealed in the 'p' direction into
 * the laptop's outbox, files in chunks under their own key.
 */
object Handoff {
    private const val CHANNEL = "sphinx.handoff"
    private const val NOTE = 8_000

    private fun channel(c: Context) = c.getSystemService(NotificationManager::class.java).createNotificationChannel(
        NotificationChannel(CHANNEL, "From your laptop", NotificationManager.IMPORTANCE_DEFAULT).apply { description = "Links, text and files your laptop sent" })

    /**
     * Something a laptop sent. A file is fetched and saved off the wake's thread; the rest is one notification. Each is
     * also kept, for the Texts and Files tabs, until the owner removes it (a file only once it is saved).
     */
    fun receive(c: Context, p: Pairing, rid: String, it: HandoffItem) {
        if (it.type == "file") Thread { runCatching { saveFile(c, p, rid, it.file!!) }.onFailure { e -> Log.warn("handoff file not saved", e.javaClass.simpleName) } }.start()
        else {
            notify(c, rid, it, p.name, null)
            keep(c, if (it.type == "link") SentItem(kind = SentKind.LINK, url = it.url, laptop = p.name) else SentItem(kind = SentKind.TEXT, text = it.text, laptop = p.name))
        }
    }

    /** Kept on its own thread: the wake that brought it may carry a code request behind it (Fable, 2026-10-27). */
    private fun keep(c: Context, item: SentItem) {
        val app = c.applicationContext
        val it = item.copy(id = SphinxCrypto.newId(12), at = System.currentTimeMillis())
        Thread { runCatching { SentStore.add(app, it) }.onFailure { e -> Log.warn("handoff not kept", e.javaClass.simpleName) } }.start()
    }

    private fun saveFile(c: Context, p: Pairing, rid: String, f: FileRef) {
        val data = HandoffRules.assemble(f, (0 until f.chunks).map { RelayClient.getChunk(p, f.fid, it) }) ?: run { Log.warn("handoff file refused"); return }
        runCatching { RelayClient.dropFile(p, f.fid) }
        val cr = c.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, f.name)
            put(MediaStore.Downloads.MIME_TYPE, f.mime)
            put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/Sphinx")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        val uri = cr.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: error("no Downloads")
        cr.openOutputStream(uri)!!.use { it.write(data) }
        cr.update(uri, ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }, null, null)
        data.fill(0)
        Log.info("handoff file saved to Download/Sphinx")
        notify(c, rid, HandoffItem("file", file = f), p.name, uri)
        keep(c, SentItem(kind = SentKind.FILE, name = f.name, mime = f.mime, size = f.size, uri = uri.toString(), laptop = p.name))
    }

    private fun notify(c: Context, rid: String, it: HandoffItem, laptop: String, saved: Uri?) {
        channel(c)
        val id = NOTE + (rid.hashCode() and 0xff)
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val b = NotificationCompat.Builder(c, CHANNEL).setSmallIcon(R.drawable.ic_notify)
            .setContentTitle(when (it.type) { "link" -> if (it.open) "Open on this phone" else "A link from $laptop"; "text" -> "Text from $laptop"; else -> "Saved to Download/Sphinx" })
            .setContentText(when (it.type) { "link" -> it.url; "text" -> it.text; else -> it.file!!.name })
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setAutoCancel(true)
        val copy = { text: String -> PendingIntent.getBroadcast(c, id, Intent(c, CopyReceiver::class.java).putExtra(CopyReceiver.TEXT, text).putExtra(CopyReceiver.NOTE, id), flags) }
        when (it.type) {
            "link" -> {
                // Only an http(s) link (checked again) becomes a browser intent, and only at a tap.
                val open = PendingIntent.getActivity(c, id, Intent(Intent.ACTION_VIEW, Uri.parse(HandoffRules.httpUrl(it.url)!!)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), flags)
                b.setContentIntent(open).addAction(0, "Open", open).addAction(0, "Copy", copy(it.url!!))
            }
            "text" -> b.setStyle(NotificationCompat.BigTextStyle().bigText(it.text)).setContentIntent(copy(it.text!!)).addAction(0, "Copy", copy(it.text))
            else -> {
                val open = PendingIntent.getActivity(c, id, Intent(Intent.ACTION_VIEW).setDataAndType(saved, it.file!!.mime)
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK), flags)
                b.setContentIntent(open).addAction(0, "Open", open)
            }
        }
        runCatching { c.getSystemService(NotificationManager::class.java).notify(id, b.build()) }.onFailure { e -> Log.warn("handoff not shown", e.javaClass.simpleName) }
    }

    /**
     * To a laptop: a file's chunks go up first, then the handoff, sealed with the next 'p' counter inside the store's
     * lock, into that laptop's outbox. Blocking.
     */
    fun send(c: Context, pid: String, item: HandoffItem, data: ByteArray? = null) {
        val store = SphinxStore.get(c)
        val p0 = store.pairing(pid) ?: error("That laptop isn't paired any more")
        val it = if (item.type == "file") {
            val (ref, chunks) = HandoffRules.prepare(item.file!!.name, item.file.mime, data!!)
            chunks.forEachIndexed { n, blob -> RelayClient.putChunk(p0, ref.fid, n, ref.chunks, blob) }
            HandoffItem("file", file = ref)
        } else item
        val rid = SphinxCrypto.newId(16)
        var blob: String? = null
        val p = store.updatePairing(pid) { p -> SphinxLogic.push(p, rid, it, System.currentTimeMillis()).let { (b, n) -> blob = b; n } } ?: error("That laptop isn't paired any more")
        RelayClient.outbox(p, rid, blob!!)
        Log.info("handoff sent to a laptop", it.type)
    }
}

/**
 * A notification's Copy: the text to the clipboard, at a tap, marked sensitive (no clipboard preview or keyboard
 * suggestion shows it) and cleared after a minute, as a code is (review 2026-10-27: it stayed there for good).
 */
class CopyReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        val text = i.getStringExtra(TEXT) ?: return
        SecureClipboard.copy(c, "text", text, clearMs = 60_000L)
        c.getSystemService(NotificationManager::class.java).cancel(i.getIntExtra(NOTE, 0))
    }

    companion object {
        const val TEXT = "sphinx.copy.text"
        const val NOTE = "sphinx.copy.note"
    }
}

/**
 * The share sheet's "Send to laptop": a link (sent as "open on the laptop", one tap), a text or a file up to 8 MB, to
 * the one paired laptop or the one picked. The laptop shows it and acts only at a click there.
 */
class ShareActivity : ComponentActivity() {
    private class Shared(val item: HandoffItem, val data: ByteArray?)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Like every Sphinx screen: no screenshots, no recents preview of what is being sent.
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        setContent { SphinxTheme { Screen() } }
    }

    /**
     * The app that shared it: what Android says (Android 14 and later, when the app opted in), else the referrer it gave,
     * which the app sets itself and so is marked "(unverified)" (review 2026-10-27).
     */
    private fun sharedBy(): String? {
        val sure = if (android.os.Build.VERSION.SDK_INT >= 34) launchedFromPackage else null
        val pkg = (sure ?: referrer?.takeIf { it.scheme == "android-app" }?.host)?.takeIf { it != packageName } ?: return null
        val name = runCatching { packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
        return SharedBy.label(name, verified = sure != null)
    }

    /** What was shared, or why it can't go. A link shared alone (Chrome's Share) goes as "open on the laptop". */
    private fun read(): Pair<Shared?, String?> {
        if (intent?.action != Intent.ACTION_SEND) return null to "Nothing to send."
        @Suppress("DEPRECATION") val stream = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
        if (stream != null) {
            if (!HandoffRules.shareable(stream.scheme, stream.authority, packageName)) return null to "Sphinx sends only files an app shares as content, not a file path."
            val clip = intent.clipData?.let { cd -> (0 until cd.itemCount).mapNotNull { cd.getItemAt(it).uri?.toString() } }.orEmpty()
            if (!HandoffRules.granted(intent.flags, stream.toString(), clip))
                return null to "The sharing app didn't give Sphinx access to that file. Share it from an app that does (Files, Photos)."
            val cr = contentResolver
            var name = "file"; var size = -1L
            cr.query(stream, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cur ->
                if (cur.moveToFirst()) { name = cur.getString(0) ?: name; size = if (cur.isNull(1)) -1 else cur.getLong(1) }
            }
            if (size > HandoffRules.MAX_FILE) return null to "Too big: at most ${HandoffRules.MAX_FILE / 1024 / 1024} MB."
            val data = cr.openInputStream(stream)?.use { capped(it, HandoffRules.MAX_FILE + 1) } ?: return null to "That file can't be read."
            if (data.size > HandoffRules.MAX_FILE) return null to "Too big: at most ${HandoffRules.MAX_FILE / 1024 / 1024} MB."
            if (data.isEmpty()) return null to "That file is empty."
            val mime = cr.getType(stream) ?: "application/octet-stream"
            return Shared(HandoffItem("file", file = FileRef("", "", HandoffRules.safeName(name), mime, data.size, HandoffRules.chunksFor(data.size), "")), data) to null
        }
        val text = intent.getStringExtra(Intent.EXTRA_TEXT)?.trim().orEmpty()
        if (text.isEmpty()) return null to "Nothing to send."
        HandoffRules.httpUrl(text)?.let { return Shared(HandoffItem("link", url = it, open = true), null) to null }
        if (text.toByteArray().size > HandoffRules.MAX_TEXT) return null to "Too long for a text (${HandoffRules.MAX_TEXT} bytes at most)."
        return Shared(HandoffItem("text", text = text), null) to null
    }

    /** At most [max] bytes of [s] (one more than the cap tells a file that is too big). */
    private fun capped(s: java.io.InputStream, max: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        while (out.size() < max) { val n = s.read(buf, 0, minOf(buf.size, max - out.size())); if (n < 0) break; out.write(buf, 0, n) }
        return out.toByteArray()
    }

    @Composable
    private fun Screen() {
        val c = Sx.p
        var shared by remember { mutableStateOf<Shared?>(null) }
        var note by remember { mutableStateOf<String?>(null) }
        var laptops by remember { mutableStateOf<List<Pairing>>(emptyList()) }
        var pick by remember { mutableStateOf<String?>(null) }
        var busy by remember { mutableStateOf(false) }
        val by = remember { sharedBy() }
        LaunchedEffect(Unit) {
            val (s, why) = withContext(Dispatchers.IO) { runCatching { read() }.getOrElse { null to "That can't be read." } }
            shared = s; note = why
            laptops = withContext(Dispatchers.IO) { SphinxStore.get(applicationContext).pairings().filter { !it.signer } }
            pick = laptops.singleOrNull()?.pid
            if (laptops.isEmpty() && why == null) note = "No laptop paired. Pair one in Sphinx first."
        }
        val s = shared
        AskScreen(body = {
            Eyebrow("Send to laptop")
            shared?.let { Group { Text(it.item.label(), Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp), style = Type.bodyMd.copy(fontWeight = FontWeight.Medium), color = c.text, maxLines = 3) } }
            Text(by?.let { "Shared by $it" } ?: "Shared by an app that didn't say which", style = Type.bodySm, color = c.text2, textAlign = TextAlign.Center)
            if (laptops.size > 1) {
                Column(Modifier.fillMaxWidth()) {
                SectionLabel("Which laptop")
                Group {
                    laptops.forEachIndexed { i, p ->
                        if (i > 0) Hairline()
                        Row(Modifier.fillMaxWidth().clickable(role = Role.RadioButton) { pick = p.pid }.padding(horizontal = 8.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(pick == p.pid, { pick = p.pid }, colors = RadioButtonDefaults.colors(selectedColor = c.primary, unselectedColor = c.text2))
                            Text(p.name, style = Type.bodyMd.copy(fontWeight = FontWeight.Medium), color = c.text)
                        }
                    }
                }
                }
            }
            note?.let { Text(it, Modifier, style = Type.bodySm, color = c.text2, textAlign = TextAlign.Center) }
        }, actions = {
            if (s != null && pick != null) {
                SxButton(if (s.item.type == "link") "Open on laptop" else "Send to laptop", {
                    // Behind his fingerprint, like the app itself: what leaves the phone is his call, not the sharing app's.
                    Sphinx.gate(this@ShareActivity, title = "Send to the laptop", subtitle = s.item.label().take(60), onFail = { note = it }, onOk = {
                        busy = true
                        lifecycleScope.launch {
                            val r = withContext(Dispatchers.IO) { runCatching { Handoff.send(applicationContext, pick!!, s.item, s.data) } }
                            note = r.exceptionOrNull()?.let { "Not sent: ${it.message ?: it.javaClass.simpleName}" }
                                ?: "Sent. The laptop shows it within half a minute; nothing opens until you click there."
                            busy = false
                            if (r.isSuccess) { delay(1500); finish() }
                        }
                    })
                }, Modifier.fillMaxWidth(), enabled = !busy)
            }
            SxButton("Close", { finish() }, Modifier.fillMaxWidth(), kind = Kind.SECONDARY)
        })
    }
}
