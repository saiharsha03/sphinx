package dev.sphinx

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

/**
 * The Keys safe: recovery phrases, backup codes and small key files. Adding needs no fingerprint (the public key seals);
 * showing or saving one needs a fresh fingerprint each time. Files come in and go out only through the system's file
 * picker (no storage permission). The screen is already FLAG_SECURE (MainActivity). [samples]: screenshot tests only.
 */
@Composable
fun KeysPane(samples: Samples? = null) {
    val ctx = LocalContext.current
    val app = ctx.applicationContext
    val c = Sx.p
    val scope = rememberCoroutineScope()
    var entries by remember { mutableStateOf<List<SafeEntry>>(emptyList()) }
    var bump by remember { mutableIntStateOf(0) }
    var note by remember { mutableStateOf<String?>(null) }
    var adding by remember { mutableStateOf(false) }
    var title by remember { mutableStateOf("") }
    var text by remember { mutableStateOf("") }
    // One entry open on screen (id, its text), hidden after a minute; one waiting to be saved where he picks.
    var shown by remember { mutableStateOf<Pair<String, String>?>(null) }
    var export by remember { mutableStateOf<Pair<SafeEntry, ByteArray>?>(null) }
    LaunchedEffect(bump) { entries = samples?.keys ?: withContext(Dispatchers.IO) { SafeStore.get(app).entries() } }
    LaunchedEffect(shown) { if (shown != null) { delay(60_000); shown = null } }

    val pickIn = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) scope.launch {
            val r = withContext(Dispatchers.IO) {
                runCatching {
                    val cr = app.contentResolver
                    val name = cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { if (it.moveToFirst()) it.getString(0) else null } ?: "file"
                    val data = cr.openInputStream(uri)!!.use { s -> s.readBytes().also { if (it.size > SafeStore.MAX_ENTRY) { it.fill(0); error("A file is ${SafeStore.MAX_ENTRY / 1024} KB at most.") } } }
                    SafeStore.get(app).add(title.ifBlank { name }, "file", name, cr.getType(uri) ?: "application/octet-stream", data)
                }
            }
            note = r.exceptionOrNull()?.let { it.message ?: "It couldn't be added." } ?: "Added. It is sealed: opening it takes your fingerprint."
            title = ""; adding = false; bump++
        }
    }
    val pickOut = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri: Uri? ->
        val ex = export
        export = null
        if (ex != null) scope.launch {
            val r = withContext(Dispatchers.IO) { runCatching { if (uri != null) app.contentResolver.openOutputStream(uri)!!.use { it.write(ex.second) } } }
            ex.second.fill(0)
            note = if (uri == null) "Not saved." else r.exceptionOrNull()?.let { "Not saved: ${it.javaClass.simpleName}" } ?: "Saved where you picked."
        }
    }

    fun withFingerprint(e: SafeEntry, why: String, then: (ByteArray) -> Unit) {
        val (u, problem) = Sphinx.unwrapper(ctx)
        if (u == null) { note = problem; return }
        Sphinx.fingerprint(ctx, "$why ${e.title}", "From the Keys safe", u, onOk = {
            runCatching { SafeStore.get(app).open(e, u) }.onSuccess(then).onFailure { note = "It didn't open (${it.javaClass.simpleName})." }
        }, onFail = { note = it })
    }

    @Composable
    fun EntryRow(e: SafeEntry, first: Boolean) {
        var open by remember(e.id) { mutableStateOf(false) }
        var confirm by remember(e.id) { mutableStateOf(false) }
        LaunchedEffect(confirm) { if (confirm) { delay(4000); confirm = false } }
        if (!first) Hairline()
        Column(Modifier.fillMaxWidth().riseIn()) {
            ListRow(e.title, (if (e.kind == "file") "File · ${e.name} · " else "Text · ") + "${maxOf(1, e.size / 1024)} KB · " +
                DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(e.added)), onClick = { open = !open }) { Pill("sealed") }
            if (shown?.first == e.id) Text(shown!!.second, Modifier.padding(start = 16.dp, end = 16.dp, bottom = 12.dp).fillMaxWidth().clip(Corner.control)
                .background(c.surface3).border(1.dp, c.border, Corner.control).padding(12.dp), style = Type.codeSm, color = c.text)
            if (open || shown?.first == e.id) Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 12.dp, bottom = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (e.kind == "text") SxButton(if (shown?.first == e.id) "Hide" else "Show",
                    { if (shown?.first == e.id) shown = null else withFingerprint(e, "Show") { b -> shown = e.id to String(b); b.fill(0) } }, kind = Kind.SECONDARY, small = true)
                SxButton("Save to…", { withFingerprint(e, "Save") { b -> export = e to b; AppLock.goingInside(); pickOut.launch(if (e.kind == "file") e.name else "${e.title}.txt") } },
                    kind = Kind.SECONDARY, small = true)
                Spacer(Modifier.weight(1f))
                SxButton(if (confirm) "Tap again to delete" else "Delete", {
                    if (confirm) scope.launch { withContext(Dispatchers.IO) { SafeStore.get(app).delete(e.id) }; confirm = false; bump++ } else confirm = true
                }, kind = Kind.DANGER, small = true)
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
        Text("Recovery phrases, backup codes and small key files. Each one opens with your fingerprint, and leaves the phone only inside your encrypted backup.",
            Modifier.padding(horizontal = 4.dp), style = Type.bodySm, color = c.text2)
        if (entries.isEmpty()) Group { ListRow("Nothing here yet.") }
        val texts = entries.filter { it.kind != "file" }
        val files = entries.filter { it.kind == "file" }
        if (texts.isNotEmpty()) Column {
            SectionLabel("Recovery")
            Group { texts.forEachIndexed { i, e -> EntryRow(e, i == 0) } }
        }
        if (files.isNotEmpty()) Column {
            SectionLabel("Files")
            Group { files.forEachIndexed { i, e -> EntryRow(e, i == 0) } }
        }
        if (adding) Group {
            Column(Modifier.padding(16.dp)) {
                OutlinedTextField(title, { title = it }, Modifier.fillMaxWidth(), label = { Text("Name") }, singleLine = true, colors = fieldColors())
                OutlinedTextField(text, { text = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Text (a phrase, backup codes)") }, minLines = 3,
                    keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password), colors = fieldColors())
                Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SxButton("Save text", {
                        val data = text.toByteArray()
                        scope.launch {
                            val r = withContext(Dispatchers.IO) { runCatching { SafeStore.get(app).add(title, "text", "", "text/plain", data) } }
                            note = r.exceptionOrNull()?.message ?: "Added."
                            if (r.isSuccess) { text = ""; title = ""; adding = false }
                            bump++
                        }
                    }, enabled = text.isNotBlank(), small = true)
                    SxButton("Cancel", { adding = false; text = ""; title = "" }, kind = Kind.SECONDARY, small = true)
                }
            }
        } else Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            SxButton("Add text", { adding = true }, Modifier.weight(1f), kind = Kind.SECONDARY)
            // A file takes its own name.
            SxButton("Pick a file", { AppLock.goingInside(); pickIn.launch(arrayOf("*/*")) }, Modifier.weight(1f), kind = Kind.SECONDARY)
        }
        Note(note)
    }
}

/**
 * Backup's state, shared by its section and the danger zone (Turn off, Turn the phrase off): Google's (always on,
 * nothing to set), the relay copy with its passcode, and the 24-word phrase (off by default; shown once).
 */
@Stable
class BackupModel(private val app: Context, private val scope: CoroutineScope, relayDefault: String, private val builtInToken: String = "") {
    var state by mutableStateOf<BackupState?>(null)
    var counts by mutableStateOf(0 to 0)
    var bump by mutableIntStateOf(0)
    var note by mutableStateOf<String?>(null)
    var busy by mutableStateOf(false)
    var editing by mutableStateOf(false)
    var relay by mutableStateOf(relayDefault)
    var token by mutableStateOf("")
    var pass by mutableStateOf("")
    var again by mutableStateOf("")
    /** The passcode in use now: changing it, or the relay, needs it (Backups.setUp). */
    var current by mutableStateOf("")
    var words by mutableStateOf<List<String>?>(null)

    fun loaded(s: BackupState?, n: Int) {
        state = s; counts = (s?.accounts?.size ?: 0) to n
        // The built-in token is never shown or carried in the field (an older state may still hold it).
        s?.relay?.let { relay = it.relay; token = it.token.takeIf { t -> t != builtInToken }.orEmpty() }
    }

    fun run(done: String, work: () -> Unit) {
        busy = true; note = "Working… (the passcode's key takes a few seconds)"
        scope.launch {
            val r = withContext(Dispatchers.IO) { runCatching(work) }
            note = r.exceptionOrNull()?.let { Backups.why(it) } ?: done
            busy = false; bump++
            if (r.isSuccess) { pass = ""; again = ""; current = ""; editing = false }
        }
    }

    fun turnOff() = run("The relay backup is off and its copy deleted.") { Backups.turnOff(app) }
    fun phraseOff() = run("The recovery phrase is off; its copy on the relay is deleted.") { Backups.phraseOff(app) }
}

@Composable
fun rememberBackupModel(samples: Samples?): BackupModel {
    val ctx = LocalContext.current
    val app = ctx.applicationContext
    val scope = rememberCoroutineScope()
    val m = remember { BackupModel(app, scope, ctx.getString(R.string.sphinx_relay), ctx.getString(R.string.sphinx_relay_token)) }
    LaunchedEffect(m.bump) {
        if (samples != null) m.loaded(samples.backup, samples.accounts)
        else { val (s, n) = withContext(Dispatchers.IO) { Backups.local(app).read() to SphinxStore.get(app).accounts().size }; m.loaded(s, n) }
    }
    return m
}

/** A passcode field's mask: dots, or the text itself while he has tapped Show (the screens are FLAG_SECURE). */
fun masked(see: Boolean) = if (see) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation()

/** Show / Hide at the end of a passcode field. */
@Composable
fun SeeToggle(see: Boolean, onToggle: () -> Unit) {
    Text(if (see) "Hide" else "Show", Modifier.clip(Corner.control).clickable(role = Role.Button, onClick = onToggle).padding(horizontal = 12.dp, vertical = 8.dp),
        style = Type.bodySm.copy(fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold), color = Sx.p.primary)
}

/** Settings, Backup: the three paths and their actions (turning things off lives in the danger zone). */
@Composable
fun BackupPane(m: BackupModel) {
    val ctx = LocalContext.current
    val app = ctx.applicationContext
    val c = Sx.p
    val r = m.state?.relay
    var see by remember { mutableStateOf(false) }
    Group {
        ListRow("Google backup", "Android backs up Sphinx's sealed backup with your Google account, end-to-end encrypted with this phone's screen lock. As strong as your Google account plus that screen lock.") {
            Value("On", ok = true)
        }
        ListRow("Relay backup", if (r == null) "Opens with your passcode" else "${r.relay.removePrefix("https://")}, after every change. Opens with your passcode", rule = true) {
            Value(if (r == null) "Off" else "On", ok = r != null)
        }
        ListRow("Recovery phrase", "24 words, shown once", rule = true) { Value(if (r?.phraseId?.isNotEmpty() == true) "On" else "Off", ok = r?.phraseId?.isNotEmpty() == true) }
        ListRow("In it", "${m.counts.first} of ${m.counts.second} account(s), the Keys safe, your sites. Never the laptop pairings: they pair again.", rule = true)
        // The phrase needs the relay backup, so with the relay backup off both are off.
        if (r == null) { Hairline(); GroupText("Without the relay backup or the recovery phrase, adding a new fingerprint to this phone clears your codes for good.", color = c.danger) }
        Hairline()
        if (m.editing) Column(Modifier.padding(16.dp)) {
            if (r != null) OutlinedTextField(m.current, { m.current = it }, Modifier.fillMaxWidth().padding(bottom = 8.dp), label = { Text("Current backup passcode") }, singleLine = true,
                visualTransformation = masked(see), trailingIcon = { SeeToggle(see) { see = !see } }, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false), colors = fieldColors())
            // Another relay origin: the token typed for the old one doesn't go along.
            OutlinedTextField(m.relay, { if (!RelayClient.sameOrigin(it, m.relay)) m.token = ""; m.relay = it }, Modifier.fillMaxWidth(), label = { Text("Relay") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), colors = fieldColors())
            OutlinedTextField(m.token, { m.token = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Relay token (the first time)") }, singleLine = true, colors = fieldColors())
            OutlinedTextField(m.pass, { m.pass = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Backup passcode (12+ characters)") }, singleLine = true,
                visualTransformation = masked(see), trailingIcon = { SeeToggle(see) { see = !see } }, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false), colors = fieldColors())
            Text(Passcode.hint(m.pass), Modifier.padding(top = 4.dp), style = Type.bodySm, color = c.text2)
            OutlinedTextField(m.again, { m.again = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("The same passcode again") }, singleLine = true,
                visualTransformation = masked(see), trailingIcon = { SeeToggle(see) { see = !see } }, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false), colors = fieldColors())
            Text("A new phone restores with this passcode alone. Anyone who gets the relay's copy can try passcodes offline, so make it a long phrase you won't forget.",
                Modifier.padding(top = 6.dp), style = Type.bodySm, color = c.text2)
            Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SxButton(if (r == null) "Turn on" else "Change passcode", {
                    val p = m.pass; val relay = m.relay.trim().trimEnd('/'); val token = m.token; val now = m.current.takeIf { r != null }
                    val moved = r != null && relay != r.relay
                    // Every secret goes to that relay: a fresh fingerprint on the codes key first.
                    Sphinx.confirm(ctx, if (r == null) "Turn on the relay backup" else "Change the relay backup", "It sends every code's secret, sealed, to $relay", onOk = {
                        m.run(if (r == null) "The relay backup is on." else if (moved) "Your backup now goes to ${relay.removePrefix("https://")}." else "Passcode changed.") {
                            Backups.setUp(app, relay, token.trim(), p, now)
                        }
                    }, onFail = { m.note = it })
                }, enabled = !m.busy && m.pass == m.again && Passcode.problem(m.pass) == null && m.relay.startsWith("https://") && (r == null || m.current.isNotBlank()), small = true)
                SxButton("Cancel", { m.editing = false; m.pass = ""; m.again = ""; m.current = "" }, kind = Kind.SECONDARY, small = true)
            }
        } else ListRow(if (r == null) "Back up to the relay…" else "Change passcode…", titleColor = c.primary, onClick = if (m.busy) null else ({ m.editing = true })) { Chevron() }
        // The recovery phrase: shown once, never stored, never shown again.
        val w = m.words
        if (w != null) {
            Hairline()
            Column(Modifier.padding(16.dp)) {
                Kicker("Your recovery phrase")
                Text(w.chunked(4).mapIndexed { i, row -> row.mapIndexed { j, x -> "${i * 4 + j + 1}. $x" }.joinToString("   ") }.joinToString("\n"),
                    Modifier.padding(top = 8.dp).fillMaxWidth().clip(Corner.control).background(c.surface3).border(1.dp, c.border, Corner.control).padding(12.dp),
                    style = Type.codeSm, color = c.text)
                Text("Write these 24 words on paper and keep it safe. They open your relay backup without the passcode, even if this phone and your Google account are gone. Sphinx won't show them again.",
                    Modifier.padding(top = 8.dp), style = Type.bodySm, color = c.text2)
                Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SxButton("I wrote them down", {
                        val ws = w
                        Sphinx.confirm(ctx, "Turn on the recovery phrase", "These words will open your relay backup", onOk = {
                            m.words = null; m.run("The recovery phrase is on.") { Backups.phraseOn(app, ws) }
                        }, onFail = { m.note = it })
                    }, enabled = !m.busy, small = true)
                    SxButton("Cancel", { m.words = null }, kind = Kind.SECONDARY, small = true)
                }
            }
        } else if (r != null && r.phraseId.isEmpty())
            ListRow("Turn on a recovery phrase…", titleColor = c.primary, rule = true, onClick = if (m.busy) null else ({ m.words = Bip39.phrase() })) { Chevron() }
    }
    Note(m.note)
}

/** The destructive actions Settings already had, together and in red: the relay backup, the phrase, the signing unlock. */
@Composable
fun DangerZone(backup: BackupModel, signing: SigningModel) {
    val r = backup.state?.relay
    val phrase = r?.phraseId?.isNotEmpty() == true
    val unlock = signing.current != null
    if (r == null && !unlock) return
    var confirm by remember { mutableStateOf(false) }
    LaunchedEffect(confirm) { if (confirm) { delay(4000); confirm = false } }
    val c = Sx.p
    Column {
        SectionLabel("Danger zone", danger = true)
        Group(border = c.danger.copy(alpha = 0.45f)) {
            var first = true
            if (r != null) {
                ListRow("Turn off the relay backup", "Deletes its copy on the relay.", titleColor = c.dangerText, onClick = if (backup.busy) null else backup::turnOff)
                first = false
            }
            if (phrase) {
                ListRow("Turn the phrase off", "Deletes its copy on the relay.", titleColor = c.dangerText, rule = true, onClick = if (backup.busy) null else backup::phraseOff)
            }
            if (unlock) ListRow(if (confirm) "Tap again to remove" else "Remove the signing unlock", "Signing then needs the passkey.", titleColor = c.dangerText, rule = !first,
                onClick = { if (confirm) { signing.remove(); confirm = false } else confirm = true })
        }
    }
}

/** Restore on a new phone (or after a new fingerprint cleared the codes): the relay, then the passcode or the 24 words. */
@Composable
fun RestorePane(onDone: (String) -> Unit) {
    val ctx = LocalContext.current
    val app = ctx.applicationContext
    val c = Sx.p
    val scope = rememberCoroutineScope()
    var open by remember { mutableStateOf(false) }
    var relay by remember { mutableStateOf(ctx.getString(R.string.sphinx_relay)) }
    var byPhrase by remember { mutableStateOf(false) }
    var secret by remember { mutableStateOf("") }
    var token by remember { mutableStateOf("") }
    var note by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var see by remember { mutableStateOf(false) }
    if (!open) { SxButton("Restore from a backup…", { open = true }, Modifier.fillMaxWidth(), kind = Kind.SECONDARY); return }
    Column {
        SectionLabel("Restore", Modifier.padding(top = 8.dp))
        Group {
            Column(Modifier.padding(16.dp)) {
                Text("Your Google backup comes back by itself when Android restores this phone. Otherwise, from your relay:", style = Type.bodySm, color = c.text2)
                OutlinedTextField(relay, { if (!RelayClient.sameOrigin(it, relay)) token = ""; relay = it }, Modifier.fillMaxWidth().padding(top = 12.dp), label = { Text("Relay") }, singleLine = true, colors = fieldColors())
                // Sphinx's own relay takes the token built in; another relay that asks for one needs it typed.
                if (!RelayClient.sameOrigin(relay, ctx.getString(R.string.sphinx_relay)))
                    OutlinedTextField(token, { token = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Relay token (if it asks for one)") }, singleLine = true, colors = fieldColors())
                // A segmented control: passcode or the 24 words.
                Row(Modifier.padding(top = 12.dp).fillMaxWidth().clip(Corner.control).background(c.surface1).border(1.dp, c.border, Corner.control).padding(4.dp)) {
                    for ((label, phrase) in listOf("Passcode" to false, "Recovery phrase" to true)) {
                        val on = byPhrase == phrase
                        androidx.compose.foundation.layout.Box(Modifier.weight(1f).clip(Corner.control)
                            .then(if (on) Modifier.background(c.surface3).border(1.dp, c.rim, Corner.control) else Modifier)
                            .clickable(role = Role.Tab) { byPhrase = phrase; secret = "" }.padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
                            Text(label, style = Type.bodySm.copy(fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold), color = if (on) c.text else c.text2)
                        }
                    }
                }
                OutlinedTextField(secret, { secret = it }, Modifier.fillMaxWidth().padding(top = 12.dp), label = { Text(if (byPhrase) "The 24 words" else "Backup passcode") },
                    minLines = if (byPhrase) 3 else 1, singleLine = !byPhrase,
                    visualTransformation = masked(byPhrase || see), trailingIcon = if (byPhrase) null else ({ SeeToggle(see) { see = !see } }),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false), colors = fieldColors())
                SxButton("Restore", restore@{
                    val words = if (byPhrase) Bip39.check(secret) ?: run { note = "That isn't a valid 24-word phrase (check the words and their order)."; return@restore } else null
                    val s = secret
                    // A restore joins what this phone holds to the backup it brings: his fingerprint on the codes key first.
                    Sphinx.confirm(ctx, "Restore from the relay", "What this phone holds joins that backup", onFail = { note = it }, onOk = {
                    busy = true; note = "Restoring… (a few seconds)"
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { runCatching { Backups.restore(app, relay.trim().trimEnd('/'), passcode = s.takeIf { !byPhrase }, words = words, typed = token.trim()) } }
                        busy = false
                        r.onSuccess { n -> secret = ""; onDone("Restored $n account(s) and the Keys safe. Pair your laptops again.") }.onFailure { note = Backups.why(it) }
                    }
                    })
                }, Modifier.padding(top = 12.dp).fillMaxWidth(), enabled = !busy && secret.isNotBlank())
                Note(note)
            }
        }
    }
}
