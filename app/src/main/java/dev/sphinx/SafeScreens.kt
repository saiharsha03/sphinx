package dev.sphinx

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

@Composable
private fun Note(text: String?, error: Boolean = false) {
    text?.let { Text(it, Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodySmall, color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant) }
}

/**
 * The Keys safe: recovery phrases, backup codes and small key files. Adding needs no fingerprint (the public key seals);
 * showing or saving one needs a fresh fingerprint each time. Files come in and go out only through the system's file
 * picker (no storage permission). The screen is already FLAG_SECURE (MainActivity).
 */
@Composable
fun KeysPane() {
    val ctx = LocalContext.current
    val app = ctx.applicationContext
    val c = MaterialTheme.colorScheme
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
    LaunchedEffect(bump) { entries = withContext(Dispatchers.IO) { SafeStore.get(app).entries() } }
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

    Column(Modifier.widthIn(max = 640.dp)) {
        Text("Keys safe", Modifier.padding(top = 8.dp), style = MaterialTheme.typography.titleLarge)
        Text("Recovery phrases, backup codes and small key files. Each one opens with your fingerprint, and leaves the phone only inside your encrypted backup.",
            style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
        if (entries.isEmpty()) Note("Nothing here yet.")
        for (e in entries) Column(Modifier.fillMaxWidth()) {
            HorizontalDivider(color = c.outlineVariant, modifier = Modifier.padding(top = 8.dp))
            Row(Modifier.padding(top = 8.dp)) {
                Column(Modifier.weight(1f)) {
                    Text(e.title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
                    Text((if (e.kind == "file") "File ${e.name}, " else "Text, ") + "${maxOf(1, e.size / 1024)} KB · " +
                        DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(e.added)), style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
                }
            }
            if (shown?.first == e.id) Text(shown!!.second, Modifier.padding(vertical = 8.dp), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
            var confirm by remember(e.id) { mutableStateOf(false) }
            Row {
                if (e.kind == "text") TextButton({ if (shown?.first == e.id) shown = null else withFingerprint(e, "Show") { b -> shown = e.id to String(b); b.fill(0) } }) {
                    Text(if (shown?.first == e.id) "Hide" else "Show")
                }
                TextButton({ withFingerprint(e, "Save") { b -> export = e to b; pickOut.launch(if (e.kind == "file") e.name else "${e.title}.txt") } }) { Text("Save to…") }
                TextButton({
                    if (confirm) scope.launch { withContext(Dispatchers.IO) { SafeStore.get(app).delete(e.id) }; confirm = false; bump++ } else confirm = true
                }) { Text(if (confirm) "Tap again to delete" else "Delete") }
            }
        }
        HorizontalDivider(color = c.outlineVariant, modifier = Modifier.padding(top = 8.dp))
        if (adding) {
            OutlinedTextField(title, { title = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Name") }, singleLine = true)
            OutlinedTextField(text, { text = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Text (a phrase, backup codes)") }, minLines = 3,
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password))
            Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button({
                    val data = text.toByteArray()
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { runCatching { SafeStore.get(app).add(title, "text", "", "text/plain", data) } }
                        note = r.exceptionOrNull()?.message ?: "Added."
                        if (r.isSuccess) { text = ""; title = ""; adding = false }
                        bump++
                    }
                }, enabled = text.isNotBlank()) { Text("Save text") }
                TextButton({ pickIn.launch(arrayOf("*/*")) }) { Text("Pick a file…") }
                TextButton({ adding = false; text = ""; title = "" }) { Text("Cancel") }
            }
        } else Button({ adding = true }, Modifier.padding(top = 12.dp)) { Text("Add to the safe") }
        Note(note)
    }
}

/**
 * Backup, in Settings: Google's (always on, nothing to set), the relay copy with its passcode, and the 24-word phrase
 * (off by default; shown once).
 */
@Composable
fun BackupPane() {
    val ctx = LocalContext.current
    val app = ctx.applicationContext
    val c = MaterialTheme.colorScheme
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<BackupState?>(null) }
    var counts by remember { mutableStateOf(0 to 0) }
    var bump by remember { mutableIntStateOf(0) }
    var note by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf(false) }
    var relay by remember { mutableStateOf(ctx.getString(R.string.sphinx_relay)) }
    var token by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    var words by remember { mutableStateOf<List<String>?>(null) }
    LaunchedEffect(bump) {
        val (s, n) = withContext(Dispatchers.IO) { Backups.local(app).read() to SphinxStore.get(app).accounts().size }
        state = s; counts = (s?.accounts?.size ?: 0) to n
        s?.relay?.let { relay = it.relay; token = it.token }
    }
    fun run(done: String, work: () -> Unit) {
        busy = true; note = "Working… (the passcode's key takes a few seconds)"
        scope.launch {
            val r = withContext(Dispatchers.IO) { runCatching(work) }
            note = r.exceptionOrNull()?.let { Backups.why(it) } ?: done
            busy = false; bump++
            if (r.isSuccess) { pass = ""; again = ""; editing = false }
        }
    }
    val r = state?.relay
    Column(Modifier.widthIn(max = 640.dp).padding(top = 24.dp)) {
        Kicker("Backup")
        Fact("Google", "On. Android backs up Sphinx's sealed backup with your Google account, end-to-end encrypted with this phone's screen lock. As strong as your Google account plus that screen lock.")
        Fact("In it", "${counts.first} of ${counts.second} account(s), the Keys safe, your sites. Never the laptop pairings: they pair again.")
        Fact("The relay", if (r == null) "Off" else "On, ${r.relay.removePrefix("https://")}, after every change")
        Fact("Phrase", if (r?.phraseId?.isNotEmpty() == true) "On (24 words)" else "Off")
        if (editing) {
            OutlinedTextField(relay, { relay = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Relay") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
            OutlinedTextField(token, { token = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Relay token (the first time)") }, singleLine = true)
            OutlinedTextField(pass, { pass = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Backup passcode (12+ characters)") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false))
            Text(Passcode.hint(pass), Modifier.padding(top = 4.dp), style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
            OutlinedTextField(again, { again = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("The same passcode again") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false))
            Text("A new phone restores with this passcode alone. Anyone who gets the relay's copy can try passcodes offline, so make it a long phrase you won't forget.",
                Modifier.padding(top = 4.dp), style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
            Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button({ val p = pass; run(if (r == null) "The relay backup is on." else "Passcode changed.") { Backups.setUp(app, relay.trim().trimEnd('/'), token.trim(), p) } },
                    enabled = !busy && pass == again && Passcode.problem(pass) == null && relay.startsWith("https://")) { Text(if (r == null) "Turn on" else "Change passcode") }
                TextButton({ editing = false; pass = ""; again = "" }) { Text("Cancel") }
            }
        } else Row {
            TextButton({ editing = true }, enabled = !busy) { Text(if (r == null) "Back up to the relay…" else "Change passcode…") }
            if (r != null) TextButton({ run("The relay backup is off and its copy deleted.") { Backups.turnOff(app) } }, enabled = !busy) { Text("Turn off") }
        }
        // The recovery phrase: shown once, never stored, never shown again.
        val w = words
        if (w != null) {
            Kicker("Your recovery phrase", Modifier.padding(top = 16.dp))
            Text(w.chunked(4).mapIndexed { i, row -> row.mapIndexed { j, x -> "${i * 4 + j + 1}. $x" }.joinToString("   ") }.joinToString("\n"),
                Modifier.padding(top = 8.dp), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
            Text("Write these 24 words on paper and keep it safe. They open your relay backup without the passcode, even if this phone and your Google account are gone. Sphinx won't show them again.",
                Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
            Row {
                Button({ val ws = w; words = null; run("The recovery phrase is on.") { Backups.phraseOn(app, ws) } }, enabled = !busy) { Text("I wrote them down") }
                TextButton({ words = null }) { Text("Cancel") }
            }
        } else if (r != null) Row {
            if (r.phraseId.isEmpty()) TextButton({ words = Bip39.phrase() }, enabled = !busy) { Text("Turn on a recovery phrase…") }
            else TextButton({ run("The recovery phrase is off; its copy on the relay is deleted.") { Backups.phraseOff(app) } }, enabled = !busy) { Text("Turn the phrase off") }
        }
        Note(note)
    }
}

/** Restore on a new phone (or after a new fingerprint cleared the codes): the relay, then the passcode or the 24 words. */
@Composable
fun RestorePane(onDone: (String) -> Unit) {
    val ctx = LocalContext.current
    val app = ctx.applicationContext
    val scope = rememberCoroutineScope()
    var open by remember { mutableStateOf(false) }
    var relay by remember { mutableStateOf(ctx.getString(R.string.sphinx_relay)) }
    var byPhrase by remember { mutableStateOf(false) }
    var secret by remember { mutableStateOf("") }
    var note by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    if (!open) { TextButton({ open = true }, Modifier.padding(top = 8.dp)) { Text("Restore from a backup…") }; return }
    Column(Modifier.widthIn(max = 560.dp).padding(top = 16.dp)) {
        Kicker("Restore")
        Text("Your Google backup comes back by itself when Android restores this phone. Otherwise, from your relay:", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(relay, { relay = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Relay") }, singleLine = true)
        Row {
            TextButton({ byPhrase = false; secret = "" }) { Text("Passcode", fontWeight = if (!byPhrase) FontWeight.Bold else FontWeight.Normal) }
            TextButton({ byPhrase = true; secret = "" }) { Text("Recovery phrase", fontWeight = if (byPhrase) FontWeight.Bold else FontWeight.Normal) }
        }
        OutlinedTextField(secret, { secret = it }, Modifier.fillMaxWidth(), label = { Text(if (byPhrase) "The 24 words" else "Backup passcode") },
            minLines = if (byPhrase) 3 else 1, singleLine = !byPhrase,
            visualTransformation = if (byPhrase) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false))
        Button({
            val words = if (byPhrase) Bip39.check(secret) ?: run { note = "That isn't a valid 24-word phrase (check the words and their order)."; return@Button } else null
            busy = true; note = "Restoring… (a few seconds)"
            val s = secret
            scope.launch {
                val r = withContext(Dispatchers.IO) { runCatching { Backups.restore(app, relay.trim().trimEnd('/'), passcode = s.takeIf { !byPhrase }, words = words) } }
                busy = false
                r.onSuccess { n -> secret = ""; onDone("Restored $n account(s) and the Keys safe. Pair your laptops again.") }.onFailure { note = Backups.why(it) }
            }
        }, Modifier.padding(top = 8.dp), enabled = !busy && secret.isNotBlank()) { Text("Restore") }
        Note(note)
    }
}
