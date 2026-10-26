package dev.sphinx

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

/** The app: behind a fingerprint, screenshots blocked, locked again on screen-off or a minute away. */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        Sphinx.channels(this)
        Thread { if (SphinxStore.get(applicationContext).pairings().isNotEmpty()) Push.schedule(applicationContext) }.start()
        setContent { SphinxTheme { SphinxScreen() } }
    }
}

enum class Tab(val word: String) { ACCOUNTS("Accounts"), KEYS("Keys"), LAPTOPS("Laptops"), SETTINGS("Settings") }

/** An import in progress: what the QR held, which are ticked, what was refused and why. */
data class Picking(val found: List<Imported>, val ticked: Set<Int>, val refused: List<Refused>, val batch: Pair<Int, Int>?)

/** Everything the screen shows; [shown] is the one code on screen (account id, code, seconds left). */
data class Home(
    val tab: Tab = Tab.ACCOUNTS,
    val accounts: List<CodeAccount> = emptyList(),
    val pairings: List<Pairing> = emptyList(),
    val picking: Picking? = null,
    val shown: Triple<String, String, Int>? = null,
    val editing: String? = null,
    val fullScreen: Boolean = true,
    /** "Display over other apps": a request opens full screen while the phone is in use, not only as a banner. */
    val overApps: Boolean = true,
    val watcher: Boolean = false,
    /** Sites with no account here that send their code by text or email (SphinxStore.textSites). */
    val textSites: List<String> = emptyList(),
    val note: String? = null,
)

/** When the app locks again. Pure, so the rule is tested. */
object AppLock {
    /** Protects the codes and the account names: this long away and Sphinx asks for the fingerprint again. */
    const val AWAY_MS = 60_000L

    /** On stop: the screen went off with Sphinx shown. */
    fun onStop(interactive: Boolean): Boolean = !interactive

    /** On start: it was away longer than [AWAY_MS]. */
    fun onStart(stoppedAt: Long, now: Long): Boolean = stoppedAt > 0 && now - stoppedAt > AWAY_MS
}

@Composable
fun SphinxScreen() {
    val ctx = LocalContext.current
    val app = ctx.applicationContext
    val scope = rememberCoroutineScope()
    var view by remember { mutableStateOf(Home()) }
    var bump by remember { mutableIntStateOf(0) }
    var unlocked by remember { mutableStateOf(false) }
    var failure by remember { mutableStateOf<String?>(null) }
    var stoppedAt by remember { mutableLongStateOf(0L) }
    fun unlock() { failure = null; Sphinx.gate(ctx, onOk = { unlocked = true }, onFail = { failure = it }) }
    fun lock() { unlocked = false; view = view.copy(shown = null) }
    LaunchedEffect(Unit) {
        // The backup first (a first run makes it; a Google restore is opened here), then the lock.
        withContext(Dispatchers.IO) { runCatching { Backups.start(app) }.getOrNull() }?.let { view = view.copy(note = it) }
        bump++
        unlock()
    }
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) {
        stoppedAt = System.currentTimeMillis()
        if (AppLock.onStop(ctx.getSystemService(PowerManager::class.java)?.isInteractive != false)) lock()
    }
    LifecycleEventEffect(Lifecycle.Event.ON_START) {
        if (AppLock.onStart(stoppedAt, System.currentTimeMillis())) { lock(); unlock() }
        // The app in front: one look at each inbox (the only fetch besides the FCM wake and the heartbeat).
        Thread { runCatching { Sphinx.wake(app) } }.start()
        bump++
    }
    // An import left half done (back, a lock, the screen going) wipes the secrets it held.
    DisposableEffect(Unit) { onDispose { view.picking?.found?.forEach { it.secret.fill(0) } } }
    LaunchedEffect(unlocked, bump) {
        if (!unlocked) return@LaunchedEffect
        val s = SphinxStore.get(app)
        val (a, p) = withContext(Dispatchers.IO) { s.accounts() to s.pairings() }
        val t = withContext(Dispatchers.IO) { s.textSites() }
        val watcher = Settings.Secure.getString(app.contentResolver, "enabled_notification_listeners")?.contains(app.packageName) == true
        view = view.copy(accounts = a, pairings = p, textSites = t, fullScreen = Sphinx.canFullScreen(app), overApps = Settings.canDrawOverlays(app), watcher = watcher)
    }
    // A shown code counts down and hides itself when its period ends.
    LaunchedEffect(view.shown?.first) {
        while (view.shown != null) {
            delay(1000)
            val s = view.shown ?: break
            view = view.copy(shown = if (s.third <= 1) null else s.copy(third = s.third - 1))
        }
    }

    fun scan(onText: (String) -> Unit) {
        val opts = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(ctx, opts).startScan()
            .addOnSuccessListener { code -> code.rawValue?.let(onText) }
            .addOnFailureListener { e -> view = view.copy(note = "The scanner didn't start: ${e.message}") }
    }
    fun settings(action: String) { runCatching { ctx.startActivity(Intent(action, Uri.parse("package:${ctx.packageName}"))) } }

    val calls = Calls(
        tab = { view = view.copy(tab = it, note = null) },
        scanAccounts = {
            scan { raw ->
                val r = Totp.parse(raw)
                view = if (r == null) view.copy(note = "That QR isn't an Authenticator export or an otpauth code.")
                else view.copy(picking = Picking(r.accounts, r.accounts.indices.toSet(), r.refused, r.batch), note = null)
            }
        },
        tick = { i -> view.picking?.let { p -> view = view.copy(picking = p.copy(ticked = if (i in p.ticked) p.ticked - i else p.ticked + i)) } },
        saveTicked = {
            val p = view.picking
            if (p != null) scope.launch {
                val chosen = p.found.filterIndexed { i, _ -> i in p.ticked }
                p.found.filterIndexed { i, _ -> i !in p.ticked }.forEach { it.secret.fill(0) }
                val made = withContext(Dispatchers.IO) { runCatching { SphinxStore.get(app).add(chosen) }.onFailure { Log.warn("import failed", it.javaClass.simpleName) }.getOrNull() }
                if (made != null) Log.info("imported ${made.size} account(s)")
                view = view.copy(picking = null, note = if (made == null) "They couldn't be saved." else p.batch?.takeIf { it.first < it.second }?.let { "Saved. That was QR ${it.first} of ${it.second}: scan the next one." })
                bump++
            }
        },
        cancelPick = { view.picking?.found?.forEach { it.secret.fill(0) }; view = view.copy(picking = null) },
        show = { a ->
            val (u, why) = Sphinx.unwrapper(ctx)
            if (u == null) view = view.copy(note = why)
            else Sphinx.fingerprint(ctx, "Show the ${a.title()} code", "It hides when it changes", u, onOk = {
                val now = System.currentTimeMillis()
                runCatching { SphinxStore.get(app).code(a, u, now) }.onSuccess { code ->
                    view = view.copy(shown = Triple(a.id, code, Totp.left(now, a.period)))
                    Log.info("code shown on the phone", a.issuer.take(40))
                }.onFailure { view = view.copy(note = "It didn't open (${it.javaClass.simpleName}).") }
            }, onFail = { view = view.copy(note = it) })
        },
        edit = { view = view.copy(editing = it) },
        saveDomains = { a, text ->
            val parts = text.split(',', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }
            val bad = parts.filter { Domains.savable(it) == null }
            if (bad.isNotEmpty()) "Not a site Sphinx can trust (a public suffix or not a host): ${bad.joinToString(", ")}"
            else {
                val ds = parts.mapNotNull { Domains.savable(it) }.distinct()
                scope.launch { withContext(Dispatchers.IO) { SphinxStore.get(app).update(a.copy(domains = ds, apps = (a.apps + Domains.appsFor(ds)).distinct())) }; view = view.copy(editing = null); bump++ }
                null
            }
        },
        saveTextSites = { text ->
            val parts = text.split(',', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }
            val bad = parts.filter { Domains.savable(it) == null }
            if (bad.isNotEmpty()) "Not a site Sphinx can trust (a public suffix or not a host): ${bad.joinToString(", ")}"
            else {
                scope.launch { withContext(Dispatchers.IO) { SphinxStore.get(app).saveTextSites(parts) }; Log.info("texted-code sites saved", "${parts.size}"); view = view.copy(editing = null); bump++ }
                null
            }
        },
        delete = { a -> scope.launch { withContext(Dispatchers.IO) { SphinxStore.get(app).delete(a.id) }; Log.info("deleted an account"); bump++ } },
        pair = {
            scan { raw ->
                scope.launch {
                    val r = withContext(Dispatchers.IO) { runCatching { Sphinx.pair(app, raw) } }
                    view = view.copy(note = r.exceptionOrNull()?.let { "Pairing failed: ${it.message}" }
                        ?: if (r.getOrNull()?.push == false) "Paired, but its relay can't wake this phone yet: requests arrive only when you open Sphinx."
                        else "Paired. The laptop shows it in a few seconds.")
                    bump++
                }
            }
        },
        unpair = { p -> scope.launch { withContext(Dispatchers.IO) { Sphinx.unpair(app, p.pid) }; bump++ } },
        openFullScreen = { settings(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT) },
        openOverApps = { settings(Settings.ACTION_MANAGE_OVERLAY_PERMISSION) },
        openWatcher = { runCatching { ctx.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)) } },
        restored = { view = view.copy(note = it); bump++ },
    )

    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).safeDrawingPadding()) {
        Column(Modifier.padding(start = 20.dp, end = 20.dp, top = 16.dp, bottom = 8.dp)) {
            Kicker("Sphinx")
            Text("2FA codes", style = MaterialTheme.typography.headlineMedium)
            Text("Each code needs your fingerprint", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (!unlocked) Locked(failure, ::unlock) else Content(view, calls)
    }
}

class Calls(
    val tab: (Tab) -> Unit = {},
    val scanAccounts: () -> Unit = {},
    val tick: (Int) -> Unit = {},
    val saveTicked: () -> Unit = {},
    val cancelPick: () -> Unit = {},
    val show: (CodeAccount) -> Unit = {},
    val edit: (String?) -> Unit = {},
    val saveDomains: (CodeAccount, String) -> String? = { _, _ -> null },
    val saveTextSites: (String) -> String? = { null },
    val delete: (CodeAccount) -> Unit = {},
    val pair: () -> Unit = {},
    val unpair: (Pairing) -> Unit = {},
    val openFullScreen: () -> Unit = {},
    val openOverApps: () -> Unit = {},
    val openWatcher: () -> Unit = {},
    val restored: (String) -> Unit = {},
)

@Composable
private fun Locked(failure: String?, onUnlock: () -> Unit) {
    Column(Modifier.padding(horizontal = 20.dp, vertical = 32.dp).widthIn(max = 560.dp)) {
        Kicker("Locked")
        Text("Your 2FA accounts are behind your fingerprint.", Modifier.padding(top = 8.dp), style = MaterialTheme.typography.titleLarge)
        failure?.let { Text(it, Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        Button(onUnlock, Modifier.padding(top = 24.dp)) { Text("Unlock") }
    }
}

@Composable
private fun Content(v: Home, calls: Calls) {
    val c = MaterialTheme.colorScheme
    LazyColumn(contentPadding = PaddingValues(start = 20.dp, end = 20.dp, bottom = 48.dp)) {
        item {
            Row(Modifier.padding(bottom = 8.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                for (t in Tab.entries) TextButton({ calls.tab(t) }) {
                    Text(t.word, fontWeight = if (t == v.tab) FontWeight.Bold else FontWeight.Normal, color = if (t == v.tab) c.primary else c.onSurfaceVariant)
                }
            }
            v.note?.let { Text(it, Modifier.padding(bottom = 12.dp).widthIn(max = 560.dp), style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant) }
        }
        when {
            v.picking != null -> item { PickList(v.picking, calls) }
            v.tab == Tab.ACCOUNTS -> {
                if (v.accounts.isEmpty()) item {
                    Text("No accounts yet.", Modifier.padding(top = 16.dp), style = MaterialTheme.typography.titleLarge)
                    Text(
                        "In Google Authenticator: menu, Transfer accounts, Export. Tick only the few you want here, then scan the QR it shows. A plain otpauth QR from a site works too.",
                        Modifier.padding(top = 8.dp).widthIn(max = 560.dp), style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant,
                    )
                }
                items(v.accounts.size) { i -> AccountRow(v.accounts[i], v, calls) }
                item { Button(calls.scanAccounts, Modifier.padding(top = 16.dp)) { Text("Import from Authenticator") } }
                if (v.accounts.isEmpty()) item { RestorePane { msg -> calls.restored(msg) } }
            }
            v.tab == Tab.LAPTOPS -> {
                if (v.pairings.isEmpty()) item {
                    Text("No laptop paired.", Modifier.padding(top = 16.dp), style = MaterialTheme.typography.titleLarge)
                    Text("Install the Sphinx extension in Chrome, set your relay on its options page, show its pairing code and scan it here.",
                        Modifier.padding(top = 8.dp).widthIn(max = 560.dp), style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
                }
                items(v.pairings.size) { i -> PairingRow(v.pairings[i], calls) }
                item { Button(calls.pair, Modifier.padding(top = 16.dp)) { Text("Pair a laptop") } }
            }
            v.tab == Tab.KEYS -> item { KeysPane() }
            else -> item { Column { SettingsPane(v, calls); BackupPane() } }
        }
    }
}

@Composable
private fun AccountRow(a: CodeAccount, v: Home, calls: Calls) {
    val c = MaterialTheme.colorScheme
    var confirm by remember { mutableStateOf(false) }
    var draft by remember(v.editing) { mutableStateOf(a.domains.joinToString(", ")) }
    var problem by remember(v.editing) { mutableStateOf<String?>(null) }
    LaunchedEffect(confirm) { if (confirm) { delay(4000); confirm = false } }
    Column(Modifier.fillMaxWidth()) {
        HorizontalDivider(color = c.outlineVariant)
        Row(Modifier.padding(top = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(a.issuer.ifBlank { "Account" }, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
                if (a.name.isNotBlank()) Text(a.name, style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant, maxLines = 1)
            }
            val shown = v.shown?.takeIf { it.first == a.id }
            if (shown != null) Column(horizontalAlignment = Alignment.End) {
                Text(shown.second.chunked(if (a.digits == 8) 4 else 3).joinToString(" "), style = MaterialTheme.typography.titleLarge, color = c.primary)
                Text("${shown.third} s", style = MaterialTheme.typography.labelSmall, color = c.onSurfaceVariant)
            } else Text(if (a.domains.isEmpty()) "No website yet" else "${a.digits} digits", style = MaterialTheme.typography.labelMedium,
                color = if (a.domains.isEmpty()) c.primary else c.onSurfaceVariant)
        }
        Text("Fills on: " + a.domains.joinToString(", ").ifEmpty { "nowhere yet. Add its site under Sites." }, Modifier.padding(top = 4.dp),
            style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
        if (a.algo != Algo.SHA1 || a.period != Totp.PERIOD) Text("Code: ${a.algo.wire}, every ${a.period} s", style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
        if (v.editing == a.id) {
            OutlinedTextField(draft, { draft = it; problem = null }, Modifier.fillMaxWidth().padding(top = 8.dp), placeholder = { Text("github.com, *.example.com") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
            Text("Each site is one exact host. Start it with *. to let its subdomains fill too.", Modifier.padding(top = 4.dp), style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
            problem?.let { Text(it, Modifier.padding(top = 4.dp), style = MaterialTheme.typography.bodySmall, color = c.error) }
            Row {
                TextButton({ problem = calls.saveDomains(a, draft) }) { Text("Save") }
                TextButton({ calls.edit(null) }) { Text("Cancel") }
            }
        } else Row {
            TextButton({ calls.show(a) }) { Text("Show") }
            TextButton({ calls.edit(a.id) }) { Text("Sites") }
            TextButton({ if (confirm) { calls.delete(a); confirm = false } else confirm = true }) { Text(if (confirm) "Tap again to delete" else "Delete") }
        }
    }
}

@Composable
private fun PickList(p: Picking, calls: Calls) {
    val c = MaterialTheme.colorScheme
    Column(Modifier.widthIn(max = 640.dp)) {
        Text(if (p.found.isEmpty()) "Nothing to import" else "Tick the ones Sphinx should keep", Modifier.padding(top = 8.dp), style = MaterialTheme.typography.titleLarge)
        p.batch?.let { Text("QR ${it.first} of ${it.second} from Authenticator.", style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant) }
        Spacer(Modifier.height(8.dp))
        p.found.forEachIndexed { i, im ->
            HorizontalDivider(color = c.outlineVariant)
            Row(Modifier.fillMaxWidth().clickable(role = Role.Checkbox) { calls.tick(i) }.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(i in p.ticked, { calls.tick(i) })
                Column(Modifier.weight(1f)) {
                    Text(im.issuer.ifBlank { "Account" }, style = MaterialTheme.typography.bodyLarge)
                    Text(listOfNotNull(im.name.ifBlank { null }, Domains.forIssuer(im.issuer).firstOrNull() ?: "no site yet").joinToString(" · "),
                        style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant, maxLines = 1)
                }
            }
        }
        if (p.refused.isNotEmpty()) {
            Kicker("Left out", Modifier.padding(top = 16.dp, bottom = 4.dp))
            for (r in p.refused) Fact(r.label, r.why)
        }
        Text("Only the ticked ones are saved, sealed on this phone. They never leave it.", Modifier.padding(top = 16.dp), style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
        Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            if (p.ticked.isNotEmpty()) Button(calls.saveTicked) { Text("Save ${p.ticked.size}") }
            TextButton(calls.cancelPick) { Text("Cancel") }
        }
    }
}

@Composable
private fun PairingRow(p: Pairing, calls: Calls) {
    var confirm by remember { mutableStateOf(false) }
    LaunchedEffect(confirm) { if (confirm) { delay(4000); confirm = false } }
    Column(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Row(Modifier.padding(vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(p.name, Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
            Text(SphinxCrypto.tag(p), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Fact("Relay", p.relay.removePrefix("https://"))
        Fact("Wake", if (p.push) "Firebase: requests arrive at once" else "Its relay can't wake this phone (no FCM account there yet)")
        Fact("Paired", DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(p.added)))
        Fact("Last", if (p.lastUsed > 0) DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(p.lastUsed)) else "Not used yet")
        TextButton({ if (confirm) { calls.unpair(p); confirm = false } else confirm = true }) { Text(if (confirm) "Tap again to unpair" else "Unpair") }
    }
}

@Composable
private fun Setting(title: String, line: String, on: Boolean, open: () -> Unit) {
    val c = MaterialTheme.colorScheme
    Column(Modifier.fillMaxWidth()) {
        HorizontalDivider(color = c.outlineVariant)
        Row(Modifier.padding(vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                Text(line, style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
            }
            Text(if (on) "On" else "Off", style = MaterialTheme.typography.labelMedium, color = if (on) c.onSurfaceVariant else c.primary)
        }
        if (!on) TextButton(open) { Text("Open the setting") }
    }
}

/**
 * Codes by text or email: sites with no account here whose code comes by SMS or email. The laptop asks on them like on
 * a saved site; the phone then offers the texted code, sent with the fingerprint, typed in and never submitted.
 */
@Composable
private fun TextSitesRow(v: Home, calls: Calls) {
    val c = MaterialTheme.colorScheme
    var draft by remember(v.editing) { mutableStateOf(v.textSites.joinToString(", ")) }
    var problem by remember(v.editing) { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxWidth()) {
        HorizontalDivider(color = c.outlineVariant)
        Text("Codes by text or email", Modifier.padding(top = 12.dp), style = MaterialTheme.typography.bodyLarge)
        Text("Sites with no account here that text or email their code. While the laptop asks there, Sphinx offers the code from the text (needs notification access); your fingerprint sends it, and it is typed in, never submitted.",
            style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
        Text("Sites: " + v.textSites.joinToString(", ").ifEmpty { "none" }, Modifier.padding(top = 4.dp), style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
        if (v.editing == TEXT_SITES_EDIT) {
            OutlinedTextField(draft, { draft = it; problem = null }, Modifier.fillMaxWidth().padding(top = 8.dp), placeholder = { Text("shop.example.com, *.bank.example") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
            problem?.let { Text(it, Modifier.padding(top = 4.dp), style = MaterialTheme.typography.bodySmall, color = c.error) }
            Row {
                TextButton({ problem = calls.saveTextSites(draft) }) { Text("Save") }
                TextButton({ calls.edit(null) }) { Text("Cancel") }
            }
        } else TextButton({ calls.edit(TEXT_SITES_EDIT) }) { Text("Edit sites") }
        Text("On the laptop, press Refresh sites and Allow on the extension's options page afterwards.", style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
    }
}

private const val TEXT_SITES_EDIT = "sphinx.textsites"

@Composable
private fun SettingsPane(v: Home, calls: Calls) {
    Column(Modifier.widthIn(max = 640.dp)) {
        Setting("Ask over the lock screen", "A laptop request wakes the screen and asks there. Needs full-screen notifications for Sphinx.", v.fullScreen, calls.openFullScreen)
        Setting("Open full screen while you use the phone", "Without it a request is a banner when the phone is unlocked. Needs Display over other apps (used only for this).", v.overApps, calls.openOverApps)
        Setting("Notification access", "Two things, both matched and never kept: an imported account's app asking for a 2FA code gets a Copy offer, and while a laptop request waits, a code in a text or email (Messages, Gmail, Outlook and other SMS and mail apps) is offered to send to the laptop.", v.watcher, calls.openWatcher)
        TextSitesRow(v, calls)
        Spacer(Modifier.height(12.dp))
        Fact("Every code", "Your fingerprint, every time. No PIN, no grace window.")
        Fact("A request", "Expires in 60 s. Approving doesn't unlock the phone.")
        Fact("Fills on", "Only the exact sites saved for that account (subdomains only where a site starts with *.).")
        Fact("The relay", "Sees sealed blobs only: no site, name or code.")
        Kicker("Keep out of Sphinx", Modifier.padding(top = 24.dp, bottom = 4.dp))
        Text(
            "Your Google account, your bank and your main email. A code here and a password on the same laptop is one device holding both factors; for those, keep the code in your authenticator app alone.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
