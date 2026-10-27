package dev.sphinx

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
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
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
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

enum class Tab(val word: String) { ACCOUNTS("Codes"), KEYS("Keys"), LAPTOPS("Laptops"), SETTINGS("Settings") }

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
    /**
     * A backup set aside unopened: one Android restored from Google (opened with his fingerprint), or this phone's own
     * after a new fingerprint cleared the codes (opened only with its backup passcode or recovery phrase).
     */
    val google: Backups.SetAside? = null,
    /** A retire after a new fingerprint couldn't finish yet (Backups.ready refuses every backup send until it does). */
    val retiring: Boolean = false,
)

/** When the app locks again. Pure, so the rule is tested. */
object AppLock {
    /**
     * Set just before Sphinx opens its own QR scanner or file picker: that trip out of the app is part of what he is
     * doing, so it doesn't lock. Anything else that takes Sphinx off the screen locks it (owner, 2026-10-26: "the app
     * should auto lock whenever I move away from the app").
     */
    @Volatile private var insideUntil = 0L

    /** The scanner or picker gets [INSIDE_MS] (it protects against a stale exemption covering a later departure). */
    const val INSIDE_MS = 30_000L
    /** Even from the scanner or picker, this long away locks. */
    const val AWAY_MS = 60_000L

    fun goingInside(now: Long = android.os.SystemClock.elapsedRealtime()) { insideUntil = now + INSIDE_MS }
    fun inside(now: Long = android.os.SystemClock.elapsedRealtime()): Boolean = now < insideUntil
    fun clear() { insideUntil = 0L }

    /** On stop: the screen going off always locks; leaving locks unless it's Sphinx's own scanner or picker. */
    fun onStop(inside: Boolean, interactive: Boolean): Boolean = !interactive || !inside

    /** On start: away (not inside) locks, and so does a stay outside longer than [AWAY_MS] even from the scanner. */
    fun onStart(stoppedAt: Long, now: Long, inside: Boolean): Boolean = stoppedAt > 0 && (!inside || now - stoppedAt > AWAY_MS)
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
        stoppedAt = android.os.SystemClock.elapsedRealtime()
        if (AppLock.onStop(AppLock.inside(), ctx.getSystemService(android.os.PowerManager::class.java)?.isInteractive != false)) lock()
    }
    LifecycleEventEffect(Lifecycle.Event.ON_START) {
        val now = android.os.SystemClock.elapsedRealtime()
        val wasInside = AppLock.inside(now)
        AppLock.clear()
        if (AppLock.onStart(stoppedAt, now, wasInside)) { lock(); unlock() }
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
        val g = withContext(Dispatchers.IO) { runCatching { Backups.waiting(app) }.getOrNull() }
        val stuck = withContext(Dispatchers.IO) { runCatching { Backups.local(app).retirePending() }.getOrDefault(false) }
        view = view.copy(accounts = a, pairings = p, textSites = t, fullScreen = Sphinx.canFullScreen(app), overApps = Settings.canDrawOverlays(app), watcher = watcher, google = g,
            retiring = stuck)
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
        AppLock.goingInside()
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
        openGoogle = { id, done ->
            Sphinx.confirm(ctx, "Open the Google backup", "Its codes are sealed to this phone", onOk = {
                scope.launch {
                    val r = withContext(Dispatchers.IO) { runCatching { Backups.adopt(app, id) } }
                    view = view.copy(note = r.getOrElse { it.message ?: "It didn't open (${it.javaClass.simpleName})." }); done(); bump++
                }
            }, onFail = { view = view.copy(note = it); done() })
        },
        openSetAside = { id, secret, done ->
            scope.launch {
                val r = withContext(Dispatchers.IO) { runCatching { Backups.adoptWith(app, id, secret) } }
                view = view.copy(note = r.getOrElse { it.message ?: "It didn't open." }); done(); bump++
            }
        },
        leaveGoogle = { id, done -> scope.launch { withContext(Dispatchers.IO) { Backups.dropForeign(app, id) }; done(); bump++ } },
        scan = { onText -> scan(onText) },
    )


    SphinxFrame(view, calls, unlocked, failure, ::unlock)
}

/**
 * The frame around every tab: the wordmark line, the tab, and the tab bar (a side rail on a wide screen, the Fold's
 * inner one). Locked, only the unlock shows. Stateless, so the screenshot tests render it with sample data.
 */
@Composable
fun SphinxFrame(view: Home, calls: Calls, unlocked: Boolean, failure: String?, onUnlock: () -> Unit) {
    val p = Sx.p
    val wide = LocalConfiguration.current.screenWidthDp >= 600
    val items = listOf(
        NavItem(Glyph.CODES, Tab.ACCOUNTS.word, view.tab == Tab.ACCOUNTS) { calls.tab(Tab.ACCOUNTS) },
        NavItem(Glyph.KEYS, Tab.KEYS.word, view.tab == Tab.KEYS) { calls.tab(Tab.KEYS) },
        NavItem(Glyph.LAPTOPS, Tab.LAPTOPS.word, view.tab == Tab.LAPTOPS) { calls.tab(Tab.LAPTOPS) },
        NavItem(Glyph.SETTINGS, Tab.SETTINGS.word, view.tab == Tab.SETTINGS) { calls.tab(Tab.SETTINGS) },
    )
    if (wide) Row(Modifier.fillMaxSize().background(p.canvas)) {
        if (unlocked) SideRail(items, Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Vertical + WindowInsetsSides.Start)))
        Column(Modifier.weight(1f).windowInsetsPadding(WindowInsets.safeDrawing.only(if (unlocked) WindowInsetsSides.Vertical + WindowInsetsSides.End else WindowInsetsSides.Vertical + WindowInsetsSides.Horizontal))) {
            TopBar()
            Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                Box(Modifier.widthIn(max = 680.dp)) { if (!unlocked) Locked(failure, onUnlock) else Content(view, calls, 24) }
            }
        }
    } else Column(Modifier.fillMaxSize().background(p.canvas)) {
        Column(Modifier.weight(1f).fillMaxWidth().windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal))) {
            TopBar()
            Box(Modifier.weight(1f)) { if (!unlocked) Locked(failure, onUnlock) else Content(view, calls, 16) }
        }
        if (unlocked) BottomBar(items, Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Bottom + WindowInsetsSides.Horizontal)))
        else Box(Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Bottom)))
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
    /** The set-aside Google backup: open it (a fingerprint first), or leave it closed for good. */
    val openGoogle: (String, () -> Unit) -> Unit = { _, _ -> },
    /** The backup a new fingerprint set aside: opened with its passcode or 24 words. */
    val openSetAside: (String, String, () -> Unit) -> Unit = { _, _, _ -> },
    /** Each names the copy the card shows (its id) and says when it is done, so the card's buttons wait meanwhile. */
    val leaveGoogle: (String, () -> Unit) -> Unit = { _, _ -> },
    /** The code scanner, for the signing unlock QR (Settings, Signing). */
    val scan: ((String) -> Unit) -> Unit = {},
    /** Screenshot tests only: sample data for the panes that read Keystore-backed stores. Null = the real stores. */
    val samples: Samples? = null,
    /** Screenshot tests only: the rows shown opened (account or pairing ids). */
    val opened: Set<String> = emptySet(),
)

/** What the Keys, Backup and Signing panes and About show in a screenshot test, in place of the stores. */
class Samples(val keys: List<SafeEntry> = emptyList(), val backup: BackupState? = null, val accounts: Int = 0, val unlock: SealedUnlock? = null, val version: String = "")

@Composable
private fun Locked(failure: String?, onUnlock: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(horizontal = 24.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Column(Modifier.widthIn(max = 400.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Wordmark()
            Text("Your 2FA accounts are behind your fingerprint.", Modifier.padding(top = 20.dp), style = Type.headlineMd, color = Sx.p.text, textAlign = TextAlign.Center)
            failure?.let { Text(it, Modifier.padding(top = 8.dp), style = Type.bodySm, color = Sx.p.danger, textAlign = TextAlign.Center) }
            SxButton("Unlock", onUnlock, Modifier.padding(top = 28.dp).fillMaxWidth())
        }
    }
}

@Composable
private fun Content(v: Home, calls: Calls, margin: Int) {
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(start = margin.dp, end = margin.dp, top = 4.dp, bottom = 32.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp)) {
        when {
            v.picking != null -> {
                item { Header("Import") }
                v.note?.let { item { NoteCard(it) } }
                item { PickList(v.picking, calls) }
            }
            v.tab == Tab.ACCOUNTS -> {
                item { Header("Codes", "Your fingerprint shows each one") { PlusButton(calls.scanAccounts, "Import from Authenticator") } }
                if (v.retiring) item { NoteCard("A new fingerprint cleared the codes, and this phone's backup couldn't be set aside yet. Backups are paused until it is: restart Sphinx.") }
                v.google?.let { g -> item { SetAsideCard(g, calls) } }
                v.note?.let { item { NoteCard(it) } }
                if (v.accounts.isEmpty()) item {
                    Column {
                        Group {
                            ListRow("No accounts yet.",
                                "In Google Authenticator: menu, Transfer accounts, Export. Tick only the few you want here, then scan the QR it shows. A plain otpauth QR from a site works too.")
                        }
                        SxButton("Import from Authenticator", calls.scanAccounts, Modifier.fillMaxWidth().padding(top = 16.dp))
                        Box(Modifier.padding(top = 20.dp)) { RestorePane { msg -> calls.restored(msg) } }
                    }
                } else item {
                    Column {
                        SectionLabel("Accounts")
                        Group { v.accounts.forEachIndexed { i, a -> if (i > 0) Hairline(); AccountRow(a, v, calls) } }
                    }
                }
            }
            v.tab == Tab.LAPTOPS -> {
                item { Header("Laptops", "Where your codes are typed in") }
                v.note?.let { item { NoteCard(it) } }
                val laptops = v.pairings.filter { !it.signer }
                item {
                    Column {
                        SectionLabel("Paired")
                        Group {
                            if (laptops.isEmpty()) ListRow("No laptop paired.", "Install the Sphinx extension in Chrome, set your relay on its options page, show its pairing code and scan it here.")
                            laptops.forEachIndexed { i, p -> if (i > 0) Hairline(); PairingRow(p, calls) }
                        }
                    }
                }
                if (v.pairings.any { it.signer }) item { NoteLine("The release Signer lives in Settings, Signing.") }
                item { SxButton("Pair a laptop", calls.pair, Modifier.fillMaxWidth()) }
            }
            v.tab == Tab.KEYS -> {
                item { Header("Keys", "Each one opens with your fingerprint") }
                v.note?.let { item { NoteCard(it) } }
                item { KeysPane(calls.samples) }
            }
            else -> {
                item { Header("Settings") }
                v.note?.let { item { NoteCard(it) } }
                item { SettingsTab(v, calls) }
            }
        }
    }
}

/**
 * One account, one compact row: the tile, the name and its handle, its site in a small cartouche, and the code in a
 * cartouche. The code stays hidden (••• •••) until a fingerprint shows it; then it shows grouped (842 190) with the
 * ring for its period and hides when it changes. Tapping the row opens its sites and Delete.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AccountRow(a: CodeAccount, v: Home, calls: Calls) {
    val p = Sx.p
    var open by remember { mutableStateOf(a.id in calls.opened) }
    var confirm by remember { mutableStateOf(false) }
    var draft by remember(v.editing) { mutableStateOf(a.domains.joinToString(", ")) }
    var problem by remember(v.editing) { mutableStateOf<String?>(null) }
    LaunchedEffect(confirm) { if (confirm) { delay(4000); confirm = false } }
    val shown = v.shown?.takeIf { it.first == a.id }
    Column(Modifier.fillMaxWidth().riseIn()) {
        Row(Modifier.fillMaxWidth().clickable(role = Role.Button, onClickLabel = "Sites and Delete") { open = !open }
            .defaultMinSize(minHeight = 56.dp).padding(horizontal = 12.dp, vertical = 9.dp), verticalAlignment = Alignment.CenterVertically) {
            IconTile(a.issuer.ifBlank { a.name })
            Column(Modifier.weight(1f).padding(horizontal = 10.dp)) {
                Text(buildAnnotatedString {
                    append(a.issuer.ifBlank { "Account" })
                    if (a.name.isNotBlank()) withStyle(SpanStyle(fontWeight = FontWeight.Normal, fontSize = 12.5.sp, color = p.text2)) { append(" · ${a.name}") }
                }, style = Type.bodyMd.copy(fontWeight = FontWeight.SemiBold), color = p.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Box(Modifier.padding(top = 3.dp)) {
                    if (a.domains.isEmpty()) Pill("no site yet", p.primary)
                    else Pill(a.domains.first() + if (a.domains.size > 1) " +${a.domains.size - 1}" else "")
                }
            }
            // The code's cartouche: tap it to show (a fingerprint each time).
            Cartouche(Modifier.clip(CircleShape).clickable(role = Role.Button, onClickLabel = "Show the code") { calls.show(a) }) {
                if (shown != null) { CountdownRing(shown.third, a.period); Spacer(Modifier.width(8.dp)) }
                Crossfade(shown?.second, animationSpec = if (Sx.motion) tween(400) else snap(), label = "code") { code ->
                    if (code != null) Text(code.chunked(if (a.digits == 8) 4 else 3).joinToString(" "), style = Type.code, color = p.text, maxLines = 1)
                    else Text(if (a.digits == 8) "•••• ••••" else "••• •••", style = Type.codeHidden, color = p.text2, maxLines = 1)
                }
            }
        }
        if (open) Column(Modifier.fillMaxWidth().padding(start = 52.dp, end = 12.dp, bottom = 10.dp)) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                if (a.domains.isEmpty()) Text("Fills on: nowhere yet. Add its site under Sites.", style = Type.bodySm, color = p.primary)
                else {
                    Text("Fills on", Modifier.align(Alignment.CenterVertically), style = Type.bodySm, color = p.text2)
                    a.domains.forEach { Pill(it, max = 240.dp) }
                }
            }
            if (a.algo != Algo.SHA1 || a.period != Totp.PERIOD) Text("Code: ${a.algo.wire}, every ${a.period} s", Modifier.padding(top = 6.dp), style = Type.codeSm, color = p.text2)
            if (v.editing == a.id) Column(Modifier.padding(top = 10.dp)) {
                OutlinedTextField(draft, { draft = it; problem = null }, Modifier.fillMaxWidth(), placeholder = { Text("github.com, *.example.com") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), colors = fieldColors())
                Text("Each site is one exact host. Start it with *. to let its subdomains fill too.", Modifier.padding(top = 6.dp), style = Type.bodySm, color = p.text2)
                problem?.let { Text(it, Modifier.padding(top = 4.dp), style = Type.bodySm, color = p.danger) }
                Row(Modifier.padding(top = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SxButton("Save", { problem = calls.saveDomains(a, draft) }, small = true)
                    SxButton("Cancel", { calls.edit(null) }, kind = Kind.SECONDARY, small = true)
                }
            } else Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SxButton("Sites", { calls.edit(a.id) }, kind = Kind.SECONDARY, small = true)
                Spacer(Modifier.weight(1f))
                SxButton(if (confirm) "Tap again to delete" else "Delete", { if (confirm) { calls.delete(a); confirm = false } else confirm = true }, kind = Kind.DANGER, small = true)
            }
        }
    }
}

/** A backup set aside unopened (Backups.SetAside): Google's opens with his fingerprint, a cleared one with its passcode or phrase. */
@Composable
private fun SetAsideCard(g: Backups.SetAside, calls: Calls) {
    var secret by remember(g.id) { mutableStateOf("") }
    var confirm by remember(g.id) { mutableStateOf(false) }
    // One operation at a time on this card: open and delete both wait until the other is done (review 2026-10-27).
    var busy by remember(g.id) { mutableStateOf(false) }
    var see by remember(g.id) { mutableStateOf(false) }
    LaunchedEffect(confirm) { if (confirm) { delay(4000); confirm = false } }
    val what = "${g.accounts} account(s) and ${g.safe} Keys safe entr${if (g.safe == 1) "y" else "ies"}."
    val field = g.cleared && g.reopenable
    Group {
        if (g.cleared && !g.reopenable) ListRow("Your codes were cleared by a new fingerprint",
            "$what This copy can only be opened with the relay passcode or 24 words, and this one had neither, so it can't be reopened.")
        else if (g.cleared) ListRow("Your codes were cleared by a new fingerprint", "$what The backup kept on this phone opens with your backup passcode or recovery phrase, not a fingerprint.")
        else ListRow("A Google backup came with this phone", "$what Nothing of it is opened until you do, with your fingerprint.")
        if (field) OutlinedTextField(secret, { secret = it }, Modifier.fillMaxWidth().padding(horizontal = 16.dp), label = { Text("Backup passcode or the 24 words") },
            visualTransformation = masked(see), trailingIcon = { SeeToggle(see) { see = !see } },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false), colors = fieldColors())
        Hairline(Modifier.padding(top = if (field) 12.dp else 0.dp))
        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (field) SxButton("Open it", { busy = true; calls.openSetAside(g.id, secret.trim()) { busy = false }; secret = "" }, small = true, enabled = !busy && secret.isNotBlank())
            else if (!g.cleared) SxButton("Open it", { busy = true; calls.openGoogle(g.id) { busy = false } }, small = true, enabled = !busy)
            // It deletes the copy for good: a second tap.
            SxButton(if (confirm) "Tap again to delete it" else if (g.reopenable) "Don't open it" else "Delete it",
                { if (confirm) { confirm = false; busy = true; calls.leaveGoogle(g.id) { busy = false } } else confirm = true },
                kind = if (confirm) Kind.DANGER else Kind.SECONDARY, small = true, enabled = !busy)
        }
    }
}

@Composable
private fun PickList(p: Picking, calls: Calls) {
    val c = Sx.p
    Column {
        Text(if (p.found.isEmpty()) "Nothing to import" else "Tick the ones Sphinx should keep", Modifier.padding(horizontal = 4.dp), style = Type.headlineMd, color = c.text)
        p.batch?.let { Text("QR ${it.first} of ${it.second} from Authenticator.", Modifier.padding(top = 4.dp, start = 4.dp), style = Type.bodySm, color = c.text2) }
        if (p.found.isNotEmpty()) Group(Modifier.padding(top = 16.dp)) {
            p.found.forEachIndexed { i, im ->
                if (i > 0) Hairline()
                Row(Modifier.fillMaxWidth().clickable(role = Role.Checkbox) { calls.tick(i) }.padding(horizontal = 12.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconTile(im.issuer.ifBlank { im.name })
                    Column(Modifier.weight(1f).padding(horizontal = 10.dp)) {
                        Text(im.issuer.ifBlank { "Account" }, style = Type.bodyMd.copy(fontWeight = FontWeight.SemiBold), color = c.text)
                        Text(listOfNotNull(im.name.ifBlank { null }, Domains.forIssuer(im.issuer).firstOrNull() ?: "no site yet").joinToString(" · "),
                            style = Type.bodySm, color = c.text2, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Checkbox(i in p.ticked, { calls.tick(i) }, colors = CheckboxDefaults.colors(checkedColor = c.primary, uncheckedColor = c.text2, checkmarkColor = c.onPrimary))
                }
            }
        }
        if (p.refused.isNotEmpty()) {
            SectionLabel("Left out", Modifier.padding(top = 20.dp))
            Group { p.refused.forEachIndexed { i, r -> Fact(r.label, r.why, rule = i > 0) } }
        }
        Text("Only the ticked ones are saved, sealed on this phone. They never leave it.", Modifier.padding(top = 16.dp, start = 4.dp), style = Type.bodySm, color = c.text2)
        Row(Modifier.padding(top = 16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            SxButton("Cancel", calls.cancelPick, Modifier.weight(1f), kind = Kind.SECONDARY)
            if (p.ticked.isNotEmpty()) SxButton("Save ${p.ticked.size}", calls.saveTicked, Modifier.weight(1f))
        }
    }
}

/** A pairing, one row: its name, when it was last used and whether its relay wakes the phone. Tapping opens its facts and Unpair. */
@Composable
fun PairingRow(p: Pairing, calls: Calls) {
    var open by remember { mutableStateOf(p.pid in calls.opened) }
    var confirm by remember { mutableStateOf(false) }
    LaunchedEffect(confirm) { if (confirm) { delay(4000); confirm = false } }
    val last = if (p.lastUsed > 0) "Last used " + DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(p.lastUsed)) else "Not used yet"
    val sub = if (p.signer) "Release signing only · " + (if (p.push) "paired" else "can't wake this phone")
        else "$last · " + if (p.push) "wakes this phone" else "can't wake this phone"
    Column(Modifier.fillMaxWidth()) {
        ListRow(p.name, sub, onClick = { open = !open }) {
            Box(Modifier.size(7.dp).clip(CircleShape).background(if (p.push) Sx.p.success else Sx.p.text2))
        }
        if (open) {
            Fact("Tag", SphinxCrypto.tag(p))
            Fact("Relay", p.relay.removePrefix("https://"))
            if (p.signer) Fact("Asks", "Release signing only (Settings, Signing)")
            Fact("Wake", if (p.push) "Firebase: requests arrive at once" else "Its relay can't wake this phone (no FCM account there yet)")
            Fact("Paired", DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(p.added)))
            Fact("Last", if (p.lastUsed > 0) DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(p.lastUsed)) else "Not used yet")
            Hairline()
            Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 10.dp), horizontalArrangement = Arrangement.End) {
                SxButton(if (confirm) "Tap again to unpair" else "Unpair", { if (confirm) { calls.unpair(p); confirm = false } else confirm = true }, kind = Kind.DANGER, small = true)
            }
        }
    }
}

/** A system setting Sphinx needs: its state as a toggle; off, the row (or the toggle) opens the setting. */
@Composable
private fun Setting(title: String, line: String, on: Boolean, open: () -> Unit, rule: Boolean) =
    ListRow(title, line, rule = rule, onClick = if (on) null else open) { SxSwitch(on, if (on) null else open) }

/**
 * Codes by text or email: sites with no account here whose code comes by SMS or email. The laptop asks on them like on
 * a saved site; the phone then offers the texted code, sent with the fingerprint, typed in and never submitted.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TextSitesGroup(v: Home, calls: Calls) {
    val c = Sx.p
    var draft by remember(v.editing) { mutableStateOf(v.textSites.joinToString(", ")) }
    var problem by remember(v.editing) { mutableStateOf<String?>(null) }
    Group {
        ListRow("Codes by text or email",
            "Sites with no account here that text or email their code. While the laptop asks there, Sphinx offers the code from the text (needs notification access); your fingerprint sends it, and it is typed in, never submitted.")
        FlowRow(Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 12.dp), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Sites", Modifier.align(Alignment.CenterVertically), style = Type.bodySm, color = c.text2)
            if (v.textSites.isEmpty()) Text("none", style = Type.bodySm, color = c.text2) else v.textSites.forEach { Pill(it, max = 240.dp) }
        }
        Hairline()
        if (v.editing == TEXT_SITES_EDIT) Column(Modifier.padding(16.dp)) {
            OutlinedTextField(draft, { draft = it; problem = null }, Modifier.fillMaxWidth(), placeholder = { Text("shop.example.com, *.bank.example") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), colors = fieldColors())
            problem?.let { Text(it, Modifier.padding(top = 4.dp), style = Type.bodySm, color = c.danger) }
            Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SxButton("Save", { problem = calls.saveTextSites(draft) }, small = true)
                SxButton("Cancel", { calls.edit(null) }, kind = Kind.SECONDARY, small = true)
            }
        } else ListRow("Edit sites", "On the laptop, press Refresh sites and Allow on the extension's options page afterwards.", onClick = { calls.edit(TEXT_SITES_EDIT) }) { Chevron() }
    }
}

private const val TEXT_SITES_EDIT = "sphinx.textsites"

/** Settings: one card per topic, a label and a clear gap between each; the destructive actions together in red at the end. */
@Composable
private fun SettingsTab(v: Home, calls: Calls) {
    val backup = rememberBackupModel(calls.samples)
    val signing = rememberSigningModel(calls.samples)
    val ctx = LocalContext.current
    val version = calls.samples?.version ?: remember {
        runCatching { ctx.packageManager.getPackageInfo(ctx.packageName, 0).let { "${it.versionName} (${it.longVersionCode})" } }.getOrDefault("")
    }
    Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
        Column {
            SectionLabel("Lock")
            Group {
                ListRow("Every code", "Your fingerprint, every time. No PIN, no grace window.")
                ListRow("A request", "Expires in 60 s. Approving doesn't unlock the phone.", rule = true)
            }
        }
        Column {
            SectionLabel("Laptop requests")
            Group {
                Setting("Ask over the lock screen", "A laptop request wakes the screen and asks there. Needs full-screen notifications for Sphinx.", v.fullScreen, calls.openFullScreen, rule = false)
                Setting("Open full screen while you use the phone", "Without it a request is a banner when the phone is unlocked. Needs Display over other apps (used only for this).", v.overApps, calls.openOverApps, rule = true)
                Setting("Notification access", "Two things, both matched and never kept: an imported account's app asking for a 2FA code gets a Copy offer, and while a laptop request waits, a code in a text or email (Messages, Gmail, Outlook and other SMS and mail apps) is offered to send to the laptop.", v.watcher, calls.openWatcher, rule = true)
                ListRow("Fills on", "Only the exact sites saved for that account (subdomains only where a site starts with *.).", rule = true)
                ListRow("The relay", "Sees sealed blobs only: no site, name or code.", rule = true)
            }
        }
        Column {
            SectionLabel("Codes by text or email")
            TextSitesGroup(v, calls)
        }
        Column {
            SectionLabel("Backup")
            BackupPane(backup)
        }
        Column {
            SectionLabel("Signing")
            SigningPane(signing, calls.scan, v.pairings.filter { it.signer }, calls)
        }
        Column {
            SectionLabel("Keep out of Sphinx")
            Group {
                GroupText("Your Google account, your bank and your main email. A code here and a password on the same laptop is one device holding both factors; for those, keep the code in your authenticator app alone.")
            }
        }
        DangerZone(backup, signing)
        if (version.isNotEmpty()) Text("Sphinx $version", Modifier.fillMaxWidth().padding(top = 4.dp), style = Type.bodySm, color = Sx.p.text2, textAlign = TextAlign.Center)
    }
}
