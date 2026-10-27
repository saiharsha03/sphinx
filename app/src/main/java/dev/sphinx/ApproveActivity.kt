package dev.sphinx

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The question over the lock screen ("Code for github.com (work)?"), started by the full-screen notification. It shows
 * when locked and turns the screen on, but never dismisses the keyguard: approving sends the code, the phone stays
 * locked. Approve is the fingerprint (strong biometrics only), Deny answers no, 60 s and it expires. A code.ready asks
 * the same way ("Signing in to github.com"): the yes opens a 30 s window instead of sending a code. The same screen
 * sends a texted code to the waiting laptop (text mode) and copies a code on the phone itself (copy mode). Screenshots and the recents preview are blocked (FLAG_SECURE).
 */
class ApproveActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val rid = intent.getStringExtra(EXTRA_RID)
        val account = intent.getStringExtra(EXTRA_ACCOUNT)
        // The banner's Deny: no screen, just the answer.
        if (rid != null && intent.getBooleanExtra(EXTRA_DENY, false)) {
            lifecycleScope.launch { withContext(Dispatchers.IO) { Sphinx.deny(applicationContext, rid) }; finish() }
            return
        }
        val now = intent.getBooleanExtra(EXTRA_NOW, false)
        val text = intent.getBooleanExtra(EXTRA_TEXT, false)
        val sign = intent.getBooleanExtra(EXTRA_SIGN, false)
        setContent {
            SphinxTheme {
                if (rid != null && sign) SignHost(rid)
                else if (rid != null && text) TextHost(rid) else if (rid != null) AskHost(rid, now) else if (account != null) CopyHost(account) else finish()
            }
        }
    }

    private fun locked() = getSystemService(KeyguardManager::class.java)?.isKeyguardLocked == true

    @Composable
    private fun AskHost(rid: String, approveNow: Boolean = false) {
        val asks by Sphinx.asks.collectAsState()
        val p = asks.firstOrNull { it.waitId == rid }
        var note by remember { mutableStateOf<String?>(null) }
        var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
        // Over the keyguard only the issuer shows, never the account names, until the fingerprint.
        val names = !locked()
        LaunchedEffect(p) {
            while (p != null && now < p.expires) { delay(500); now = System.currentTimeMillis() }
            if (p != null) { withContext(Dispatchers.IO) { Sphinx.expire(applicationContext) }; finish() }
        }
        if (p == null) {
            ApproveContent(null, 0, note ?: "This request has expired or was answered.", names, onApprove = {}, onDeny = { finish() })
            return
        }
        val approve: (CodeAccount) -> Unit = approve@{ a ->
            val (u, why) = Sphinx.unwrapper(this)
            if (u == null) { note = why; return@approve }
            Sphinx.fingerprint(this, SphinxLogic.question(p.copy(picked = a.id), names), "From ${p.laptop}. The phone stays locked.", u,
                // The fingerprint was the yes: the screen goes at once and the code is sent behind it. A send that fails
                // shows on the laptop (it times out).
                onOk = { Sphinx.inBackground(applicationContext) { app -> Sphinx.approve(app, p, a.id, u) }; finish() },
                onFail = { note = it })
        }
        val single = p.accounts.firstOrNull { it.id == p.picked } ?: p.accounts.singleOrNull()
        // Unlocked and in hand, or from the banner's Approve, the fingerprint asks at once. Locked, the Approve tap stays
        // first: on phones whose fingerprint sensor is the power key, waking the phone must never approve a code.
        LaunchedEffect(rid) { if (single != null && (approveNow || names)) approve(single) }
        ApproveContent(p, ((p.expires - now) / 1000).toInt().coerceAtLeast(0), note, names,
            onApprove = approve,
            onDeny = { lifecycleScope.launch { withContext(Dispatchers.IO) { Sphinx.deny(applicationContext, rid) }; finish() } })
    }

    /**
     * A texted code for the waiting laptop. The tap on the notification (or its Send) was the ask, so the fingerprint asks
     * at once; over the keyguard the prompt names the site, not the digits.
     */
    @Composable
    private fun TextHost(rid: String) {
        val asks by Sphinx.asks.collectAsState()
        val p = asks.firstOrNull { it.waitId == rid }
        var note by remember { mutableStateOf<String?>(null) }
        val unlocked = !locked()
        LaunchedEffect(rid) {
            val offer = Sphinx.textedFor(rid)
            if (p == null || offer == null) { note = "This request has expired or was answered."; return@LaunchedEffect }
            Sphinx.gate(this@ApproveActivity,
                onOk = { Sphinx.inBackground(applicationContext) { app -> Sphinx.sendText(app, offer) }; finish() },
                onFail = { finish() },
                title = if (unlocked) "Send ${offer.code} to ${p.host}?" else "Send the texted code to ${p.host}?",
                subtitle = "From ${p.laptop}. The laptop types it in.")
        }
        SendContent(p?.host, note) { finish() }
    }

    /**
     * The release signer's question. The fingerprint unwraps the sealed unlock secret (a CryptoObject on the codes key),
     * from which the one key file's secret goes back to the signer for this one sign. Always a deliberate Approve tap on
     * this screen first, which shows the whole hash: never a prompt on its own, never from the banner (review 2026-10-27).
     */
    @Composable
    private fun SignHost(rid: String) {
        val asks by Sphinx.signAsks.collectAsState()
        val a = asks.firstOrNull { it.waitId == rid }
        var note by remember { mutableStateOf<String?>(null) }
        var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
        LaunchedEffect(a) {
            while (a != null && now < a.expires) { delay(500); now = System.currentTimeMillis() }
            if (a != null) { withContext(Dispatchers.IO) { Sphinx.expire(applicationContext) }; finish() }
        }
        if (a == null) {
            SignContent(null, 0, note ?: "This request has expired or was answered.", onApprove = {}, onDeny = { finish() })
            return
        }
        val approve: () -> Unit = approve@{
            val (u, why) = Sphinx.unwrapper(this)
            if (u == null) { note = why; return@approve }
            Sphinx.fingerprint(this, SigningRules.question(a), SigningRules.detail(a), u,
                onOk = { Sphinx.inBackground(applicationContext) { app -> Sphinx.approveSign(app, a, u) }; finish() },
                onFail = { note = it })
        }
        SignContent(a, ((a.expires - now) / 1000).toInt().coerceAtLeast(0), note, onApprove = approve,
            onDeny = { lifecycleScope.launch { withContext(Dispatchers.IO) { Sphinx.deny(applicationContext, rid) }; finish() } })
    }

    @Composable
    private fun CopyHost(id: String) {
        var a by remember { mutableStateOf<CodeAccount?>(null) }
        var note by remember { mutableStateOf<String?>(null) }
        LaunchedEffect(id) { a = withContext(Dispatchers.IO) { SphinxStore.get(applicationContext).accounts().firstOrNull { it.id == id } } }
        val acc = a ?: return
        // Over the keyguard: the issuer only, never the account name.
        val label = SphinxLogic.copyLabel(acc, getSystemService(KeyguardManager::class.java)?.isKeyguardLocked != true)
        LaunchedEffect(acc) {
            val (u, why) = Sphinx.unwrapper(this@ApproveActivity)
            if (u == null) { note = why; return@LaunchedEffect }
            Sphinx.fingerprint(this@ApproveActivity, "Copy the $label code", SecureClipboard.promise(this@ApproveActivity), u,
                onOk = { runCatching { Sphinx.copy(applicationContext, acc, u) }.onFailure { Log.warn("copy failed", it.javaClass.simpleName) }; finish() },
                onFail = { finish() })
        }
        CopyContent(label, note) { finish() }
    }

    companion object {
        /** The request's waitId (Pending.waitId, SignAsk.waitId): its pairing and rid. */
        private const val EXTRA_RID = "sphinx.rid"
        private const val EXTRA_NOW = "sphinx.now"
        private const val EXTRA_DENY = "sphinx.deny"
        private const val EXTRA_ACCOUNT = "sphinx.account"
        private const val EXTRA_TEXT = "sphinx.text"
        private const val EXTRA_SIGN = "sphinx.sign"

        /** A release-signing request (docs/DESIGN.md, Release signing). It has no "now": a sign is approved only with a tap on its screen. */
        fun sign(c: Context, rid: String) = ask(c, rid).putExtra(EXTRA_SIGN, true)

        /** A texted code's Send: the fingerprint, then it goes to that waiting request. */
        fun text(c: Context, rid: String) = ask(c, rid).putExtra(EXTRA_TEXT, true)

        /** The banner's buttons: Approve goes straight to the fingerprint, Deny answers without a screen. */
        fun approveNow(c: Context, rid: String) = ask(c, rid).putExtra(EXTRA_NOW, true)
        fun deny(c: Context, rid: String) = ask(c, rid).putExtra(EXTRA_DENY, true)

        fun ask(c: Context, rid: String) = Intent(c, ApproveActivity::class.java).putExtra(EXTRA_RID, rid)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_USER_ACTION or Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS)

        fun copy(c: Context, id: String) = Intent(c, ApproveActivity::class.java).putExtra(EXTRA_ACCOUNT, id)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS)
    }
}

/**
 * "The riddle": the frame of every question Sphinx asks full screen (a code, a signing, a texted code, a copy). The
 * wordmark at the top, a faint large Sphinx behind (its jade eye pulsing slowly), the question and its facts, then the
 * [footer] (the time left) and the answers at the bottom in the thumb zone.
 */
@Composable
fun AskScreen(body: @Composable ColumnScope.() -> Unit, actions: @Composable ColumnScope.() -> Unit, footer: @Composable ColumnScope.() -> Unit = {}) {
    val c = Sx.p
    Box(Modifier.fillMaxSize().background(c.canvas).safeDrawingPadding()) {
        Column(Modifier.fillMaxSize()) {
            TopBar()
            Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.BottomCenter) {
                SphinxMark(300.dp, c.ghost, ghost = true, Modifier.padding(bottom = 24.dp))
                Column(Modifier.fillMaxSize().widthIn(max = 480.dp).align(Alignment.TopCenter).verticalScroll(rememberScrollState()).padding(horizontal = 22.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(22.dp), horizontalAlignment = Alignment.CenterHorizontally, content = body)
            }
            Column(Modifier.widthIn(max = 480.dp).fillMaxWidth().align(Alignment.CenterHorizontally).padding(start = 22.dp, end = 22.dp, top = 8.dp, bottom = 26.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)) {
                footer()
                actions()
            }
        }
    }
}

/** The jade caps over the question: who asks. */
@Composable
fun Eyebrow(text: String) = Text(text.uppercase(), Modifier.fillMaxWidth().padding(top = 16.dp), style = Type.eyebrow, color = Sx.p.primary, textAlign = TextAlign.Center)

/** The time left, in mono, and that approving doesn't unlock the phone. */
@Composable
fun Timer(secondsLeft: Int) =
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Text("expires in %d:%02d".format(secondsLeft / 60, secondsLeft % 60), style = Type.codeSm.copy(fontSize = 12.sp),
            color = if (secondsLeft < 5) Sx.p.danger else Sx.p.text2)
        Text("Approving doesn't unlock the phone.", Modifier.padding(top = 4.dp), style = Type.bodySm, color = Sx.p.text2)
    }

/** Deny (outline) and Approve (solid jade), side by side. */
@Composable
fun AnswerPair(onDeny: () -> Unit, onApprove: () -> Unit) =
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        SxButton("Deny", onDeny, Modifier.weight(1f), kind = Kind.SECONDARY)
        SxButton("Approve", onApprove, Modifier.weight(1f))
    }

/** The approval page. A single account shows Approve; several without a match on the page's user name list each one. */
@Composable
fun ApproveContent(p: Pending?, secondsLeft: Int, note: String?, names: Boolean, onApprove: (CodeAccount) -> Unit, onDeny: () -> Unit) {
    val c = Sx.p
    val single = p?.let { q -> q.accounts.firstOrNull { it.id == q.picked } ?: q.accounts.singleOrNull() }
    AskScreen(body = {
        if (p == null) {
            Text(note ?: "", Modifier.padding(top = 48.dp), style = Type.headlineMd, color = c.text, textAlign = TextAlign.Center)
            return@AskScreen
        }
        Eyebrow("Your laptop asks")
        QuestionCartouche(if (p.ready) "Signing in to ${p.host}" else "Code for ${p.host}?")
        Group {
            single?.let { Fact("Account", SphinxLogic.rowLabel(p, it, names), rule = false) }
            Fact("Laptop", p.laptop, rule = single != null)
            Fact("Then", if (p.ready) "the code for the next ${SphinxLogic.WINDOW_MS / 1000} s" else "typed in and sent")
        }
        if (single == null) Column(Modifier.fillMaxWidth()) {
            SectionLabel("Which account")
            Group {
                p.accounts.forEachIndexed { i, a ->
                    ListRow(SphinxLogic.rowLabel(p, a, names), if (names) a.issuer else null, rule = i > 0, onClick = { onApprove(a) }) {
                        Text("Approve", style = Type.bodyMd.copy(fontWeight = FontWeight.SemiBold), color = c.primary)
                    }
                }
            }
            if (!names) Text("Names show once the phone is unlocked.", Modifier.padding(top = 8.dp, start = 4.dp), style = Type.bodySm, color = c.text2)
        }
        note?.let { Text(it, style = Type.bodySm, color = c.danger, textAlign = TextAlign.Center) }
    }, footer = {
        if (p != null) Timer(secondsLeft)
    }, actions = {
        if (p == null) SxButton("Close", onDeny, Modifier.fillMaxWidth(), kind = Kind.SECONDARY)
        else if (single != null) AnswerPair(onDeny) { onApprove(single) }
        else SxButton("Deny", onDeny, Modifier.fillMaxWidth(), kind = Kind.SECONDARY)
    })
}

/** The texted-code page behind the fingerprint prompt: the site it goes to, or why it can't. */
@Composable
fun SendContent(host: String?, note: String?, onClose: () -> Unit) {
    val c = Sx.p
    AskScreen(body = {
        Eyebrow("A texted code")
        QuestionCartouche(host?.let { "Texted code for $it" } ?: "Texted code")
        Text(note ?: "Touch the sensor to send it to the laptop. It types it in and doesn't submit.", style = Type.bodySm,
            color = if (note != null) c.danger else c.text2, textAlign = TextAlign.Center)
    }, actions = { SxButton("Close", onClose, Modifier.fillMaxWidth(), kind = Kind.SECONDARY) })
}

@Composable
fun CopyContent(label: String, note: String?, onClose: () -> Unit) {
    val c = Sx.p
    AskScreen(body = {
        Eyebrow("Copy a code")
        QuestionCartouche("$label code")
        Text(note ?: "Touch the sensor to copy it. The clipboard clears in 30 s.", style = Type.bodySm,
            color = if (note != null) c.danger else c.text2, textAlign = TextAlign.Center)
    }, actions = { SxButton("Close", onClose, Modifier.fillMaxWidth(), kind = Kind.SECONDARY) })
}
