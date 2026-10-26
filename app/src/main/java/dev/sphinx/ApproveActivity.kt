package dev.sphinx

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
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
        setContent {
            SphinxTheme {
                if (rid != null && text) TextHost(rid) else if (rid != null) AskHost(rid, now) else if (account != null) CopyHost(account) else finish()
            }
        }
    }

    private fun locked() = getSystemService(KeyguardManager::class.java)?.isKeyguardLocked == true

    @Composable
    private fun AskHost(rid: String, approveNow: Boolean = false) {
        val asks by Sphinx.asks.collectAsState()
        val p = asks.firstOrNull { it.rid == rid }
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
                onOk = { Sphinx.inBackground(applicationContext) { app -> Sphinx.approve(app, rid, a.id, u) }; finish() },
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
        val p = asks.firstOrNull { it.rid == rid }
        var note by remember { mutableStateOf<String?>(null) }
        val unlocked = !locked()
        LaunchedEffect(rid) {
            val code = Sphinx.textedFor(rid)
            if (p == null || code == null) { note = "This request has expired or was answered."; return@LaunchedEffect }
            Sphinx.gate(this@ApproveActivity,
                onOk = { Sphinx.inBackground(applicationContext) { app -> Sphinx.sendText(app, rid) }; finish() },
                onFail = { finish() },
                title = if (unlocked) "Send $code to ${p.host}?" else "Send the texted code to ${p.host}?",
                subtitle = "From ${p.laptop}. The laptop types it in.")
        }
        SendContent(p?.host, note) { finish() }
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
        private const val EXTRA_RID = "sphinx.rid"
        private const val EXTRA_NOW = "sphinx.now"
        private const val EXTRA_DENY = "sphinx.deny"
        private const val EXTRA_ACCOUNT = "sphinx.account"
        private const val EXTRA_TEXT = "sphinx.text"

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

/** The approval page. A single account shows Approve; several without a match on the page's user name list each one. */
@Composable
fun ApproveContent(p: Pending?, secondsLeft: Int, note: String?, names: Boolean, onApprove: (CodeAccount) -> Unit, onDeny: () -> Unit) {
    val c = MaterialTheme.colorScheme
    Column(Modifier.fillMaxSize().background(c.background).navigationBarsPadding().padding(horizontal = 24.dp)) {
        Column(Modifier.weight(1f).widthIn(max = 480.dp).fillMaxWidth().align(Alignment.CenterHorizontally), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
            Kicker("Sphinx · 2FA code")
            Spacer(Modifier.height(16.dp))
            if (p == null) {
                Text(note ?: "", style = MaterialTheme.typography.titleLarge)
                return@Column
            }
            val single = p.accounts.firstOrNull { it.id == p.picked } ?: p.accounts.singleOrNull()
            Box(Modifier.size(80.dp).clip(CircleShape).background(c.primary), contentAlignment = Alignment.Center) {
                Text(p.host.take(1).uppercase(), style = MaterialTheme.typography.headlineMedium, color = c.onPrimary)
            }
            Spacer(Modifier.height(16.dp))
            Text(if (p.ready) "Signing in to ${p.host}" else "Sign in to ${p.host}?", style = MaterialTheme.typography.headlineSmall)
            if (p.ready) Text("Approve the code for the next ${SphinxLogic.WINDOW_MS / 1000} seconds", Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodyLarge, color = c.onSurfaceVariant)
            single?.let { a ->
                Spacer(Modifier.height(12.dp))
                Box(Modifier.clip(MaterialTheme.shapes.small).background(c.surfaceVariant).padding(horizontal = 12.dp, vertical = 6.dp)) {
                    Text(SphinxLogic.rowLabel(p, a, names), style = MaterialTheme.typography.bodyLarge)
                }
            }
            Spacer(Modifier.height(12.dp))
            Text("From ${p.laptop}", style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
            Spacer(Modifier.height(16.dp))
            // The time left, draining: a request lives SphinxCrypto.TTL_MS.
            val total = (SphinxCrypto.TTL_MS / 1000).toInt().coerceAtLeast(1)
            LinearProgressIndicator(progress = { (secondsLeft.toFloat() / total).coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(4.dp))
            Text("$secondsLeft s left · approving doesn't unlock the phone", style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
            if (single == null) {
                Kicker("Which account", Modifier.padding(top = 24.dp, bottom = 4.dp))
                for (a in p.accounts) Column(Modifier.fillMaxWidth().clickable(role = Role.Button) { onApprove(a) }) {
                    HorizontalDivider(color = c.outlineVariant)
                    Row(Modifier.padding(vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(SphinxLogic.rowLabel(p, a, names), style = MaterialTheme.typography.bodyLarge)
                            if (names) Text(a.issuer, style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
                        }
                        Text("Approve", color = c.primary, style = MaterialTheme.typography.labelLarge)
                    }
                }
                if (!names) Text("Names show once the phone is unlocked.", Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodySmall, color = c.onSurfaceVariant)
            }
            note?.let { Text(it, Modifier.padding(top = 16.dp), style = MaterialTheme.typography.bodySmall, color = c.error) }
        }
        Column(Modifier.widthIn(max = 480.dp).fillMaxWidth().align(Alignment.CenterHorizontally).padding(bottom = 24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            if (p == null) TextButton(onDeny) { Text("Close") }
            else {
                (p.accounts.firstOrNull { it.id == p.picked } ?: p.accounts.singleOrNull())?.let { single ->
                    Button({ onApprove(single) }, Modifier.fillMaxWidth().height(56.dp)) { Text("Approve") }
                    Spacer(Modifier.height(8.dp))
                }
                TextButton(onDeny) { Text("Deny") }
            }
        }
    }
}

/** The texted-code page behind the fingerprint prompt: the site it goes to, or why it can't. */
@Composable
fun SendContent(host: String?, note: String?, onClose: () -> Unit) {
    val c = MaterialTheme.colorScheme
    Column(Modifier.fillMaxSize().background(c.background).padding(horizontal = 24.dp), verticalArrangement = Arrangement.Center) {
        Kicker("Sphinx · 2FA code")
        Text(host?.let { "Texted code for $it" } ?: "Texted code", Modifier.padding(top = 8.dp), style = MaterialTheme.typography.headlineSmall)
        Text(note ?: "Touch the sensor to send it to the laptop. It types it in and doesn't submit.", Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodySmall,
            color = if (note != null) c.error else c.onSurfaceVariant)
        TextButton(onClose, Modifier.padding(top = 16.dp)) { Text("Close") }
    }
}

@Composable
fun CopyContent(label: String, note: String?, onClose: () -> Unit) {
    val c = MaterialTheme.colorScheme
    Column(Modifier.fillMaxSize().background(c.background).padding(horizontal = 24.dp), verticalArrangement = Arrangement.Center) {
        Kicker("Sphinx · 2FA code")
        Text("$label code", Modifier.padding(top = 8.dp), style = MaterialTheme.typography.headlineSmall)
        Text(note ?: "Touch the sensor to copy it. The clipboard clears in 30 s.", Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodySmall,
            color = if (note != null) c.error else c.onSurfaceVariant)
        TextButton(onClose, Modifier.padding(top = 16.dp)) { Text("Close") }
    }
}
