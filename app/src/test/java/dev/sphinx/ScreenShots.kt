package dev.sphinx

import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.activity.ComponentActivity
import androidx.compose.runtime.Composable
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

/**
 * The screens rendered to PNG (app/build/shots/<name>.png) with sample data: every screen is FLAG_SECURE, so this is
 * how the look is checked. Nothing here touches Keystore, the relay or a real account.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class ScreenShots {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private fun shot(name: String, content: @Composable () -> Unit) {
        compose.setContent { SphinxTheme(content = content) }
        compose.mainClock.advanceTimeBy(2_000)
        compose.waitForIdle()
        val root = compose.activity.window.decorView
        val bmp = Bitmap.createBitmap(root.width, root.height, Bitmap.Config.ARGB_8888)
        root.draw(Canvas(bmp))
        val dir = File(System.getProperty("user.dir"), "build/shots").apply { mkdirs() }
        File(dir, "$name.png").outputStream().use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    private val day = 1_792_000_000_000L
    private val accounts = listOf(
        CodeAccount("a1", "GitHub", "work", listOf("github.com")),
        CodeAccount("a2", "Cloudflare", "ops@example.com", listOf("dash.cloudflare.com", "*.cloudflareaccess.com")),
        CodeAccount("a3", "Fastmail", "me@example.com", listOf("app.fastmail.com"), digits = 8, algo = Algo.SHA256, period = 60),
        CodeAccount("a4", "Hetzner", "", emptyList()),
    )
    private val laptops = listOf(
        Pairing("p1", "Work laptop", relay = "https://relay.example.com", added = day - 86_400_000L * 9, lastUsed = day - 3_600_000L, push = true, l2p = ByteArray(32) { 1 }),
        Pairing("p2", "Home desktop", relay = "https://relay.example.com", added = day - 86_400_000L * 30, push = false, l2p = ByteArray(32) { 2 }),
        Pairing("p3", "Signer", relay = "https://relay.example.com", added = day, push = true, signer = true, l2p = ByteArray(32) { 3 }),
    )
    // Relative to the clock, so the rows read "just now" and "12 min ago" whenever the shot is taken.
    private val now = System.currentTimeMillis()
    private val sent = listOf(
        SentItem("s1", now - 20_000L, "Chrome laptop", SentKind.TEXT, text = "Meeting room code 4471"),
        SentItem("s2", now - 12 * 60_000L, "Chrome laptop", SentKind.LINK, url = "https://example.com/docs"),
        SentItem("s3", now - 3 * 86_400_000L, "Chrome laptop", SentKind.TEXT, text = "Pick up the parcel at the front desk before 6, they close early on Fridays"),
        SentItem("s4", now - 40_000L, "Chrome laptop", SentKind.FILE, name = "invoice-oct.pdf", mime = "application/pdf", size = 184 * 1024, uri = "content://media/external/downloads/1"),
        SentItem("s5", now - 2 * 3_600_000L, "Chrome laptop", SentKind.FILE, name = "team-photo.jpg", mime = "image/jpeg", size = 2_300 * 1024, uri = "content://media/external/downloads/2"),
        SentItem("s6", now - 5 * 86_400_000L, "Chrome laptop", SentKind.FILE, name = "notes.txt", mime = "text/plain", size = 900, uri = "content://media/external/downloads/3"),
    )
    private val samples = Samples(
        keys = listOf(
            SafeEntry("k1", "Google recovery codes", "text", size = 220, added = day),
            SafeEntry("k2", "SSH deploy key", "file", "id_ed25519", size = 3200, added = day - 86_400_000L * 4),
        ),
        backup = BackupState(relay = RelayBackup(relay = "https://relay.example.com", phraseId = "x")), accounts = 4,
        unlock = SealedUnlock("3fa9c1", day), version = "1.1.0 (2)",
    )
    private fun home(tab: Tab, shown: Triple<String, String, Int>? = null) =
        Home(tab = tab, accounts = accounts, pairings = laptops, sent = sent, shown = shown, fullScreen = true, overApps = false, watcher = true, textSites = listOf("shop.example.com"))

    @Test @Config(sdk = [35], qualifiers = "w393dp-h852dp-xhdpi")
    fun codes() = shot("codes") { SphinxFrame(home(Tab.ACCOUNTS, Triple("a1", "842190", 21)), Calls(samples = samples), true, null) {} }

    @Test @Config(sdk = [35], qualifiers = "w393dp-h852dp-xhdpi")
    fun codesExpiring() = shot("codes-expiring") { SphinxFrame(home(Tab.ACCOUNTS, Triple("a2", "317554", 4)), Calls(samples = samples), true, null) {} }

    @Test @Config(sdk = [35], qualifiers = "w393dp-h852dp-xhdpi")
    fun codesOpen() = shot("codes-open") { SphinxFrame(home(Tab.ACCOUNTS), Calls(samples = samples, opened = setOf("a2")), true, null) {} }

    @Test @Config(sdk = [35], qualifiers = "w673dp-h841dp-xhdpi")
    fun codesFold() = shot("codes-fold") { SphinxFrame(home(Tab.ACCOUNTS), Calls(samples = samples), true, null) {} }

    @Test @Config(sdk = [35], qualifiers = "w393dp-h852dp-xhdpi")
    fun locked() = shot("locked") { SphinxFrame(Home(), Calls(samples = samples), false, null) {} }

    @Test @Config(sdk = [35], qualifiers = "w393dp-h3400dp-xhdpi")
    fun settings() = shot("settings") { SphinxFrame(home(Tab.SETTINGS), Calls(samples = samples), true, null) {} }

    @Test @Config(sdk = [35], qualifiers = "w393dp-h852dp-xhdpi")
    fun keys() = shot("keys") { SphinxFrame(home(Tab.KEYS), Calls(samples = samples), true, null) {} }

    @Test @Config(sdk = [35], qualifiers = "w393dp-h852dp-xhdpi")
    fun laptops() = shot("laptops") { SphinxFrame(home(Tab.LAPTOPS), Calls(samples = samples, opened = setOf("p2")), true, null) {} }

    @Test @Config(sdk = [35], qualifiers = "w393dp-h852dp-xhdpi")
    fun texts() = shot("texts") { SphinxFrame(home(Tab.TEXTS), Calls(samples = samples), true, null) {} }

    @Test @Config(sdk = [35], qualifiers = "w393dp-h852dp-xhdpi")
    fun files() = shot("files") { SphinxFrame(home(Tab.FILES), Calls(samples = samples), true, null) {} }

    @Test @Config(sdk = [35], qualifiers = "w393dp-h852dp-xhdpi")
    fun approve() = shot("approve") {
        ApproveContent(Pending("r1", "p1", "Work laptop", "github.com", accounts = listOf(accounts[0]), picked = null, expires = 0), 42, null, true, {}, {})
    }

    @Test @Config(sdk = [35], qualifiers = "w393dp-h852dp-xhdpi")
    fun approvePick() = shot("approve-pick") {
        ApproveContent(Pending("r1", "p1", "Work laptop", "github.com", accounts = listOf(accounts[0], accounts[0].copy(id = "a9", name = "personal")), picked = null, expires = 0),
            4, null, true, {}, {})
    }

    @Test @Config(sdk = [35], qualifiers = "w393dp-h852dp-xhdpi")
    fun sign() = shot("sign") {
        SignContent(SignAsk("r2", "p3", "Signer", "Sphinx 1.2.0", "sphinx", "9f2c" + "a".repeat(56) + "41d0", 18_400_000, 0), 51, null, {}, {})
    }
}
