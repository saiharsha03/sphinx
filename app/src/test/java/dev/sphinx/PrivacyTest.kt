package dev.sphinx

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** What the source promises about secrets: where they are stored, what the log may say, and what opens a code. */
class PrivacyTest {
    private val src = File("src/main/java/dev/sphinx")
    private fun all() = src.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    @Test fun theAccountsAndPairingsLiveOnlyInTheSealedPrefs() {
        val store = File(src, "SphinxStore.kt").readText()
        assertTrue(store.contains("SphinxStore(prefs::read, prefs::write, keys, dropKey = keys::delete, backup = Backups.local(app)"))
        // Only the sealed prefs and the clipboard's own nonce use SharedPreferences; no database.
        val prefsUsers = all().filter { it.readText().contains("getSharedPreferences(") }.map { it.name }.toSet()
        assertEquals(setOf("Vault.kt"), prefsUsers)
        assertFalse(all().any { it.readText().let { t -> t.contains("SQLiteOpenHelper") || t.contains("openFileOutput") } })
        // Files only in two folders: the sealed backup (backup/) and the Keys safe's sealed contents (safe/).
        val dirs = all().flatMap { f -> Regex("""File\((?:c\.applicationContext|app)\.filesDir, "([^"]+)"\)""").findAll(f.readText()).map { it.groupValues[1] }.toList() }.toSet()
        assertEquals(setOf("backup", "safe"), dirs)
        assertEquals(2, all().count { it.readText().contains("filesDir") })
    }

    @Test fun logLinesNeverCarryACodeOrAKey() {
        val calls = Regex("""Log\.(info|warn)\(([^\n]*)\)""").findAll(all().joinToString("\n") { it.readText() }).map { it.groupValues[2] }.toList()
        assertTrue(calls.size >= 10)
        // The account's user name, the page's hint, a code, a secret or any key material: never an argument.
        for (c in calls) for (bad in listOf("code)", "code,", "\$code", "secret", ".wk", ".ct", "l2p", "p2l", "relayKey", "blob", "hello", "user", "hint", "a.name", "it.name", "p.name", "raw"))
            assertFalse("$bad in Log.$c", c.contains(bad))
    }

    @Test fun theCodesKeyIsFingerprintOnly() {
        val vault = File(src, "Vault.kt").readText()
        assertTrue(vault.contains(".setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)"))
        assertTrue(vault.contains(".setInvalidatedByBiometricEnrollment(true)"))
        val prompts = File(src, "Sphinx.kt").readText()
        assertFalse(all().any { it.readText().contains("DEVICE_CREDENTIAL") })
        assertEquals(2, Regex("setAllowedAuthenticators\\(Authenticators.BIOMETRIC_STRONG\\)").findAll(prompts).count())
        // Approving never dismisses the keyguard; every screen that shows a code or an account blocks screenshots.
        assertFalse(all().any { it.readText().contains("requestDismissKeyguard") })
        for (f in listOf("ApproveActivity.kt", "MainActivity.kt")) assertTrue(f, File(src, f).readText().contains("FLAG_SECURE"))
    }

    @Test fun notificationsAreReadOnlyFromWatchedAppsAndTextsOnlyWhileARequestWaits() {
        // The watcher decides from the package alone, before any notification text is read.
        val w = File(src, "Watcher.kt").readText()
        assertTrue(w.indexOf("Sphinx.watches(") in 0 until w.indexOf("EXTRA_TITLE"))
        val s = File(src, "Sphinx.kt").readText()
        assertTrue(s.contains("(pkg in Domains.TEXT_APPS && waiting())"))
        assertTrue(s.contains("if (waiting()) Domains.textCode(pkg, title, text)"))
        // The texted code lives in memory only, keyed by its request, and goes with it.
        assertTrue(s.contains("private val texted = TextOffers()"))
        assertFalse(File(src, "SphinxStore.kt").readText().contains("texted"))
    }

    @Test fun firebaseIsOptionalAndCarriesOnlyTheSyncAndTheSealedBlobs() {
        val manifest = File("src/main/AndroidManifest.xml").readText()
        assertTrue(manifest.contains("firebase_messaging_auto_init_enabled\" android:value=\"false"))
        assertTrue(manifest.contains("firebase_analytics_collection_deactivated\" android:value=\"true"))
        val push = File(src, "Push.kt").readText()
        assertTrue(push.contains("d[\"t\"] != \"sync\" || !d.keys.all { it == \"t\" || it == \"sphinx\" }"))
        // No google-services plugin: the build reads the optional json itself.
        assertFalse(File("build.gradle.kts").readText().contains("com.google.gms.google-services"))
    }

    @Test fun noLiveConnectionOnlyTheFcmWakeTheAppInFrontAndTheHeartbeat() {
        // No foreground service, no permanent notification, no long poll.
        val manifest = File("src/main/AndroidManifest.xml").readText()
        assertFalse(manifest.contains("FOREGROUND_SERVICE") || manifest.contains("foregroundServiceType"))
        assertFalse(all().any { it.readText().let { t -> t.contains("startForeground") || t.contains("readMs = 40_000") } })
        assertTrue(File(src, "RelayClient.kt").readText().contains("query = \"wait=0\""))
        // Pairing without an FCM token says so instead of pairing something that could never be woken.
        assertTrue(File(src, "Sphinx.kt").readText().contains("val token = Push.token(c) ?: error("))
    }

    @Test fun theAppCarriesNoSecretsOrHosts() {
        // A public repo: no real relay host, IP or key in the source. The relay comes from the pairing QR.
        for (f in all()) {
            val t = f.readText()
            assertFalse(f.name, Regex("""https://(?!relay\.example\.com)[a-z0-9.-]+\.[a-z]{2,}""").containsMatchIn(t.lines().filter { !it.trimStart().startsWith("*") && !it.trimStart().startsWith("//") }.joinToString("\n")))
            assertFalse(f.name, Regex("""\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b""").containsMatchIn(t))
        }
    }
}
