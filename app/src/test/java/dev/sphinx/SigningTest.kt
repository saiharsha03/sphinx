package dev.sphinx

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Release signing (docs/DESIGN.md, Release signing): who may ask, what is checked, and the unlock secret sealed behind the fingerprint. */
class SigningTest {
    private val now = 1_800_000_000_000L
    private val u = ByteArray(32) { it.toByte() }
    private val signer = Pairing("S".repeat(22), "Signer", ByteArray(32) { 1 }, ByteArray(32) { 2 }, "https://relay.example.com", ByteArray(32) { 3 }, added = now, signer = true)
    private val laptop = signer.copy(pid = "L".repeat(22), name = "Work laptop", signer = false)
    private val sha = "ab12" + "0".repeat(56) + "ef90"

    private fun req(p: Pairing, kind: String, body: Map<String, Any?>, exp: Long = now + 60_000, rid: String = "R".repeat(22)) =
        rid to SphinxCrypto.seal(p.l2p, p.pid, 'q', 1, exp, json.writeValueAsBytes(SphinxLogic.envelope(kind, rid, body)))

    private val salt = "AAECAwQFBgcICQoLDA0ODw"   // bytes 0..15
    private val good = mapOf("label" to "Sphinx 1.2.0", "key" to "sphinx", "sha256" to sha, "size" to 5_000_000, "alias" to "sphinx",
        "cert_sha256" to "ab".repeat(32), "salt" to salt, "unlock" to "a16a6e", "fv" to 2)

    private fun sign(p: Pairing, body: Map<String, Any?> = good, enrolled: Boolean = true, exp: Long = now + 60_000): Decision {
        val (rid, blob) = req(p, "sign.approve", body, exp)
        return SphinxLogic.decide(p, rid, blob, emptyList(), now, enrolled = enrolled)
    }

    private fun why(d: Decision) = ((d as Decision.Answer).reply["body"] as Map<*, *>)["why"]

    @Test fun theSignersPairingAsksAndThePhoneShowsWhatItSigns() {
        val a = (sign(signer) as Decision.Sign).ask
        assertEquals(SignAsk("R".repeat(22), signer.pid, "Signer", "Sphinx 1.2.0", "sphinx", sha, 5_000_000, now + 60_000,
            "sphinx", "ab".repeat(32), salt, "a16a6e", 2, SphinxCrypto.tag(signer)), a)
        assertEquals("Sign Sphinx 1.2.0?", SigningRules.question(a))
        assertEquals("sha256 ab12…ef90 · key sphinx · 4.8 MB", SigningRules.detail(a))
        assertEquals(listOf("ab120000 00000000 00000000 00000000", "00000000 00000000 00000000 0000ef90"), SigningRules.grouped(sha).lines())
        // Held to the signer's own sealed expiry, never a fresh 60 s.
        assertEquals(now + 20_000, (sign(signer, exp = now + 20_000) as Decision.Sign).ask.expires)
    }

    @Test fun onlyTheSignerMayAskAndItMayAskNothingElse() {
        assertEquals("unsupported kind", why(sign(laptop)))
        val (rid, blob) = req(signer, "code.request", mapOf("host" to "github.com"))
        assertEquals("unsupported kind", why(SphinxLogic.decide(signer, rid, blob, emptyList(), now)))
        val (rid2, blob2) = req(signer, "domains.request", emptyMap())
        assertEquals("unsupported kind", why(SphinxLogic.decide(signer, rid2, blob2, emptyList(), now)))
        assertFalse("sign.approve" in SphinxLogic.KINDS)
        // A QR without x=sign makes an ordinary pairing.
        val qr = "sphinx:1?p=${"P".repeat(22)}&k=${SphinxCrypto.enc(ByteArray(32) { 9 })}&s=${SphinxCrypto.enc(ByteArray(16) { 7 })}&r=https://relay.example.com&n=Signer"
        assertFalse(SphinxCrypto.offer(qr)!!.signer)
        val o = SphinxCrypto.offer("$qr&x=sign")!!
        assertTrue(o.signer)
        assertTrue(SphinxCrypto.accept(o, now)!!.first.signer)
    }

    @Test fun aBadOrUnenrolledRequestIsRefusedWithoutAsking() {
        for (bad in listOf(good + ("sha256" to "AB12"), good + ("sha256" to sha.uppercase()), good + ("key" to "../x"), good + ("label" to ""),
                good + ("label" to "a\nb"), good + ("label" to "x".repeat(81)), good + ("size" to 0), good + ("size" to "10"), good - "key",
                // The key file it names: an old signer that sends none, or a bad alias, certificate, salt, unlock id or version.
                good - "salt", good - "cert_sha256", good + ("alias" to "a|b"), good + ("salt" to "AAEC"), good + ("unlock" to "XYZ"), good + ("fv" to 3)))
            assertEquals(bad.toString(), "bad request", why(sign(signer, bad)))
        assertEquals("no unlock secret on the phone", why(sign(signer, enrolled = false)))
        val d = sign(signer, enrolled = false) as Decision.Answer
        assertEquals("sign.approve.reply", d.reply["kind"])
        assertEquals(1L, d.pairing.recv)
    }

    @Test fun aYesCarriesTheShownKeysOwnSecretNeverU() {
        val a = (sign(signer) as Decision.Sign).ask
        val k = SigningRules.keySecret(u, a)
        // The signer's key_secret for the same file (the signer's own tests: U = 0..31, salt 0..15, sphinx / sphinx / ab x 32).
        assertEquals("1ecca805b361bc398151da3eb139136110ff5336cdd0b8472204d8ccd52c4bd5", k.joinToString("") { "%02x".format(it) })
        assertEquals("2f2d10ccaf9c3a6ee174e480697e382784a89b929d4a2b2f3827aa609b5fd608", SigningRules.keySecret(u, a.copy(fv = 1)).joinToString("") { "%02x".format(it) })
        // Bound to the key he was shown: another name or certificate gives another secret.
        assertFalse(k.contentEquals(SigningRules.keySecret(u, a.copy(key = "other"))))
        assertFalse(k.contentEquals(SigningRules.keySecret(u, a.copy(cert = "cd".repeat(32)))))
        val yes = SigningRules.approved("R".repeat(22), k)["body"] as Map<*, *>
        assertEquals(mapOf("ok" to true, "k" to SphinxCrypto.enc(k)), yes)
        assertFalse(yes.values.contains(SphinxCrypto.enc(u)))
        assertEquals(mapOf("ok" to false, "why" to "denied"), SigningRules.no("R".repeat(22), "denied")["body"])
    }

    @Test fun aSecondSignerIsRefusedAndASignIsApprovedOnlyOnItsScreen() {
        assertTrue(SigningRules.mayPair(true, listOf(laptop)))
        assertFalse(SigningRules.mayPair(true, listOf(laptop, signer)))
        assertTrue(SigningRules.mayPair(false, listOf(signer)))
        // The sign notification: private over the keyguard, Deny only (no Approve that skips the full-hash screen), and
        // the sign screen never prompts on its own.
        val src = java.io.File("src/main/java/dev/sphinx")
        val ask = java.io.File(src, "Sphinx.kt").readText().substringAfter("private fun askSign").substringBefore("private fun cancelSign")
        assertTrue(ask.contains("VISIBILITY_PRIVATE") && ask.contains("setPublicVersion") && !ask.contains("VISIBILITY_PUBLIC"))
        assertFalse(ask.contains("\"Approve\""))
        val host = java.io.File(src, "ApproveActivity.kt").readText().substringAfter("private fun SignHost").substringBefore("private fun CopyHost")
        assertFalse(host.contains("LaunchedEffect(rid)"))
        assertFalse(java.io.File(src, "ApproveActivity.kt").readText().contains("signNow"))
    }

    @Test fun aLegacyKeyFileIsPinnedToItsSaltAndNeverUnderAnotherName() {
        val v1 = (sign(signer, good + ("fv" to 1)) as Decision.Sign).ask
        var pins = SignPins()
        assertNull(pins.refusal(v1))                                     // the first approval pins it
        pins = pins.after(v1)
        assertNull(pins.refusal(v1))
        // Another salt under the same name, or this salt under a decoy name: refused.
        assertEquals("this legacy key file changed", pins.refusal(v1.copy(salt = "BBECAwQFBgcICQoLDA0ODw")))
        assertEquals("this key file is another key's", pins.refusal(v1.copy(key = "decoy")))
        // The same 16 bytes spelled another way (padded, or non-zero trailing bits) is the same salt to the pin...
        for (alias in listOf("AAECAwQFBgcICQoLDA0ODw==", "AAECAwQFBgcICQoLDA0ODx")) {
            assertEquals(alias, "this key file is another key's", pins.refusal(v1.copy(key = "decoy", salt = alias)))
            // ...and the request itself is refused: only the canonical spelling is taken.
            assertEquals(alias, "bad request", why(sign(signer, good + ("fv" to 1) + ("salt" to alias))))
        }
        // Once a name was seen as v2, a v1 file under it is refused; v2 asks are never pinned.
        val v2 = v1.copy(fv = 2)
        assertNull(pins.refusal(v2))
        pins = pins.after(v2)
        assertEquals("this key is v2 now: a legacy file under its name is refused", pins.refusal(v1))
        assertFalse("sphinx" in pins.v1)
        // Codex: after the move to v2 the old v1 salt keeps its owner, so a kept v1 file can't come back under a decoy,
        // in either version.
        assertEquals("this key file is another key's", pins.refusal(v1.copy(key = "decoy")))
        assertEquals("this key file is another key's", pins.refusal(v1.copy(key = "decoy", fv = 2)))
        // Kept in the sealed prefs beside U.
        val kv = HashMap<String, String>()
        val store = UnlockStore({ kv[it] }, { k, v -> if (v == null) kv.remove(k) else kv[k] = v }, FakeKeys(), { now })
        store.savePins(pins)
        assertEquals(pins, store.pins())
    }

    @Test fun thePasskeyAndTheQrGiveU() {
        // The same words the signer's Python makes for these bytes (the signer's own tests).
        val words = Bip39.phrase(u)
        assertEquals(listOf("abandon", "amount", "liar", "amount", "expire", "adjust"), words.take(6))
        assertEquals("unaware", words.last())
        assertArrayEquals(u, SigningRules.fromPasskey("  " + words.joinToString(" ").uppercase() + "\n"))
        assertNull(SigningRules.fromPasskey((words.dropLast(1) + "abandon").joinToString(" ")))
        assertArrayEquals(u, SigningRules.unlockQr("sphinx-unlock:1?u=${SphinxCrypto.enc(u)}"))
        assertNull(SigningRules.unlockQr("sphinx-unlock:1?u=${SphinxCrypto.enc(u.copyOf(31))}"))
        assertNull(SigningRules.unlockQr("otpauth://totp/x?secret=${SphinxCrypto.enc(u)}"))
        assertEquals("a16a6e", SigningRules.unlockId(u))
    }

    @Test fun uIsSealedAndOpensOnlyAfterTheFingerprint() {
        val keys = FakeKeys()
        val kv = HashMap<String, String>()
        val store = UnlockStore({ kv[it] }, { k, v -> if (v == null) kv.remove(k) else kv[k] = v }, keys, { now })
        assertFalse(store.enrolled())
        val given = u.copyOf()
        assertEquals("a16a6e", store.enroll(given))
        assertTrue(given.all { it == 0.toByte() })
        assertFalse(kv.values.joinToString().contains(SphinxCrypto.enc(u)))
        val un = keys.unwrapper()
        assertTrue(runCatching { store.open(un) }.isFailure)
        keys.approved = true
        assertArrayEquals(u, store.open(un))
        store.remove()
        assertFalse(store.enrolled())
    }
}
