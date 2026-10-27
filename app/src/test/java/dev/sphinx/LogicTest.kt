package dev.sphinx

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.PublicKey
import javax.crypto.Cipher

/** A software stand-in for the Keystore codes pair: opens only after the fake prompt says yes. */
class FakeKeys : BoxKeys {
    private val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.genKeyPair()
    var approved = false
    var unwraps = 0
    /** Set to what Keystore throws after a new fingerprint enrolment. */
    var broken: Exception? = null
    override fun publicKey(): PublicKey = kp.public
    override fun unwrapper(): Unwrapper = broken?.let { throw it } ?: object : Unwrapper {
        override fun unwrap(wrapped: ByteArray): ByteArray {
            check(approved) { "no fingerprint" }
            unwraps++
            return Cipher.getInstance(Rsa.TRANSFORM).apply { init(Cipher.DECRYPT_MODE, kp.private, Rsa.OAEP) }.doFinal(wrapped)
        }
    }
}

class LogicTest {
    private val secret = "12345678901234567890".toByteArray()
    private val now = 1_800_000_000_000L
    private val keys = FakeKeys()
    private val kv = HashMap<String, String>()
    /** Stands in for KeyPermanentlyInvalidatedException (an android.jar stub in plain unit tests). */
    class Invalidated : Exception()
    private var dropped = 0
    private val store = SphinxStore({ synchronized(kv) { kv[it] } }, { k, v -> synchronized(kv) { if (v == null) kv.remove(k) else kv[k] = v } }, keys, { now },
        dropKey = { dropped++ }, invalidated = { it is Invalidated })
    private val pairing = Pairing("P".repeat(22), "Work laptop", ByteArray(32) { 1 }, ByteArray(32) { 2 }, "https://relay.example.com", ByteArray(32) { 3 }, added = now)

    private fun accounts(vararg a: Pair<String, String>) = store.add(a.map { (issuer, name) -> Imported(issuer, name, secret.copyOf(), Algo.SHA1, 6, 30) })

    /** A laptop envelope: "t" picks the kind (code or domains), the rest is its body. */
    private fun req(fields: Map<String, Any?>, ctr: Long = 1, exp: Long = now + 60_000, rid: String = fields["rid"] as String): Pair<String, String> {
        val env = SphinxLogic.envelope((fields["kind"] as String?) ?: "${fields["t"]}.request", fields["rid"] as String, fields - "t" - "rid" - "kind")
        return rid to SphinxCrypto.seal(pairing.l2p, pairing.pid, 'q', ctr, exp, json.writeValueAsBytes(env))
    }

    @Test fun aCodeRequestForASavedSiteAsksHim() {
        accounts("GitHub" to "alex-work")
        val (rid, blob) = req(mapOf("t" to "code", "rid" to "R".repeat(22), "host" to "github.com", "user" to ""))
        val d = SphinxLogic.decide(pairing, rid, blob, store.accounts(), now) as Decision.Ask
        assertEquals("github.com", d.pending.host)
        assertEquals(1L, d.pairing.recv)
        assertEquals(now + 60_000, d.pending.expires)
        assertEquals("Code for github.com (alex-work)?", SphinxLogic.question(d.pending))
        // Over the keyguard: the issuer only, never the account name.
        assertEquals("Code for github.com (GitHub)?", SphinxLogic.question(d.pending, names = false))
        assertEquals("GitHub, account 1", SphinxLogic.rowLabel(d.pending, d.pending.accounts[0], names = false))
        assertEquals("alex-work", SphinxLogic.rowLabel(d.pending, d.pending.accounts[0], names = true))
    }

    @Test fun aLookalikeOrUnknownSiteGetsARefusalWithoutAsking() {
        accounts("GitHub" to "alex-work")
        for (host in listOf("github.com.evil.io", "evilgithub.com", "gitlab.com", "gist.github.com")) {
            val (rid, blob) = req(mapOf("t" to "code", "rid" to "R".repeat(22), "host" to host))
            val d = SphinxLogic.decide(pairing, rid, blob, store.accounts(), now) as Decision.Answer
            assertEquals("code.reply", d.reply["kind"])
            val b = d.reply["body"] as Map<*, *>
            assertEquals(false, b["ok"]); assertEquals("no account", b["why"])
            assertFalse(d.line.contains("alex"))
        }
        assertEquals(0, keys.unwraps)
    }

    @Test fun severalAccountsPickByThePageUserElseAsk() {
        accounts("GitHub" to "alex-work", "GitHub" to "alex@example.com")
        val (rid, blob) = req(mapOf("t" to "code", "rid" to "R".repeat(22), "host" to "github.com", "user" to "alex-work"))
        val d = SphinxLogic.decide(pairing, rid, blob, store.accounts(), now) as Decision.Ask
        assertEquals(2, d.pending.accounts.size)
        assertEquals(d.pending.accounts.first { it.name == "alex-work" }.id, d.pending.picked)
        val (rid2, blob2) = req(mapOf("t" to "code", "rid" to "S".repeat(22), "host" to "github.com", "user" to "nobody"), ctr = 2)
        val d2 = SphinxLogic.decide(pairing, rid2, blob2, store.accounts(), now) as Decision.Ask
        assertNull(d2.pending.picked)
        assertEquals("Code for github.com?", SphinxLogic.question(d2.pending))
    }

    @Test fun aRequestCarriedByTheWakeTakesTheSameChecksAsAFetchedOne() {
        accounts("GitHub" to "w")
        val (rid, blob) = req(mapOf("t" to "code", "rid" to "R".repeat(22), "host" to "github.com"))
        val wake = """[{"pid":"${pairing.pid}","rid":"$rid","blob":"$blob"}]"""
        val fetched = RelayClient.Blob(pairing.pid, rid, blob)
        var p = pairing   // the stored counter, as SphinxStore keeps it
        val seen = ArrayList<String>()
        val handle = { b: RelayClient.Blob ->
            when (val d = SphinxLogic.decide(p, b.rid, b.blob, store.accounts(), now)) {
                is Decision.Drop -> { seen += d.why; false }
                is Decision.Ask -> { p = d.pairing; seen += "ask"; true }
                is Decision.Answer -> { p = d.pairing; seen += "answer"; true }
                is Decision.Handoff -> { p = d.pairing; seen += "handoff"; true }
                is Decision.Sign -> { p = d.pairing; seen += "sign"; true }
            }
        }
        // Carried: asked at once; the inbox's copy is acked, not run again.
        val acked = ArrayList<RelayClient.Blob>()
        SphinxLogic.drain(SphinxLogic.carried(wake), { listOf(fetched) }, acked, handle)
        assertEquals(listOf("ask"), seen)
        assertEquals(listOf(fetched), acked)
        // The same wake again (a replay): the counter refuses it.
        seen.clear()
        SphinxLogic.drain(SphinxLogic.carried(wake), { emptyList() }, ArrayList(), handle)
        assertEquals(listOf("replay"), seen)
        // A forged carry (not sealed with the pairing's key) is refused and doesn't stand in for the real fetched one.
        p = pairing; seen.clear()
        val fake = SphinxCrypto.seal(ByteArray(32), pairing.pid, 'q', 1, now + 60_000, json.writeValueAsBytes(SphinxLogic.envelope("code.request", rid, mapOf("host" to "github.com"))))
        val forged = """[{"pid":"${pairing.pid}","rid":"$rid","blob":"$fake"}]"""
        SphinxLogic.drain(SphinxLogic.carried(forged), { listOf(fetched) }, ArrayList(), handle)
        assertEquals(listOf("bad seal", "ask"), seen)
    }

    @Test fun aWakeCarriesOnlyBlobsInTheRelaysOwnShape() {
        val pid = "P".repeat(22); val rid = "R".repeat(22); val blob = "b".repeat(40)
        assertEquals(listOf(RelayClient.Blob(pid, rid, blob)), SphinxLogic.carried("""[{"pid":"$pid","rid":"$rid","blob":"$blob"}]"""))
        for (bad in listOf(null, "", "{}", "not json", """[{"pid":"$pid","rid":"$rid"}]""", """[{"pid":"$pid","rid":"$rid","blob":"$blob","x":1}]""",
            """[{"pid":"short","rid":"$rid","blob":"$blob"}]""", """[{"pid":"$pid","rid":"$rid","blob":"has spaces in it, not b64url"}]""",
            """[{"pid":"$pid","rid":"$rid","blob":5}]""", "[" + "x".repeat(5000) + "]"))
            assertTrue(bad.toString(), SphinxLogic.carried(bad).isEmpty())
        // At most 20, and one bad entry doesn't drop the good ones beside it.
        val many = (1..25).joinToString(",", "[", "]") { """{"pid":"$pid","rid":"${"r".repeat(16)}${it.toString().padStart(6, '0')}","blob":"$blob"}""" }
        assertEquals(20, SphinxLogic.carried(many).size)
        assertEquals(1, SphinxLogic.carried("""[{"pid":"x"},{"pid":"$pid","rid":"$rid","blob":"$blob"}]""").size)
    }

    @Test fun replayedExpiredTamperedOrMovedRequestsAreDropped() {
        accounts("GitHub" to "w")
        val body = mapOf("t" to "code", "rid" to "R".repeat(22), "host" to "github.com")
        val (rid, blob) = req(body, ctr = 5)
        assertEquals("replay", (SphinxLogic.decide(pairing.copy(recv = 5), rid, blob, store.accounts(), now) as Decision.Drop).why)
        assertEquals("expired", (SphinxLogic.decide(pairing, rid, blob, store.accounts(), now + 61_000) as Decision.Drop).why)
        assertEquals("rid mismatch", (SphinxLogic.decide(pairing, "T".repeat(22), blob, store.accounts(), now) as Decision.Drop).why)
        assertEquals("bad seal", (SphinxLogic.decide(pairing.copy(l2p = ByteArray(32)), rid, blob, store.accounts(), now) as Decision.Drop).why)
        // A reply blob (the other direction) can't be passed off as a request.
        val wrongWay = SphinxCrypto.seal(pairing.l2p, pairing.pid, 'r', 9, now + 60_000, json.writeValueAsBytes(SphinxLogic.envelope("code.request", "R".repeat(22), body)))
        assertEquals("direction", (SphinxLogic.decide(pairing, rid, wrongWay, store.accounts(), now) as Decision.Drop).why)
    }

    @Test fun requestsPostedOutOfOrderBothArriveEachOnce() {
        // Codex's reproduction (review 2026-10-27): the laptop's counters 1 and 2, the POST of 2 got to the relay first.
        accounts("GitHub" to "w")
        val (rid2, blob2) = req(mapOf("t" to "code", "rid" to "B".repeat(22), "host" to "github.com"), ctr = 2)
        val (rid1, blob1) = req(mapOf("t" to "code", "rid" to "A".repeat(22), "host" to "github.com"), ctr = 1)
        val after2 = (SphinxLogic.decide(pairing, rid2, blob2, store.accounts(), now) as Decision.Ask).pairing
        assertEquals(2L, after2.recv); assertEquals(listOf(1L), after2.gaps)
        val after1 = (SphinxLogic.decide(after2, rid1, blob1, store.accounts(), now) as Decision.Ask).pairing
        assertEquals(2L, after1.recv); assertTrue(after1.gaps.isEmpty())
        // Each once: both again are replays.
        assertEquals("replay", (SphinxLogic.decide(after1, rid1, blob1, store.accounts(), now) as Decision.Drop).why)
        assertEquals("replay", (SphinxLogic.decide(after1, rid2, blob2, store.accounts(), now) as Decision.Drop).why)
        // A pairing saved before the window (no gaps) stays strict; the window reaches SIZE back at most.
        assertEquals("replay", (SphinxLogic.decide(pairing.copy(recv = 2), rid1, blob1, store.accounts(), now) as Decision.Drop).why)
        assertEquals(ReplayWindow.SIZE - 1, ReplayWindow.after(100, 2, emptyList()).second.size)
    }

    @Test fun theDomainListAnswersWithoutHim() {
        accounts("GitHub" to "w", "Hetzner" to "me", "Acme" to "x")
        val (rid, blob) = req(mapOf("t" to "domains", "rid" to "D".repeat(22)))
        val d = SphinxLogic.decide(pairing, rid, blob, store.accounts(), now) as Decision.Answer
        assertEquals("domains.reply", d.reply["kind"])
        assertEquals(listOf("accounts.hetzner.com", "github.com"), (d.reply["body"] as Map<*, *>)["domains"])
        assertEquals(0, keys.unwraps)
    }

    @Test fun theCodeNeedsTheFingerprintAndRepliesAreSealedWithACounter() {
        val a = accounts("GitHub" to "w").single()
        // The secret is only ciphertext in the store.
        assertFalse(kv.values.joinToString().contains("GEZDGNBV"))
        assertFalse(kv.values.any { it.contains(String(secret)) })
        try { store.code(a, store.unwrapper(), 59_000); error("opened without a fingerprint") } catch (_: IllegalStateException) {}
        keys.approved = true
        assertEquals("287082", store.code(a, store.unwrapper(), 59_000))
        val (blob, next) = SphinxLogic.reply(pairing, SphinxLogic.code("R".repeat(22), a, "287082", 59_000), now)
        assertEquals(1L, next.sent)
        val o = SphinxCrypto.open(pairing.p2l, pairing.pid, 'r', blob, 0, now) as Opened.Ok
        val body = json.readTree(o.plain)
        assertEquals("code.reply", body.path("kind").asText()); assertEquals(1, body.path("v").asInt()); assertEquals("R".repeat(22), body.path("rid").asText())
        assertEquals("287082", body.path("body").path("code").asText()); assertEquals("w", body.path("body").path("account").asText())
        // Made at 59 s: 1 s left, and its period ends at unix second 60, so the laptop drops it if it arrives later.
        assertEquals(1, body.path("body").path("ttl").asInt()); assertEquals(60L, body.path("body").path("until").asLong())
        assertTrue(SphinxCrypto.open(pairing.p2l, pairing.pid, 'r', blob, 1, now) is Opened.No)
    }

    @Test fun kindsThatArentBuiltYetAreRefusedSealedNeverActedOn() {
        accounts("GitHub" to "w")
        for ((i, kind) in listOf("tab.send", "sms.code", "clip.send", "presence", "call.ring", "").withIndex()) {
            val env = SphinxLogic.envelope(kind, "K".repeat(22), mapOf("url" to "https://github.com"))
            val blob = SphinxCrypto.seal(pairing.l2p, pairing.pid, 'q', i + 1L, now + 60_000, json.writeValueAsBytes(env))
            val d = SphinxLogic.decide(pairing, "K".repeat(22), blob, store.accounts(), now) as Decision.Answer
            assertEquals("error", d.reply["kind"]); assertEquals("unsupported kind", (d.reply["body"] as Map<*, *>)["why"])
        }
        // An envelope of another version, or not an envelope at all, is dropped.
        val old = SphinxCrypto.seal(pairing.l2p, pairing.pid, 'q', 1, now + 60_000, """{"v":2,"kind":"code.request","rid":"${"R".repeat(22)}"}""".toByteArray())
        assertEquals("envelope version", (SphinxLogic.decide(pairing, "R".repeat(22), old, store.accounts(), now) as Decision.Drop).why)
        val list = SphinxCrypto.seal(pairing.l2p, pairing.pid, 'q', 1, now + 60_000, "[1,2]".toByteArray())
        assertEquals("unreadable", (SphinxLogic.decide(pairing, "R".repeat(22), list, store.accounts(), now) as Decision.Drop).why)
        assertEquals(setOf("code.request", "code.ready", "domains.request", "handoff.send"), SphinxLogic.KINDS)
    }

    // ---- pre-approval (code.ready) ----

    private fun ask(kind: String, rid: Char, host: String, ctr: Long, user: String = ""): Pending =
        (SphinxLogic.decide(pairing, rid.toString().repeat(22), req(mapOf("kind" to kind, "rid" to rid.toString().repeat(22), "host" to host, "user" to user), ctr = ctr).second, store.accounts(), now) as Decision.Ask).pending

    /** His fingerprint on [ready] for its single account: the window it opens. */
    private fun approve(ready: Pending): Primed {
        val a = ready.accounts.single()
        keys.approved = true
        return SphinxLogic.prime(ready, a, store.codes(a, keys.unwrapper(), SphinxLogic.windowTimes(now, a.period)), now)
    }

    // 2026-10-26: the laptop holds the window's codes, so the code field fills with no trip to the phone.
    @Test fun anApprovedReadyHandsTheLaptopTheWindowsCodesCutAtItsEnd() {
        accounts("GitHub" to "alex-work")
        val a = store.accounts().single()
        val at = 1_000_000_040_000L   // 20 s into a 30 s period (1_000_000_020 starts one): the 60 s window spans this period and the next two
        val times = SphinxLogic.windowTimes(at, a.period)
        val held = SphinxLogic.held(a, times, listOf("111111", "222222", "222222").take(times.size), at)
        @Suppress("UNCHECKED_CAST") val codes = held["codes"] as List<Map<String, Any?>>
        assertEquals(listOf("111111", "222222", "222222"), codes.map { it["code"] })
        assertEquals(1_000_000_020L, codes[0]["from"]); assertEquals(1_000_000_050L, codes[0]["until"])
        assertEquals(1_000_000_050L, codes[1]["from"]); assertEquals(1_000_000_080L, codes[1]["until"])
        assertEquals(1_000_000_080L, codes[2]["from"]); assertEquals(1_000_000_100L, codes[2]["until"])   // the window's end, not the period's
        assertEquals(true, (SphinxLogic.readied("r".repeat(22), true, held = held)["body"] as Map<*, *>)["ok"])
    }

    @Test fun aReadyAsksHimLikeACodeRequestAndItsAnswerNeverCarriesACode() {
        accounts("GitHub" to "alex-work")
        val r = ask("code.ready", 'Y', "github.com", 1)
        assertTrue(r.ready)
        assertEquals("Signing in to github.com (alex-work): approve the code for 60 s?", SphinxLogic.question(r))
        assertEquals("Signing in to github.com (GitHub): approve the code for 60 s?", SphinxLogic.question(r, names = false))
        for (body in listOf(SphinxLogic.readied(r.rid, true), SphinxLogic.no(r, "denied"), SphinxLogic.no(r, "expired"))) {
            assertEquals("code.ready.reply", body["kind"])
            assertFalse((body["body"] as Map<*, *>).containsKey("code"))
        }
        assertEquals(0, keys.unwraps)
        // Not a saved site: refused like a code request, in its own kind.
        val d = SphinxLogic.decide(pairing, "Z".repeat(22), req(mapOf("kind" to "code.ready", "rid" to "Z".repeat(22), "host" to "gitlab.com"), ctr = 2).second, store.accounts(), now) as Decision.Answer
        assertEquals("code.ready.reply", d.reply["kind"]); assertEquals("no account", (d.reply["body"] as Map<*, *>)["why"])
    }

    @Test fun theWindowOpensOnlyOnHisFingerprintAndOneUnwrapCoversIt() {
        val a = accounts("GitHub" to "alex-work").single()
        val r = ask("code.ready", 'Y', "github.com", 1)
        assertTrue(runCatching { store.codes(a, keys.unwrapper(), SphinxLogic.windowTimes(now, a.period)) }.isFailure)
        approve(r)
        assertEquals(1, keys.unwraps)
    }

    @Test fun aCodeRequestInTheWindowIsServedWithoutAPromptAndSpendsIt() {
        accounts("GitHub" to "alex-work")
        val w = PreApproval().apply { open(approve(ask("code.ready", 'Y', "github.com", 1))) }
        val req = ask("code.request", 'R', "github.com", 2)
        for (at in listOf(now + 1_000, now + 29_000)) assertEquals(Totp.code(secret, at), SphinxLogic.served(approve(ask("code.ready", 'Y', "github.com", 9)), req, at)?.second)
        val (acc, code) = w.take(req, now + 5_000)!!
        assertEquals("alex-work", acc.name); assertEquals(Totp.code(secret, now + 5_000), code)
        // Spent on one delivered code: the next asks him as today.
        assertNull(w.take(ask("code.request", 'S', "github.com", 3), now + 6_000))
    }

    @Test fun outsideTheWindowAnotherSitePairingOrAccountFallsBack() {
        accounts("GitHub" to "alex-work", "GitLab" to "alex")
        val w = approve(ask("code.ready", 'Y', "github.com", 1))
        val req = ask("code.request", 'R', "github.com", 2)
        assertTrue(SphinxLogic.served(w, req, now + 59_999) != null)
        assertNull(SphinxLogic.served(w, req, now + 60_000))
        assertNull(SphinxLogic.served(w, ask("code.request", 'S', "gitlab.com", 3), now + 1_000))
        assertNull(SphinxLogic.served(w, req.copy(pid = "Q".repeat(22)), now + 1_000))
        // The page named another account than the one he approved.
        assertNull(SphinxLogic.served(w, req.copy(picked = "someone-else"), now + 1_000))
        // A ready never draws a code from a window, and a denied one opens nothing (no window, no unwrap).
        assertNull(SphinxLogic.served(w, ask("code.ready", 'U', "github.com", 4), now + 1_000))
        assertNull(PreApproval().take(ask("code.request", 'V', "github.com", 5), now + 1_000))
    }

    @Test fun theWindowIsThePairingAndTheSiteNotTheExactHost() {
        val a = accounts("AWS" to "alex").single()
        store.update(a.copy(domains = listOf("signin.aws.amazon.com", "*.signin.aws.amazon.com")))
        val w = approve(ask("code.ready", 'Y', "signin.aws.amazon.com", 1))
        assertEquals(Totp.code(secret, now + 2_000), SphinxLogic.served(w, ask("code.request", 'R', "us-east-1.signin.aws.amazon.com", 2), now + 2_000)?.second)
    }

    // 2026-10-27: a code request no longer waits behind an unanswered pre-approval (up to 60 s); it takes its place.
    @Test fun aCodeRequestTakesThePlaceOfItsSitesUnansweredPreApprovalOnly() {
        accounts("GitHub" to "alex-work", "GitLab" to "alex")
        val ready = ask("code.ready", 'Y', "github.com", 1)
        assertEquals(listOf(ready), SphinxLogic.supersedes(listOf(ready), ask("code.request", 'R', "github.com", 2), now))
        assertEquals(emptyList<Pending>(), SphinxLogic.supersedes(listOf(ready), ask("code.request", 'S', "gitlab.com", 3), now))
        assertEquals(emptyList<Pending>(), SphinxLogic.supersedes(listOf(ready), ask("code.request", 'T', "github.com", 4), ready.expires))
        assertEquals(emptyList<Pending>(), SphinxLogic.supersedes(listOf(ready), ask("code.ready", 'U', "github.com", 5), now))
    }

    @Test fun theWindowIsSixtySecondsAndItsCodesCoverEveryPeriodItTouches() {
        assertEquals(60_000L, SphinxLogic.WINDOW_MS)
        val t = 1_800_000_029_000L
        assertEquals(listOf(t, t + 30_000, t + 60_000), SphinxLogic.windowTimes(t, 30))
    }

    @Test fun theCopyScreenNamesOnlyTheIssuerOverTheKeyguard() {
        val a = accounts("GitHub" to "alex-work").single()
        assertEquals("GitHub (alex-work)", SphinxLogic.copyLabel(a, names = true))
        assertEquals("GitHub", SphinxLogic.copyLabel(a, names = false))
        assertEquals("Account", SphinxLogic.copyLabel(a.copy(issuer = ""), names = false))
        // The activity uses it for both the screen and the prompt title, and checks the keyguard first.
        val src = java.io.File("src/main/java/dev/sphinx/ApproveActivity.kt").readText()
        assertTrue(src.contains("SphinxLogic.copyLabel(acc, getSystemService(KeyguardManager::class.java)?.isKeyguardLocked != true)"))
        assertFalse(src.contains("acc.title()"))
    }

    @Test fun aFrameOnAnotherSavedSiteGetsNothing() {
        accounts("GitHub" to "w", "GitLab" to "x")
        val (rid, blob) = req(mapOf("t" to "code", "rid" to "R".repeat(22), "host" to "github.com", "frame" to "gitlab.com"))
        val d = SphinxLogic.decide(pairing, rid, blob, store.accounts(), now) as Decision.Answer
        assertEquals("no account", (d.reply["body"] as Map<*, *>)["why"])
        // The same site in tab and frame is fine; the pending request remembers the frame.
        val (rid2, blob2) = req(mapOf("t" to "code", "rid" to "S".repeat(22), "host" to "github.com", "frame" to "github.com"), ctr = 2)
        assertEquals("github.com", (SphinxLogic.decide(pairing, rid2, blob2, store.accounts(), now) as Decision.Ask).pending.frame)
        // The domain list says which sites sit on one account (no names), so the laptop can check the same.
        val (rid3, blob3) = req(mapOf("t" to "domains", "rid" to "D".repeat(22)), ctr = 3)
        assertEquals(listOf(listOf("github.com"), listOf("gitlab.com")), ((SphinxLogic.decide(pairing, rid3, blob3, store.accounts(), now) as Decision.Answer).reply["body"] as Map<*, *>)["groups"])
    }

    @Test fun aRequestKeepsTheLaptopsOwnExpiry() {
        accounts("GitHub" to "w")
        // Sealed by the laptop 50 s ago: 10 s left, not a fresh 60.
        val (rid, blob) = req(mapOf("t" to "code", "rid" to "R".repeat(22), "host" to "github.com"), exp = now + 10_000)
        assertEquals(now + 10_000, (SphinxLogic.decide(pairing, rid, blob, store.accounts(), now) as Decision.Ask).pending.expires)
        // And an expiry further out than 60 s is held to 60 s.
        val (rid2, blob2) = req(mapOf("t" to "code", "rid" to "S".repeat(22), "host" to "github.com"), ctr = 2, exp = now + 110_000)
        assertEquals(now + 60_000, (SphinxLogic.decide(pairing, rid2, blob2, store.accounts(), now) as Decision.Ask).pending.expires)
    }

    @Test fun aNewFingerprintClearsTheCodesInsteadOfBrickingThem() {
        accounts("GitHub" to "w", "Hetzner" to "x")
        store.putPairing(pairing)
        keys.broken = Invalidated()
        val e = runCatching { store.unwrapper() }.exceptionOrNull()
        assertTrue(e is SphinxStore.Cleared)
        assertEquals("Codes cleared by a new fingerprint: restore them from your backup (Accounts, Restore), or import again", e!!.message)
        assertTrue(store.accounts().isEmpty())
        assertEquals(1, dropped)
        assertEquals(pairing.pid, store.pairing(pairing.pid)?.pid)          // the laptops stay paired
        // Any other failure is not a reason to wipe.
        accounts("GitHub" to "w")
        keys.broken = IllegalStateException("busy")
        assertTrue(runCatching { store.unwrapper() }.exceptionOrNull() is IllegalStateException)
        assertEquals(1, store.accounts().size)
        assertEquals(1, dropped)
    }

    @Test fun theRetireMarkerIsWrittenBeforeTheKeyGoesAndWithoutItNothingGoes() {
        val order = ArrayList<String>()
        var failMarker = false
        val k = FakeKeys().apply { broken = Invalidated() }
        val kv2 = HashMap<String, String>()
        val s = SphinxStore({ kv2[it] }, { a, v -> if (v == null) kv2.remove(a) else kv2[a] = v }, k, { now }, dropKey = { order += "drop" },
            invalidated = { it is Invalidated }, retiring = { if (failMarker) error("disk full"); order += "marker" })
        s.add(listOf(Imported("GitHub", "w", secret.copyOf(), Algo.SHA1, 6, 30)))
        failMarker = true
        assertFalse(runCatching { s.unwrapper() }.exceptionOrNull() is SphinxStore.Cleared)
        assertEquals(emptyList<String>(), order)                          // no marker: nothing dropped, the account stays
        assertEquals(1, s.accounts().size)
        failMarker = false
        assertTrue(runCatching { s.unwrapper() }.exceptionOrNull() is SphinxStore.Cleared)
        assertEquals(listOf("marker", "drop"), order)
    }

    @Test fun eachAccountHasItsOwnNotificationSlot() {
        val made = accounts(*(1..45).map { "Issuer$it" to "n$it" }.toTypedArray())
        assertEquals((0 until 45).toList(), made.map { it.slot })
        store.delete(made[3].id)
        val again = accounts("New" to "y").single()
        assertEquals(3, again.slot)                                         // a freed slot is reused, never a shared one
        assertEquals(store.accounts().size, store.accounts().map { it.slot }.toSet().size)
        // An edit keeps the slot.
        store.update(again.copy(domains = listOf("new.example"), slot = 99))
        assertEquals(3, store.accounts().first { it.id == again.id }.slot)
    }

    @Test fun pairingCountersSurviveConcurrentUpdates() {
        store.putPairing(pairing)
        val threads = (1..8).map { Thread { repeat(25) { store.updatePairing(pairing.pid) { p -> SphinxLogic.reply(p, mapOf("x" to 1), now).second } } } }
        threads.forEach { it.start() }; threads.forEach { it.join() }
        assertEquals(200L, store.pairing(pairing.pid)!!.sent)
        assertNull(store.updatePairing("gone") { it })
    }

    @Test fun sitesEditKeepTheSealedSecret() {
        val a = accounts("Acme" to "x").single()
        assertTrue(a.domains.isEmpty())
        store.update(a.copy(domains = listOf("acme.io"), wk = ByteArray(0), ct = ByteArray(0)))
        val b = store.accounts().single()
        assertEquals(listOf("acme.io"), b.domains)
        keys.approved = true
        assertEquals(Totp.code(secret, now), store.code(b, store.unwrapper()))
        store.delete(b.id)
        assertTrue(store.accounts().isEmpty())
        assertTrue(SphinxStore.ACCOUNTS !in kv)
    }

    // ---- codes from an SMS or email (2026-10-25) ----

    @Test fun aTextedCodeSiteWaitsForATextAndGoesToTheLaptopAsItsOwnSite() {
        accounts("GitHub" to "w")
        store.saveTextSites(listOf("shop.example", "github.io", "not a host"))
        assertEquals(listOf("shop.example"), store.textSites())                  // a public suffix or junk is never saved
        val (rid, blob) = req(mapOf("t" to "code", "rid" to "R".repeat(22), "host" to "shop.example", "frame" to "shop.example"))
        val d = SphinxLogic.decide(pairing, rid, blob, store.accounts(), now, textSites = store.textSites()) as Decision.Ask
        assertTrue(d.pending.textOnly)
        assertTrue(d.pending.accounts.isEmpty())
        assertEquals(now + 60_000, d.pending.expires)
        // A frame on another site, a lookalike, or the same site without the list: refused, nothing waits.
        for ((i, f) in listOf("shop.example" to "evil.io", "shop.example.evil.io" to "shop.example.evil.io").withIndex()) {
            val (r2, b2) = req(mapOf("t" to "code", "rid" to "S$i".padEnd(22, 'x'), "host" to f.first, "frame" to f.second), ctr = 2L + i)
            assertEquals("no account", ((SphinxLogic.decide(pairing, r2, b2, store.accounts(), now, textSites = store.textSites()) as Decision.Answer).reply["body"] as Map<*, *>)["why"])
        }
        val (r3, b3) = req(mapOf("t" to "code", "rid" to "T".repeat(22), "host" to "shop.example"), ctr = 9)
        assertTrue(SphinxLogic.decide(pairing, r3, b3, store.accounts(), now) is Decision.Answer)
        // The laptop learns it as a one-site group, beside the accounts' groups.
        val (rd, bd) = req(mapOf("t" to "domains", "rid" to "D".repeat(22)), ctr = 10)
        val body = (SphinxLogic.decide(pairing, rd, bd, store.accounts(), now, textSites = store.textSites()) as Decision.Answer).reply["body"] as Map<*, *>
        assertEquals(listOf("github.com", "shop.example"), body["domains"])
        assertEquals(listOf(listOf("github.com"), listOf("shop.example")), body["groups"])
        assertEquals(0, keys.unwraps)
    }

    @Test fun aTextedCodeGoesBackSealedMarkedViaTextToTheNewestFreshRequest() {
        val (blob, _) = SphinxLogic.reply(pairing, SphinxLogic.texted("R".repeat(22), "4829"), now)
        val b = json.readTree((SphinxCrypto.open(pairing.p2l, pairing.pid, 'r', blob, 0, now) as Opened.Ok).plain).path("body")
        assertEquals("4829", b.path("code").asText()); assertEquals("text", b.path("via").asText()); assertTrue(b.path("ok").asBoolean())
        val old = Pending("A".repeat(22), pairing.pid, "L", "a.example", accounts = emptyList(), picked = null, expires = now + 10_000)
        val new = old.copy(rid = "B".repeat(22), expires = now + 50_000)
        val gone = old.copy(rid = "C".repeat(22), expires = now - 1)
        assertEquals(new.rid, SphinxLogic.forText(listOf(old, new, gone), now)?.rid)
        assertNull(SphinxLogic.forText(listOf(gone), now))                        // no fresh request: nothing is offered
        // A pre-approval takes no code: a texted one never goes to it (a code request for its site would be left waiting).
        assertEquals(old.rid, SphinxLogic.forText(listOf(old, new.copy(ready = true)), now)?.rid)
        assertNull(SphinxLogic.forText(listOf(new.copy(ready = true)), now))
    }

    @Test fun aTextedCodeSendsExactlyTheOfferItsPromptShowed() {
        val t = TextOffers()
        val shown = t.offer("P/R", "482913")
        // Another text arrives while the prompt is up: the answer to the old prompt sends nothing.
        val newer = t.offer("P/R", "551200")
        assertFalse(t.take(shown))
        assertTrue(t.take(newer))
        assertFalse(t.take(newer))                                         // once
        assertNull(t["P/R"])
    }

    @Test fun aWaitingRequestCantBeReplacedAndAnAnswerTakesOnlyTheOneShown() {
        val w = Waiting<Pending> { it.waitId }
        val shown = Pending("R".repeat(22), pairing.pid, "L", "github.com", accounts = emptyList(), picked = null, expires = now + 60_000)
        assertTrue(w.add(shown))
        // Another request under the same pairing and rid is refused; the one on screen stays.
        val swapped = shown.copy(host = "evil.example")
        assertFalse(w.add(swapped))
        assertTrue(w[shown.waitId] === shown)
        // The same rid from another pairing is another request.
        assertTrue(w.add(shown.copy(pid = "Q".repeat(22))))
        // An answer takes exactly the request it was shown, once; a look-alike takes nothing.
        assertFalse(w.take(swapped))
        assertTrue(w.take(shown))
        assertFalse(w.take(shown))
    }

    @Test fun onlyASmsOrEmailWithCodeWordingAndOneCodeIsOffered() {
        val sms = "com.google.android.apps.messaging"
        assertEquals("482913", Domains.textCode(sms, "AcmeBank", "482913 is your verification code. Don't share it."))
        assertEquals("4829", Domains.textCode(sms, "Shop", "Your Shop code is 4829"))
        assertEquals("12345678", Domains.textCode("com.google.android.gm", "Sign in to Example", "Use 12345678 to sign in. It expires soon."))
        assertEquals("482913", Domains.textCode("com.microsoft.office.outlook", "Your one-time code", "Code: 482913"))
        // A bank's wording (2026-10-26: no offer came); its phone number isn't a second code.
        assertEquals("123456", Domains.textCode(sms, "55501", "Acme Bank: DO NOT share this code. We will NEVER call you or text you for it. Code 123456. Reply HELP if you didn't request this code."))
        assertEquals("123456", Domains.textCode(sms, "55501", "Acme Bank: Your Online Banking authorization code is 123456. If you didn't request it, call 555.010.1234."))
        // Not an SMS or mail app, no code wording, a promo, money, two numbers, too short or too long: nothing.
        assertNull(Domains.textCode("com.whatsapp", "x", "482913 is your verification code"))
        assertNull(Domains.textCode(sms, "Mom", "Call me at 4829 after lunch"))
        assertNull(Domains.textCode(sms, "Shop", "Use promo code 4829 for 20% off"))
        assertNull(Domains.textCode(sms, "Bank", "OTP 482913 for a payment of \$25.00"))
        assertNull(Domains.textCode(sms, "Bank", "Your code is 482913 for the card ending 1234"))
        assertNull(Domains.textCode(sms, "X", "Your code is 482"))
        assertNull(Domains.textCode(sms, "X", "Your code is 482913771"))
        assertNull(Domains.textCode(sms, "X", "Your code is 48-29-13"))
    }

    @Test fun pairingsPersistTheirCounters() {
        store.putPairing(pairing.copy(recv = 4, sent = 2))
        val p = store.pairing(pairing.pid)!!
        assertEquals(4L, p.recv); assertEquals(2L, p.sent)
        assertTrue(p.l2p.contentEquals(pairing.l2p))
        store.unpair(pairing.pid)
        assertNull(store.pairing(pairing.pid))
    }
}
