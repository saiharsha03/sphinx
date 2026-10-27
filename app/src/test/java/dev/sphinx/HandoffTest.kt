package dev.sphinx

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Handoff on the phone: the same rules and chunk format as the extension, its own counter, nothing acted on unchecked. */
class HandoffTest {
    @Test fun aSharingAppNamedOnlyByItsOwnReferrerIsMarkedUnverified() {
        assertEquals("Files", SharedBy.label("Files", verified = true))
        assertEquals("Files (unverified)", SharedBy.label("Files", verified = false))
    }

    @Test fun onlyAFileTheSharingAppGrantedIsRead() {
        val u = "content://com.example.files/doc/1"
        assertEquals(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION, HandoffRules.GRANT_READ)
        assertTrue(HandoffRules.granted(HandoffRules.GRANT_READ, u, listOf(u)))
        // No grant on the intent (Sphinx's own access would read it), or the grant for another URI: refused.
        assertFalse(HandoffRules.granted(0, u, listOf(u)))
        assertFalse(HandoffRules.granted(HandoffRules.GRANT_READ, u, listOf("content://com.example.files/doc/2")))
        assertFalse(HandoffRules.granted(HandoffRules.GRANT_READ, u, emptyList()))
    }

    @Test fun onlyAnotherAppsContentUriIsRead() {
        assertTrue(HandoffRules.shareable("content", "com.example.files.provider", "dev.sphinx"))
        // A file path is read as Sphinx itself: its own backup/key.bin. Refused, as are Sphinx's own providers.
        assertFalse(HandoffRules.shareable("file", null, "dev.sphinx"))
        assertFalse(HandoffRules.shareable("file", "", "dev.sphinx"))
        assertFalse(HandoffRules.shareable("content", "dev.sphinx.androidx-startup", "dev.sphinx"))
        assertFalse(HandoffRules.shareable("content", "dev.sphinx", "dev.sphinx"))
        assertFalse(HandoffRules.shareable("content", "com.example.a;dev.sphinx.firebaseinitprovider", "dev.sphinx"))
        assertFalse(HandoffRules.shareable("content", null, "dev.sphinx"))
        assertFalse(HandoffRules.shareable(null, "com.example", "dev.sphinx"))
        assertTrue(HandoffRules.shareable("CONTENT", "dev.sphinxer.files", "dev.sphinx"))
    }

    private val v = json.readTree(File("../extension/test/vectors.json"))
    private val now = 1_800_000_000_000L - 50_000
    private val pairing = Pairing("P".repeat(22), "Work laptop", ByteArray(32) { 1 }, ByteArray(32) { 2 }, "https://relay.example.com", ByteArray(32) { 3 }, added = now)
    private fun node(s: String) = json.readTree(s)

    @Test fun aChunkMatchesTheVectorAndOpensOnlyInItsPlace() {
        val f = v.path("file")
        val key = SphinxCrypto.dec(f.path("key").asText())!!; val fid = f.path("fid").asText(); val plain = SphinxCrypto.dec(f.path("plain").asText())!!
        assertEquals(f.path("blob").asText(), HandoffRules.sealChunk(key, fid, 1, 3, plain))
        assertArrayEquals(plain, HandoffRules.openChunk(key, fid, 1, 3, f.path("blob").asText()))
        assertNull(HandoffRules.openChunk(key, fid, 0, 3, f.path("blob").asText()))
        assertNull(HandoffRules.openChunk(key, fid, 1, 4, f.path("blob").asText()))
        assertNull(HandoffRules.openChunk(key, "G".repeat(22), 1, 3, f.path("blob").asText()))
    }

    @Test fun thePushDirectionMatchesTheVectorAndHasItsOwnCounter() {
        val p = v.path("push")
        val o = SphinxCrypto.open(SphinxCrypto.dec(v.path("p2l").asText())!!, v.path("pid").asText(), 'p', p.path("blob").asText(), 0, p.path("exp").asLong() - 1000) as Opened.Ok
        assertEquals(p.path("plain").asText(), String(o.plain))
        val (blob, next) = SphinxLogic.push(pairing.copy(sent = 7), "H".repeat(22), HandoffItem("link", url = "https://example.com/", open = true), now)
        assertEquals(1L, next.pushSent); assertEquals(7L, next.sent)       // the replies' counter is untouched
        val back = SphinxCrypto.open(pairing.p2l, pairing.pid, 'p', blob, 0, now) as Opened.Ok
        val env = json.readTree(back.plain)
        assertEquals("handoff.send", env.path("kind").asText()); assertEquals(true, env.path("body").path("open").asBoolean())
        // A laptop reading replies ('r') can't take it for one.
        assertTrue(SphinxCrypto.open(pairing.p2l, pairing.pid, 'r', blob, 0, now) is Opened.No)
        // Its expiry is under the 2 minutes open() allows.
        assertTrue(HandoffRules.PUSH_TTL_MS < 120_000)
    }

    @Test fun linksAreHttpOnlyTextAndFilesHaveCapsNamesStayInTheFolder() {
        for (u in listOf("javascript:alert(1)", "intent://x#Intent;end", "content://x/y", "file:///sdcard/a", "https://u:p@example.com/", "https:///nohost", "x".repeat(3000)))
            assertNull(u, HandoffRules.httpUrl(u))
        assertEquals("https://example.com/a?b=1", HandoffRules.httpUrl(" https://example.com/a?b=1 "))
        assertNull(HandoffRules.item(node("""{"type":"link","url":"javascript:alert(1)"}""")))
        assertNull(HandoffRules.item(node("""{"type":"text","text":"${"é".repeat(1501)}"}""")))
        assertNull(HandoffRules.item(node("""{"type":"text","text":"  "}""")))
        assertNull(HandoffRules.item(node("""{"type":"shell","cmd":"rm"}""")))
        assertEquals("passwd", HandoffRules.safeName("../../etc/passwd"))
        assertEquals("evil.exe", HandoffRules.safeName("C:\\Users\\x\\..\\evil.exe"))
        assertEquals("hidden", HandoffRules.safeName("...hidden"))
        assertEquals("file", HandoffRules.safeName("../"))
        val f = """{"fid":"${"F".repeat(22)}","key":"${"K".repeat(43)}","name":"../a.pdf","mime":"application/pdf","size":${HandoffRules.CHUNK + 1},"chunks":2,"sha256":"${"0".repeat(64)}"}"""
        assertEquals("a.pdf", HandoffRules.item(node("""{"type":"file","file":$f}"""))!!.file!!.name)
        assertNull(HandoffRules.item(node("""{"type":"file","file":${f.replace("\"chunks\":2", "\"chunks\":3")}}""")))
        assertEquals("application/octet-stream", HandoffRules.item(node("""{"type":"file","file":${f.replace("application/pdf", "text/html; x")}}"""))!!.file!!.mime)
    }

    @Test fun aFileRoundTripsAndATamperedOrShortOneIsRefused() {
        val data = ByteArray(HandoffRules.CHUNK + 777) { (it % 251).toByte() }
        val (ref, chunks) = HandoffRules.prepare("../report.pdf", "application/pdf", data)
        assertEquals(2, chunks.size); assertEquals("report.pdf", ref.name)
        assertArrayEquals(data, HandoffRules.assemble(ref, chunks))
        assertNull(HandoffRules.assemble(ref, listOf(chunks[0], null)))
        assertNull(HandoffRules.assemble(ref, chunks.reversed()))
        assertNull(HandoffRules.assemble(ref.copy(sha256 = "0".repeat(64)), chunks))
        assertTrue(runCatching { HandoffRules.prepare("big", "x/y", ByteArray(HandoffRules.MAX_FILE + 1)) }.isFailure)
        // Every file gets its own key.
        assertTrue(HandoffRules.prepare("a", "x/y", data).first.key != ref.key)
    }

    @Test fun aLaptopsHandoffIsDecidedAsOneAndABadOneIsRefused() {
        fun req(body: Map<String, Any?>, ctr: Long): Pair<String, String> {
            val rid = "R$ctr".padEnd(22, 'x')
            return rid to SphinxCrypto.seal(pairing.l2p, pairing.pid, 'q', ctr, now + 60_000, json.writeValueAsBytes(SphinxLogic.envelope("handoff.send", rid, body)))
        }
        val (rid, blob) = req(mapOf("type" to "link", "url" to "https://example.com/x", "open" to true), 1)
        val d = SphinxLogic.decide(pairing, rid, blob, emptyList(), now) as Decision.Handoff
        assertEquals("https://example.com/x", d.item.url); assertTrue(d.item.open); assertEquals(1L, d.pairing.recv)
        val (r2, b2) = req(mapOf("type" to "link", "url" to "javascript:alert(1)"), 2)
        val bad = SphinxLogic.decide(pairing.copy(recv = 1), r2, b2, emptyList(), now) as Decision.Answer
        assertEquals("error", bad.reply["kind"])
        assertNotNull(SphinxLogic.KINDS.find { it == "handoff.send" })
    }

    @Test fun nothingArrivedIsActedOnWithoutATapAndFilesGoToDownloadSphinx() {
        val src = File("src/main/java/dev/sphinx/Share.kt").readText()
        assertTrue(src.contains("Environment.DIRECTORY_DOWNLOADS + \"/Sphinx\""))
        assertTrue(src.contains("Intent(Intent.ACTION_VIEW, Uri.parse(HandoffRules.httpUrl(it.url)!!))"))
        // No startActivity on arrival: links and files open only from the notification's PendingIntent.
        val receive = src.substringAfter("fun receive(").substringBefore("fun send(")
        assertTrue(!receive.contains("startActivity("))
        val manifest = File("src/main/AndroidManifest.xml").readText()
        assertTrue(!manifest.contains("WRITE_EXTERNAL_STORAGE") && !manifest.contains("READ_EXTERNAL_STORAGE") && !manifest.contains("MANAGE_EXTERNAL_STORAGE"))
    }
}
