package dev.sphinx

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** X25519 against RFC 7748, and the whole wire format against the vectors pyca/cryptography made (the extension and the relay check the same file). */
class CryptoTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val v = json.readTree(File("../extension/test/vectors.json"))
    private fun b(k: String) = SphinxCrypto.dec(v.path(k).asText())!!

    @Test fun rfc7748() {
        assertArrayEquals(
            hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
            X25519.mul(hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"), hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")),
        )
        val alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bob = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        assertArrayEquals(hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), X25519.publicKey(alice))
        assertArrayEquals(hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), X25519.publicKey(bob))
        val shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        assertArrayEquals(shared, X25519.mul(alice, X25519.publicKey(bob)))
        assertArrayEquals(shared, X25519.mul(bob, X25519.publicKey(alice)))
    }

    @Test fun pairingMatchesTheVectors() {
        val o = SphinxCrypto.offer(v.path("qr").asText())!!
        assertEquals(v.path("pid").asText(), o.pid)
        assertEquals("Chrome", o.name)
        assertEquals("https://relay.example.com", o.relay)
        assertEquals("", o.token)
        val (p, hello) = SphinxCrypto.accept(o, 1L, b("phone_priv"))!!
        assertArrayEquals(b("l2p"), p.l2p)
        assertArrayEquals(b("p2l"), p.p2l)
        assertArrayEquals(b("relay"), p.relayKey)
        assertEquals("https://relay.example.com", p.relay)
        assertEquals(v.path("hello").asText(), hello)
        assertArrayEquals(b("relay"), SphinxCrypto.relayKey(o))
        assertArrayEquals(b("phone_pub"), X25519.publicKey(b("phone_priv")))
    }

    @Test fun offersThatArentPairingQrs() {
        assertNull(SphinxCrypto.offer("otpauth://totp/x?secret=AAAA"))
        assertNull(SphinxCrypto.offer("sphinx:1?p=short&k=x&s=y"))
        val q = v.path("qr").asText()
        assertNull(SphinxCrypto.offer(q.replace(Regex("&s=[^&]+"), "&s=AAAA")))
        // The relay must be an https origin: no http, no path, no user part.
        for (r in listOf("http://relay.example.com", "https://relay.example.com/v1", "https://u@relay.example.com", ""))
            assertNull(r, SphinxCrypto.offer(q.replace("https://relay.example.com", r)))
        assertEquals("https://relay.example.com", SphinxCrypto.offer(q.replace("https://relay.example.com", "https://relay.example.com/"))!!.relay)
        // The relay's registration token rides along when the laptop set one; a malformed one is dropped.
        assertEquals("tok_1", SphinxCrypto.offer("$q&t=tok_1")!!.token)
        assertEquals("", SphinxCrypto.offer("$q&t=bad%20token")!!.token)
        // An all-zero shared secret (a low-order laptop key) is refused.
        val zero = SphinxCrypto.offer(q.replace(Regex("&k=[^&]+"), "&k=" + SphinxCrypto.enc(ByteArray(32))))!!
        assertNull(SphinxCrypto.accept(zero, 1L))
    }

    @Test fun sealAndOpenMatchTheVectorsAndRefuseReplayAndExpiry() {
        val r = v.path("request")
        val blob = SphinxCrypto.seal(b("l2p"), v.path("pid").asText(), 'q', r.path("ctr").asLong(), r.path("exp").asLong(), r.path("plain").asText().toByteArray(), SphinxCrypto.dec(r.path("iv").asText())!!)
        assertEquals(r.path("blob").asText(), blob)
        val rep = v.path("reply")
        val now = rep.path("exp").asLong() - 30_000
        val ok = SphinxCrypto.open(b("p2l"), v.path("pid").asText(), 'r', rep.path("blob").asText(), 0, now) as Opened.Ok
        assertEquals(rep.path("plain").asText(), ok.plain.toString(Charsets.UTF_8))
        fun why(key: ByteArray = b("p2l"), pid: String = v.path("pid").asText(), dir: Char = 'r', blob: String = rep.path("blob").asText(), last: Long = 0, at: Long = now) =
            (SphinxCrypto.open(key, pid, dir, blob, last, at) as Opened.No).why
        assertEquals("replay", why(last = 3))
        assertEquals("expired", why(at = rep.path("exp").asLong() + 1))
        assertEquals("expiry too far out", why(at = rep.path("exp").asLong() - 200_000))
        assertEquals("direction", why(dir = 'q'))
        assertEquals("bad seal", why(key = b("l2p")))
        assertEquals("bad seal", why(pid = "x".repeat(22)))
        val t = SphinxCrypto.dec(rep.path("blob").asText())!!.also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertEquals("bad seal", why(blob = SphinxCrypto.enc(t)))
        assertEquals("malformed", why(blob = "AAAA"))
    }

    @Test fun theRelaySignatureMatchesTheServerAndTheExtension() {
        val s = v.path("sign")
        val h = SphinxCrypto.signed(b("relay"), "P".repeat(22), s.path("method").asText(), s.path("path").asText(), s.path("query").asText(),
            s.path("body").asText().toByteArray(), s.path("ts").asLong() * 1000, s.path("nonce").asText())
        assertEquals(s.path("sig").asText(), h["x-sphinx-sig"])
        assertEquals(s.path("ts").asText(), h["x-sphinx-ts"])
        assertEquals("P".repeat(22), h["x-sphinx-pid"])
    }

    @Test fun aFreshPairingRoundTrips() {
        val laptop = X25519.newPrivate()
        val o = Offer(SphinxCrypto.newId(), X25519.publicKey(laptop), ByteArray(16) { it.toByte() }, "https://relay.example.com", "L")
        val (p, hello) = SphinxCrypto.accept(o, 5L)!!
        val phonePub = SphinxCrypto.dec(hello)!!.copyOf(32)
        val keys = Hkdf.derive(X25519.mul(laptop, phonePub), o.secret, "sphinx v1|${o.pid}", 64)
        assertArrayEquals(keys.copyOfRange(0, 32), p.l2p)
        val blob = SphinxCrypto.seal(p.p2l, p.pid, 'r', 1, 100_000, "hi".toByteArray())
        assertTrue(SphinxCrypto.open(keys.copyOfRange(32, 64), p.pid, 'r', blob, 0, 50_000) is Opened.Ok)
        assertNotNull(SphinxCrypto.tag(p))
    }
}
