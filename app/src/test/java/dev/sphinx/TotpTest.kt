package dev.sphinx

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.util.Base64

class TotpTest {
    private val sha1 = "12345678901234567890".toByteArray()
    private val sha256 = "12345678901234567890123456789012".toByteArray()
    private val sha512 = "1234567890123456789012345678901234567890123456789012345678901234".toByteArray()

    /** RFC 6238 Appendix B, all three algorithms, 8 digits, 30 s. */
    @Test fun rfc6238Vectors() {
        val rows = listOf(
            59L to listOf("94287082", "46119246", "90693936"),
            1111111109L to listOf("07081804", "68084774", "25091201"),
            1111111111L to listOf("14050471", "67062674", "99943326"),
            1234567890L to listOf("89005924", "91819424", "93441116"),
            2000000000L to listOf("69279037", "90698825", "38618901"),
            20000000000L to listOf("65353130", "77737706", "47863826"),
        )
        for ((t, want) in rows) {
            assertEquals("$t sha1", want[0], Totp.code(sha1, t * 1000, Algo.SHA1, 8))
            assertEquals("$t sha256", want[1], Totp.code(sha256, t * 1000, Algo.SHA256, 8))
            assertEquals("$t sha512", want[2], Totp.code(sha512, t * 1000, Algo.SHA512, 8))
        }
        // Six digits are the last six of the same truncation.
        assertEquals("287082", Totp.code(sha1, 59_000))
        assertEquals(1, Totp.left(59_000))
        assertEquals(30, Totp.left(60_000))
    }

    @Test fun base32() {
        assertArrayEquals("12345678901234567890".toByteArray(), Totp.base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
        assertArrayEquals("12345678901234567890".toByteArray(), Totp.base32("gezd gnbv gy3t qojq gezd gnbv gy3t qojq"))
        assertNull(Totp.base32("not base32!"))
    }

    @Test fun plainOtpauth() {
        val r = Totp.parse("otpauth://totp/GitHub:alex-work?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub")!!
        val a = r.accounts.single()
        assertEquals("GitHub", a.issuer); assertEquals("alex-work", a.name); assertEquals(Algo.SHA1, a.algo); assertEquals(6, a.digits); assertEquals(30, a.period)
        val s = Totp.parse("otpauth://totp/Acme%20Corp:me%40acme.io?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60")!!.accounts.single()
        assertEquals("Acme Corp", s.issuer); assertEquals("me@acme.io", s.name); assertEquals(Algo.SHA256, s.algo); assertEquals(8, s.digits); assertEquals(60, s.period)
        // HOTP and anything else is refused, plainly.
        val h = Totp.parse("otpauth://hotp/Bank:me?secret=GEZDGNBV&counter=3")!!
        assertTrue(h.accounts.isEmpty()); assertTrue(h.refused.single().why.contains("HOTP"))
        assertTrue(Totp.parse("otpauth://totp/X:y?secret=GEZDGNBV&digits=7")!!.refused.single().why.contains("7-digit"))
        assertTrue(Totp.parse("otpauth://totp/X:y?secret=GEZDGNBV&algorithm=MD5")!!.refused.isNotEmpty())
        assertNull(Totp.parse("https://github.com"))
    }

    // ---- a MigrationPayload built here, field by field ----

    private fun varint(o: ByteArrayOutputStream, v: Long) { var x = v; while (x and 0x7fL.inv() != 0L) { o.write(((x and 0x7f) or 0x80).toInt()); x = x ushr 7 }; o.write(x.toInt()) }
    private fun field(o: ByteArrayOutputStream, n: Int, b: ByteArray) { varint(o, (n shl 3 or 2).toLong()); varint(o, b.size.toLong()); o.write(b) }
    private fun field(o: ByteArrayOutputStream, n: Int, v: Long) { varint(o, (n shl 3).toLong()); varint(o, v) }

    private fun otp(secret: ByteArray, name: String, issuer: String, algo: Long, digits: Long, type: Long) = ByteArrayOutputStream().also { o ->
        field(o, 1, secret); field(o, 2, name.toByteArray()); field(o, 3, issuer.toByteArray()); field(o, 4, algo); field(o, 5, digits); field(o, 6, type)
    }.toByteArray()

    private fun uri(vararg params: ByteArray, size: Long = 1, index: Long = 0): String {
        val o = ByteArrayOutputStream()
        params.forEach { field(o, 1, it) }
        field(o, 2, 1); field(o, 3, size); field(o, 4, index); field(o, 5, 12345)
        return "otpauth-migration://offline?data=" + URLEncoder.encode(Base64.getEncoder().encodeToString(o.toByteArray()), "UTF-8")
    }

    @Test fun authenticatorExport() {
        val r = Totp.parse(uri(
            otp(sha1, "GitHub:alex-work", "GitHub", 1, 1, 2),
            otp(sha256, "me@example.com", "Dropbox", 2, 2, 2),
            otp(sha1, "Bank:me", "Bank", 1, 1, 1),            // HOTP
            otp(sha1, "Old:me", "Old", 4, 1, 2),             // MD5
            size = 3, index = 1,
        ))!!
        assertEquals(listOf("GitHub" to "alex-work", "Dropbox" to "me@example.com"), r.accounts.map { it.issuer to it.name })
        assertEquals(Algo.SHA256, r.accounts[1].algo); assertEquals(8, r.accounts[1].digits); assertEquals(30, r.accounts[1].period)
        assertArrayEquals(sha1, r.accounts[0].secret)
        assertEquals(Totp.code(sha1, 59_000), Totp.code(r.accounts[0].secret, 59_000))
        assertEquals(listOf("Bank · me", "Old · me"), r.refused.map { it.label })
        assertTrue(r.refused[0].why.contains("HOTP"))
        assertEquals(2 to 3, r.batch)
        // Broken data is "not an export", not a crash.
        assertNull(Totp.parse("otpauth-migration://offline?data=%%%"))
        assertNull(Totp.parse("otpauth-migration://offline?data=" + Base64.getEncoder().encodeToString(byteArrayOf(0x0a, 0x7f, 1))))
    }
}
