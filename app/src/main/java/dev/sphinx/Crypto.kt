package dev.sphinx

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** HKDF-SHA256 (RFC 5869). */
object Hkdf {
    fun derive(ikm: ByteArray, salt: ByteArray, info: String, length: Int = 32): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var n = 1
        while (out.size() < length) {
            mac.update(t); mac.update(info.toByteArray()); mac.update(n.toByte())
            t = mac.doFinal(); out.write(t); n++
        }
        return out.toByteArray().copyOf(length)
    }
}

/**
 * X25519 (RFC 7748) in plain Kotlin: Keystore and the Android versions Sphinx runs on don't all offer XDH, and the
 * phone's half is used once, at pairing, then thrown away (only the derived keys are kept, sealed). Not constant-time;
 * with a single use per key there is nothing to time.
 */
object X25519 {
    private val P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val A24 = BigInteger.valueOf(121665)
    private val BASE = ByteArray(32).also { it[0] = 9 }

    private fun le(b: ByteArray) = BigInteger(1, b.reversedArray())
    private fun out(x: BigInteger): ByteArray {
        val be = x.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        return (ByteArray(32 - be.size) + be).reversedArray()
    }

    fun mul(k: ByteArray, u: ByteArray): ByteArray {
        require(k.size == 32 && u.size == 32)
        val s = k.copyOf().also { it[0] = (it[0].toInt() and 248).toByte(); it[31] = ((it[31].toInt() and 127) or 64).toByte() }
        val x1 = le(u.copyOf().also { it[31] = (it[31].toInt() and 127).toByte() }).mod(P)
        var x2 = BigInteger.ONE; var z2 = BigInteger.ZERO; var x3 = x1; var z3 = BigInteger.ONE
        var swap = 0
        for (t in 254 downTo 0) {
            val bit = (s[t / 8].toInt() shr (t % 8)) and 1
            if (swap xor bit == 1) { x2 = x3.also { x3 = x2 }; z2 = z3.also { z3 = z2 } }
            swap = bit
            val a = x2.add(z2).mod(P); val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P); val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P); val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P); val cb = c.multiply(b).mod(P)
            x3 = da.add(cb).pow(2).mod(P)
            z3 = x1.multiply(da.subtract(cb).pow(2)).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e))).mod(P)
        }
        if (swap == 1) { x2 = x3; z2 = z3 }
        return out(x2.multiply(z2.modPow(P.subtract(BigInteger.valueOf(2)), P)).mod(P))
    }

    fun publicKey(priv: ByteArray): ByteArray = mul(priv, BASE)
    fun newPrivate(random: SecureRandom = SecureRandom()): ByteArray = ByteArray(32).also { random.nextBytes(it) }
}

/** One paired laptop, as the phone keeps it (sealed). The keys are derived; neither private key is kept. */
data class Pairing(
    val pid: String = "",
    val name: String = "",
    /** Laptop to phone (requests) and phone to laptop (replies), AES-256-GCM. */
    val l2p: ByteArray = ByteArray(0),
    val p2l: ByteArray = ByteArray(0),
    /** The relay this pairing lives on (from the QR) and its HMAC key there, the only key the relay learns. */
    val relay: String = "",
    val relayKey: ByteArray = ByteArray(0),
    /** The highest request counter accepted so far, and the last reply counter sent. */
    val recv: Long = 0,
    val sent: Long = 0,
    val added: Long = 0,
    val lastUsed: Long = 0,
    /** The relay wakes this pairing's phone through FCM (it said so to the push token): no long poll for it then. */
    val push: Boolean = false,
    /** The last phone-to-laptop handoff counter sent (direction 'p', its own counter beside the replies'). */
    val pushSent: Long = 0,
)

/** The laptop's pairing QR, parsed. [token] is the relay's registration token, when it asks for one (not part of any key). */
data class Offer(val pid: String, val laptop: ByteArray, val secret: ByteArray, val relay: String, val name: String, val token: String = "")

/** What opening a blob gave: the plaintext, or the reason it was refused (for the log, never the content). */
sealed class Opened {
    /** [exp] is the sender's sealed expiry: what a request is held to, never a fresh 60 s from when it arrived. */
    class Ok(val ctr: Long, val plain: ByteArray, val exp: Long = Long.MAX_VALUE) : Opened()
    class No(val why: String) : Opened()
}

/**
 * Sphinx's wire format, shared with the Chrome extension (extension/crypto.js, same test vectors):
 *  QR      sphinx:1?p=<pid>&k=<laptop X25519 public>&s=<16-byte secret>&r=<relay URL>&n=<name>[&t=<relay token>]
 *          (b64url, no padding)
 *  ecdh    X25519(phone private, laptop public); all-zero refused
 *  keys    HKDF-SHA256(ecdh, salt = secret, info = "sphinx v1|<pid>", 64): l2p = first 32, p2l = last 32
 *  relay   HKDF-SHA256(secret, salt = pid, info = "sphinx relay v1"): the relay's HMAC key, the only one it learns
 *  hello   phone public (32) | HMAC-SHA256(HKDF(secret, pid, "sphinx hello v1"), "sphinx hello v1|pid|laptop|phone")
 *          so the relay, which never saw the QR, can't slip in a key of its own.
 *  blob    b64url( 1 | dir ('q' request, 'r' reply) | ctr u64 | exp ms u64 | iv 12 | AES-GCM ciphertext and tag )
 *          AAD = "sphinx|<pid>|" + the 18 header bytes. Refused: wrong version or direction, ctr not above the last
 *          one taken, expired, or an expiry more than 2 minutes out.
 */
object SphinxCrypto {
    const val TTL_MS = 60_000L
    private const val SKEW_MS = 120_000L
    private val random = SecureRandom()
    private val b64u = Base64.getUrlEncoder().withoutPadding()
    private val b64d = Base64.getUrlDecoder()
    /** The relay: an https origin, no path (its routes are /v1/...). */
    private val RELAY = Regex("^https://[a-z0-9.-]+(:[0-9]{1,5})?$")

    fun enc(b: ByteArray): String = b64u.encodeToString(b)
    fun dec(s: String): ByteArray? = runCatching { b64d.decode(s) }.getOrNull()
    fun newId(bytes: Int = 16): String = enc(ByteArray(bytes).also { random.nextBytes(it) })

    fun offer(qr: String): Offer? {
        val s = qr.trim()
        if (!s.startsWith("sphinx:1?")) return null
        val q = s.substringAfter('?').split('&').filter { '=' in it }.associate { it.substringBefore('=') to URLDecoder.decode(it.substringAfter('='), "UTF-8") }
        val pid = q["p"]?.takeIf { Regex("^[A-Za-z0-9_-]{22}$").matches(it) } ?: return null
        val k = q["k"]?.let(::dec)?.takeIf { it.size == 32 } ?: return null
        val sec = q["s"]?.let(::dec)?.takeIf { it.size == 16 } ?: return null
        val relay = q["r"]?.trim()?.lowercase()?.trimEnd('/')?.takeIf { RELAY.matches(it) } ?: return null
        val token = q["t"]?.takeIf { Regex("^[A-Za-z0-9_-]{1,128}$").matches(it) }.orEmpty()
        return Offer(pid, k, sec, relay, q["n"]?.trim()?.take(40)?.ifEmpty { null } ?: "Laptop", token)
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)

    fun relayKey(o: Offer): ByteArray = Hkdf.derive(o.secret, o.pid.toByteArray(), "sphinx relay v1")

    fun hello(o: Offer, phonePub: ByteArray): String {
        val k = Hkdf.derive(o.secret, o.pid.toByteArray(), "sphinx hello v1")
        return enc(phonePub + hmac(k, "sphinx hello v1|${o.pid}|${enc(o.laptop)}|${enc(phonePub)}".toByteArray()))
    }

    /** The phone's side of pairing: its key pair (the private half dropped here), the pairing, the hello for the laptop. */
    fun accept(o: Offer, now: Long, priv: ByteArray = X25519.newPrivate(random)): Pair<Pairing, String>? {
        try {
            val shared = X25519.mul(priv, o.laptop)
            if (shared.all { it == 0.toByte() }) return null
            val keys = Hkdf.derive(shared, o.secret, "sphinx v1|${o.pid}", 64)
            shared.fill(0)
            val pub = X25519.publicKey(priv)
            return Pairing(o.pid, o.name, keys.copyOfRange(0, 32), keys.copyOfRange(32, 64), o.relay, relayKey(o), added = now) to hello(o, pub)
        } finally { priv.fill(0) }
    }

    private fun aad(pid: String, header: ByteArray) = "sphinx|$pid|".toByteArray() + header

    fun seal(key: ByteArray, pid: String, dir: Char, ctr: Long, exp: Long, plain: ByteArray, iv: ByteArray = ByteArray(12).also { random.nextBytes(it) }): String {
        val header = ByteBuffer.allocate(18).put(1).put(dir.code.toByte()).putLong(ctr).putLong(exp).array()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        c.updateAAD(aad(pid, header))
        return enc(header + iv + c.doFinal(plain))
    }

    fun open(key: ByteArray, pid: String, dir: Char, blob: String, last: Long, now: Long): Opened {
        val b = dec(blob)?.takeIf { it.size >= 18 + 12 + 16 } ?: return Opened.No("malformed")
        val bb = ByteBuffer.wrap(b)
        if (bb.get() != 1.toByte()) return Opened.No("version")
        if (bb.get() != dir.code.toByte()) return Opened.No("direction")
        val ctr = bb.getLong()
        val exp = bb.getLong()
        val plain = try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, b, 18, 12))
            c.updateAAD(aad(pid, b.copyOfRange(0, 18)))
            c.doFinal(b, 30, b.size - 30)
        } catch (_: Exception) { return Opened.No("bad seal") }
        return when {
            ctr <= last -> Opened.No("replay")
            exp < now -> Opened.No("expired")
            exp > now + SKEW_MS -> Opened.No("expiry too far out")
            else -> Opened.Ok(ctr, plain, exp)
        }
    }

    /**
     * The relay's HMAC headers for one call (relay/README.md): the same scheme the laptop signs with, under the
     * pairing's relay key. The signature covers the method, path, query, time, a single-use nonce and the body's hash.
     */
    fun signed(relayKey: ByteArray, pid: String, method: String, path: String, query: String, body: ByteArray, nowMs: Long, nonce: String = newId()): Map<String, String> {
        val ts = (nowMs / 1000).toString()
        val hash = MessageDigest.getInstance("SHA-256").digest(body).joinToString("") { "%02x".format(it) }
        val sig = enc(hmac(relayKey, "$method\n$path\n$query\n$ts\n$nonce\n$hash".toByteArray()))
        return mapOf("x-sphinx-pid" to pid, "x-sphinx-ts" to ts, "x-sphinx-nonce" to nonce, "x-sphinx-sig" to sig)
    }

    /** A short fingerprint of a pairing for the screen (both sides can show it). */
    fun tag(p: Pairing): String = MessageDigest.getInstance("SHA-256").digest(p.l2p + p.p2l).take(3).joinToString("") { "%02x".format(it) }
}
