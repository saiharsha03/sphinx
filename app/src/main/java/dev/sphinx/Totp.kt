package dev.sphinx

import java.net.URLDecoder
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** The HMAC behind a code (RFC 6238 allows all three; Google Authenticator exports say which). */
enum class Algo(val mac: String, val wire: String) {
    SHA1("HmacSHA1", "SHA1"), SHA256("HmacSHA256", "SHA256"), SHA512("HmacSHA512", "SHA512");

    companion object { fun of(s: String?): Algo? = entries.firstOrNull { it.wire.equals(s?.replace("-", ""), ignoreCase = true) } }
}

/** One TOTP account as an import yields it, secret included. Lives only until it is sealed (SphinxStore). */
class Imported(val issuer: String, val name: String, val secret: ByteArray, val algo: Algo, val digits: Int, val period: Int)

/** Why an entry in an export can't come in. Shown as is. */
class Refused(val label: String, val why: String)

data class ImportResult(val accounts: List<Imported>, val refused: List<Refused>, val batch: Pair<Int, Int>? = null)

/**
 * RFC 6238 codes and the two QR formats Sphinx takes: Google Authenticator's "Transfer accounts" export
 * (`otpauth-migration://offline?data=...`, a protobuf MigrationPayload) and a plain `otpauth://totp/...` QR.
 * TOTP only: HOTP and anything else is refused plainly. Pure; the secret bytes never leave this process.
 */
object Totp {
    const val PERIOD = 30

    /** The code for [atMs]: counter = floor(t / period), HMAC, dynamic truncation (RFC 4226 section 5.3). */
    fun code(secret: ByteArray, atMs: Long, algo: Algo = Algo.SHA1, digits: Int = 6, period: Int = PERIOD): String {
        val counter = Math.floorDiv(atMs / 1000, period.toLong())
        val mac = Mac.getInstance(algo.mac).apply { init(SecretKeySpec(secret, algo.mac)) }.doFinal(ByteBuffer.allocate(8).putLong(counter).array())
        val o = mac[mac.size - 1].toInt() and 0x0f
        val bin = ((mac[o].toInt() and 0x7f) shl 24) or ((mac[o + 1].toInt() and 0xff) shl 16) or ((mac[o + 2].toInt() and 0xff) shl 8) or (mac[o + 3].toInt() and 0xff)
        var mod = 1L
        repeat(digits) { mod *= 10 }
        return (bin % mod).toString().padStart(digits, '0')
    }

    /** Seconds until the code for [atMs] changes. */
    fun left(atMs: Long, period: Int = PERIOD): Int = period - ((atMs / 1000) % period).toInt()

    // ---- base32 (RFC 4648), as otpauth URIs carry secrets ----

    private const val B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun base32(s: String): ByteArray? {
        val clean = s.uppercase().filterNot { it == ' ' || it == '-' || it == '=' }
        if (clean.isEmpty()) return null
        val out = java.io.ByteArrayOutputStream()
        var buf = 0
        var bits = 0
        for (ch in clean) {
            val v = B32.indexOf(ch).takeIf { it >= 0 } ?: return null
            buf = (buf shl 5) or v
            bits += 5
            if (bits >= 8) { out.write((buf shr (bits - 8)) and 0xff); bits -= 8 }
        }
        return out.toByteArray()
    }

    // ---- the QR formats ----

    /** Whatever the scanner read. Null when it is neither format (the screen says so). */
    fun parse(qr: String): ImportResult? {
        val s = qr.trim()
        return runCatching {
            when {
                s.startsWith("otpauth-migration://", ignoreCase = true) -> migration(s)
                s.startsWith("otpauth://", ignoreCase = true) -> plain(s)
                else -> null
            }
        }.getOrNull()
    }

    private fun query(uri: String): Map<String, String> = uri.substringAfter('?', "").split('&').filter { '=' in it }.associate {
        it.substringBefore('=').lowercase() to URLDecoder.decode(it.substringAfter('='), "UTF-8")
    }

    /** `otpauth://totp/Issuer:account?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30`. */
    fun plain(uri: String): ImportResult {
        val type = uri.substringAfter("://").substringBefore('/').lowercase()
        val label = URLDecoder.decode(uri.substringAfter("://").substringAfter('/', "").substringBefore('?'), "UTF-8")
        val q = query(uri)
        val issuer = q["issuer"]?.trim().orEmpty().ifEmpty { label.substringBefore(':', "").trim() }
        val name = label.substringAfter(':').trim()
        val shown = listOf(issuer, name).filter { it.isNotEmpty() }.joinToString(" · ").ifEmpty { "This code" }
        if (type != "totp") return ImportResult(emptyList(), listOf(Refused(shown, if (type == "hotp") "HOTP (counter) codes aren't supported, only time-based ones" else "Not a time-based (TOTP) code")))
        val secret = q["secret"]?.let(::base32) ?: return ImportResult(emptyList(), listOf(Refused(shown, "The QR has no readable secret")))
        val algo = if (q["algorithm"] == null) Algo.SHA1 else Algo.of(q["algorithm"]) ?: return ImportResult(emptyList(), listOf(Refused(shown, "Unknown algorithm ${q["algorithm"]}")))
        val digits = q["digits"]?.toIntOrNull() ?: 6
        val period = q["period"]?.toIntOrNull() ?: PERIOD
        if (digits != 6 && digits != 8) return ImportResult(emptyList(), listOf(Refused(shown, "$digits-digit codes aren't supported")))
        if (period !in 15..120) return ImportResult(emptyList(), listOf(Refused(shown, "A $period-second period isn't supported")))
        return ImportResult(listOf(Imported(issuer, name, secret, algo, digits, period)), emptyList())
    }

    /** Google Authenticator's export: `data` is base64 of a MigrationPayload. Period is always 30 there. */
    fun migration(uri: String): ImportResult? {
        val data = query(uri)["data"] ?: return null
        val bytes = runCatching { java.util.Base64.getDecoder().decode(data.replace('-', '+').replace('_', '/').let { it + "=".repeat((4 - it.length % 4) % 4) }) }.getOrNull() ?: return null
        val ok = ArrayList<Imported>()
        val refused = ArrayList<Refused>()
        var size = 0
        var index = 0
        val root = runCatching { Proto(bytes).fields() }.getOrNull() ?: return null
        for ((field, value) in root) when (field) {
            1 -> (value as? ByteArray)?.let { one(it, ok, refused) }
            3 -> size = (value as? Long)?.toInt() ?: 0
            4 -> index = (value as? Long)?.toInt() ?: 0
        }
        return ImportResult(ok, refused, if (size > 1) index + 1 to size else null)
    }

    private fun one(b: ByteArray, ok: MutableList<Imported>, refused: MutableList<Refused>) {
        val f = runCatching { Proto(b).fields() }.getOrNull() ?: return
        fun bytes(n: Int) = f.firstOrNull { it.first == n }?.second as? ByteArray
        fun num(n: Int) = (f.firstOrNull { it.first == n }?.second as? Long) ?: 0L
        val issuer = bytes(3)?.toString(Charsets.UTF_8)?.trim().orEmpty()
        val raw = bytes(2)?.toString(Charsets.UTF_8)?.trim().orEmpty()
        // Authenticator often stores "Issuer:account" as the name.
        val name = if (':' in raw && (issuer.isEmpty() || raw.substringBefore(':').trim().equals(issuer, true))) raw.substringAfter(':').trim() else raw
        val shown = listOf(issuer, name).filter { it.isNotEmpty() }.joinToString(" · ").ifEmpty { "An account" }
        val secret = bytes(1)
        val algo = when (num(4)) { 0L, 1L -> Algo.SHA1; 2L -> Algo.SHA256; 3L -> Algo.SHA512; else -> null }
        val digits = when (num(5)) { 0L, 1L -> 6; 2L -> 8; else -> 0 }
        when {
            num(6) == 1L -> refused += Refused(shown, "HOTP (counter) codes aren't supported, only time-based ones")
            num(6) != 2L -> refused += Refused(shown, "Not a time-based (TOTP) code")
            secret == null || secret.isEmpty() -> refused += Refused(shown, "No secret in the export")
            algo == null -> refused += Refused(shown, "MD5 or an unknown algorithm isn't supported")
            digits == 0 -> refused += Refused(shown, "Unknown code length")
            else -> ok += Imported(issuer, name, secret, algo, digits, PERIOD)
        }
    }

    /** Just enough protobuf: varints and length-delimited fields; fixed ones are skipped. */
    private class Proto(private val b: ByteArray) {
        private var i = 0

        private fun varint(): Long {
            var shift = 0
            var out = 0L
            while (true) {
                require(i < b.size && shift < 64)
                val x = b[i++].toInt() and 0xff
                out = out or ((x and 0x7f).toLong() shl shift)
                if (x and 0x80 == 0) return out
                shift += 7
            }
        }

        fun fields(): List<Pair<Int, Any>> = buildList {
            while (i < b.size) {
                val key = varint()
                val field = (key ushr 3).toInt()
                when ((key and 7).toInt()) {
                    0 -> add(field to varint())
                    1 -> { require(i + 8 <= b.size); i += 8 }
                    2 -> { val n = varint().toInt(); require(n >= 0 && i + n <= b.size); add(field to b.copyOfRange(i, i + n)); i += n }
                    5 -> { require(i + 4 <= b.size); i += 4 }
                    else -> error("bad wire type")
                }
            }
        }
    }
}
