package dev.sphinx

import com.fasterxml.jackson.databind.JsonNode
import java.net.URI
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** A file in a handoff: its chunks wait on the relay sealed under [key], which travels only inside the sealed message. */
data class FileRef(val fid: String, val key: String, val name: String, val mime: String, val size: Int, val chunks: Int, val sha256: String)

/**
 * One handoff between the phone and a laptop (docs/DESIGN.md, "Handoff"): a link ([open]: "continue on the other
 * device"), a bit of text, or a small file. The same rules as the extension's handoff.js, on both ends: links are
 * http(s) only, text and files have caps, a file name can't climb out of its folder. Nothing that arrives is acted on
 * without a tap.
 */
data class HandoffItem(val type: String, val url: String? = null, val open: Boolean = false, val text: String? = null, val file: FileRef? = null) {
    fun body(): Map<String, Any?> = when (type) {
        "link" -> mapOf("type" to "link", "url" to url, "open" to open)
        "text" -> mapOf("type" to "text", "text" to text)
        else -> mapOf("type" to "file", "file" to file!!.let {
            mapOf("fid" to it.fid, "key" to it.key, "name" to it.name, "mime" to it.mime, "size" to it.size, "chunks" to it.chunks, "sha256" to it.sha256)
        })
    }

    /** One line for a notification or the share screen. */
    fun label(): String = when (type) {
        "link" -> (if (open) "Open " else "Link: ") + (runCatching { URI(url).host }.getOrNull() ?: url)
        "text" -> "Text: " + text!!.take(60) + if (text.length > 60) "…" else ""
        else -> "File: ${file!!.name} (${maxOf(1, file.size / 1024)} KB)"
    }
}

/** How the share screen names the sharing app: unverified when it came from a referrer the app set itself. */
object SharedBy {
    fun label(name: String, verified: Boolean): String = if (verified) name else "$name (unverified)"
}

object HandoffRules {
    /** Plaintext bytes per file chunk, and at most this many: 8 MiB a file (the relay's caps, relay/sphinx_relay.py). */
    const val CHUNK = 512 * 1024
    const val MAX_CHUNKS = 16
    const val MAX_FILE = CHUNK * MAX_CHUNKS
    /** Bytes of UTF-8: the sealed envelope must stay under the relay's 4 KB blob. */
    const val MAX_TEXT = 3000
    const val MAX_URL = 2048
    /** A phone-to-laptop handoff waits for the laptop's next look (every 30 s); open() refuses more than 2 min out. */
    const val PUSH_TTL_MS = 110_000L

    /**
     * Whether Sphinx may read a shared file: only a content:// URI another app's provider serves, never a file:// path
     * (read as Sphinx, it would reach Sphinx's own files: backup/key.bin and state.bin) nor one of Sphinx's own
     * providers ([own] is the package name; review 2026-10-27).
     */
    fun shareable(scheme: String?, authority: String?, own: String): Boolean =
        scheme.equals("content", ignoreCase = true) && !authority.isNullOrBlank() &&
            authority.split(';').none { a -> a.trim().let { it.equals(own, ignoreCase = true) || it.startsWith("$own.", ignoreCase = true) } }

    /**
     * Whether the sharing app granted Sphinx this [uri] itself: the read grant on the intent ([flags], as Android's
     * FLAG_GRANT_READ_URI_PERMISSION) and the URI in its ClipData ([clip]). Android checks that the sharing app may grant
     * it, so a document only Sphinx can read (one he picked in Sphinx before) can't be passed in without it (review
     * 2026-10-27: Sphinx's own grants were enough).
     */
    fun granted(flags: Int, uri: String, clip: List<String>): Boolean = (flags and GRANT_READ) != 0 && uri in clip

    /** Intent.FLAG_GRANT_READ_URI_PERMISSION. */
    const val GRANT_READ = 0x1

    private val FID = Regex("^[A-Za-z0-9_-]{22}$")
    private val KEY = Regex("^[A-Za-z0-9_-]{43}$")
    private val HEX = Regex("^[0-9a-f]{64}$")
    private val MIME = Regex("^[a-z0-9.+-]{1,60}/[a-z0-9.+-]{1,60}$", RegexOption.IGNORE_CASE)

    /** An http or https link, or null: no javascript:, intent:, content:, file: or a user:password part. */
    fun httpUrl(u: String?): String? {
        val t = u?.trim() ?: return null
        if (t.isEmpty() || t.length > MAX_URL) return null
        val x = runCatching { URI(t) }.getOrNull() ?: return null
        val scheme = x.scheme?.lowercase()
        if ((scheme != "https" && scheme != "http") || x.host.isNullOrEmpty() || x.rawUserInfo != null) return null
        return t
    }

    /** A file name safe to save under: no folders, no control characters, no leading dots, at most 120 characters. */
    fun safeName(n: String?): String {
        val s = (n ?: "").filter { it.code >= 0x20 && it.code != 0x7f }.split('/', '\\').last().trimStart('.', ' ', '\t').trim().take(120)
        return s.ifEmpty { "file" }
    }

    fun chunksFor(size: Int): Int = maxOf(1, (size + CHUNK - 1) / CHUNK)

    /** A handoff body as it may be sent or shown, or null (the same checks as handoff.js `item`). */
    fun item(b: JsonNode): HandoffItem? {
        if (!b.isObject) return null
        return when (b.path("type").asText()) {
            "link" -> httpUrl(b.path("url").takeIf { it.isTextual }?.asText())?.let { HandoffItem("link", url = it, open = b.path("open").asBoolean(false) && b.path("open").isBoolean) }
            "text" -> b.path("text").takeIf { it.isTextual }?.asText()?.takeIf { it.isNotBlank() && it.toByteArray().size <= MAX_TEXT }?.let { HandoffItem("text", text = it) }
            "file" -> {
                val f = b.path("file")
                val size = f.path("size").takeIf { it.isInt }?.asInt() ?: return null
                val fid = f.path("fid").asText(); val key = f.path("key").asText(); val sha = f.path("sha256").asText()
                if (!FID.matches(fid) || !KEY.matches(key) || !HEX.matches(sha) || size < 1 || size > MAX_FILE || f.path("chunks").asInt(-1) != chunksFor(size)) return null
                val mime = f.path("mime").asText().takeIf { MIME.matches(it) }?.lowercase() ?: "application/octet-stream"
                HandoffItem("file", file = FileRef(fid, key, safeName(f.path("name").asText()), mime, size, chunksFor(size), sha))
            }
            else -> null
        }
    }

    // ---- file chunks: AES-256-GCM under the file's own key; iv = 8 zero bytes + the index (u32 BE); AAD binds place ----

    private fun cipher(mode: Int, key: ByteArray, fid: String, n: Int, total: Int) = Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, ByteBuffer.allocate(12).putInt(8, n).array()))
        updateAAD("sphinx file v1|$fid|$n|$total".toByteArray())
    }

    fun sealChunk(key: ByteArray, fid: String, n: Int, total: Int, plain: ByteArray): String =
        SphinxCrypto.enc(cipher(Cipher.ENCRYPT_MODE, key, fid, n, total).doFinal(plain))

    /** The chunk's plaintext, or null when it isn't this file's chunk [n] of [total]. */
    fun openChunk(key: ByteArray, fid: String, n: Int, total: Int, blob: String): ByteArray? =
        runCatching { cipher(Cipher.DECRYPT_MODE, key, fid, n, total).doFinal(SphinxCrypto.dec(blob)!!) }.getOrNull()

    fun sha256Hex(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    /** A new file's reference and its sealed chunks, ready to upload. The key is fresh for every file. */
    fun prepare(name: String, mime: String, data: ByteArray): Pair<FileRef, List<String>> {
        require(data.isNotEmpty() && data.size <= MAX_FILE) { "A file must be 1 byte to ${MAX_FILE / 1024 / 1024} MB" }
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val fid = SphinxCrypto.newId(16)
        val total = chunksFor(data.size)
        val chunks = (0 until total).map { n -> sealChunk(key, fid, n, total, data.copyOfRange(n * CHUNK, minOf(data.size, (n + 1) * CHUNK))) }
        val ref = FileRef(fid, SphinxCrypto.enc(key), safeName(name), mime.takeIf { MIME.matches(it) }?.lowercase() ?: "application/octet-stream", data.size, total, sha256Hex(data))
        key.fill(0)
        return ref to chunks
    }

    /** Joins downloaded chunks, each opened, then checks the size and hash the sealed message promised. Null: refused. */
    fun assemble(f: FileRef, blobs: List<String?>): ByteArray? {
        if (blobs.size != f.chunks) return null
        val key = SphinxCrypto.dec(f.key) ?: return null
        val out = java.io.ByteArrayOutputStream(f.size)
        for ((n, b) in blobs.withIndex()) out.write(b?.let { openChunk(key, f.fid, n, f.chunks, it) } ?: return null)
        key.fill(0)
        val data = out.toByteArray()
        return data.takeIf { it.size == f.size && sha256Hex(it) == f.sha256 }
    }
}
