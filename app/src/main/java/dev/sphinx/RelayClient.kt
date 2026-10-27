package dev.sphinx

import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * The phone's calls to the relay (relay/README.md). Only pairing ids, the relay key (once, at pairing) and sealed
 * blobs cross here. Every call but registering a pairing is HMAC-signed with that pairing's relay key. Blocking.
 */
object RelayClient {
    /**
     * A request blob from a paired laptop: [pid] its pairing, [rid] its opaque id, [blob] sealed to the pairing's key.
     * Fetched from the pairing's inbox, or carried by an FCM wake (SphinxMessaging).
     */
    data class Blob(val pid: String, val rid: String, val blob: String)

    class Failed(val status: Int) : Exception("relay $status")

    /**
     * The registration value to send to [relay]: the one the QR or the screen gave ([given]), else the one built into
     * this app ([builtIn]) and only when [relay] is the built-in relay's own origin ([builtInRelay]). A QR naming another
     * relay never gets the owner's token (review 2026-10-27).
     */
    fun tokenFor(relay: String, given: String, builtInRelay: String, builtIn: String): String {
        val home = sameOrigin(relay, builtInRelay)
        // The built-in value passed back in (a stored or pre-filled field) is still the built-in one: home only.
        if (given.isNotBlank() && (given != builtIn || home)) return given
        return if (home) builtIn else ""
    }

    /**
     * The token to keep with a backup set up for [relay]: what he typed, never the built-in value, and never the old
     * relay's own token carried to another origin (review 2026-10-27: a token is bound to the relay it was given for).
     */
    fun keepToken(typed: String, relay: String, builtIn: String, oldRelay: String?, oldToken: String?): String {
        val t = typed.trim()
        if (t.isEmpty() || t == builtIn) return ""
        if (oldRelay != null && t == oldToken && !sameOrigin(relay, oldRelay)) return ""
        return t
    }

    /** Scheme, host and port equal (https's 443 written or not). */
    fun sameOrigin(a: String, b: String): Boolean {
        fun origin(s: String) = runCatching {
            val u = java.net.URI(s.trim())
            val scheme = u.scheme?.lowercase() ?: return null
            val host = u.host?.lowercase() ?: return null
            Triple(scheme, host, if (u.port == -1) (if (scheme == "https") 443 else if (scheme == "http") 80 else -1) else u.port)
        }.getOrNull()
        val x = origin(a)
        return x != null && x == origin(b)
    }

    /** The connection, sent and answered 2xx (else [Failed]); the caller reads its body and disconnects. */
    private fun open(base: String, method: String, path: String, body: ByteArray?, headers: Map<String, String>, readMs: Int): HttpURLConnection {
        val c = URL(base + path).openConnection() as HttpURLConnection
        try {
            c.requestMethod = method
            c.connectTimeout = 10_000
            c.readTimeout = readMs
            c.instanceFollowRedirects = false
            c.useCaches = false
            headers.forEach { (k, v) -> c.setRequestProperty(k, v) }
            if (body != null) {
                c.doOutput = true
                c.setRequestProperty("content-type", "application/json")
                c.outputStream.use { it.write(body) }
            }
            val status = c.responseCode
            if (status !in 200..299) throw Failed(status)
            return c
        } catch (e: Exception) { c.disconnect(); throw e }
    }

    private fun call(base: String, method: String, path: String, body: ByteArray?, headers: Map<String, String>, readMs: Int = 15_000): String? {
        val c = open(base, method, path, body, headers, readMs)
        try {
            if (c.responseCode == 204) return null
            return c.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
        } finally { c.disconnect() }
    }

    /** A GET whose body is streamed into [sink] as it arrives (the app's APK), never held in memory; [onOpen] gets the connection (to disconnect it from elsewhere). */
    private fun stream(base: String, path: String, headers: Map<String, String>, sink: OutputStream, readMs: Int, onOpen: (HttpURLConnection) -> Unit = {}) {
        val c = open(base, "GET", path, null, headers, readMs)
        onOpen(c)
        try { c.inputStream.use { it.copyTo(sink) } } finally { c.disconnect() }
    }

    private fun signed(p: Pairing, method: String, path: String, body: Any?, readMs: Int = 15_000, query: String = ""): String? {
        val bytes = body?.let { json.writeValueAsBytes(it) }
        val h = SphinxCrypto.signed(p.relayKey, p.pid, method, URL(p.relay + path).path, query, bytes ?: ByteArray(0), System.currentTimeMillis())
        return call(p.relay, method, path + (if (query.isEmpty()) "" else "?$query"), bytes, h, readMs)
    }

    /** An unsigned call (the backup's routes: a new phone has no pairing). */
    fun plain(base: String, method: String, path: String, body: Any?, headers: Map<String, String> = emptyMap()): String? =
        call(base, method, path, body?.let { json.writeValueAsBytes(it) }, headers, 60_000)

    /**
     * Registers the pairing and the phone's hello (the laptop fetches it and checks it against the QR's secret).
     * [token]: the relay's registration token when it requires one (SPHINX_REGISTER_TOKEN), carried in the QR.
     */
    fun pair(p: Pairing, hello: String, token: String) {
        val h = if (token.isNotBlank()) mapOf("x-sphinx-token" to token) else emptyMap()
        call(p.relay, "POST", "/v1/pairings", json.writeValueAsBytes(mapOf("pid" to p.pid, "key" to SphinxCrypto.enc(p.relayKey), "hello" to hello)), h)
    }

    fun unpair(p: Pairing) { signed(p, "DELETE", "/v1/pairings/${p.pid}", null) }

    /** This pairing's queued requests, now (no long poll: after an FCM wake, the app coming to the front, the heartbeat). */
    fun inbox(p: Pairing): List<Blob> {
        val text = signed(p, "GET", "/v1/inbox", null, query = "wait=0") ?: return emptyList()
        return json.readTree(text).path("items").map { Blob(p.pid, it.path("rid").asText(), it.path("blob").asText()) }
    }

    /** The phone's FCM token for this pairing ("" forgets it). True when the relay will wake the phone through FCM. */
    fun push(p: Pairing, token: String): Boolean =
        signed(p, "POST", "/v1/push", mapOf("token" to token))?.let { json.readTree(it).path("push").asBoolean(false) } ?: false

    /** Takes handled blobs off the relay's queue (they stay, at most 60 s, until acked). */
    fun ack(p: Pairing, rids: List<String>) { signed(p, "POST", "/v1/inbox/ack", mapOf("rids" to rids)) }

    /** A sealed handoff for the laptop's outbox (it looks every 30 s). */
    fun outbox(p: Pairing, rid: String, blob: String) { signed(p, "POST", "/v1/outbox", mapOf("rid" to rid, "blob" to blob)) }

    /** One sealed file chunk up, or down (null when the relay has none), and the file gone once it arrived. */
    fun putChunk(p: Pairing, fid: String, n: Int, total: Int, blob: String) { signed(p, "PUT", "/v1/files/$fid/$n", mapOf("blob" to blob), readMs = 60_000, query = "of=$total") }

    fun getChunk(p: Pairing, fid: String, n: Int): String? =
        runCatching { signed(p, "GET", "/v1/files/$fid/$n", null, readMs = 60_000) }.getOrNull()?.let { json.readTree(it).path("blob").asText(null) }

    fun dropFile(p: Pairing, fid: String) { signed(p, "DELETE", "/v1/files/$fid", null) }

    fun reply(p: Pairing, rid: String, blob: String) { signed(p, "POST", "/v1/replies", mapOf("rid" to rid, "blob" to blob)) }

    // ---- the app's own update (Update.kt): a release the relay's owner put there, served to any pairing ----

    /** The relay's current release as its JSON text, or null when it has none (404). */
    fun app(p: Pairing): String? = try { signed(p, "GET", "/v1/app", null) } catch (e: Failed) { if (e.status == 404) null else throw e }

    /** The release's APK, streamed into [sink] (signed like every call; a long read timeout for the file). */
    fun appFile(p: Pairing, sink: OutputStream, onOpen: (HttpURLConnection) -> Unit = {}) {
        val path = "/v1/app/file"
        val h = SphinxCrypto.signed(p.relayKey, p.pid, "GET", URL(p.relay + path).path, "", ByteArray(0), System.currentTimeMillis())
        stream(p.relay, path, h, sink, readMs = 120_000, onOpen = onOpen)
    }
}
