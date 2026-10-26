package dev.sphinx

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

    private fun call(base: String, method: String, path: String, body: ByteArray?, headers: Map<String, String>, readMs: Int = 15_000): String? {
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
            if (status == 204) return null
            if (status !in 200..299) throw Failed(status)
            return c.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
        } finally { c.disconnect() }
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
}
