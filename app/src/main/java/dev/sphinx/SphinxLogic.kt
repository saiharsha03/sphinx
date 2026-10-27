package dev.sphinx


/** A laptop's request, opened and checked, waiting for his answer. In memory only, gone after [expires]. */
data class Pending(
    val rid: String,
    val pid: String,
    val laptop: String,
    val host: String,
    /** The frame the code field is in, when it isn't the tab itself (both must be the same account's sites). */
    val frame: String = host,
    /** The accounts that may fill on [host]; [picked] when the page's user name named one of them. */
    val accounts: List<CodeAccount>,
    val picked: String?,
    val expires: Long,
    /** A site saved for texted codes only (no account): nothing to approve until an SMS or email code arrives. */
    val textOnly: Boolean = false,
    /** A pre-approval (code.ready): his fingerprint opens a [Primed] window for the code that follows; no code goes back now. */
    val ready: Boolean = false,
) {
    /** Its id among the waiting requests: the pairing and the laptop's rid together (another pairing may pick the same rid). */
    val waitId: String get() = "$pid/$rid"
}

/**
 * The requests waiting for his answer, by [key] (pairing and rid). A second request under a key that waits is refused,
 * never put in place of the first, and an answer takes exactly the request the screen showed (review 2026-10-27: an
 * approval must not land on a request another pairing slipped in under the same rid).
 */
class Waiting<T : Any>(private val key: (T) -> String) {
    private val m = java.util.concurrent.ConcurrentHashMap<String, T>()

    /** False when one already waits under its key (it stays). */
    fun add(x: T): Boolean = m.putIfAbsent(key(x), x) == null

    operator fun get(k: String): T? = m[k]

    /** Takes [shown] if it is still the very request waiting under its key. */
    @Synchronized fun take(shown: T): Boolean = (m[key(shown)] === shown).also { if (it) m.remove(key(shown)) }

    fun remove(k: String): T? = m.remove(k)

    val values: Collection<T> get() = m.values
    fun isEmpty(): Boolean = m.isEmpty()
}

/**
 * His fingerprint on a code.ready (owner, 2026-10-26: "prefetch the code ... when password is being entered"): for one
 * pairing, one site (eTLD+1) and one account, until [until]. The codes key needs his fingerprint for every use, so the
 * window holds the codes of the periods it spans, computed at his yes (never the secret). In memory only, never on disk;
 * spent on one delivered code.
 */
class Primed(val pid: String, val site: String, val accountId: String, private val period: Int, private val codes: Map<Long, String>, val until: Long) {
    fun codeAt(now: Long): String? = codes[now / 1000 / period]
}

/** The one open window (the newest yes wins). In memory only, never on disk. */
class PreApproval {
    private var w: Primed? = null

    @Synchronized fun open(p: Primed) { w = p }

    /** The code for [r] from the window, which it spends (one delivered code), or null: today's flow. */
    @Synchronized fun take(r: Pending, now: Long): Pair<CodeAccount, String>? = SphinxLogic.served(w, r, now)?.also { w = null }

    /** Forgets a window that has ended. */
    @Synchronized fun close(now: Long) { if (w?.let { it.until <= now } == true) w = null }
}

/**
 * One texted code offered for one waiting request ([id] its waitId). [gen] makes each offer its own: a newer text for
 * the same request is a new offer, and an answer sends exactly the offer its prompt showed (review 2026-10-27: a text
 * arriving during the prompt swapped the code that went out).
 */
data class TextOffer(val id: String, val code: String, val gen: Long)

class TextOffers {
    private val m = java.util.concurrent.ConcurrentHashMap<String, TextOffer>()
    private val n = java.util.concurrent.atomic.AtomicLong()

    fun offer(id: String, code: String): TextOffer = TextOffer(id, code, n.incrementAndGet()).also { m[id] = it }
    operator fun get(id: String): TextOffer? = m[id]
    /** Takes [o] only if it is still the offer for its request: true once, for exactly that code. */
    fun take(o: TextOffer): Boolean = m.remove(o.id, o)
    fun drop(id: String): TextOffer? = m.remove(id)
    fun keep(f: (String) -> Boolean) { m.keys.removeAll { !f(it) } }
}

/**
 * The replay window (review 2026-10-27): a request's sealed counter is taken if it is above the highest seen, or one
 * skipped below it ([Pairing.gaps], at most [SIZE] back) and not yet seen. Requests the laptop posted out of order both
 * arrive; each still only once. A pairing saved before has no gaps: strict, as it was.
 */
object ReplayWindow {
    const val SIZE = 32

    fun floor(recv: Long): Long = maxOf(0L, recv - SIZE)

    fun fresh(ctr: Long, recv: Long, gaps: List<Long>): Boolean = ctr > recv || ctr in gaps

    fun after(ctr: Long, recv: Long, gaps: List<Long>): Pair<Long, List<Long>> =
        if (ctr <= recv) recv to gaps.filter { it != ctr }
        else ctr to (gaps + (maxOf(recv + 1, ctr - SIZE + 1) until ctr)).filter { it > ctr - SIZE }
}

/** What the phone does with one blob from the relay. */
sealed class Decision {
    /** Couldn't be opened or read (bad seal, replay, expired, bad JSON): logged, no reply (there is no one to trust). */
    data class Drop(val why: String) : Decision()
    /** Answered without him: the domain list, or a refusal (no account saved for that site). */
    data class Answer(val pairing: Pairing, val rid: String, val reply: Map<String, Any?>, val line: String) : Decision()
    /** Needs his fingerprint. */
    data class Ask(val pairing: Pairing, val pending: Pending) : Decision()
    /** A link, text or file from the laptop (handoff.send): shown with Open / Copy, never acted on without a tap. */
    data class Handoff(val pairing: Pairing, val rid: String, val item: HandoffItem) : Decision()
    /** The release signer asks to sign (sign.approve): needs his fingerprint, which opens the unlock secret. */
    data class Sign(val pairing: Pairing, val ask: SignAsk) : Decision()
}

/**
 * The pure part of Sphinx on the phone: open a request, check it, and decide. A request names only the page's host
 * (taken by the extension from the tab, not from the page) and the user name on the page as a hint; the reply carries
 * the code or a refusal. The phone matches the host again here (Domains.matches), whatever the laptop thought.
 *
 * Every message is one typed envelope, sealed whole: `{"v": 1, "kind": "<area>.<verb>", "rid": "...", "body": {...}}`.
 * Kinds today: code.request / code.reply, code.ready / code.ready.reply, domains.request / domains.reply, and from the release signer's pairing only, sign.approve / sign.approve.reply (docs/DESIGN.md, Release signing). One pairing carries every kind; the ones
 * planned on it (tab.send, sms.code, clip.push, clip.send, presence, call.ring) are refused
 * as "unsupported kind" until each is built and reviewed (docs/DESIGN.md). Laptop to phone is direction 'q', phone to
 * laptop 'r', each with its own counter, whatever the kind.
 */
object SphinxLogic {
    const val V = 1
    const val MAX_DOMAINS = 60
    /** The kinds a laptop may send now. Anything else gets a sealed "unsupported kind", never an action. */
    val KINDS = setOf("code.request", "code.ready", "domains.request", "handoff.send")
    /**
     * How long his yes on a code.ready stays good: 30 s (owner, 2026-10-26: "hold only for 30 seconds"). It protects
     * against an approval that never ends: a compromised laptop could otherwise pull codes for that site long after he
     * signed in. Enough to go from the password to the code field.
     */
    const val WINDOW_MS = 30_000L

    fun envelope(kind: String, rid: String, body: Map<String, Any?>): Map<String, Any?> = mapOf("v" to V, "kind" to kind, "rid" to rid, "body" to body)

    /** The accounts a request could be for, as one key: the same choice again (two AWS accounts) remembers his last pick. */
    fun choiceKey(found: List<CodeAccount>): String = found.map { it.id }.sorted().joinToString(",")

    /**
     * [textSites]: sites saved for texted codes only (SphinxStore.textSites). They go to the laptop as one-site groups, so
     * the extension asks there under the same tab, frame and origin rules, and a request for one waits (textOnly) for an
     * SMS or email code he sends with his fingerprint (owner, 2026-10-25).
     */
    fun decide(p: Pairing, rid: String, blob: String, accounts: List<CodeAccount>, now: Long, lastPick: (String) -> String? = { null }, textSites: List<String> = emptyList(),
               enrolled: Boolean = false): Decision {
        val o = SphinxCrypto.open(p.l2p, p.pid, 'q', blob, ReplayWindow.floor(p.recv), now)
        if (o is Opened.No) return Decision.Drop(o.why)
        o as Opened.Ok
        if (!ReplayWindow.fresh(o.ctr, p.recv, p.gaps)) return Decision.Drop("replay")
        val (recv, gaps) = ReplayWindow.after(o.ctr, p.recv, p.gaps)
        val seen = p.copy(recv = recv, gaps = gaps, lastUsed = now)
        val n = runCatching { json.readTree(o.plain) }.getOrNull()?.takeIf { it.isObject } ?: return Decision.Drop("unreadable")
        if (n.path("v").asInt() != V) return Decision.Drop("envelope version")
        // The rid inside the seal must be the one outside it: the relay can't move a sealed request onto another id.
        if (n.path("rid").asText() != rid) return Decision.Drop("rid mismatch")
        val body = n.path("body")
        val kind = n.path("kind").asText()
        // The release signer's pairing asks for signing and nothing else; no other pairing may ask for it (docs/DESIGN.md, Release signing).
        if (p.signer || kind == SigningRules.KIND) {
            if (!p.signer || kind != SigningRules.KIND)
                return Decision.Answer(seen, rid, envelope("error", rid, mapOf("ok" to false, "why" to "unsupported kind")), "refused an unsupported kind")
            val ask = SigningRules.ask(rid, p, body, minOf(o.exp, now + SphinxCrypto.TTL_MS))
                ?: return Decision.Answer(seen, rid, SigningRules.no(rid, "bad request"), "refused a bad sign request")
            if (!enrolled) return Decision.Answer(seen, rid, SigningRules.no(rid, "no unlock secret on the phone"), "sign request: no unlock secret here")
            return Decision.Sign(seen, ask)
        }
        return when (kind) {
            // The sites, and which sit together on one account (so the laptop can require tab and frame on the same one). No names.
            "domains.request" -> Decision.Answer(seen, rid, envelope("domains.reply", rid, mapOf(
                "ok" to true, "domains" to (accounts.flatMap { it.domains } + textSites).distinct().sorted().take(MAX_DOMAINS),
                "groups" to (accounts.map { it.domains.sorted() } + textSites.map { listOf(it) }).filter { it.isNotEmpty() }.distinct().take(MAX_DOMAINS),
            )), "domain list sent")
            // A handoff: checked here (http(s) links only, caps), shown by Handoff.receive; it needs no reply.
            "handoff.send" -> HandoffRules.item(body)?.let { Decision.Handoff(seen, rid, it) }
                ?: Decision.Answer(seen, rid, envelope("error", rid, mapOf("ok" to false, "why" to "bad handoff")), "refused a handoff")
            "code.request" -> codeAsk(p, seen, rid, body, o.exp, now, accounts, lastPick, textSites, ready = false)
            // Sent when he types or autofills a password on a saved site: the same checks and question, a window as the answer.
            "code.ready" -> codeAsk(p, seen, rid, body, o.exp, now, accounts, lastPick, textSites, ready = true)
            else -> Decision.Answer(seen, rid, envelope("error", rid, mapOf("ok" to false, "why" to "unsupported kind")), "refused an unsupported kind")
        }
    }

    private fun codeAsk(p: Pairing, seen: Pairing, rid: String, body: com.fasterxml.jackson.databind.JsonNode, exp: Long, now: Long,
                        accounts: List<CodeAccount>, lastPick: (String) -> String?, textSites: List<String>, ready: Boolean): Decision {
        val host = Domains.normalize(body.path("host").asText()) ?: return Decision.Answer(seen, rid, no(rid, "bad host", ready), "refused a request without a site")
        val frame = if (body.path("frame").isMissingNode || body.path("frame").isNull) host
            else Domains.normalize(body.path("frame").asText()) ?: return Decision.Answer(seen, rid, no(rid, "bad host", ready), "refused a request without a site")
        // One account must cover both the tab and the frame: a frame on another saved site gets nothing.
        val found = Domains.candidates(host, accounts, frame) { it.domains }
        if (found.isEmpty()) {
            // A texted-code site, tab and frame both on it: it waits for a code from an SMS or email, still behind his fingerprint.
            // Nothing to pre-approve there: its code comes in a text.
            if (!ready && Domains.candidates(host, textSites, frame) { listOf(it) }.isNotEmpty())
                return Decision.Ask(seen, Pending(rid, p.pid, p.name, host, frame, emptyList(), null, minOf(exp, now + SphinxCrypto.TTL_MS), textOnly = true))
            return Decision.Answer(seen, rid, no(rid, "no account", ready), "request from $host: no account for it")
        }
        val hint = body.path("user").asText("").take(120)
        // The page's user name first; else the account he picked last time between these same accounts (owner,
        // 2026-10-23: AWS's authenticator names don't carry the user name he types).
        val picked = Domains.pick(found, hint) { it.name }
            ?: if (found.size > 1) lastPick(choiceKey(found))?.let { id -> found.firstOrNull { it.id == id } } else null
        // Held to the laptop's own sealed expiry (at most 60 s from now), never a fresh window from arrival.
        return Decision.Ask(seen, Pending(rid, p.pid, p.name, host, frame, found, picked?.id, minOf(exp, now + SphinxCrypto.TTL_MS), ready = ready))
    }

    fun refusal(rid: String, why: String): Map<String, Any?> = envelope("code.reply", rid, mapOf("ok" to false, "why" to why))

    /** A pre-approval's answer: ready or not, never a code (a code goes only to the code field's own request). */
    fun readied(rid: String, ok: Boolean, why: String? = null, held: Map<String, Any?>? = null): Map<String, Any?> =
        envelope("code.ready.reply", rid, if (ok) mapOf("ok" to true, "for" to WINDOW_MS / 1000) + (held ?: emptyMap()) else mapOf("ok" to false, "why" to why))

    /**
     * The window's codes for the laptop to hold, sealed like every reply (owner, 2026-10-26: "hold it and refresh if it
     * expires", "hold only for 30 seconds"): each with the unix seconds it is good from and until, the last cut at the
     * window's end, so the code field fills with no trip to the phone. The laptop keeps them in memory only.
     */
    fun held(a: CodeAccount, times: List<Long>, codes: List<String>, now: Long, only: Boolean = false): Map<String, Any?> {
        val end = (now + WINDOW_MS) / 1000
        val list = times.zip(codes).map { (t, code) -> val from = t / 1000 / a.period * a.period; Triple(from, minOf(from + a.period, end), code) }
            .distinctBy { it.first }.filter { it.second > it.first }
        // [only]: the site has this one account on the phone, so a user name the page shows later can't mean another.
        return mapOf("account" to a.name.ifBlank { a.issuer }, "only" to only, "codes" to list.map { (f, u, code) -> mapOf("code" to code, "from" to f, "until" to u) })
    }

    /** "No" in the kind the request was. */
    fun no(rid: String, why: String, ready: Boolean): Map<String, Any?> = if (ready) readied(rid, false, why) else refusal(rid, why)
    fun no(p: Pending, why: String): Map<String, Any?> = no(p.rid, why, p.ready)

    /** The times whose codes cover a window opened at [now]: one in each period it touches. */
    fun windowTimes(now: Long, period: Int): List<Long> =
        (generateSequence(now) { it + period * 1000L }.takeWhile { it < now + WINDOW_MS } + (now + WINDOW_MS)).toList()

    /** The window his fingerprint on [p] opens for account [a], holding [codes] (computed at [windowTimes]). */
    fun prime(p: Pending, a: CodeAccount, codes: List<String>, now: Long): Primed =
        Primed(p.pid, Domains.site(p.host), a.id, a.period, windowTimes(now, a.period).map { it / 1000 / a.period }.zip(codes).toMap(), now + WINDOW_MS)

    /**
     * A code request [r] served from the open window [w] without asking him: same pairing, same site, the window's account
     * among those that may fill there (and the one the page named, if it named one), before [Primed.until]. Null: today's flow.
     */
    fun served(w: Primed?, r: Pending, now: Long): Pair<CodeAccount, String>? {
        if (w == null || r.ready || r.textOnly || now >= w.until || r.pid != w.pid || Domains.site(r.host) != w.site) return null
        if (r.picked != null && r.picked != w.accountId) return null
        val a = r.accounts.firstOrNull { it.id == w.accountId } ?: return null
        return w.codeAt(now)?.let { a to it }
    }

    /**
     * One wake-up's blobs. Those the FCM wake carried go first through [handle], the one path a fetched blob takes
     * (pairing lookup, seal, counter, expiry), so a forged or replayed one is refused the same way. Then the relay's
     * inbox is fetched and acked as before (into [handled]); its copy of a carried blob that was taken isn't run twice,
     * only acked. A carried blob that was refused doesn't stand in for the fetched one (owner, 2026-10-26).
     */
    fun drain(carried: List<RelayClient.Blob>, fetch: () -> List<RelayClient.Blob>, handled: MutableList<RelayClient.Blob>, handle: (RelayClient.Blob) -> Boolean) {
        val taken = carried.filter { handle(it) }.map { it.pid to it.rid }.toSet()
        for (b in fetch()) {
            if (b.pid to b.rid !in taken) handle(b)
            handled += b
        }
    }

    private val PID = Regex("^[A-Za-z0-9_-]{22}$")
    private val RID = Regex("^[A-Za-z0-9_-]{16,32}$")
    private val BLOB = Regex("^[A-Za-z0-9_-]{24,5600}$")

    /**
     * The blobs an FCM wake carried (its "sphinx" value): each exactly {pid, rid, blob} in the relay's own shapes, at
     * most 20; anything else is dropped. Only the shape is checked here; [drain] runs each through the usual seal checks.
     */
    fun carried(raw: String?): List<RelayClient.Blob> {
        if (raw.isNullOrEmpty() || raw.length > 4096) return emptyList()
        val n = runCatching { json.readTree(raw) }.getOrNull()?.takeIf { it.isArray } ?: return emptyList()
        return n.take(20).mapNotNull { e ->
            if (!e.isObject || e.size() != 3 || listOf("pid", "rid", "blob").any { !e.path(it).isTextual }) return@mapNotNull null
            val b = RelayClient.Blob(e.path("pid").asText(), e.path("rid").asText(), e.path("blob").asText())
            b.takeIf { PID.matches(it.pid) && RID.matches(it.rid) && BLOB.matches(it.blob) }
        }
    }

    /** A code request that came while its site's pre-approval still waits for him: it waits on that answer, no second prompt. */
    /** The pre-approvals (code.ready) still unanswered that code request [r] takes the place of: its pairing's, for its site. */
    fun supersedes(pending: Collection<Pending>, r: Pending, now: Long): List<Pending> =
        if (r.ready || r.textOnly) emptyList()
        else pending.filter { it.ready && it.expires > now && it.pid == r.pid && Domains.site(it.host) == Domains.site(r.host) }

    /**
     * A code made at [now]: [ttl] seconds left, and `until`, the unix second its period ends, so the laptop drops a code
     * that arrives after it changed instead of typing and submitting a dead one (review 2026-10-27).
     */
    fun code(rid: String, a: CodeAccount, code: String, now: Long): Map<String, Any?> {
        val left = Totp.left(now, a.period)
        return envelope("code.reply", rid, mapOf("ok" to true, "code" to code, "account" to a.name.ifBlank { a.issuer }, "ttl" to left, "until" to now / 1000 + left))
    }

    /** A code from an SMS or email he sent with his fingerprint: `via: "text"` tells the laptop to type it and not submit. */
    fun texted(rid: String, code: String): Map<String, Any?> =
        envelope("code.reply", rid, mapOf("ok" to true, "code" to code, "account" to "", "via" to "text"))

    /**
     * The newest laptop code request still waiting at [now], for a texted code to answer (any site: he sees which one).
     * Never a pre-approval (code.ready): it takes no code, and a code request for its site would be left waiting (review 2026-10-27).
     */
    fun forText(pending: Collection<Pending>, now: Long): Pending? = pending.filter { it.expires > now && !it.ready }.maxByOrNull { it.expires }

    /**
     * A handoff to the laptop, sealed in the phone-push direction 'p' with its own counter ([Pairing.pushSent]), so it
     * never races the replies' counter. It waits in the laptop's outbox on the relay.
     */
    fun push(p: Pairing, rid: String, item: HandoffItem, now: Long): Pair<String, Pairing> {
        val next = p.pushSent + 1
        val blob = SphinxCrypto.seal(p.p2l, p.pid, 'p', next, now + HandoffRules.PUSH_TTL_MS, json.writeValueAsBytes(envelope("handoff.send", rid, item.body())))
        return blob to p.copy(pushSent = next, lastUsed = now)
    }

    /** Seals a reply with the next counter; returns the blob and the pairing to save. */
    fun reply(p: Pairing, body: Map<String, Any?>, now: Long): Pair<String, Pairing> {
        val next = p.sent + 1
        val blob = SphinxCrypto.seal(p.p2l, p.pid, 'r', next, now + SphinxCrypto.TTL_MS, json.writeValueAsBytes(body))
        return blob to p.copy(sent = next, lastUsed = now)
    }

    /**
     * "Code for github.com (work)?". With [names] false (over the keyguard, before his fingerprint) only the issuer:
     * "Code for github.com (GitHub)?", so a locked phone never shows which accounts he has.
     */
    fun question(p: Pending, names: Boolean = true): String {
        val a = p.accounts.firstOrNull { it.id == p.picked } ?: p.accounts.singleOrNull()
        val label = if (names) a?.name?.takeIf { it.isNotBlank() } else (a ?: p.accounts.firstOrNull())?.issuer?.takeIf { it.isNotBlank() }
        if (p.ready) return "Signing in to ${p.host}" + (label?.let { " ($it)" } ?: "") + ": approve the code for ${WINDOW_MS / 1000} s?"
        return "Code for ${p.host}" + (label?.let { " ($it)" } ?: "") + "?"
    }

    /** The copy screen's and prompt's name for an account: "GitHub (work)", or over the keyguard just "GitHub". */
    fun copyLabel(a: CodeAccount, names: Boolean): String = if (names) a.title() else a.issuer.ifBlank { "Account" }

    /** One row of the "which account" list: the name, or over the keyguard "GitHub, account 2". */
    fun rowLabel(p: Pending, a: CodeAccount, names: Boolean): String =
        if (names) a.name.ifBlank { a.issuer } else "${a.issuer.ifBlank { "Account" }}, account ${p.accounts.indexOf(a) + 1}"
}
