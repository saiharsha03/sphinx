package dev.sphinx

import com.fasterxml.jackson.core.type.TypeReference
import android.content.Context
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class SentKind { TEXT, LINK, FILE }

/**
 * Something a laptop sent, kept on the phone (the Texts and Files tabs) until the owner removes it: a text, a link, or
 * a file already saved to Download/Sphinx ([uri] is its MediaStore uri). Sealed with the rest of the store, not part
 * of the backup. Every field has a default so Jackson can build it like a CodeAccount.
 */
data class SentItem(
    val id: String = "",
    val at: Long = 0,
    /** The laptop's name at the time it sent this. */
    val laptop: String = "",
    val kind: SentKind = SentKind.TEXT,
    val text: String? = null,
    val url: String? = null,
    val name: String? = null,
    val mime: String? = null,
    val size: Int = 0,
    val uri: String? = null,
)

/** The pure rules of the sent list: newest first, at most [MAX] kept, cleared by tab. */
/** Bumped on every change to the list, so the tabs reload without a round trip through the screen (Codex, 2026-10-27). */
object SentFeed {
    val version = kotlinx.coroutines.flow.MutableStateFlow(0L)
    fun bump() { version.value = version.value + 1 }
}

/**
 * Where the list lives: its own sealed prefs under a TEE key, apart from the secrets' StrongBox store and its lock, so a
 * laptop's handoff never holds a code request behind a slow seal (Fable, 2026-10-27). Blocking: call off the main thread.
 */
object SentStore {
    private const val SLOT = "sent"
    private val lock = Any()
    private fun prefs(c: Context) = SealedPrefs(c.applicationContext, "sphinx_sent", "sphinx.sent", strongBox = false)

    fun sent(c: Context): List<SentItem> = prefs(c).read(SLOT)?.let { runCatching { json.readValue(it, object : TypeReference<List<SentItem>>() {}) }.getOrNull() }.orEmpty()

    private fun save(c: Context, l: List<SentItem>) = prefs(c).write(SLOT, if (l.isEmpty()) null else json.writeValueAsString(l))

    fun add(c: Context, item: SentItem) { synchronized(lock) { save(c, SentRules.add(sent(c), item)) }; SentFeed.bump() }
    fun remove(c: Context, id: String) { synchronized(lock) { save(c, SentRules.remove(sent(c), id)) }; SentFeed.bump() }
    fun clear(c: Context, kinds: Set<SentKind>) { synchronized(lock) { save(c, SentRules.clear(sent(c), kinds)) }; SentFeed.bump() }
}

object SentRules {
    const val MAX = 200
    /** The list's rough size cap, so a read stays a few milliseconds: texts are up to 3000 bytes, urls 2048. */
    const val MAX_BYTES = 64 * 1024

    /** What [it] costs in the sealed list, about: its strings and the fixed fields. */
    fun bytes(it: SentItem): Int = (it.text?.length ?: 0) + (it.url?.length ?: 0) + (it.name?.length ?: 0) + (it.uri?.length ?: 0) + it.laptop.length + 120

    /** [item] in front of [all], the oldest beyond [MAX] items or [MAX_BYTES] dropped. */
    fun add(all: List<SentItem>, item: SentItem): List<SentItem> {
        val kept = (listOf(item) + all.filter { it.id != item.id }).sortedByDescending { it.at }.take(MAX).toMutableList()
        var total = kept.sumOf(::bytes)
        while (kept.size > 1 && total > MAX_BYTES) total -= bytes(kept.removeAt(kept.size - 1))
        return kept
    }

    fun remove(all: List<SentItem>, id: String): List<SentItem> = all.filter { it.id != id }

    fun clear(all: List<SentItem>, kinds: Set<SentKind>): List<SentItem> = all.filter { it.kind !in kinds }

    /** The kinds one tab holds: Texts shows texts and links, Files the files. */
    fun tabOf(kind: SentKind): Set<SentKind> = if (kind == SentKind.FILE) setOf(SentKind.FILE) else setOf(SentKind.TEXT, SentKind.LINK)

    /** "just now", "12 min ago", "3 h ago", then the day ("Oct 26"). */
    fun ago(at: Long, now: Long): String {
        val d = now - at
        return when {
            d < 60_000L -> "just now"
            d < 3_600_000L -> "${d / 60_000L} min ago"
            d < 86_400_000L -> "${d / 3_600_000L} h ago"
            else -> SimpleDateFormat("MMM d", Locale.getDefault()).format(Date(at))
        }
    }

    /** A text's first line, for its row. */
    fun firstLine(text: String): String = text.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() } ?: text
}
