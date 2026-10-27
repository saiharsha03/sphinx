package dev.sphinx

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
object SentRules {
    const val MAX = 200

    /** [item] in front of [all], the oldest beyond [MAX] dropped. */
    fun add(all: List<SentItem>, item: SentItem): List<SentItem> = (listOf(item) + all.filter { it.id != item.id }).sortedByDescending { it.at }.take(MAX)

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
