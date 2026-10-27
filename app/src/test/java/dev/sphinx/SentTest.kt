package dev.sphinx

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** What laptops sent, as the Texts and Files tabs keep it: newest first, 200 at most, forgotten one by one or by tab. */
class SentTest {
    private fun item(n: Int, kind: SentKind = SentKind.TEXT) = SentItem(id = "i$n", at = n.toLong(), laptop = "L", kind = kind, text = "t$n")

    @Test fun newestFirstAndTheOldestDroppedPast200() {
        var all = emptyList<SentItem>()
        for (n in 1..230) all = SentRules.add(all, item(n))
        // And a byte cap: long texts drop the oldest well before 200.
        var big = emptyList<SentItem>()
        for (n in 1..60) big = SentRules.add(big, SentItem(id = "b$n", at = n.toLong(), laptop = "L", kind = SentKind.TEXT, text = "x".repeat(3000)))
        assertTrue(big.size < 60 && big.sumOf(SentRules::bytes) <= SentRules.MAX_BYTES && big.first().id == "b60")
        assertEquals(200, all.size)
        assertEquals("i230", all.first().id)
        assertEquals("i31", all.last().id)
        assertTrue(all.zipWithNext().all { (a, b) -> a.at > b.at })
    }

    @Test fun anOlderArrivalStillSortsByItsTime() {
        val all = SentRules.add(SentRules.add(emptyList(), item(5)), item(3))
        assertEquals(listOf("i5", "i3"), all.map { it.id })
    }

    @Test fun removedByIdAndClearedByTab() {
        val all = listOf(item(3, SentKind.FILE), item(2, SentKind.LINK), item(1))
        assertEquals(listOf("i3", "i1"), SentRules.remove(all, "i2").map { it.id })
        assertEquals(all, SentRules.remove(all, "nope"))
        // Texts clears texts and links; Files only the files.
        assertEquals(listOf("i3"), SentRules.clear(all, SentRules.tabOf(SentKind.TEXT)).map { it.id })
        assertEquals(listOf("i3"), SentRules.clear(all, SentRules.tabOf(SentKind.LINK)).map { it.id })
        assertEquals(listOf("i2", "i1"), SentRules.clear(all, SentRules.tabOf(SentKind.FILE)).map { it.id })
    }

    @Test fun whenItCameIsRelativeForADayThenTheDate() {
        val now = 1_792_000_000_000L
        assertEquals("just now", SentRules.ago(now - 30_000L, now))
        assertEquals("12 min ago", SentRules.ago(now - 12 * 60_000L, now))
        assertEquals("3 h ago", SentRules.ago(now - 3 * 3_600_000L, now))
        assertFalse(SentRules.ago(now - 3 * 86_400_000L, now).endsWith("ago"))
        assertEquals("Meeting room code 4471", SentRules.firstLine("\nMeeting room code 4471\nsecond line"))
    }

    @Test fun anItemSurvivesTheStoresJson() {
        val s = SentItem("id1", 7, "Laptop", SentKind.FILE, name = "a.pdf", mime = "application/pdf", size = 10, uri = "content://x/1")
        val back = json.readValue(json.writeValueAsString(listOf(s)), object : com.fasterxml.jackson.core.type.TypeReference<List<SentItem>>() {})
        assertEquals(listOf(s), back)
    }
}
