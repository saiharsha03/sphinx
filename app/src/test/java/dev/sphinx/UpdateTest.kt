package dev.sphinx

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The updater's pure rules: what a release may look like, when it is newer, and when a downloaded APK is the one promised. */
class UpdateTest {
    private val sha = "ab".repeat(32)
    private fun release(vararg over: Pair<String, Any?>): String {
        val m = mutableMapOf<String, Any?>("versionCode" to 6, "versionName" to "1.3.0", "sha256" to sha, "size" to 4_200_000, "file" to "sphinx-1.3.0.apk", "notes" to "Faster wake.")
        over.forEach { (k, v) -> if (v == null) m.remove(k) else m[k] = v }
        return json.writeValueAsString(m)
    }

    @Test fun parseAcceptsTheRelaysRelease() {
        val r = UpdateRules.parse(release())!!
        assertEquals(AppRelease(6, "1.3.0", sha, 4_200_000, "sphinx-1.3.0.apk", "Faster wake."), r)
        // Notes are optional; a blank one is none.
        assertNull(UpdateRules.parse(release("notes" to null))!!.notes)
        assertNull(UpdateRules.parse(release("notes" to "  "))!!.notes)
    }

    @Test fun parseRefusesWhatTheRelayWouldRefuse() {
        assertNull(UpdateRules.parse(release("sha256" to sha.uppercase())))
        assertNull(UpdateRules.parse(release("sha256" to sha.dropLast(1))))
        assertNull(UpdateRules.parse(release("file" to "../sphinx.apk")))
        assertNull(UpdateRules.parse(release("file" to "a/b.apk")))
        assertNull(UpdateRules.parse(release("file" to "a\\b.apk")))
        assertNull(UpdateRules.parse(release("file" to "sphinx.zip")))
        assertNull(UpdateRules.parse(release("size" to 0)))
        assertNull(UpdateRules.parse(release("size" to UpdateRules.MAX_SIZE + 1)))
        assertNull(UpdateRules.parse(release("versionCode" to 0)))
        assertNull(UpdateRules.parse(release("versionCode" to "6")))
        assertNull(UpdateRules.parse(release("versionName" to "")))
        assertNull(UpdateRules.parse(release("versionName" to "x".repeat(41))))
        assertNull(UpdateRules.parse(release("notes" to "x".repeat(2001))))
        assertNull(UpdateRules.parse(release("file" to null)))
        assertNull(UpdateRules.parse("not json"))
        assertNull(UpdateRules.parse("[]"))
    }

    @Test fun newerMeansAHigherVersionCode() {
        val r = UpdateRules.parse(release())!!
        assertTrue(UpdateRules.newer(r, 5))
        assertFalse(UpdateRules.newer(r, 6))
        assertFalse(UpdateRules.newer(r, 7))
    }

    @Test fun sameSignersIgnoresOrderAndMissesNothing() {
        val a = byteArrayOf(1, 2, 3); val b = byteArrayOf(4, 5, 6)
        assertTrue(UpdateRules.sameSigners(listOf(a, b), listOf(b.copyOf(), a.copyOf())))
        assertTrue(UpdateRules.sameSigners(listOf(a), listOf(a.copyOf())))
        assertFalse(UpdateRules.sameSigners(listOf(a, b), listOf(a)))
        assertFalse(UpdateRules.sameSigners(listOf(a), listOf(a, b)))
        assertFalse(UpdateRules.sameSigners(listOf(a), listOf(b)))
        assertFalse(UpdateRules.sameSigners(emptyList(), emptyList()))
        assertFalse(UpdateRules.sameSigners(listOf(a, a), listOf(a, b)))
    }

    @Test fun verifiedChecksSizeHashPackageVersionAndKeyInThatOrder() {
        val r = UpdateRules.parse(release())!!
        val key = byteArrayOf(9, 9, 9)
        val own = Archive("dev.sphinx", 5, listOf(key))
        val apk = Archive("dev.sphinx", 6, listOf(key.copyOf()))
        assertNull(UpdateRules.verified(r, own, r.size.toLong(), sha, apk))
        assertEquals("The download isn't the size the release says.", UpdateRules.verified(r, own, r.size - 1L, sha, apk))
        assertEquals("The download doesn't match the release's hash.", UpdateRules.verified(r, own, r.size.toLong(), "cd".repeat(32), apk))
        assertEquals("The download isn't an APK Android can read.", UpdateRules.verified(r, own, r.size.toLong(), sha, null))
        assertEquals("The download isn't Sphinx.", UpdateRules.verified(r, own, r.size.toLong(), sha, apk.copy(packageName = "dev.other")))
        assertEquals("The download isn't the version the release says.", UpdateRules.verified(r, own, r.size.toLong(), sha, apk.copy(versionCode = 7)))
        assertEquals("The download isn't newer than this app.", UpdateRules.verified(r, Archive("dev.sphinx", 6, listOf(key)), r.size.toLong(), sha, apk))
        assertEquals("The download isn't signed with this app's key.", UpdateRules.verified(r, own, r.size.toLong(), sha, apk.copy(signers = listOf(byteArrayOf(1)))))
        assertNotNull(UpdateRules.verified(r, own, r.size.toLong(), sha, apk.copy(signers = emptyList())))
    }

    @Test fun aCheckLeavesADownloadAloneAndClearsAnOldOffer() {
        val r = UpdateRules.parse(release())!!
        assertTrue(UpdateRules.afterCheck(UpdateState.None, r, 5) is UpdateState.Available)
        assertTrue(UpdateRules.afterCheck(UpdateState.Available(r), r, 6) is UpdateState.None)
        assertTrue(UpdateRules.afterCheck(UpdateState.Available(r), null, 5) is UpdateState.None)
        assertTrue(UpdateRules.afterCheck(UpdateState.Failed(r, "x"), r, 5) is UpdateState.Available)
        val down = UpdateState.Downloading(r)
        assertTrue(UpdateRules.afterCheck(down, null, 5) === down)
        // The installer was opened and dismissed: a check offers the release again instead of saying Android is still asking.
        assertTrue(UpdateRules.afterCheck(UpdateState.Ready(r, "p"), r, 5) is UpdateState.Available)
    }

    @Test fun sha256HexIsLowercase() {
        assertEquals("00ff10", UpdateRules.sha256Hex(byteArrayOf(0, -1, 16)))
    }
}
