package dev.sphinx

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Owner, 2026-10-26: "the app should auto lock whenever I move away from the app". */
class AppLockTest {
    @Test fun leavingLocksEveryTime() {
        assertTrue(AppLock.onStop(inside = false, interactive = true))
        assertTrue(AppLock.onStart(stoppedAt = 1_000L, now = 2_000L, inside = false))
    }

    @Test fun sphinxsOwnScannerAndPickerDoNotLock() {
        assertFalse(AppLock.onStop(inside = true, interactive = true))
        assertFalse(AppLock.onStart(stoppedAt = 1_000L, now = 5_000L, inside = true))
    }

    @Test fun theScreenGoingOffOrALongStayOutsideStillLocks() {
        assertTrue(AppLock.onStop(inside = true, interactive = false))
        assertTrue(AppLock.onStart(stoppedAt = 1_000L, now = 1_000L + AppLock.AWAY_MS + 1, inside = true))
    }

    @Test fun theExemptionExpires() {
        AppLock.goingInside(now = 0L)
        assertTrue(AppLock.inside(now = AppLock.INSIDE_MS - 1))
        assertFalse(AppLock.inside(now = AppLock.INSIDE_MS))
        AppLock.clear()
    }

    @Test fun theFirstStartIsTheOpeningLockNotARelock() = assertFalse(AppLock.onStart(stoppedAt = 0L, now = 5_000L, inside = false))
}
