package dev.sphinx

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** The backup: Argon2id and BIP39 against reference vectors, the sealed state, and each restore path end to end. */
class BackupTest {
    private val now = 1_800_000_000_000L
    private val secret = "12345678901234567890".toByteArray()
    private val fast = Kdf(m = 256, t = 3, p = 1)
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun tmp(): File = Files.createTempDirectory("sphinx-backup").toFile()

    /** A phone: its own Keystore stand-in, sealed prefs, a backup folder and a Keys safe folder. */
    private inner class Phone(val dir: File = tmp()) {
        val keys = FakeKeys().apply { approved = true }
        val kv = HashMap<String, String>()
        val backup = LocalBackup(File(dir, "backup")) { now }
        var changes = 0
        val store = SphinxStore({ kv[it] }, { k, v -> if (v == null) kv.remove(k) else kv[k] = v }, keys, { now }, backup = backup, changed = { changes++ })
        val safe = SafeStore({ kv[it] }, { k, v -> if (v == null) kv.remove(k) else kv[k] = v }, keys, File(dir, "safe"), { now }, backup) { changes++ }
        fun code(issuer: String) = store.code(store.accounts().first { it.issuer == issuer }, keys.unwrapper(), now)
    }

    private fun Phone.importTwo() = store.add(listOf(
        Imported("GitHub", "alex", secret.copyOf(), Algo.SHA1, 6, 30),
        Imported("Dropbox", "alex@example.com", "ABCDEFGHIJ0123456789".toByteArray(), Algo.SHA256, 8, 30),
    ))

    @Test fun argon2idMatchesTheReferenceImplementation() {
        // argon2-cffi (the reference C implementation): hash_secret_raw(b"password", b"somesalt", 2, 65536, 1, 32, Type.ID)
        assertEquals("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
            hex(BackupCrypto.argon2id("password".toByteArray(), "somesalt".toByteArray(), Kdf(m = 65536, t = 2, p = 1))))
        assertEquals("19bc829fd8a9a5a984947bccf2f0e74cb99b546ddfd455123d6807772aaf4c1d",
            hex(BackupCrypto.argon2id("correct horse battery staple".toByteArray(), ByteArray(16) { it.toByte() }, Kdf(m = 256, t = 3, p = 1))))
        // The cost the app uses is memory-hard: 64 MiB, 3 passes.
        assertEquals(Kdf(65536, 3, 1), Kdf())
    }

    @Test fun theRecoveryPhraseIsBip39() {
        assertEquals(2048, Bip39.WORDS.size)
        val words = Bip39.phrase(ByteArray(32) { 0x7f })
        // The official BIP39 vector (entropy 7f x 32), and its seed with the passphrase TREZOR.
        assertEquals("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title", words.joinToString(" "))
        assertEquals("bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87", hex(Bip39.seed(words, "TREZOR")))
        assertEquals(words, Bip39.check("  LEGAL winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title "))
        // A wrong checksum (two words swapped), a word off the list, or 23 words: refused.
        assertNull(Bip39.check((listOf(words[1], words[0]) + words.drop(2)).joinToString(" ")))
        assertNull(Bip39.check((words.dropLast(1) + "zzzz").joinToString(" ")))
        assertNull(Bip39.check(words.drop(1).joinToString(" ")))
        assertTrue(Bip39.phrase() != Bip39.phrase())
    }

    @Test fun thePasscodeIsTwelvePlusAndTheHintPushesAPhrase() {
        assertNotNull(Passcode.problem("short pass"))
        assertNotNull(Passcode.problem("aaaaaaaaaaaaaaaa"))
        assertNull(Passcode.problem("correct horse battery staple"))
        assertTrue(Passcode.hint("Tr0ub4dor&3xy").startsWith("Weak"))
        assertEquals("Strong", Passcode.hint("copper lantern orbit meadow river"))
    }

    @Test fun aRecordOpensOnlyWithItsOwnPasscodeAndSlot() {
        val bk = BackupCrypto.newKey()
        val sealed = BackupCrypto.sealState(bk, BackupState(accounts = listOf(BackupAccount("a1", "GitHub", secret = "c2VjcmV0"))))
        val salt = ByteArray(16) { 9 }
        val k = BackupCrypto.passKeys("copper lantern orbit meadow", salt, fast)
        val record = BackupCrypto.record("pass", k.key, bk, sealed)
        val (bk2, sealed2) = BackupCrypto.openRecord("pass", BackupCrypto.passKeys("copper lantern orbit meadow", salt, fast).key, record)!!
        assertArrayEquals(bk, bk2)
        assertEquals("GitHub", BackupCrypto.openState(bk2, sealed2)!!.accounts.single().issuer)
        // A wrong passcode, another salt, another slot, or a flipped byte: nothing opens.
        assertNull(BackupCrypto.openRecord("pass", BackupCrypto.passKeys("copper lantern orbit meadoW", salt, fast).key, record))
        assertNull(BackupCrypto.openRecord("pass", BackupCrypto.passKeys("copper lantern orbit meadow", ByteArray(16) { 8 }, fast).key, record))
        assertNull(BackupCrypto.openRecord("phrase-slot", k.key, record))
        assertNull(BackupCrypto.openState(bk, sealed.copyOf().also { it[20] = (it[20] + 1).toByte() }))
        // The auth value the relay checks is not the wrapping key, and differs per passcode.
        assertFalse(k.auth == SphinxCrypto.enc(k.key))
        assertFalse(k.auth == BackupCrypto.passKeys("another long passcode here", salt, fast).auth)
    }

    @Test fun everyChangeReachesTheSealedStateAndTheStateNeverHoldsPairings() {
        val p = Phone()
        p.backup.start()
        p.importTwo()
        p.store.putPairing(Pairing("P".repeat(22), "Laptop", ByteArray(32), ByteArray(32), "https://relay.example.com", ByteArray(32)))
        var s = p.backup.read()!!
        assertEquals(listOf("GitHub", "Dropbox"), s.accounts.map { it.issuer })
        assertArrayEquals(secret, SphinxCrypto.dec(s.accounts[0].secret))
        assertTrue(p.store.accounts().all { p.store.backedUp(it.id) })
        val gh = p.store.accounts().first { it.issuer == "GitHub" }
        p.store.update(gh.copy(domains = listOf("github.com", "*.github.com")))
        p.store.saveTextSites(listOf("shop.example"))
        p.safe.add("Recovery codes", "text", "", "text/plain", "one two three".toByteArray())
        p.store.delete(p.store.accounts().first { it.issuer == "Dropbox" }.id)
        s = p.backup.read()!!
        assertEquals(listOf("github.com", "*.github.com"), s.accounts.single().domains)
        assertEquals(listOf("shop.example"), s.textSites)
        assertEquals("one two three", String(SphinxCrypto.dec(s.safe.single().data)!!))
        assertEquals(5, p.changes)
        // On disk: only ciphertext, and nothing of the pairing anywhere in the state.
        val disk = String(p.backup.stateFile.readBytes(), Charsets.ISO_8859_1)
        assertFalse(disk.contains("GitHub") || disk.contains("one two three"))
        assertFalse(json.writeValueAsString(s).contains("P".repeat(22)))
    }

    @Test fun theGooglePathRestoresOnANewPhoneWithItsOwnKeysAndRetiresTheKey() {
        val old = Phone()
        old.backup.start()
        old.importTwo()
        old.safe.add("Keystore", "file", "../release.p12", "application/x-pkcs12", ByteArray(3000) { 7 })
        val codes = listOf(old.code("GitHub"), old.code("Dropbox"))
        // What Android carries: exactly the two files, into a new phone with new Keystore keys.
        val fresh = Phone()
        File(fresh.dir, "backup").mkdirs()
        old.backup.stateFile.copyTo(fresh.backup.stateFile); old.backup.keyFile.copyTo(fresh.backup.keyFile)
        val state = fresh.backup.read()!!
        assertEquals(2, fresh.store.restore(state))
        assertEquals(1, fresh.safe.restore(state.safe))
        assertEquals(codes, listOf(fresh.code("GitHub"), fresh.code("Dropbox")))
        val e = fresh.safe.entries().single()
        assertEquals("release.p12", e.name)
        assertArrayEquals(ByteArray(3000) { 7 }, fresh.safe.open(e, fresh.keys.unwrapper()))
        // The old phone's keys can't open the new phone's seals.
        assertTrue(runCatching { fresh.store.code(fresh.store.accounts()[0], old.keys.unwrapper(), now) }.isFailure)
        // The key that travelled is retired: a new one seals the same state.
        val before = fresh.backup.key()!!
        fresh.backup.rotate()
        assertFalse(before.contentEquals(fresh.backup.key()!!))
        assertNull(BackupCrypto.openState(before, fresh.backup.stateFile.readBytes()))
        assertEquals(2, fresh.backup.read()!!.accounts.size)
        // Restoring twice adds nothing.
        assertEquals(0, fresh.store.restore(state))
    }

    @Test fun theRelayPathAndThePhrasePathOpenTheSameState() {
        val old = Phone()
        old.backup.start()
        old.importTwo()
        val bk = old.backup.key()!!
        val sealed = old.backup.stateFile.readBytes()
        val salt = ByteArray(16) { 5 }
        val pass = BackupCrypto.passKeys("copper lantern orbit meadow river", salt, fast)
        val words = Bip39.phrase(ByteArray(32) { 0x2a })
        val phrase = BackupCrypto.phraseKeys(Bip39.seed(words))
        val atPass = BackupCrypto.record("pass", pass.key, bk, sealed)
        val atPhrase = BackupCrypto.record(phrase.id, phrase.key, bk, sealed)
        for ((slot, key, rec) in listOf(Triple("pass", BackupCrypto.passKeys("copper lantern orbit meadow river", salt, fast).key, atPass),
            Triple(BackupCrypto.phraseKeys(Bip39.seed(Bip39.check(words.joinToString(" "))!!)).id, BackupCrypto.phraseKeys(Bip39.seed(words)).key, atPhrase))) {
            val (k, s) = BackupCrypto.openRecord(slot, key, rec)!!
            val fresh = Phone()
            assertEquals(2, fresh.store.restore(BackupCrypto.openState(k, s)!!))
            assertEquals(old.code("GitHub"), fresh.code("GitHub"))
        }
        // The phrase's slot id, key and auth are three different values, none of them the seed.
        assertEquals(3, setOf(phrase.id, SphinxCrypto.enc(phrase.key), phrase.auth).size)
        // Another phrase opens nothing.
        assertNull(BackupCrypto.openRecord(phrase.id, BackupCrypto.phraseKeys(Bip39.seed(Bip39.phrase(ByteArray(32) { 1 }))).key, atPhrase))
    }

    @Test fun oneLocalBackupPerFolderAndAStopBetweenANewKeyAndItsStateStillOpens() {
        val dir = File(tmp(), "backup")
        assertTrue(LocalBackup.at(dir) === LocalBackup.at(File(dir.path)))
        val l = LocalBackup(dir) { now }
        l.start(BackupState(textSites = listOf("a.example")))
        // A rotate that stopped after key.next and the state sealed with it, before key.bin moved: the state opens with key.next.
        val next = BackupCrypto.newKey()
        File(dir, "key.next").writeBytes(next)
        l.stateFile.writeBytes(BackupCrypto.sealState(next, BackupState(textSites = listOf("b.example"))))
        assertEquals(listOf("b.example"), l.read()!!.textSites)
        assertArrayEquals(next, l.keyFile.readBytes())
        assertFalse(File(dir, "key.next").exists())
        // Many changes at once through the one instance: none is lost.
        val shared = LocalBackup.at(File(tmp(), "backup")).apply { start() }
        (1..8).map { i -> Thread { repeat(10) { j -> shared.update { it.copy(textSites = it.textSites + "s$i-$j.example") } } }.apply { start() } }.forEach { it.join() }
        assertEquals(80, shared.read()!!.textSites.size)
    }

    @Test fun aFullKeysSafeFitsTheRelaysLimitAndOldRecordsStillOpen() {
        val bk = BackupCrypto.newKey()
        val safe = (0 until 16).map { BackupSafe("s$it", "file $it", "file", "f$it", "x/y", now, SphinxCrypto.enc(ByteArray(SafeStore.MAX_TOTAL / 16) { 1 })) }
        val sealed = BackupCrypto.sealState(bk, BackupState(safe = safe))
        val k = BackupCrypto.passKeys("copper lantern orbit meadow", ByteArray(16), fast)
        val record = BackupCrypto.record("pass", k.key, bk, sealed)
        assertTrue("${record.length}", record.length < 8_000_000)
        assertArrayEquals(bk, BackupCrypto.openRecord("pass", k.key, record)!!.first)
        // A v1 record (the same JSON, base64'd once more) still opens.
        val v1 = SphinxCrypto.enc(json.writeValueAsBytes(mapOf("v" to 1, "wrapped" to json.readTree(record).path("wrapped").asText(), "state" to SphinxCrypto.enc(sealed))))
        assertArrayEquals(bk, BackupCrypto.openRecord("pass", k.key, v1)!!.first)
    }

    @Test fun aRestoreTakesNoArgon2CostBelowOursAndNoShortSalt() {
        val salt = ByteArray(16)
        assertTrue(BackupCrypto.trusted(Kdf(), salt))
        assertTrue(BackupCrypto.trusted(Kdf(m = 131072, t = 4), salt))
        assertFalse(BackupCrypto.trusted(Kdf(m = 8192, t = 1), salt))
        assertFalse(BackupCrypto.trusted(Kdf(m = 65536, t = 2), salt))
        assertFalse(BackupCrypto.trusted(Kdf(m = 32768, t = 3), salt))
        assertFalse(BackupCrypto.trusted(Kdf(), ByteArray(8)))
        assertFalse(BackupCrypto.trusted(null, salt))
    }

    @Test fun changingThePasscodeNeedsTheCurrentOne() {
        val salt = ByteArray(16) { 3 }
        val k = BackupCrypto.passKeys("copper lantern orbit meadow", salt, fast)
        val r = RelayBackup("https://relay.example.com", salt = SphinxCrypto.enc(salt), kdf = fast, passKey = SphinxCrypto.enc(k.key), passAuth = k.auth)
        assertTrue(BackupCrypto.proves("copper lantern orbit meadow", r))
        assertFalse(BackupCrypto.proves("copper lantern orbit meadoW", r))
        assertFalse(BackupCrypto.proves("", r))
    }

    @Test fun aRestoreKeepsWhatThePhoneAlreadyHeld() {
        val here = BackupState(accounts = listOf(BackupAccount("a1", "Here"), BackupAccount("a2", "Both")), safe = listOf(BackupSafe("k1", "here")), textSites = listOf("h.example"))
        val back = BackupState(accounts = listOf(BackupAccount("a2", "Both, restored"), BackupAccount("a3", "Back")), safe = listOf(BackupSafe("k2", "back")),
            textSites = listOf("b.example"), relay = RelayBackup("https://relay.example.com"))
        val m = BackupCrypto.merged(back, here)
        // On a duplicate id the entry already on the phone wins, as the stores keep it.
        assertEquals(listOf("Here", "Both", "Back"), m.accounts.map { it.issuer })
        assertEquals(setOf("k1", "k2"), m.safe.map { it.id }.toSet())
        assertEquals(setOf("h.example", "b.example"), m.textSites.toSet())
        assertEquals("https://relay.example.com", m.relay?.relay)
        assertEquals(back, BackupCrypto.merged(back, null))
    }

    private fun relayOn(l: LocalBackup, phrase: Boolean = true): RelayBackup {
        val k = BackupCrypto.passKeys("copper lantern orbit meadow", ByteArray(16), fast)
        val r = RelayBackup("https://relay.example.com", "", SphinxCrypto.enc(ByteArray(16)), fast, SphinxCrypto.enc(k.key), k.auth,
            if (phrase) "P".repeat(43) else "", if (phrase) SphinxCrypto.enc(ByteArray(32) { 4 }) else "", if (phrase) "A".repeat(43) else "")
        l.update { it.copy(relay = r) }
        return r
    }

    @Test fun turningOffSaysSoWhenTheRelayKeptItsCopy() {
        val l = LocalBackup(File(tmp(), "backup")) { now }.apply { start() }
        relayOn(l)
        val asked = ArrayList<String>()
        val e = runCatching { Backups.turnOff(l) { _, slot, _ -> asked += slot; if (slot == "pass") throw RelayClient.Failed(503) } }.exceptionOrNull()
        assertTrue(e?.message.orEmpty(), e?.message.orEmpty().contains("couldn't be deleted"))
        assertEquals(listOf("pass", "P".repeat(43)), asked)
        assertNull(l.read()!!.relay)
        // Both deletes taken: no complaint.
        relayOn(l)
        Backups.turnOff(l) { _, _, _ -> }
        assertNull(l.read()!!.relay)
    }

    @Test fun aSnapshotIsOneConsistentPairAndAMoveDeletesTheOldRelaysSlots() {
        val l = LocalBackup(File(tmp(), "backup")) { now }.apply { start(BackupState(textSites = listOf("a.example"))) }
        val (bk, s, sealed) = l.snapshot()!!
        assertEquals(s, BackupCrypto.openState(bk, sealed)!!.copy(at = s.at))
        // A rotation after it doesn't change the pair it gave; the next snapshot is the new pair.
        l.rotate()
        val (bk2, _, sealed2) = l.snapshot()!!
        assertFalse(bk2.contentEquals(bk))
        assertNotNull(BackupCrypto.openState(bk2, sealed2))
        assertNull(BackupCrypto.openState(bk, sealed2))
        // The upload sends what one snapshot holds: its record opens with that BK to that state.
        val r = relayOn(l, phrase = false)
        var body: Map<String, Any?>? = null
        Backups.upload(l) { _, _, b -> body = b }
        val (k3, st3) = BackupCrypto.openRecord("pass", SphinxCrypto.dec(r.passKey)!!, body!!["blob"] as String)!!
        assertNotNull(BackupCrypto.openState(k3, st3))
        // Moving to another relay: both of the old relay's slots are deleted; a failure is returned to be said.
        val asked = ArrayList<String>()
        assertNull(Backups.dropSlots(r.copy(phraseId = "P".repeat(43))) { _, slot, _ -> asked += slot })
        assertEquals(listOf("pass", "P".repeat(43)), asked)
        assertTrue(Backups.dropSlots(r) { _, _, _ -> throw RelayClient.Failed(503) } is RelayClient.Failed)
    }

    @Test fun anUploadNeverCreatesASlotAndAPhraseGoneFromTheRelayIsOffHereToo() {
        val l = LocalBackup(File(tmp(), "backup")) { now }.apply { start() }
        relayOn(l)
        val puts = ArrayList<Pair<String, Map<String, Any?>>>()
        Backups.upload(l) { _, slot, body -> puts += slot to body; if (slot != "pass") throw RelayClient.Failed(404) }
        assertTrue(puts.all { it.second["create"] == false })
        // The phrase slot was gone: off here, and the passcode's copy sent again without it.
        assertEquals(listOf("pass", "P".repeat(43), "pass"), puts.map { it.first })
        assertEquals("", l.read()!!.relay!!.phraseId)
        // Any other failure is passed on (the worker retries).
        relayOn(l)
        assertTrue(runCatching { Backups.upload(l) { _, slot, _ -> if (slot != "pass") throw RelayClient.Failed(503) } }.isFailure)
        assertEquals("P".repeat(43), l.read()!!.relay!!.phraseId)
    }

    @Test fun aNewFingerprintSetsTheBackupAsideAndOnlyItsPasscodeOrPhraseReopensIt() {
        val dir = File(tmp(), "backup")
        val l = LocalBackup(dir) { now }
        val salt = ByteArray(16) { 7 }
        val k = BackupCrypto.passKeys("copper lantern orbit meadow", salt, fast)
        val words = Bip39.phrase(ByteArray(32) { 3 })
        val ph = BackupCrypto.phraseKeys(Bip39.seed(words))
        val r = RelayBackup("https://relay.example.com", "", SphinxCrypto.enc(salt), fast, SphinxCrypto.enc(k.key), k.auth, ph.id, SphinxCrypto.enc(ph.key), ph.auth)
        l.start(BackupState(accounts = listOf(BackupAccount("a1", "GitHub", secret = "c2VjcmV0")), relay = r))
        assertTrue(l.stash(LocalBackup.CLEARED))
        l.start()
        assertEquals(LocalBackup.CLEARED, l.foreignWhy())
        assertTrue(l.read()!!.accounts.isEmpty())                       // nothing of it in the backup this phone keeps now
        val s = l.foreign()!!.second
        assertTrue(BackupCrypto.opens(s, "copper lantern orbit meadow", null))
        assertTrue(BackupCrypto.opens(s, null, words))
        assertFalse(BackupCrypto.opens(s, "not the passcode at all", null))
        assertFalse(BackupCrypto.opens(s, null, Bip39.phrase(ByteArray(32) { 4 })))
        assertFalse(BackupCrypto.opens(s.copy(relay = null), "copper lantern orbit meadow", null))
        // The fingerprint path (Backups.adopt) refuses it; Google's is the default reason.
        val src = File("src/main/java/dev/sphinx/Backups.kt").readText()
        assertTrue(src.contains("if (a.why == LocalBackup.CLEARED) error("))
        val sphinx = File("src/main/java/dev/sphinx/Sphinx.kt").readText().substringAfter("catch (e: SphinxStore.Cleared)").substringBefore("catch (e: Exception)")
        assertTrue(sphinx.contains("Backups.retire(c)"))
        // A relay restore joins this phone's secrets to the backup it brings: only after a codes-key fingerprint.
        val restore = File("src/main/java/dev/sphinx/SafeScreens.kt").readText().substringAfter("fun RestorePane")
        assertTrue(restore.substringBefore("Backups.restore(").contains("Sphinx.confirm("))
        val g = LocalBackup(File(tmp(), "backup")) { now }.apply { start(BackupState(accounts = listOf(BackupAccount("a2")))) }
        g.stash()
        assertEquals(LocalBackup.GOOGLE, g.foreignWhy())
    }

    @Test fun aStashAStopInterruptedIsFinishedBeforeAnythingReplacesIt() {
        val dir = File(tmp(), "backup")
        val l = LocalBackup(dir) { now }
        l.start(BackupState(accounts = listOf(BackupAccount("a1", "GitHub", secret = "c2VjcmV0"))))
        val theirs = l.key()!!
        // Codex's case: the state moved, then a stop before the key; the next start must not write a new key over it.
        val aside = File(dir, "restored").apply { mkdirs() }
        File(aside, "why").writeText(LocalBackup.GOOGLE); File(aside, "moving").writeText(LocalBackup.GOOGLE)
        java.nio.file.Files.move(l.stateFile.toPath(), File(aside, "state.bin").toPath())
        assertNull(l.foreign())                                          // half moved: not opened
        assertTrue(l.finishStash())
        assertArrayEquals(theirs, l.foreign()!!.first)
        assertFalse(l.keyFile.exists())
        l.start()
        assertArrayEquals(theirs, l.foreign()!!.first)                  // the new backup didn't touch it
        assertFalse(l.finishStash())
        // A set-aside backup whose live key was still in key.next opens with it.
        val m = LocalBackup(File(tmp(), "backup")) { now }.apply { start() }
        val next = BackupCrypto.newKey()
        File(File(tmp(), "x"), "").mkdirs()
        val d2 = m.stateFile.parentFile!!
        File(d2, "key.next").writeBytes(next)
        m.stateFile.writeBytes(BackupCrypto.sealState(next, BackupState(textSites = listOf("n.example"))))
        assertTrue(m.stash())
        assertEquals(listOf("n.example"), m.foreign()!!.second.textSites)
    }

    @Test fun aRetireStoppedAtAnyStepIsFinishedAndNothingUploadsBefore() {
        val salt = ByteArray(16)
        val k = BackupCrypto.passKeys("copper lantern orbit meadow", salt, fast)
        val relay = RelayBackup("https://relay.example.com", "", SphinxCrypto.enc(salt), fast, SphinxCrypto.enc(k.key), k.auth)
        fun old(dir: File) = LocalBackup(dir) { now }.apply { start(BackupState(accounts = listOf(BackupAccount("a1", "GitHub", secret = "c2VjcmV0")), relay = relay)) }
        // Stopped right after the marker (before the stash): the old backup is set aside, not uploaded.
        val a = old(File(tmp(), "backup")).apply { markRetire() }
        var puts = 0
        Backups.upload(a) { _, _, _ -> puts++ }
        assertEquals(0, puts)
        assertEquals(LocalBackup.CLEARED, a.foreignWhy())
        assertTrue(a.read()!!.accounts.isEmpty() && a.read()!!.relay == null)
        assertFalse(a.retirePending())
        // Stopped after the stash, before the new backup: it starts one, with no second set-aside copy.
        val dirB = File(tmp(), "backup")
        val b = old(dirB).apply { markRetire() }
        assertTrue(b.stash(LocalBackup.CLEARED))
        File(dirB, "retire.pending").writeText("stashed")
        assertTrue(b.retire())
        assertTrue(b.exists() && b.read()!!.accounts.isEmpty())
        assertEquals(1, dirB.listFiles { f -> f.name.startsWith("restored") }!!.size)
        // Stopped after the new backup, before the marker went: nothing more is stashed.
        File(dirB, "retire.pending").writeText("stashed")
        assertTrue(b.retire())
        assertEquals(1, dirB.listFiles { f -> f.name.startsWith("restored") }!!.size)
        // A retire over an empty backup sets nothing aside.
        val dirC = File(tmp(), "backup")
        val c = LocalBackup(dirC) { now }.apply { start(); markRetire() }
        assertTrue(c.retire())
        assertNull(c.foreignWhy())
        // Every path that sends or merges the backup goes through the same check first.
        val src = File("src/main/java/dev/sphinx/Backups.kt").readText()
        for (f in listOf("fun setUp(", "fun phraseOn(", "fun restore(", "internal fun upload(", "fun adopt(", "fun adoptWith("))
            assertTrue(f, src.substringAfter(f).substringBefore("\n    }").contains("ready("))
    }

    @Test fun anOpenAndADeleteThatOverlapTouchOnlyTheCopyTheyNamed() {
        // Codex round 4: copy A is opened; while that runs he deletes A; the open's cleanup must not then delete B.
        val dir = File(tmp(), "backup")
        val l = LocalBackup(dir) { now }
        l.start(BackupState(accounts = listOf(BackupAccount("a", "A", secret = "c2VjcmV0"))))
        assertTrue(l.stash())
        l.start(BackupState(accounts = listOf(BackupAccount("b", "B", secret = "c2VjcmV0"))))
        assertTrue(l.stash(LocalBackup.CLEARED))
        val a = l.aside()!!
        val b = l.aside(l.aside()!!.id.let { first -> dir.listFiles()!!.filter { it.name.startsWith("restored") }.map { File(it, "id").readText() }.first { it != first } })!!
        assertEquals("A", a.state.accounts.single().issuer); assertEquals("B", b.state.accounts.single().issuer)
        assertTrue(a.id != b.id)
        assertTrue(l.dropAside(a.id))                                    // his delete of A, mid-open
        assertFalse(l.dropAside(a.id))                                   // the open's cleanup of A: already gone, nothing else touched
        assertNull(l.aside(a.id))
        assertEquals("B", l.aside()!!.state.accounts.single().issuer)
        assertEquals(b.id, l.aside()!!.id)
        // A new stash never takes a deleted copy's id.
        l.start(BackupState(accounts = listOf(BackupAccount("c", "C", secret = "c2VjcmV0"))))
        assertTrue(l.stash())
        assertTrue(listOf(a.id, b.id).none { id -> l.aside(id)?.state?.accounts?.single()?.issuer == "C" })
        // The app opens and deletes only by the id the card showed.
        val src = File("src/main/java/dev/sphinx/Backups.kt").readText()
        assertTrue(src.contains("l.dropAside(a.id)") && !src.contains("dropForeign()"))
    }

    @Test fun aStateNoKeyCanOpenNeverStopsARetireAndAStuckOneIsShown() {
        val dir = File(tmp(), "backup")
        val l = LocalBackup(dir) { now }.apply { start(BackupState(accounts = listOf(BackupAccount("a", "A", secret = "c2VjcmV0")))) }
        l.keyFile.delete()                                              // neither key.bin nor key.next
        l.markRetire()
        assertTrue(l.retire())
        assertFalse(l.retirePending())
        assertTrue(File(dir, "state.unopenable.bin").exists())
        assertTrue(l.read()!!.accounts.isEmpty())
        // The marker goes in through a rename (no half-written file left), and the Codes tab says when one is stuck.
        l.markRetire()
        assertTrue(l.retirePending() && !File(dir, "retire.pending.tmp").exists())
        assertTrue(File("src/main/java/dev/sphinx/MainActivity.kt").readText().contains("Backups.local(app).retirePending()"))
    }

    @Test fun aSecondStashNeverOverwritesOneSetAsideBefore() {
        val dir = File(tmp(), "backup")
        val l = LocalBackup(dir) { now }
        l.start(BackupState(accounts = listOf(BackupAccount("g1", "From Google", secret = "c2VjcmV0"))))
        val google = l.key()!!
        assertTrue(l.stash())                                            // the unopened Google backup
        l.start(BackupState(accounts = listOf(BackupAccount("h1", "Here", secret = "c2VjcmV0"))))
        assertTrue(l.stash(LocalBackup.CLEARED))                          // then a new fingerprint
        // The older one is shown first and untouched; once it is dealt with, the next one comes up.
        assertArrayEquals(google, l.foreign()!!.first)
        assertEquals(LocalBackup.GOOGLE, l.foreignWhy())
        l.dropAside(l.aside()!!.id)
        assertEquals("Here", l.foreign()!!.second.accounts.single().issuer)
        assertEquals(LocalBackup.CLEARED, l.foreignWhy())
    }

    @Test fun aPairingsWindowSurvivesASaveAndReload() {
        val kv = HashMap<String, String>()
        val s = SphinxStore({ kv[it] }, { k, v -> if (v == null) kv.remove(k) else kv[k] = v }, FakeKeys(), { now })
        s.putPairing(Pairing("P".repeat(22), "Laptop", ByteArray(32), ByteArray(32), "https://relay.example.com", ByteArray(32), recv = 40, gaps = listOf(38L, 39L)))
        val back = SphinxStore({ kv[it] }, { _, _ -> }, FakeKeys(), { now }).pairing("P".repeat(22))!!
        assertEquals(listOf(38L, 39L), back.gaps)
        assertTrue(ReplayWindow.fresh(39L, back.recv, back.gaps))       // a Long, still found after the round trip
        assertFalse(ReplayWindow.fresh(37L, back.recv, back.gaps))
    }

    @Test fun aBackupThisPhoneDidntMakeIsSetAsideUnopened() {
        val dir = File(tmp(), "backup")
        val l = LocalBackup(dir) { now }
        l.start(BackupState(accounts = listOf(BackupAccount("a1", "GitHub", secret = "c2VjcmV0"))))
        val theirs = l.key()!!
        assertTrue(l.stash())
        // This phone starts its own; the other one waits, unopened, with its own key.
        l.start()
        assertTrue(l.read()!!.accounts.isEmpty())
        val (k, s) = l.foreign()!!
        assertArrayEquals(theirs, k)
        assertEquals("GitHub", s.accounts.single().issuer)
        assertFalse(l.key()!!.contentEquals(theirs))
        l.dropAside(l.aside()!!.id)
        assertNull(l.foreign())
        assertFalse(LocalBackup(File(tmp(), "none")).stash())
    }

    @Test fun theBuiltInTokenGoesOnlyToTheBuiltInRelay() {
        val home = "https://sphinx.example.com"
        assertEquals("T", RelayClient.tokenFor("https://sphinx.example.com", "", home, "T"))
        assertEquals("T", RelayClient.tokenFor("https://SPHINX.example.com:443/", "", home, "T"))
        assertEquals("", RelayClient.tokenFor("https://attacker.example", "", home, "T"))
        assertEquals("", RelayClient.tokenFor("https://sphinx.example.com.attacker.example", "", home, "T"))
        assertEquals("", RelayClient.tokenFor("http://sphinx.example.com", "", home, "T"))
        assertEquals("", RelayClient.tokenFor("https://sphinx.example.com:8443", "", home, "T"))
        // A token the QR or the screen gave goes where it says.
        assertEquals("Q", RelayClient.tokenFor("https://attacker.example", "Q", home, "T"))
        // The built-in value passed back in (a stored or pre-filled field) still goes only home.
        assertEquals("", RelayClient.tokenFor("https://attacker.example", "T", home, "T"))
        assertEquals("T", RelayClient.tokenFor(home, "T", home, "T"))
        // What a backup keeps: a typed token for its relay; not the built-in one, not the old relay's token on a move.
        assertEquals("C", RelayClient.keepToken(" C ", "https://mine.example", "T", null, null))
        assertEquals("", RelayClient.keepToken("T", home, "T", null, null))
        assertEquals("", RelayClient.keepToken("C", "https://elsewhere.example", "T", "https://mine.example", "C"))
        assertEquals("C", RelayClient.keepToken("C", "https://mine.example/", "T", "https://mine.example", "C"))
        assertEquals("D", RelayClient.keepToken("D", "https://elsewhere.example", "T", "https://mine.example", "C"))
    }

    @Test fun theProofOpensOnlyWithTheCipherHisFingerprintAuthorised() {
        val keys = FakeKeys()
        val ch = Proof.challenge(keys)
        assertFalse(Proof.check(keys.unwrapper(), ch))
        keys.approved = true
        assertTrue(Proof.check(keys.unwrapper(), ch))
        // Another key pair's cipher opens nothing.
        assertFalse(Proof.check(FakeKeys().apply { approved = true }.unwrapper(), ch))
    }

    @Test fun theKeysSafeHasCapsAndOpensOnlyWithTheFingerprint() {
        val p = Phone()
        p.backup.start()
        assertNotNull(p.safe.problem("text", ByteArray(SafeStore.MAX_TEXT + 1)))
        assertNotNull(p.safe.problem("file", ByteArray(SafeStore.MAX_ENTRY + 1)))
        assertTrue(runCatching { p.safe.add("big", "file", "x", "x/y", ByteArray(SafeStore.MAX_ENTRY + 1)) }.isFailure)
        val data = "seed words here".toByteArray()
        val e = p.safe.add("Phrase", "text", "", "text/plain", data)
        assertTrue(data.all { it == 0.toByte() })                     // the caller's copy is wiped
        assertFalse(String(File(p.dir, "safe/${e.id}.bin").readBytes(), Charsets.ISO_8859_1).contains("seed words"))
        p.keys.approved = false
        assertTrue(runCatching { p.safe.open(e, p.keys.unwrapper()) }.isFailure)
        p.keys.approved = true
        assertEquals("seed words here", String(p.safe.open(e, p.keys.unwrapper())))
        p.safe.delete(e.id)
        assertFalse(File(p.dir, "safe/${e.id}.bin").exists())
        assertTrue(p.backup.read()!!.safe.isEmpty())
    }

    @Test fun onlyTheBackupFilesTravelAndOnlyEncrypted() {
        val rules = File("src/main/res/xml/data_extraction_rules.xml").readText()
        assertTrue(rules.contains("disableIfNoEncryptionCapabilities=\"true\""))
        val includes = Regex("""<include domain="(\w+)" path="([^"]+)"""").findAll(rules).map { it.groupValues[1] + ":" + it.groupValues[2] }.toSet()
        assertEquals(setOf("file:backup/state.bin", "file:backup/key.bin", "file:backup/key.next"), includes)
        // A rotation stopped between its steps leaves the key in key.next: the cloud backup carries it too.
        assertTrue(rules.substringAfter("<cloud-backup").substringBefore("</cloud-backup>").contains("backup/key.next"))
        // A device-to-device transfer needs only the screen lock: it never carries the key that opens the state.
        val transfer = rules.substringAfter("<device-transfer>").substringBefore("</device-transfer>")
        assertTrue(transfer.contains("backup/state.bin") && !transfer.contains("key.bin"))
        assertTrue(rules.substringAfter("<cloud-backup").substringBefore("</cloud-backup>").contains("backup/key.bin"))
        val legacy = File("src/main/res/xml/backup_rules.xml").readText()
        assertEquals(3, Regex("requireFlags=\"clientSideEncryption\"").findAll(legacy).count())
        val manifest = File("src/main/AndroidManifest.xml").readText()
        assertTrue(manifest.contains("android:allowBackup=\"true\"") && manifest.contains("@xml/data_extraction_rules") && manifest.contains("@xml/backup_rules"))
    }
}
