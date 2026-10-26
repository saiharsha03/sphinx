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
        assertEquals(setOf("file:backup/state.bin", "file:backup/key.bin"), includes)
        val legacy = File("src/main/res/xml/backup_rules.xml").readText()
        assertEquals(2, Regex("requireFlags=\"clientSideEncryption\"").findAll(legacy).count())
        val manifest = File("src/main/AndroidManifest.xml").readText()
        assertTrue(manifest.contains("android:allowBackup=\"true\"") && manifest.contains("@xml/data_extraction_rules") && manifest.contains("@xml/backup_rules"))
    }
}
