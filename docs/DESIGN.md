# Sphinx: design and threat model

Google Authenticator has no API, so Sphinx holds TOTP keys itself, for the few accounts you pick, and every code needs
your fingerprint, every time. Code: `app/src/main/java/dev/sphinx/`, the relay `relay/sphinx_relay.py`, the Chrome
extension `extension/`.

## How it works
- **Import.** Accounts > Import from Authenticator scans the QR from Authenticator's *Transfer accounts > Export* (tick
  only the accounts you want there first), or a plain `otpauth://totp/...` QR. Sphinx decodes the export's protobuf,
  lists the accounts with checkboxes and saves only the ticked ones. HOTP, MD5 and anything that isn't TOTP is listed
  under "Left out" with the reason. Multi-QR exports say "QR 1 of 3: scan the next". The QR passes through Google Play
  services' code scanner (it runs the camera in its own process and hands Sphinx the text, so Sphinx has no camera
  permission); the decoded secrets are kept only until they are sealed, and wiped when the import is cancelled or the
  screen goes.
- **Storage.** Each account: issuer, account name, the sites it may fill on (each an exact host, from a list of known
  issuers' single-owner login hosts, else none until you add one; `*.host` opts that site's subdomains in; editable
  under Sites; a public suffix from the bundled Public Suffix List is refused), its phone apps, algorithm
  (SHA1/256/512), digits (6/8), period. The secret is AES-256-GCM sealed under a fresh key that is RSA-OAEP wrapped to
  `sphinx.codes`, a Keystore key pair whose private half needs a fresh strong fingerprint per use (no PIN, wiped by a
  new fingerprint enrolment). The list itself is sealed in Sphinx's own prefs under a second Keystore key
  (`sphinx.prefs`, no prompt, so a request can be matched in the background). The prefs never leave the phone; the
  secrets do only inside the encrypted backup ("Backup" below).
- **On the laptop.** The Sphinx extension finds a one-time-code field (`autocomplete=one-time-code`, otp, totp, 2fa,
  verification code, a 6/8-digit numeric field, or 4-8 one-digit boxes). As soon as the field is there (page load, or
  it appears later), and only when the tab's host *and* the frame's host are sites of one saved account, it asks the
  phone, sending both hosts and the user name the page shows (to pick between two accounts on one site). It asks on
  its own once per page; every real click into the field (`isTrusted`, so a page script can't loop it) asks again
  while no request is in flight (`SphinxDetect.shouldAsk`). The request is bound to that document, frame, origin and
  pairing; a navigation, another tab or frame never receives it. An authenticator code is typed into the field and its
  form submitted, as Enter would (the fingerprint was the yes); a texted code (below) is only typed in.
- **On the phone.** A request arrives on the FCM wake, which carries the sealed request (see
  "Wake-up" below). Sphinx checks the seal, the counter and the 60 s expiry, matches the host again, and shows
  "Code for github.com (work)?" over the lock screen (a full-screen notification; Android 14+ needs "full screen
  notifications" allowed, Settings points to it). Approve = fingerprint; Deny says no; after 60 s it expires.
  Approving doesn't unlock the phone. Several accounts and no match on the user name: you tap which one (the pick is
  remembered for that same choice). A site with no account is refused without asking (a text-only site waits for a
  texted code instead, below). The approve screen closes at the fingerprint; the send runs behind it
  (`Sphinx.inBackground`), and a send that fails shows on the laptop as no answer.
- **Codes on the phone itself.** Optional: with notification access granted, when an imported account's app posts a
  2FA-looking notification, Sphinx posts "GitHub (work) code" with Copy: fingerprint, the code goes to the clipboard
  (marked sensitive), cleared after 30 s. Show on the Accounts screen shows a code for its remaining seconds.
- **Codes by text or email.** With notification access, and only while a paired laptop's request is pending and fresh
  (the same 60 s, held to the laptop's sealed expiry), a notification from an SMS or email app (`Domains.TEXT_APPS`:
  Messages, Samsung Messages, Gmail, Outlook, Samsung Email, Yahoo Mail, Proton Mail, K-9, Fastmail) with 2FA wording
  (`TWO_FA`, or "your/the/this ... code", "code is", "Code 123456", "to sign in") and exactly one 4-8 digit number
  (`Domains.textCode`; a promo, a parcel, money, or a second number such as a card's last four: nothing; a title that
  is only a number is the sender's short code, not a second code) is offered: "Send 482913 to the laptop?" (private
  notification, "Code request" over the keyguard). The watcher decides from the package alone before reading anything
  (`Sphinx.watches`): another app's notification, or a mail app's while nothing waits, is never read. A tap on the
  offer opens the approve screen in text mode; the strong fingerprint (`Sphinx.gate`; over the keyguard the prompt
  names the site, not the digits) sends it as the sealed `code.reply {ok, code, account: "", via: "text"}` to the
  newest fresh request (`SphinxLogic.forText`), and the extension types it in (4-8 digits accepted only with
  `via: "text"`) and never submits. The code lives only in `Sphinx.texted` (memory), dropped with its request.
- **Text-only sites.** For a site with no account here, list it under Settings, Codes by text or email
  (`SphinxStore.textSites`, sealed like the rest, `Domains.savable` rules, `*.` for subdomains). `domains.reply` sends
  each as its own one-site group, so the extension grants, registers and asks there under the same exact tab-and-frame
  rule; the phone checks the host again, and a request for a listed site waits (`Pending.textOnly`, no fingerprint
  question until a text arrives).
- **The code ready before the field asks** (`code.ready`). On a saved site, as soon as the sign-in page opens with a
  visible password field (looked for at load, as the page changes and when the tab comes to the front), or as
  fallbacks once the password field holds a value (a trusted input, change or submit event, or Chrome's `:autofill`
  mark read a few times after load; `shouldReady` in `detect.js`; a page script's synthetic events never fire it),
  once per page and only while the page is visible, the worker sends `code.ready` with the tab's host from Chrome and
  the same user name hint. The phone resolves it like a `code.request` and asks "Signing in to github.com: approve the
  code for 30 s?". The fingerprint opens a window for that pairing, that site (eTLD+1, `Domains.site`, so AWS's
  regional sign-in hosts count) and that account: **30 s** (`SphinxLogic.WINDOW_MS`), so a compromised laptop can't
  pull codes long after. The Keystore key allows one use per fingerprint, so the window holds the codes of the TOTP
  periods it spans, computed at the yes (`SphinxStore.codes`, one unwrap), never the secret; in memory only
  (`PreApproval`). The reply `code.ready.reply {ok, for, account, codes: [{code, from, until}]}` carries those codes,
  the last cut at the window's end; the extension's worker holds them in memory only (`held`), for that tab and site,
  and uses them once: the code field fills with no trip to the phone. A `code.request` that still reaches the phone
  inside the window (same pairing, site and account) is answered at once with no prompt and spends the window; one that
  arrives while the pre-approval is still on screen waits on it (no second prompt).
- **Status on the laptop.** The toolbar icon's whole background is the state, per tab (drawn with OffscreenCanvas,
  `chrome.action.setIcon`; `dotState` in `background.js`): red when not paired or the phone isn't reachable, saffron
  and blinking (500 ms) while a `code.request` or `code.ready` waits on the phone, green when this tab's site is saved
  or a code just went in, grey when paired and reachable on an unsaved site. "Reachable" = the relay saw a signed call
  from the phone in the last 30 minutes (a fetch, or the heartbeat every 15 minutes); it only labels the icon. The
  worker asks `GET /v1/status` at Chrome start, install, pairing, unpair, the toolbar click, the options page, and when
  a saved site's page loads, at most once every 20 s.
- **The log** (Logcat, on the phone) says "request from github.com: approved / denied / expired / no account for it",
  pairing and import events. Never a code, a key, an account name or the page's user name.

## Handoff: links, text and files
Phone and laptop pass a link, a bit of text or a small file over the same pairing, sealed like a code; the relay sees
ciphertext only. Nothing that arrives is acted on without a click or a tap.
- **Laptop to phone.** The toolbar popup ("Open this page on my phone", a typed note, a picked file) and the right-click
  menu ("Open this page on my phone", "Send this link", "Send the selected text"; Chrome hands the page URL, link or
  selection, the page itself sends nothing) send `handoff.send` as a request (`'q'`, like a code), so it rides the FCM
  wake. The phone checks it again (`HandoffRules.item`) and shows a notification: a link with Open (a browser intent,
  http(s) only) and Copy, text with Copy (`CopyReceiver`), a file saved to **Download/Sphinx** through MediaStore (no
  storage permission) whose notification opens it. "Open this page on my phone" is a link marked `open` (continue on the
  other device): the notification says "Open on this phone".
- **Phone to laptop.** The share sheet's **Send to laptop** (`ShareActivity`: a link shared alone goes as "Open on
  laptop", one tap; else text or a file) seals `handoff.send` in its own direction **`'p'`** with its own counter
  (`Pairing.pushSent`, the laptop's `pushRecv`), so it never races the replies' counter, and posts it to the laptop's
  outbox on the relay (`POST /v1/outbox`). The extension looks every 30 s (`chrome.alarms`) and when the popup opens
  (`GET /v1/outbox`, then acks), checks each item (`handoff.js item`), lists it in the popup (storage.session, 10
  minutes), shows a badge count and a notification. A link opens in a new tab only at the popup's Open; text is copied
  only at Copy; a file downloads through `chrome.downloads` only at Download.
- **Rules on both ends.** Links: http or https only, no user:password, at most 2,048 characters. Text: at most 3,000
  bytes (the sealed envelope must fit the relay's 4 KB). Files: at most 8 MiB; the name loses any folders, control
  characters and leading dots; an unknown MIME type becomes application/octet-stream.
- **Files.** Each file gets a fresh random AES-256 key and a random id. It goes in 512 KiB chunks, each AES-GCM sealed
  with iv = 8 zero bytes + the chunk index and AAD `sphinx file v1|<fid>|<n>|<total>`, to `PUT /v1/files/{fid}/{n}?of=`;
  the key, size and SHA-256 travel only inside the sealed `handoff.send`. The receiver fetches every chunk, opens each in
  its place, checks size and hash, and deletes the file from the relay. The relay keeps chunks in memory only: at most
  16 chunks a file, 24 MiB a pairing, 64 MiB in all (refused past that, never evicted), each gone after 10 minutes.
  Vectors: `file` and `push` in `extension/test/vectors.json`.

## Keys safe
A tab for recovery material: text (recovery phrases, backup codes, up to 16 KB) and small files (keystores, JSON keys,
up to 256 KB; 64 entries and 4 MB in all, so the backup stays small). Each entry is sealed like a code's secret: AES-256-GCM
under a fresh key, RSA-OAEP wrapped to the codes key, which needs a strong fingerprint for every single use
(`SafeStore`; the content in `safe/<id>.bin`, what it is in the sealed prefs). Show and Save each take a fresh
fingerprint; the screen is FLAG_SECURE. Files come in and go out only through the system's file picker (no storage
permission). An entry never leaves the phone except inside the encrypted backup below. A new fingerprint enrolment
clears it with the codes (the backups still hold both).

## Backup
One random backup key (BK) seals the whole state (`BackupState`): the accounts with their secrets, their sites, the
text-only sites, the Keys safe, and the relay backup's own settings. Never the laptop pairings: laptops always pair
again. A fingerprint authorises one Keystore unwrap, never a whole backup, so a secret goes into the backup when it is in
clear anyway: at import (`SphinxStore.add`, `SafeStore.add`); every later change (sites, deletes) updates the sealed state
(`LocalBackup.update`). On the phone it is `backup/state.bin` (the state sealed with BK) and `backup/key.bin` (BK) in
the app's private storage. **key.bin is not behind the fingerprint**: code running as Sphinx (or anyone who can read its
private files: root, a forensic image) can open the backup without one. That is the price of a backup that works
without a fingerprint per account, and the same trade Google Authenticator's backup makes.

Three ways back, in this order:
1. **Google (primary).** Android's own backup carries exactly `backup/state.bin` and `backup/key.bin`, and nothing else
   of the app (`res/xml/data_extraction_rules.xml`: two includes; `disableIfNoEncryptionCapabilities`, and
   `requireFlags="clientSideEncryption"` in `backup_rules.xml` for older Androids), so it only goes up end-to-end
   encrypted with the phone's screen lock. Device-to-device transfer takes the same two files. On the new phone's first
   start (`Backups.start`), files that this phone didn't make (no `backup.home` in its sealed prefs, which never travel)
   are opened, every account and safe entry is sealed again with the new phone's Keystore keys, the travelled BK is
   retired for a new one (`LocalBackup.rotate`), and he is told to pair his laptops again. **This path is as strong as
   his Google account plus the old phone's screen lock**: whoever has both can restore his codes.
2. **The relay, with the backup passcode (secondary).** Settings, Backup, "Back up to the relay": a passcode of at least
   12 characters (the hint pushes for a phrase of four or more words). Argon2id (Bouncy Castle 1.80; 64 MiB, 3 passes,
   1 lane; a random 16-byte salt) turns it into a root key; HKDF gives a key that wraps BK and an auth value. The relay
   slot `pass` holds a verifier (SHA-256 of the auth value), the public salt and cost, and one record: BK wrapped for
   that slot and the sealed state. It is uploaded a few seconds after each change (`Backups.changed`, WorkManager), and
   the passcode isn't asked again (its derived key and auth are kept inside the sealed state). Restore on a new phone:
   Accounts, Restore, the relay (built in, editable), the passcode: the phone fetches the salt, derives the auth, the
   relay checks it and returns the record, and the phone opens it. No email, no account, no code. The relay guards
   tries (`Backup` in `relay/sphinx_relay.py`): 3 free per client IP, then 30 s doubling per failure; 10 free over all
   IPs, then a minute doubling (both up to a day); after 25 failures in a row it locks until someone with the VPS removes
   `backup.locked`. Counts survive a restart. **Anyone who has the relay's copy (the VPS's disk, a backup of it) can
   guess passcodes offline, limited only by the passcode's strength and Argon2id's cost**: a long phrase is the defence.
3. **The 24-word recovery phrase (tertiary, off by default).** Settings, Backup, "Turn on a recovery phrase" (the relay
   backup must be on): BIP39 (256 bits of entropy, English list, checksum), shown once and never stored. Its seed
   (PBKDF2-HMAC-SHA512, as BIP39) gives, through HKDF, a slot id, a wrapping key and an auth value; the relay keeps the
   same record under that id, so the phrase opens the backup without the passcode, the way back if both Google and the
   passcode are lost. Restore: Accounts, Restore, Recovery phrase. Turning it off deletes its slot.

The relay stores only: per slot a verifier, the passcode's salt and cost, and a ciphertext. Never the passcode, the
phrase, BK, or a secret. Not built (owner, 2026-10-26): email codes, a non-Google push, export to other authenticators.

## Wake-up
- **FCM, the only wake.** `app/google-services.json` is in every release build (its values become the resources
  FirebaseInitProvider reads; no google-services plugin, nothing else of Firebase, auto-init off until a laptop is
  paired), the phone hands its FCM token to each pairing's relay (`POST /v1/push`; `Push.register` at pairing, on a new
  token and every 15 minutes in `SphinxBeat`), and the relay's answer `{push}` is kept on the pairing. A relay with a
  service account (`SPHINX_FCM_ACCOUNT`) then sends each queued request at once as a high-priority FCM data message,
  `{"t": "sync", "sphinx": "[{pid, rid, blob}, ...]"}`: the pairing's queued blobs, newest first, as many as fit in
  3,500 bytes (`carry`, under FCM's 4 KB), else a plain `{"t": "sync"}`. `SphinxMessaging` drops any other shape
  (`SphinxLogic.carried`: only those keys, each entry exactly `{pid, rid, blob}` in the relay's own formats, at most 20)
  and hands them to `Sphinx.wake`, which runs carried blobs through the same path a fetched one takes
  (`SphinxLogic.drain`, `Sphinx.handle`: pairing lookup, seal, counter, expiry), then fetches (`GET /v1/inbox`)
  and acks; a carried blob that was taken isn't run twice, a refused one doesn't stand in for the fetched one.
- **No live connection.** No foreground service, no permanent notification, no long poll. Besides the wake, the phone
  fetches each inbox once when the app opens or comes to the front (MainActivity), and in `SphinxBeat` every 15 minutes
  (which also re-registers the token). Pairing first asks Firebase for the token: without one (no google-services.json
  in the build, no Play services) it says so and pairs nothing. A relay that answers `{push: false}` (no service
  account yet) is shown on the Laptops screen: its requests wait for the next fetch. A release build refuses to start
  without `app/google-services.json` (`preReleaseBuild` in `app/build.gradle.kts`).

## Pairing
The extension's options page shows a QR: `sphinx:1?p=<pairing id>&k=<laptop X25519 public>&s=<16-byte secret>&r=<relay>&n=<name>[&t=<relay token>]`.
Laptops > Pair a laptop scans it. The phone makes its own X25519 key, derives the keys, drops its private key, and
registers the pairing id, the relay key and its *hello* with the relay. The laptop fetches the hello, checks it
against the secret (which only the QR carried), derives the same keys and drops its private key. Unpair on either
side; unpairing on the phone also removes it from the relay.

```
ecdh   = X25519(own private, other public)            all-zero refused
keys   = HKDF-SHA256(ecdh, salt = secret, info = "sphinx v1|<pid>", 64)   l2p = [0:32], p2l = [32:64]
relay  = HKDF-SHA256(secret, salt = pid, info = "sphinx relay v1")      the only key the relay learns
hello  = phone public | HMAC(HKDF(secret, pid, "sphinx hello v1"), "sphinx hello v1|pid|laptop|phone")
blob   = 1 | dir 'q'/'r' | ctr u64 | exp ms u64 | iv 12 | AES-256-GCM(key by direction), AAD "sphinx|<pid>|" + header
```
Inside every blob is one typed envelope, `{"v": 1, "kind": "<area>.<verb>", "rid": "...", "body": {...}}`:
`code.request {host, frame, user}` / `code.reply {ok, code, account, ttl | why}` (or `{ok, code, account: "", via:
"text"}` for a texted code), `code.ready {host, frame, user}` / `code.ready.reply {ok, for, account, codes | why}` and
`domains.request {}` / `domains.reply {ok, domains, groups}`, and `handoff.send {type: link|text|file, ...}` in either
direction (laptop to phone as a request `'q'`; phone to laptop in its own direction `'p'`, no reply). Any other kind gets a sealed `error {ok: false, why: "unsupported kind"}` and
nothing happens. Refused: wrong version or direction, a counter not above the last one taken, expired, an expiry more
than 2 min out, a sealed rid that isn't the outer one. Test vectors: `extension/test/vectors.json` (made by
pyca/cryptography with `extension/test/make_vectors.py`; checked by the Kotlin tests, the extension's tests and pytest).

## Threat model, in plain words
- **What Google sees** (with the fast wake): the same sealed blobs the relay sees, their size and when they were sent,
  for the phone's FCM token. It can't open or forge one any more than the relay can, and the phone checks a carried
  blob exactly like a fetched one.
- **What the relay sees:** a pairing id, the relay key (an HMAC key that opens nothing), the phone's hello, when a
  request was made, and sealed blobs of a few hundred bytes. No site, no user name, no code. Someone with the relay
  could drop or delay requests, but can't read or forge one: forging needs the message key, which comes from the QR's
  secret and the X25519 exchange, neither of which the relay ever had. It can't swap in its own key at pairing either,
  because the phone's hello is MACed with the QR's secret.
- **Who can register a pairing:** anyone who can reach the relay, unless you set `SPHINX_REGISTER_TOKEN` (then only a
  QR carrying that token pairs). A registered pairing id can't be taken over, and the pid is 16 random bytes shown only
  in the QR. Without the token, a stranger could fill your relay's pairing slots (a nuisance, not a breach).
- **Phishing guard:** the laptop asks only on an exact saved site (subdomains only where you opted that site in), using
  the tab's and the frame's real hosts from Chrome (not anything the page says), and the phone checks again.
  `github.com.evil.io`, `evilgithub.com`, `github.co` and shared hosts like `github.io` never match. A lookalike page
  gets nothing, and no prompt.
- **Your fingerprint is the gate:** no code leaves the Keystore without a strong fingerprint on that request, on the
  question that names the site. If a request shows up that you didn't make, Deny.
- **Both factors, one device:** with Sphinx, the laptop holds the password (in Chrome) and gets the code; the phone is
  still the second thing you have, but it's only as strong as your attention to the question. Keep **your Google
  account, your bank and your main email** (and anything that can reset other accounts) out of Sphinx: leave those on
  your authenticator app alone.
- **Lost or stolen phone:** codes need your fingerprint, the keys never leave the Keystore, and a new fingerprint
  enrolment wipes the codes key (import again). Lost laptop: Unpair it on the phone.

## Relay
All routes are under `/v1`. Unsigned: `POST /v1/pairings` (the phone registers `{pid, key, hello}`; optional
`x-sphinx-token`). Signed with the pairing's relay key (both ends hold it; the route is the role): the phone's
`GET /v1/inbox` (what is queued now; no long poll), `POST /v1/inbox/ack`, `POST /v1/replies`, `DELETE /v1/pairings/{pid}`; the
laptop's `GET /v1/hello`, `POST /v1/requests`, `GET /v1/replies/{rid}` (long poll, 25 s), `GET /v1/status`
(`{paired, phone_seen, push, now}`, the phone's last signed call to the minute, in memory). The phone's `GET /v1/inbox`
takes `?wait=0` after a wake, and `POST /v1/push {token}` registers its FCM token for that pairing. Handoff: the
phone's `POST /v1/outbox`, the laptop's `GET /v1/outbox` and `POST /v1/outbox/ack` (2 minutes, 20 queued), and either
end's `PUT /v1/files/{fid}/{n}?of=`, `GET /v1/files/{fid}/{n}`, `DELETE /v1/files/{fid}` (caps above). A phone blob stays queued
until the phone acks it after handling. Limits: 60 signed calls a minute per pairing, 4 open reply long polls per pairing
and 32 in all, nonces at most 150 per pairing and 1,200 in all (refused past that, never evicted), 8 pairings
(`SPHINX_MAX_PAIRINGS`), 20 queued per pairing, 60 s TTL, 10 requests a minute per pairing, 4 KB blobs, nonces
single-use, timestamps within 60 s. See `relay/README.md`.

## The extension
Load unpacked from `extension/` (Chrome 146+: WebCrypto X25519, and `storage.local.setAccessLevel`, which Chrome 137
lacks). Options page: the relay's address (and its token, if it has one), name the laptop, Show the pairing code
(Chrome asks to allow the relay), scan it on the phone, then "Allow on these sites" (Chrome asks for exactly the saved
hosts and their www., plus subdomains only for a `*.` site). Permissions: `storage`, `scripting`; every host
permission is optional and asked for: the relay's origin, and each saved site. No content script is declared in the
manifest: the service worker registers it only for the exact granted saved sites, top frame only, and drops grants for
sites the phone no longer lists (never the relay's while it is paired). Not in incognito; no externally_connectable,
no web-accessible resources. Tests: `node --test test/<file>.test.mjs`, one file at a time (node 22+; detection, domains, crypto vectors,
message validation in the service worker, the QR encoder against segno, `shouldAsk`, texted replies, `shouldReady`,
`code.ready` and held codes, the icon states). Manual check after pairing: on a saved site the icon is green
(red if the phone hasn't been seen for 30 minutes). Open GitHub's sign-in page: "approve on your phone to have the code
ready" shows, the icon blinks, the phone asks "Signing in to github.com"; approve, sign in; the code page fills at once
with no second prompt. Let one expire, then click the field: it asks again. On a text-only site, have the site text a
code: the phone offers "Send ... to the laptop?"; send it with the fingerprint; the field fills and nothing submits. On
`https://github.com.example.com` (or any unsaved site) nothing happens.

## Security: each threat and where it is handled
| Threat | Where | How |
|---|---|---|
| Phishing / lookalike site | `Domains.kt` `Psl`, `savable`, `matches`, `candidates`, `forIssuer`; `extension/domains.js` `Psl`, `savable`, `matches`, `allowed`; `background.js` `eligible`, `register` | A saved site is one exact host (and its www.); subdomains only for a `*.host` entry; public suffixes refused from the bundled Public Suffix List (private section, wildcards and exceptions), and a `*.host` refused when any public suffix lies under it (`Psl.coversSuffixes`), the same file on both sides (tested equal); issuers seed only single-owner login hosts, never a multi-tenant parent; tab and frame host taken from Chrome, https only; the content script runs only on exact granted sites, top frame only |
| Cross-frame delivery | `background.js` `eligible`; `SphinxLogic.decide` (`body.frame`); `Domains.candidates(host, accounts, frame)` | The tab's and the frame's hosts must both be sites of the same account, checked on the laptop and again on the phone |
| A request reaching another document | `background.js` `waiting`, `keyOf`, `bound`, `content` | Bound to tab, frame id, document id, both origins and the pairing; re-checked before the reply is opened and again at delivery |
| Replay, reordering, stale requests | `Crypto.kt` `open`; `crypto.js` `open`; `SphinxLogic.decide`; `Sphinx.approve`; `sphinx_relay.py` `Relay.verify` | Strictly increasing counter per direction; the laptop's sealed expiry is enforced at approval; sealed rid must equal the outer rid; relay nonces single use, timestamps within 60 s |
| Counter races | `background.js` `locked`; `SphinxStore.kt` `updatePairing`, `putPairing`, `add`, `update`, `delete` (one lock); `Sphinx.poll` | A counter is taken and saved inside the lock; a received counter only ever moves up |
| A stale or replayed pairing hello | `background.js` `options` (`offer` generation) | Each offer has a generation; a hello is applied once, only while its offer is still current |
| Pairing hijack (relay swaps a key) | `Crypto.kt` `accept`, `hello`; `crypto.js` `finish`; `sphinx_relay.py` `Relay.pair` | The phone's hello is HMACed with the QR's secret the relay never saw; all-zero X25519 output refused; a registered pid can't be re-registered with another key |
| Reading or forging messages | `Crypto.kt` `seal`/`open`; `crypto.js` `seal`/`open` | AES-256-GCM, keys from X25519 + HKDF bound to the pairing id; AAD covers version, direction, counter, expiry, pairing id; the relay holds only an HMAC key |
| Typed envelope abuse | `SphinxLogic.decide`, `SphinxLogic.KINDS`; `background.js` `receive`, `delivered`, `heldCodes` | Version checked, unknown kinds refused sealed, never acted on; a reply must be the expected kind, rid and shape; an authenticator code must be 6-8 digits, a texted one (`via: "text"`) 4-8 |
| A forged or replayed blob in the FCM wake | `sphinx_relay.py` `carry`, `CARRY_MAX`, `fcm_payload`; `SphinxMessaging`; `SphinxLogic.carried`, `drain`; `Sphinx.handle` | Only `t` and `sphinx` keys; each entry exactly `{pid, rid, blob}` matching the relay's formats, else dropped; the same pairing lookup, seal, counter and expiry as a fetched blob; the fetched copy is still acked, and a refused carry never stands in for it |
| A texted code reaching the wrong page or anyone else | `Domains.textCode`, `TEXT_APPS`; `Sphinx.watches`, `offerText`, `sendText`, `dropText`; `SphinxLogic.decide` (`textSites`, `textOnly`), `forText`, `texted`; `ApproveActivity.TextHost`; `background.js` `delivered` (`via`); `content.js` `done` | Read only from SMS and mail apps and only while a laptop request is pending; one 4-8 digit code with 2FA wording; it answers that request only (rid, pairing, sealed), after a strong fingerprint; text-only sites are a phone-side list under the same exact-host rules, checked again on the phone; the code is in memory until the request ends, never logged; the laptop types it and never submits |
| A handoff doing something by itself | `Share.kt` `Handoff.receive`, `notify`; `background.js` `pollOutbox`, `popup` (`openLink`, `file`); `popup.js` | An arrival is a notification or a popup line; a tab opens, a text is copied, a file downloads or opens only at a click or tap; links http(s) only, checked on both ends (`HandoffRules.httpUrl`, `handoff.js httpUrl`) |
| A handoff file reading or landing where it shouldn't | `HandoffRules.prepare`, `assemble`, `safeName`; `handoff.js safeName`; `sphinx_relay.py` `put_chunk` (`FILE_CHUNKS`, `PAIR_FILE_BYTES`, `FILE_BYTES_ALL`, `FILE_TTL_S`) | A fresh key per file, chunks bound to file, place and length, size and SHA-256 checked; saved only under Download/Sphinx (MediaStore, no storage permission) or Chrome's downloads, folders stripped from the name; relay memory capped and expired |
| The Google backup | `res/xml/data_extraction_rules.xml`, `backup_rules.xml`; `Backups.start`; `LocalBackup.rotate` | Only `backup/state.bin` and `backup/key.bin` travel, and only end-to-end encrypted with the screen lock; restored files are sealed again with the new phone's keys and BK is replaced. As strong as the Google account plus the old phone's screen lock |
| The relay's backup copy | `BackupCrypto.passKeys`, `record`; `Passcode`; `sphinx_relay.py` `Backup` (`PER_IP_*`, `GLOBAL_*`, `backup.locked`) | Online: tries limited per IP and globally with doubling waits and a VPS-side lock. Offline (someone has the file): limited only by the passcode's strength and Argon2id's cost (64 MiB, 3 passes); 12 characters at least, a long phrase advised |
| The recovery phrase | `Bip39`; `BackupCrypto.phraseKeys`; `BackupPane` | 256 bits from SecureRandom, shown once, never stored; its slot id, key and auth are separate HKDF outputs of the BIP39 seed |
| The backup on the phone | `LocalBackup` (`key.bin`) | Not behind the fingerprint: code running as Sphinx, root or a forensic image of its private files can open it. Stated, not narrowed |
| Keys safe entries | `SafeStore`; `KeysPane`; `PrivacyTest` | Sealed to the fingerprint-per-use codes key, FLAG_SECURE, in and out only through the system file picker, size caps; only other copy: inside the sealed backup |
| A pre-approval outliving the sign-in | `SphinxLogic.WINDOW_MS`, `prime`, `served`, `held`; `PreApproval`; `background.js` `heldCodes`, `heldNow` | 30 s, one pairing, one site (eTLD+1), one account, spent on one code; the codes of the periods it spans (never the secret), in memory on both sides, cut at the window's end on the laptop and used once |
| Key theft at rest | `SphinxStore.kt` `add`, `code`; `Vault.kt` `KeystoreBoxKeys`, `SealedPrefs` | Secret AES-GCM sealed, key RSA-OAEP wrapped to a Keystore pair needing strong biometrics per use, invalidated on new enrolment; list sealed under a Keystore AES key; the prefs are never backed up (the sealed backup is its own row) |
| A new fingerprint enrolment | `SphinxStore.kt` `unwrapper`, `Cleared` | On `KeyPermanentlyInvalidatedException` the key entry is deleted and the accounts wiped (pairings stay); "Codes cleared by a new fingerprint: import again" |
| Using a code without you | `Sphinx.fingerprint`, `Sphinx.gate`, `ApproveActivity` | `BIOMETRIC_STRONG` only, no device credential, a CryptoObject per code; no grace window; never dismisses the keyguard; FLAG_SECURE |
| Account names on a locked screen | `ApproveActivity` (`isKeyguardLocked`), `SphinxLogic.question(names)`, `rowLabel`, `copyLabel` | Over the keyguard only the site and the issuer show ("GitHub, account 2"), never account names, until the fingerprint |
| Import secrets left in memory | `MainActivity.kt` (`DisposableEffect` wipe, `cancelPick`, `saveTicked`); `SphinxStore.add` | Every decoded secret is zero-filled once sealed, cancelled, unticked or when the screen goes |
| Page to extension messages | `content.js` (no page listeners); `background.js` `onMessage`, `fromOptions`, `fromContent` | Sender must be this extension; content and options pages get separate message sets; inputs typed and capped; pairing actions only from options.html |
| Flooding / relay exhaustion | `sphinx_relay.py` `Relay.verify`, `poll_open`, `Relay.request`, `TTL_S`, `MAX_BLOB`, `MAX_PAIRINGS`, `SPHINX_REGISTER_TOKEN`; `deploy/sphinx.caddy` (16 KB bodies) | Per-pairing and global bounds on calls, polls, nonces, queue, rate and size; refused, never evicted; every real click asks again, so the relay's 10 requests a minute per pairing is what stops a loop |
| The relay learning more than it needs for the icon | `sphinx_relay.py` `Relay.saw_phone`, `phone_seen` (`SEEN_ROUND_S`), `/v1/status` | One in-memory time per pairing of the phone's last signed call, given only to that pairing's signed laptop, rounded to the minute |
| Losing a request mid-handling | `sphinx_relay.py` `Relay.take`, `Relay.ack`; `Sphinx.poll` (ack in `finally`) | A blob stays queued until the phone handled and acked it (or 60 s pass); the counter stops a second action |
| Secrets in logs | `Vault.kt` `Log`; `sphinx_relay.py` `audit`; `PrivacyTest`, `test_the_log_never_holds_a_blob` | The phone logs site and outcome only, to Logcat; the relay logs 6 characters of the pairing id |

## Limits
- The "issuer's app in front" trigger for phone codes: only the notification trigger is built (no accessibility
  service). Show and Copy cover the rest.
- BiometricPrompt over the lock screen (an activity shown when locked) behaves differently across phones; check yours.
- The laptop's state (derived keys, counters) is in `chrome.storage.local`, unencrypted on the laptop's disk, like any
  extension's; anyone with your unlocked laptop profile can ask (and you still have to approve on the phone).
- **Content scripts can't read the pairing.** Chrome opens `storage.local` to content scripts by default. The worker
  closes it (`setAccessLevel({accessLevel: "TRUSTED_CONTEXTS"})`) at every start before any storage call or
  content-script registration, and registers the content script for the browser session only. If Chrome refuses, the
  worker fails closed (no storage, no content script). `content.js` and `detect.js` never touch storage (a test
  checks). Manual check: on a saved site, DevTools > Console, pick "Sphinx" in the context menu, run
  `await chrome.storage.local.get(null)`; it must throw "Access to storage is not allowed from this context".
- **What the content script can still reach** (stated, not narrowed). It runs on every page of each granted saved
  site, top frame, because it must find the code field before you focus it. On those pages it has the page's DOM, as
  any page script there would; it has no other site, no storage, no network beyond the page's own, and only its few
  worker messages, which are bound to its document.
- New saved sites on the phone reach the laptop when you press Refresh sites (and then Allow); there is no background
  refresh.
- FCM may delay or coalesce a wake; the heartbeat (15 minutes) and the laptop's 60 s expiry bound what that costs.
- Firebase's own libraries are in the app whenever it is built (they stay idle without `google-services.json`).
- More message kinds (a tab to the phone, an unasked SMS code pushed to the laptop, clipboard sync) could ride the same
  pairing, each a new `kind` allowed by name on the receiving side. None is built.
