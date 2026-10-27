# Changelog

## 1.2.0
A new look, and the fixes from an independent security review (four rounds, three AI reviewers; see the README's
"Security review").

**Look**
- "Basalt and jade": black, white type, one jade accent; Instrument Sans, IBM Plex Mono for codes and hashes, Marcellus
  for the name (bundled, OFL). A small Sphinx by the name whose eye blinks now and then; still when animations are off.
- Tabs Codes / Keys / Laptops / Settings (a side rail on wide screens); **+** on Codes imports.
- One compact row per account; the code in a cartouche with a 30-second ring, hidden (`••• •••`) until your fingerprint.
- The approval screens: the question large, the facts below, Deny and Approve at the bottom.
- The extension's popup, options page, on-page note and toolbar colours to match (jade, white blinking, red, grey).
- Passcode fields have Show / Hide.

**Backup**
- Turning the relay backup on, moving it, changing its passcode, and turning the phrase on need a fresh fingerprint on
  the codes key; changing the passcode or the relay also needs the current passcode. A relay restore asks for your
  fingerprint first.
- A Google backup that comes with a new phone waits on the Codes tab until you open it. "Copy apps & data" no longer
  carries the backup key.
- After a new fingerprint the phone's backup is set aside and reopens only with your relay passcode or phrase; the
  clean-up is durable and blocks every backup upload until it finishes. Settings warns when that would lose your codes.
- Each set-aside copy is kept separately and opened or deleted only by its own card.
- Restores keep what the phone already held and refuse weak key-derivation settings from a relay.
- Safer writes: one backup writer at a time, crash-safe key rotation, a smaller relay record (a full 4 MB Keys safe now
  fits), a turned-off phrase stays off, and a failed relay delete is reported.

**Relay**
- Refuses to start without `SPHINX_REGISTER_TOKEN` (`SPHINX_INSECURE_DEV=1` for local tests).
- Every backup route needs the token or a paired phone's signature; try limits and locks are per slot; a pairing's own
  tries are capped and then locked out; creating a slot needs the token itself.
- Carries queued requests to the phone all together, oldest first, or not at all.

**Approvals and codes**
- An approval answers exactly the request shown; a texted code sends exactly the code shown; a texted code never goes
  to a pre-approval.
- Requests and replies that arrive out of order are each taken once (a replay window).
- A code reply says when its period ends, and the laptop drops one that expired on the way.
- Codes held after a pre-approval are bound to the pairing and the account, and go with an unpair.
- A code is submitted only to a form posting back to the page's own site; otherwise it is only typed in.
- Pairing QRs expire after 10 minutes.

**Release signing (optional)**
- The phone answers with the secret of the one key file it shows, never the master unlock secret; v2 key files bind the
  key's name, alias and certificate; v1 files are pinned to their salt.
- Each sign needs a tap on the screen with the full hash; the notification stays private on the lock screen; one signer
  pairing at a time, its tag shown.

**Sharing**
- Share reads only files the sharing app granted, shows which app shared, asks for your fingerprint and blocks
  screenshots. Copied handoff text is marked sensitive and cleared after a minute.
- The built-in relay token goes only to the built-in relay.

## 1.1.0
First public release: 2FA codes behind your fingerprint, typed into your laptop; links, text and files between phone and
laptop; a Keys safe and three ways to restore.
