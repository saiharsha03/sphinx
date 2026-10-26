# Sphinx (Chrome extension)

2FA codes from your phone, asked on a saved site, approved with your fingerprint and typed into the field. An
authenticator code is typed in and its form submitted (your fingerprint was the yes); a code from a text or email is
only typed in. Design, threat model and checks: `../docs/DESIGN.md`.

- **Chrome 146 or later** (`minimum_chrome_version`). It needs WebCrypto X25519 and `chrome.storage.local.setAccessLevel`,
  which closes the pairing keys to content scripts. On a Chrome without it, the worker fails closed: no storage and no
  content script.
- Load it unpacked from this folder (`chrome://extensions`, Developer mode). On its options page the relay is filled in
  (type your relay's https address), add its token if it has one, show the
  pairing code, and scan it in Sphinx on the phone (Laptops, Pair a laptop). Then "Allow on these sites".
- Permissions: `storage` and `scripting`. Host access is optional and asked for: the relay's origin when you pair, and
  each saved site when you allow it.
- The toolbar icon's whole background is the state: red (not paired, or the phone not seen for 30 minutes), saffron and
  blinking (the phone is asking you), green (a saved site, or a code just went in), grey (paired, another site).
- The toolbar popup: what the phone sent (Open / Copy / Download, nothing acts by itself), and "Open this page on my
  phone", a note or a file to the phone. The right-click menu sends the page, a link or the selection. It looks for
  what the phone sent every 30 s (`alarms`). Permissions for this: `alarms`, `contextMenus`, `activeTab`, `downloads`,
  `notifications`.
- Icons in `icons/` are placeholders until the Sphinx coin art.
- No dependencies. Tests, one file at a time: `node --test test/<file>.test.mjs` (Node 22+).
