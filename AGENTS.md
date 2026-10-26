# Working on Sphinx (for coding agents)

Sphinx is three parts: `app/` (Android, `dev.sphinx`), `extension/` (Chrome, Manifest V3) and `relay/` (FastAPI).
Read `README.md` and `docs/DESIGN.md` first. If you are setting it up for someone, follow the README's "Set it up"
section in order; every step says how to check it worked.

## Rules
- **Secrets stay out of the repo.** The signing keystore and its password, `google-services.json`, the Firebase
  service account and the relay's registration token never go into git. `local.properties`, `app/google-services.json`,
  `extension/local.json`, `release/` and APKs are git-ignored. Never print a password, key or token.
- **The wire format is shared.** `app/src/main/java/dev/sphinx/Crypto.kt`, `extension/crypto.js` and
  `relay/sphinx_relay.py` speak it together. Change it only in all three, and regenerate `extension/test/vectors.json`
  with `extension/test/make_vectors.py` (needs `cryptography` and `segno`).
- **Never log a code, key, account name, laptop name or user name.** `PrivacyTest` checks the phone's log calls.
- **Limits only where they protect something**, with a comment saying what.
- **Dependencies are pinned.** New Gradle dependencies: `./gradlew --write-verification-metadata sha256 assembleDebug`,
  then check each new hash against the repository's published `.sha256`/`.sha1`. Python: `--require-hashes` lockfiles.

## Build and test
- App: `./gradlew assembleDebug testDebugUnitTest` (release: `assembleRelease`, needs `app/google-services.json` and the
  signing settings in `local.properties`; see the README's Settings reference).
- Extension: `cd extension && node --test test/<file>.test.mjs`, one file at a time.
- Relay: `cd relay && pip install --require-hashes -r requirements-dev.txt && pytest`.

## Deploy
The relay: `docs/DEPLOY.md`.
