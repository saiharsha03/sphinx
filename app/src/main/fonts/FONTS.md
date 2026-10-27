# Bundled fonts

The app's fonts are in `app/src/main/res/font/`. Android allows only font files in that folder, so this note and the
licences sit next to it in `app/src/main/fonts/`. All three families are under the SIL Open Font License 1.1:
`OFL-Marcellus.txt`, `OFL-InstrumentSans.txt`, `OFL-IBMPlexMono.txt`. They come from Google Fonts' GitHub
(github.com/google/fonts), pinned to commit `e7db6ca603fd4862010383ff17ffd6cc4ffac1c0` (2026-10-26). The files are
renamed to Android resource names; the bytes are unchanged (each git blob sha matches the repo's listing).

- Marcellus: the "Sphinx" wordmark and the big approval question only.
- Instrument Sans: all UI text. It ships as one variable font (wdth, wght); Sphinx uses weights 400, 500 and 600.
- IBM Plex Mono: codes, hashes, ids and facts (Medium 500, SemiBold 600).

| File | Source | sha256 |
|---|---|---|
| `marcellus_regular.ttf` | https://raw.githubusercontent.com/google/fonts/e7db6ca603fd4862010383ff17ffd6cc4ffac1c0/ofl/marcellus/Marcellus-Regular.ttf | `1cf0cd10b17d35e852729962cc1ffaffed94514895972458345e2df34abb2f81` |
| `instrument_sans.ttf` | https://raw.githubusercontent.com/google/fonts/e7db6ca603fd4862010383ff17ffd6cc4ffac1c0/ofl/instrumentsans/InstrumentSans%5Bwdth%2Cwght%5D.ttf | `b24f1812584816958afcf22e22d08e44318c5e51651e25d2438efdde389b33b1` |
| `plex_mono_medium.ttf` | https://raw.githubusercontent.com/google/fonts/e7db6ca603fd4862010383ff17ffd6cc4ffac1c0/ofl/ibmplexmono/IBMPlexMono-Medium.ttf | `a9b4c49bb299e05b5f6c481e7fb5e78943d2793249a0c8874ab574a2d1ea6755` |
| `plex_mono_semibold.ttf` | https://raw.githubusercontent.com/google/fonts/e7db6ca603fd4862010383ff17ffd6cc4ffac1c0/ofl/ibmplexmono/IBMPlexMono-SemiBold.ttf | `d3c38e55c78f5b0f28009fddba4834ec503278936a5986032424c9bd2d23aa46` |
