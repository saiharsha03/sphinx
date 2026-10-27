#!/bin/bash
# Publish a signed Sphinx APK for the phone's built-in updater (docs/DESIGN.md, "App update").
# Usage (on the VPS, as root): bash publish-app.sh <signed apk> [notes]
# Reads versionCode and versionName from the APK itself (aapt2 when present, else the Android manifest through
# apkanalyzer is not available here, so aapt2 is required), writes app.json beside a copy of the APK in
# /var/lib/sphinx/app (owner sphinx, mode 0640: the relay reads, nobody else), and the relay serves it from the next call.
set -euo pipefail
APK="${1:?usage: publish-app.sh <signed apk> [notes]}"
NOTES="${2:-}"
DIR="${SPHINX_APP_DIR:-/var/lib/sphinx/app}"
AAPT2="${AAPT2:-$(command -v aapt2 || true)}"
[ -f "$APK" ] || { echo "no such file: $APK" >&2; exit 1; }
[ -n "$AAPT2" ] || { echo "aapt2 not found: apt install aapt (or set AAPT2=/path/to/aapt2)" >&2; exit 1; }
BADGING="$("$AAPT2" dump badging "$APK")"
CODE="$(printf '%s' "$BADGING" | sed -n "s/.*versionCode='\([0-9]*\)'.*/\1/p" | head -1)"
NAME="$(printf '%s' "$BADGING" | sed -n "s/.*versionName='\([^']*\)'.*/\1/p" | head -1)"
PKG="$(printf '%s' "$BADGING" | sed -n "s/^package: name='\([^']*\)'.*/\1/p" | head -1)"
[ "$PKG" = "dev.sphinx" ] || { echo "not Sphinx: package $PKG" >&2; exit 1; }
[ -n "$CODE" ] && [ -n "$NAME" ] || { echo "could not read the version from the APK" >&2; exit 1; }
FILE="sphinx-$NAME.apk"
SHA="$(sha256sum "$APK" | cut -d' ' -f1)"
SIZE="$(stat -c %s "$APK")"
install -d -o sphinx -g sphinx -m 0750 "$DIR"
install -o sphinx -g sphinx -m 0640 "$APK" "$DIR/$FILE"
python3 - "$DIR/app.json.tmp" "$CODE" "$NAME" "$SHA" "$SIZE" "$FILE" "$NOTES" <<'EOF'
import json, sys
p, code, name, sha, size, file, notes = sys.argv[1:]
d = {"versionCode": int(code), "versionName": name, "sha256": sha, "size": int(size), "file": file}
if notes:
    d["notes"] = notes[:2000]
with open(p, "w", encoding="utf-8") as f:
    json.dump(d, f, indent=1)
EOF
chown sphinx:sphinx "$DIR/app.json.tmp" && chmod 0640 "$DIR/app.json.tmp" && mv "$DIR/app.json.tmp" "$DIR/app.json"
# Older APKs go: one release at a time.
find "$DIR" -maxdepth 1 -name '*.apk' ! -name "$FILE" -delete
echo "published $NAME ($CODE) as $DIR/$FILE, sha256 ${SHA:0:16}…; the phone sees it on its next check"
