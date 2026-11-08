#!/bin/bash
# Build the "vanilla economy" APK: the same tree, offline/compatibility/graphics/audio fixes and
# arm64 bridge as build_tree.sh, without any change to earned currency or progression.
#
#   guest   python _patch_guest.py vanilla  -- the original APK's libABK.so plus the base patches
#   bridge  arm64_loader\build_arm64.bat vanilla  -- -DABGO_VANILLA_ECONOMY=ON
#
# The canonical tree is never modified: it is copied to a staging directory, the two libraries
# are swapped in there, and build_tree.sh builds the copy (ABGO_TREE). Use the same signing
# key for both variants so `adb install -r` works in both directions -- and keeps the
# save, so an install that already ran the full mod keeps everything that mod unlocked.
set -euo pipefail

BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CANON="$BASE/Angry+Birds-29100-2.9.1"
STAGE="$BASE/vanilla_stage"
BRIDGE="$BASE/arm64_loader/build_arm64_vanilla/libabk_arm64_bridge.stripped.so"
OUT="${1:-$BASE/abgo_arm64_vanilla.apk}"

: "${APK_TOOLS_DIR:?Set APK_TOOLS_DIR before packaging}"
: "${APK_SIGNING_KEY:?Set APK_SIGNING_KEY before packaging}"
: "${APK_SIGNING_CERT:?Set APK_SIGNING_CERT before packaging}"

[ -f "$BRIDGE" ] || { echo "missing $BRIDGE -- run arm64_loader\\build_arm64.bat vanilla"; exit 1; }
# Release builds keep only LOGE strings; the full mod's energy/FTUE patches carry some, and the
# vanilla build compiles those functions out entirely.
if grep -aq -e "energy patch:" -e "map-ftue patch:" -e "ftue-popup patch:" -e "restore UI patch:" "$BRIDGE"; then
    echo "$BRIDGE is not a vanilla-economy build (full-mod patch strings present)"
    exit 1
fi

rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -a "$CANON/." "$STAGE/"
rm -rf "$STAGE/build" "$STAGE/dist"
(cd "$BASE" && python -I _patch_guest.py vanilla "$STAGE/assets/libABK.so")
cp -f "$BRIDGE" "$STAGE/lib/arm64-v8a/libabk_arm64_bridge.so"

ABGO_TREE="$STAGE" bash "$BASE/build_tree.sh" "$OUT"

python -I - "$OUT" "$STAGE/assets/libABK.so" "$BRIDGE" <<'EOF'
import hashlib, sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
for entry, src in (("assets/libABK.so", sys.argv[2]),
                   ("lib/arm64-v8a/libabk_arm64_bridge.so", sys.argv[3])):
    want = hashlib.sha256(open(src, "rb").read()).hexdigest()
    got = hashlib.sha256(z.read(entry)).hexdigest()
    print("  %-40s %s" % (entry, got))
    assert got == want, "%s in the APK is not the vanilla build" % entry
EOF
rm -rf "$STAGE"
