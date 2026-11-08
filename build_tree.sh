#!/bin/bash
# Build the APK from the decompiled tree.
#
# The tree is the source of truth now: it carries the arm64 bridge under lib/arm64-v8a/, the
# three ARM32 guests under assets/, every smali patch, and the cleaned manifest. Both older
# scripts (repack.sh, repack_arm64.sh) spliced entries into the *original* zip precisely to
# avoid an apktool resource rebuild -- that is no longer necessary here: a full rebuild was
# verified to reproduce res/values/public.xml byte for byte, so no resource ID moves and the
# hardcoded IDs in smali stay valid (lesson 6.2).
#
# build/ is deleted first: apktool caches compiled resources there and would happily ship a
# file you just removed from res/ (lesson 6.3).
set -euo pipefail

BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN="${APK_TOOLS_DIR:?Set APK_TOOLS_DIR to the directory containing apktool.jar, apksigner.jar and zipalign.exe}"
: "${APK_SIGNING_KEY:?Set APK_SIGNING_KEY to your APK signing key (.pk8)}"
: "${APK_SIGNING_CERT:?Set APK_SIGNING_CERT to your APK signing certificate (.x509.pem)}"
CANON="$BASE/Angry+Birds-29100-2.9.1"
# ABGO_TREE builds a staging copy instead of the canonical tree (build_vanilla.sh).
TREE="${ABGO_TREE:-$CANON}"
UNSIGNED="$BASE/abgo_tree_unsigned.apk"
ALIGNED="$BASE/abgo_tree_aligned.apk"
OUT="${1:-$BASE/abgo_arm64.apk}"

for input in "$TREE/AndroidManifest.xml" "$TREE/apktool.yml" "$BIN/apktool.jar" \
             "$BIN/apksigner.jar" "$BIN/zipalign.exe" "$APK_SIGNING_KEY" "$APK_SIGNING_CERT"; do
    [ -f "$input" ] || { echo "Missing required input: $input" >&2; exit 1; }
done

# The graphics profile is data, not code: the guest patches (_patch_guest.py, perf_tier2_forced)
# make the engine always ask for EPerformance tier 2, and s_sFiles[2] is
# android-generic_extrahigh.json. Re-encrypt it from
# _devcfg_max.json every build so restoring the tree from the original APK cannot silently
# put the stock (non-maximum) profile back.
(cd "$BASE" && python _devcfg.py max)
# _devcfg.py writes into the canonical tree; a staging tree gets the same file.
if [ "$TREE" != "$CANON" ]; then
    cp -f "$CANON/assets/data/deviceconfigs/android-generic_extrahigh.json" \
          "$TREE/assets/data/deviceconfigs/android-generic_extrahigh.json"
fi

rm -rf "$TREE/build" "$TREE/dist" "$UNSIGNED" "$ALIGNED"
java -jar "$BIN/apktool.jar" b "$TREE" -o "$UNSIGNED"

# Use the same signing identity for upgrades that must preserve existing app data.
"$BIN/zipalign.exe" -p -f 4 "$UNSIGNED" "$ALIGNED"
java -jar "$BIN/apksigner.jar" sign \
    --key "$APK_SIGNING_KEY" --cert "$APK_SIGNING_CERT" \
    --v1-signing-enabled true --v2-signing-enabled true \
    --out "$OUT" "$ALIGNED"
rm -f "$UNSIGNED" "$ALIGNED"

python - "$OUT" <<'EOF'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
abis = sorted({n.split("/")[1] for n in z.namelist() if n.startswith("lib/")})
print("ABIs in APK: %s" % (abis or "none"))
assert abis == ["arm64-v8a"], "expected arm64-v8a only, got %s" % abis
for n in ("assets/libABK.so", "assets/libSkynestSDK.so", "assets/libgnustl_shared.so",
          "assets/main.29100.com.rovio.angrybirdsgo.obb"):
    i = z.getinfo(n)
    print("  %-32s %10d %s" % (n, i.file_size, "STORED" if i.compress_type == 0 else "DEFLATED"))
    assert i.compress_type == 0, "%s must be STORED for the bridge pread path" % n
print("dex: %s" % sorted(n for n in z.namelist() if n.endswith(".dex")))
EOF
ls -la "$OUT"
