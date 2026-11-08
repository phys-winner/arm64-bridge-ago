# ARM64 Bridge for Angry Birds Go!

An experimental ARM32-to-ARM64 compatibility bridge for **Angry Birds Go! 2.9.1** on Android. It runs the original game's 32-bit native libraries inside a 64-bit process with [Dynarmic](https://github.com/azahar-emu/dynarmic), forwarding Android, graphics, audio and JNI calls to the host.

This repository contains the bridge source code, its Dynarmic patch, and local game-patching and packaging tools. It does not include APKs, OBBs, game libraries, game assets, decompiled Java/Smali, signing keys, downloaded dependencies or build outputs. You must supply your own game files.

**Status: experimental.** Earlier device testing reached gameplay and results, but a Mali-T720 device produced black frames. That rendering issue remains unresolved. Other GPUs and devices need their own validation; this is not a promise of universal compatibility.

## How it works

- Loads and relocates the original ARM32 ELF libraries in their required order: `libgnustl_shared.so`, `libSkynestSDK.so`, then `libABK.so`.
- Uses Dynarmic's A32 frontend and ARM64 backend to translate guest instructions.
- Implements host thunks for libc, Android, EGL, OpenGL ES and OpenSL ES, plus guest JNI handles and Java native entry points.
- Applies game-specific offline, startup, file I/O, audio and graphics fixes.
- Provides matching **full mod** and **vanilla economy** bridge/guest variants.
- Requests 16 KB alignment for the native bridge's loadable segments. Complete APK and device compatibility still require testing.

The Dynarmic patch adds ASIMD `VADDHN` translation and changes its ARM64 `Interpret` terminal to skip unsupported instructions. That fallback can produce incorrect behavior; it is a game-specific workaround, not a general ARM emulator.

## Source layout

| Path | Purpose |
| --- | --- |
| `arm64_loader/src/` | ELF loader, JIT host, JNI forwarding, system thunks and runtime game fixes |
| `arm64_loader/CMakeLists.txt` | Android ARM64 native build |
| `arm64_loader/build_arm64.bat` | Windows build entry point |
| `arm64_loader/prepare_dynarmic.py` | Validate and copy a pinned dependency checkout, then apply the local patch |
| `arm64_loader/patches/` | Required Dynarmic changes |
| `arm64_loader/check_symbols*.py` | Guest import and host-thunk inspection |
| `_patch_guest.py` | Hash-checked patch recipes for the original `libABK.so` |
| `_devcfg.py`, `_devcfg_max.json` | Device-profile encryption and graphics settings |
| `build_tree.sh`, `build_vanilla.sh` | Rebuild and sign an existing adapted apktool tree |
| `tests/test_tools.py` | Dependency-free checks for patch recipes, profile encryption and build-script preflight |

## Build the native bridge

The supplied wrapper targets Windows with an Android SDK installation and builds for `arm64-v8a` with `ANDROID_PLATFORM=android-26` (Android 8.0). APK packaging uses **Git Bash**. Python tools use only the Python standard library.

Requirements:

- Git and Python 3.
- Android NDK **27.2.12479018** and SDK CMake **3.22.1**, including Ninja.
- [Boost **1.83.0**](https://www.boost.org/releases/1.83.0/) headers.
- Dynarmic commit `e77b1ba0b7da7cbe93021b01a663acfe7c4dd516` with its recorded submodules and this repository's patch.

Run these commands from the repository root in PowerShell:

```powershell
git clone https://github.com/azahar-emu/dynarmic.git arm64_loader/build_deps/dynarmic-clean
git -C arm64_loader/build_deps/dynarmic-clean checkout --detach e77b1ba0b7da7cbe93021b01a663acfe7c4dd516
git -C arm64_loader/build_deps/dynarmic-clean submodule update --init --recursive
python arm64_loader/prepare_dynarmic.py arm64_loader/build_deps/dynarmic-clean
```

Download and extract the Boost source release so the header is at `arm64_loader/third_party/boost/boost/version.hpp`. Preserve its upstream license alongside the headers. No Boost library compilation is needed. Dependencies are intentionally ignored by Git.

`prepare_dynarmic.py` replaces `arm64_loader/build_deps/dynarmic-src`; keep your own dependency edits elsewhere. CMake refuses a dependency tree missing the required patch markers. The wrapper automatically selects the prepared tree; `DYNARMIC_SOURCE_DIR` can select another already patched checkout.

Set `ANDROID_SDK` to your SDK installation, or use an existing `ANDROID_HOME` / `ANDROID_SDK_ROOT`. Then build either variant:

```powershell
.\arm64_loader\build_arm64.bat
.\arm64_loader\build_arm64.bat vanilla
```

The wrapper uses the pinned NDK and CMake versions by default. `NDK_VERSION` and `CMAKE_VERSION` allow an explicitly chosen installed version; other versions have not been validated here.

Outputs:

| Variant | Package this file |
| --- | --- |
| Full mod, default | `arm64_loader/build_arm64/libabk_arm64_bridge.stripped.so` |
| Vanilla economy | `arm64_loader/build_arm64_vanilla/libabk_arm64_bridge.stripped.so` |

The unstripped `libabk_arm64_bridge.so` is retained in the same directory for debugging. CMake's `ENABLE_LOGGING=ON` option enables info/warning logs; error logs remain enabled in release builds.

## Guest patch variants

Place your original 2.9.1 APK at `Angry+Birds-29100-2.9.1.apk` in the repository root. Run from that root:

```powershell
python _patch_guest.py list
python _patch_guest.py full libABK.full.so
python _patch_guest.py vanilla libABK.vanilla.so
```

The input is `lib/armeabi-v7a/libABK.so` inside the APK. The script verifies its SHA-256, checks every original patch site before changing anything, and verifies the resulting library's SHA-256 before writing it. Use normal Python execution; `python -O` disables these assertion-based checks.

| Variant | Behavior | Guest SHA-256 |
| --- | --- | --- |
| Original | Required unmodified input | `c1cc09c47a66da7ab419720e460fa577f2f429c40e8cc05161ced0269cba66ff` |
| Full mod | 32 guest patches: compatibility fixes plus currency, energy, progression and unlock changes | `5e0fec3a933426e26f32870dd513fae994cd2efb2c9b659bfc8733e44dd36e42` |
| Vanilla economy | 22 guest patches: compatibility fixes with stock currency/progression behavior | `3861dc8931c4ee30f3b2b26cdaebc2cf9d59ba509ef27d8e7392eb5c9de74577` |

Always pair a guest variant with the matching bridge build. Vanilla economy retains offline, graphics and audio changes; it is not an untouched original game. Existing saves keep any unlocks previously granted by the full mod.

## Rebuild an existing adapted APK

**A clean clone is sufficient for building the native bridge after installing dependencies. It is not sufficient to recreate the complete adapted APK from a stock APK.** The packaging scripts expect an existing adapted apktool tree containing manifest, resources and Java/Smali integration changes. Those game-derived files are not distributed here, and these scripts do not generate those integration changes.

The expected local tree is `Angry+Birds-29100-2.9.1/`. It must already contain:

```text
AndroidManifest.xml
apktool.yml
assets/libABK.so
assets/libSkynestSDK.so
assets/libgnustl_shared.so
assets/main.29100.com.rovio.angrybirdsgo.obb
assets/data/deviceconfigs/
lib/arm64-v8a/libabk_arm64_bridge.so
```

The tree's Java native loading must use `abk_arm64_bridge`. All three ARM32 guest libraries and the embedded OBB must be listed in apktool's `doNotCompress` list. The final APK must expose only `arm64-v8a` under `lib/`. The packaging script checks these archive properties after signing.

For a full-mod rebuild, first copy the full bridge's **stripped** output to `lib/arm64-v8a/libabk_arm64_bridge.so` in the tree and place the matching patched guest at `assets/libABK.so`. `build_tree.sh` packages the libraries already present; it does not rebuild or replace them automatically.

In Git Bash, set these environment variables to your own local tool/key locations:

| Variable | Required contents |
| --- | --- |
| `APK_TOOLS_DIR` | Directory containing `apktool.jar`, `apksigner.jar`, `zipalign.exe` |
| `APK_SIGNING_KEY` | APK signing private key in `.pk8` format |
| `APK_SIGNING_CERT` | Matching `.x509.pem` certificate |

Java and Python must be available on `PATH`. The retained tree was used with apktool 3.0.3. Keep signing keys outside the repository and use the same signing identity when upgrading an existing installation to retain its data.

```bash
bash build_tree.sh
bash build_vanilla.sh
```

The default outputs are `abgo_arm64.apk` and `abgo_arm64_vanilla.apk`. Either script accepts an output path as its first argument. The vanilla script requires its native build first and creates a staging tree with the matching guest and bridge libraries. Both packaging scripts regenerate the canonical tree's graphics profile from `_devcfg_max.json`; the vanilla staging tree receives the same profile. `ABGO_TREE` lets `build_tree.sh` package a different prepared tree.

## Checks and diagnostics

```powershell
python -m unittest discover -s tests -v
python arm64_loader/check_symbols_fast.py arm64_loader/src libABK.full.so
```

The checks run without proprietary game data. When the original APK is present, they also build both guest variants in memory and check their pinned hashes. Run the symbol checker with all three guest libraries to account for symbols resolved between guests. It reports unresolved names for inspection; it does not prove full runtime compatibility.

Keep APKs, captures, logs, signing material, local state and downloaded dependencies out of commits. `.gitignore` uses a source allowlist; review `git diff --cached` before publishing any change.

## License and attribution

Copyright (C) 2026 phys-winner.

The bridge and original project tooling are licensed under **GNU GPL version 3 or, at your option, any later version** (`GPL-3.0-or-later`). See [LICENSE](LICENSE) for the complete terms. The program is distributed without warranty.

Dynarmic and its dependencies retain their upstream licenses. The Dynarmic notice is reproduced in [LICENSES/Dynarmic.txt](LICENSES/Dynarmic.txt) for upstream code appearing in the patch. Boost is separately licensed under the [Boost Software License 1.0](https://www.boost.org/LICENSE_1_0.txt). Downloaded dependencies are not relicensed by this repository.

Angry Birds Go! and its game code, assets and trademarks belong to their respective owners. This is an independent, unofficial compatibility project. Its license grants no rights to proprietary game files.
