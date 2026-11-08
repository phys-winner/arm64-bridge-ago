"""Source-tool checks; the proprietary APK is optional."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import _devcfg
import _patch_guest


class ToolChecks(unittest.TestCase):
    def test_device_config_round_trip(self):
        for size in (0, 1, 4, 7, 8, 9, 64, 2047):
            with self.subTest(size=size):
                plain = bytes(i % 256 for i in range(size))
                self.assertEqual(_devcfg.dec_bytes(_devcfg.enc_bytes(plain)), plain)

    def test_graphics_profile(self):
        plain = (ROOT / _devcfg.MAX_SRC).read_bytes().replace(b"\r\n", b"\n")
        plain += b" " * (-len(plain) % 4)
        self.assertLess(len(plain), 2000)
        encrypted = _devcfg.enc_bytes(plain)
        self.assertNotEqual(encrypted, plain)
        self.assertEqual(json.loads(_devcfg.dec_bytes(encrypted)), json.loads(plain))

    def test_patch_recipe_lengths_groups_and_overlaps(self):
        names, occupied = set(), set()
        for patch in _patch_guest.PATCHES:
            with self.subTest(patch=patch.name):
                before, after = bytes.fromhex(patch.orig), bytes.fromhex(patch.new)
                self.assertNotIn(patch.name, names)
                names.add(patch.name)
                self.assertEqual(len(before), len(after))
                self.assertGreater(len(before), 0)
                self.assertIn(patch.group, _patch_guest.GROUPS["full"])
                offsets = set(range(patch.offset, patch.offset + len(before)))
                self.assertFalse(occupied & offsets)
                occupied.update(offsets)
        self.assertEqual(len(names), 32)
        self.assertEqual(sum(p.group == "base" for p in _patch_guest.PATCHES), 22)

    @unittest.skipUnless((ROOT / _patch_guest.APK).is_file(), "original APK not supplied")
    def test_original_apk_produces_both_pinned_variants(self):
        previous = Path.cwd()
        try:
            os.chdir(ROOT)
            for variant in _patch_guest.GROUPS:
                with self.subTest(variant=variant):
                    image, _ = _patch_guest.build(variant)
                    self.assertEqual(hashlib.sha256(image).hexdigest(),
                                     _patch_guest.OUT_SHA256[variant])
        finally:
            os.chdir(previous)

    def test_packaging_requires_explicit_local_configuration(self):
        bash = Path(os.environ.get("ProgramFiles", "")) / "Git/bin/bash.exe"
        if not bash.is_file():
            bash = shutil.which("bash")
        if not bash:
            self.skipTest("Bash is not installed")
        env = os.environ.copy()
        for name in ("APK_TOOLS_DIR", "APK_SIGNING_KEY", "APK_SIGNING_CERT"):
            env.pop(name, None)
        with tempfile.TemporaryDirectory() as cwd:
            for script in ("build_tree.sh", "build_vanilla.sh"):
                with self.subTest(script=script):
                    result = subprocess.run([str(bash), str(ROOT / script)], cwd=cwd,
                                            env=env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Set APK_TOOLS_DIR", result.stderr)

    @unittest.skipUnless(os.name == "nt", "Windows build wrapper")
    def test_native_build_requires_sdk_configuration(self):
        env = os.environ.copy()
        for name in ("ANDROID_SDK", "ANDROID_HOME", "ANDROID_SDK_ROOT"):
            env.pop(name, None)
        with tempfile.TemporaryDirectory() as cwd:
            result = subprocess.run(["cmd.exe", "/d", "/c",
                                     str(ROOT / "arm64_loader/build_arm64.bat")],
                                    cwd=cwd, env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Set ANDROID_SDK", result.stdout)


if __name__ == "__main__":
    unittest.main()
