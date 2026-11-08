"""Prepare the patched Dynarmic source the bridge is built against.

The bridge needs two changes on top of the pinned azahar-emu/dynarmic commit, kept in
patches/dynarmic-e77b1ba0-abgo.patch:

  * ASIMD VADDHN -- decoder entry and A32 translation (libABK uses it);
  * EmitA32Terminal(Interpret) -- skip an instruction the arm64 backend does not implement
    instead of ASSERT_FALSE aborting the process.

They used to live only inside a sibling project's _deps checkout, which kept changing after the
shipped bridge was built; this script makes them part of this project. It copies a clean
checkout of the pinned commit (with its externals) to build_deps/dynarmic-src, applies the
patch and checks the result. build_arm64.bat picks that directory up automatically, and
CMakeLists.txt refuses to configure against a Dynarmic tree without the patch.

    python prepare_dynarmic.py <clean dynarmic checkout at e77b1ba0>
"""
import os, shutil, subprocess, sys

PIN = "e77b1ba0b7da7cbe93021b01a663acfe7c4dd516"
HERE = os.path.dirname(os.path.abspath(__file__))
PATCH = os.path.join(HERE, "patches", "dynarmic-e77b1ba0-abgo.patch")
DEST = os.path.join(HERE, "build_deps", "dynarmic-src")
MARKERS = [
    # the clean file carries the same entry commented out, so match the decoder bit pattern
    ("src/dynarmic/frontend/A32/decoder/asimd.inc", "111100101Dzznnnndddd0100N0M0mmmm"),
    ("src/dynarmic/backend/arm64/emit_arm64_a32.cpp", "MC4 arm32-to-arm64 bridge patch"),
]


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=True).stdout


def main(src):
    head = git(src, "rev-parse", "HEAD").strip()
    assert head == PIN, "%s is at %s, expected %s" % (src, head, PIN)
    dirty = git(src, "status", "--porcelain", "--ignore-submodules=none").strip()
    assert not dirty, "%s is not clean:\n%s" % (src, dirty)
    for line in git(src, "submodule", "status", "--recursive").splitlines():
        assert line[:1] == " ", "submodule not at its recorded commit: " + line

    if os.path.isdir(DEST):
        shutil.rmtree(DEST)
    shutil.copytree(src, DEST, symlinks=False)
    git(DEST, "apply", "--ignore-whitespace", PATCH)
    for rel, marker in MARKERS:
        with open(os.path.join(DEST, rel), encoding="utf-8", errors="replace") as f:
            assert marker in f.read(), "%s: marker %r missing after the patch" % (rel, marker)
    print(git(DEST, "diff", "--stat").rstrip())
    print("[+] %s ready (pinned %s + %s)" % (DEST, PIN[:12], os.path.basename(PATCH)))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(os.path.abspath(sys.argv[1]))
