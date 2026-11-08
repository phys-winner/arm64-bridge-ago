#!/usr/bin/env python3
"""Which guest imports are still unresolved once the sibling guest .so and the host thunks
are taken into account.

The bundled check_symbols.py is O(n^2) -- for every one of ~3900 dynsym entries it slices
and splits the whole 18.6 MB file, which takes over an hour on libABK.so. This does the
same job in about a second and, unlike the original, also subtracts symbols exported by the
OTHER guest objects, which is the number that actually sizes the porting work.

    python check_symbols_fast.py <src_dir> <guest.so> [more_guest.so ...]
"""
import os
import re
import struct
import sys


def parse_dynsym(path):
    """Return (imports, exports) name sets from a 32-bit little-endian ELF."""
    elf = open(path, "rb").read()
    assert elf[:4] == b"\x7fELF" and elf[4] == 1, "%s is not a 32-bit ELF" % path

    e_shoff, = struct.unpack_from("<I", elf, 0x20)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", elf, 0x2E)

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, stype, flags, addr, offset, size, link, info, align, entsize = \
            struct.unpack_from("<IIIIIIIIII", elf, off)
        sections.append(dict(name=name, type=stype, offset=offset, size=size,
                             link=link, entsize=entsize))

    shstr = sections[e_shstrndx]["offset"]

    def sec_name(s):
        b = shstr + s["name"]
        return elf[b:elf.index(b"\0", b)].decode("latin1")

    dynsym = next((s for s in sections if sec_name(s) == ".dynsym"), None)
    if dynsym is None:
        return set(), set()
    dynstr = sections[dynsym["link"]]

    imports, exports = set(), set()
    count = dynsym["size"] // 16
    for i in range(count):
        off = dynsym["offset"] + i * 16
        st_name, st_value, st_size, st_info, st_other, st_shndx = \
            struct.unpack_from("<IIIBBH", elf, off)
        if st_name == 0:
            continue
        b = dynstr["offset"] + st_name
        name = elf[b:elf.index(b"\0", b)].decode("latin1")
        if st_shndx == 0:          # SHN_UNDEF
            imports.add(name)
        elif st_value != 0 or st_size != 0:
            exports.add(name)
    return imports, exports


def registered_thunks(src_dir):
    names = set()
    pat = re.compile(r'Register(?:Thunk|Symbol)\s*\(\s*"([^"]+)"')
    for root, _dirs, files in os.walk(src_dir):
        for f in files:
            if not f.endswith((".cpp", ".h")):
                continue
            text = open(os.path.join(root, f), encoding="utf-8", errors="replace").read()
            names.update(pat.findall(text))
    return names


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    src_dir, guests = sys.argv[1], sys.argv[2:]

    thunks = registered_thunks(src_dir)
    all_imports, all_exports = set(), set()
    per_lib = {}
    for g in guests:
        imp, exp = parse_dynsym(g)
        per_lib[os.path.basename(g)] = (imp, exp)
        all_imports |= imp
        all_exports |= exp

    unresolved = sorted(all_imports - all_exports - thunks)

    print("registered thunks in %s : %d" % (src_dir, len(thunks)))
    for name, (imp, exp) in per_lib.items():
        print("  %-24s imports %4d  exports %5d" % (name, len(imp), len(exp)))
    print("union imports %d, satisfied intra-set %d, UNRESOLVED %d"
          % (len(all_imports), len(all_imports & all_exports), len(unresolved)))

    # crude grouping so the remaining work can be sized per subsystem
    groups = [
        ("EGL",       lambda n: n.startswith("egl")),
        ("GLESv2",    lambda n: n.startswith("gl")),
        ("OpenSLES",  lambda n: n.startswith("sl") or n.startswith("SL_")),
        ("libandroid", lambda n: n.startswith(("AAsset", "ANativeWindow", "AConfiguration",
                                               "ALooper", "AInputQueue"))),
        ("liblog",    lambda n: n.startswith("__android_log")),
        ("libm",      lambda n: n in {"acos", "asin", "atan", "atan2", "cbrt", "ceil", "cos",
                                      "cosh", "exp", "exp2", "expf", "fmod", "hypot", "ldexp",
                                      "log", "log10", "log2", "modf", "pow", "sin", "sinh",
                                      "sqrt", "tan", "tanh", "trunc", "round", "fmin", "fmax"}),
    ]
    seen = set()
    for label, pred in groups:
        hit = [n for n in unresolved if pred(n)]
        seen.update(hit)
        if hit:
            print("\n[%s] %d" % (label, len(hit)))
            print("  " + " ".join(sorted(hit)))
    rest = [n for n in unresolved if n not in seen]
    print("\n[libc/other] %d" % len(rest))
    for n in sorted(rest):
        print("  " + n)


if __name__ == "__main__":
    main()
