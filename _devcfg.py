"""Decrypt / encrypt Angry Birds Go! device-config JSON.

The files in assets/data/deviceconfigs/*.json are XXTEA (corrected block TEA)
with the key hardcoded in CDeviceConfig::LoadDeviceConfigFileJson (0x277D78):

    v57[0] = 1142310036; v57[1] = 810418456; v58 = 0x8D3D7B3B5A2E1A85

XGSEncrypt_decryptXXTEA (0x4C6444) is textbook btea with rounds = 6 + 52/n and
n = size/4, so a trailing tail of size%4 bytes is passed through untouched.

    python _devcfg.py d <file.json> [out]    -> plaintext (stdout, or a file)
    python _devcfg.py e <plain> <file.json>  -> encrypt plain into file.json
    python _devcfg.py max                    -> _devcfg_max.json -> the tree's
                                                android-generic_extrahigh.json

`max` is the one the build scripts call. _patch_guest.py makes CApp::MainLoadingFunc ask
for EPerformance tier 2 unconditionally, and s_sFiles[2] is "android-generic_extrahigh", so
that one file is the whole graphics profile. Stock extrahigh is not actually the maximum --
it leaves SOFT_PARTICLES, FXAA and tone mapping off and turns TARGET_30_FPS and
POST_PROCESS_BLOOM_FE the wrong way round versus CDebugManager::SetDefaults -- hence a
replacement rather than a patch to the shipped one.

Two groups of keys here are not in any shipped profile at all:

  CAR_*_LOD, SMACKABLE_LOD_*  CDebugManager::LoadDeviceSpecific copies them, but no profile
                              sets them, so they ran on SetDefaults (cars dropped a LOD at
                              20 m and were culled at 400). CCar::RenderOpaque squares each
                              threshold and compares against squared camera distance, so a
                              large value simply means "never leave LOD 0".
  RENDER_SCALE_X/Y            the size of the scene render target, read once in
                              CRenderManager's constructor and cached in
                              s_iScaledScreenWidth/Height. Above 1.0 it is supersampling.
                              1.5 measured free on the realme (125 fps, same as 1.0); 2.0
                              misses the 8.33 ms budget and halves the frame rate.
                              Never set it below 1.0.
"""
import struct, sys

DELTA = 0x9E3779B9
KEY = [1142310036, 810418456, 0x5A2E1A85, 0x8D3D7B3B]


def _mx(y, z, s, k, p, e):
    return ((((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF)))
            ^ (((s ^ y) + (k[(p & 3) ^ e])) ^ z)) & 0xFFFFFFFF


def _mx_correct(y, z, s, k, p, e):
    # matches the decompiled loop: ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((s^y) + (k[(p&3)^e] ^ z))
    return ((((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF)))
            ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))) & 0xFFFFFFFF


def decrypt(v, k=KEY):
    n = len(v)
    if n < 2:
        return v
    rounds = 6 + 52 // n
    s = (rounds * DELTA) & 0xFFFFFFFF
    y = v[0]
    while rounds > 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = v[p] = (v[p] - _mx_correct(y, z, s, k, p, e)) & 0xFFFFFFFF
        z = v[n - 1]
        y = v[0] = (v[0] - _mx_correct(y, z, s, k, 0, e)) & 0xFFFFFFFF
        s = (s - DELTA) & 0xFFFFFFFF
        rounds -= 1
    return v


def encrypt(v, k=KEY):
    n = len(v)
    if n < 2:
        return v
    rounds = 6 + 52 // n
    s = 0
    z = v[n - 1]
    while rounds > 0:
        s = (s + DELTA) & 0xFFFFFFFF
        e = (s >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = v[p] = (v[p] + _mx_correct(y, z, s, k, p, e)) & 0xFFFFFFFF
        y = v[0]
        z = v[n - 1] = (v[n - 1] + _mx_correct(y, z, s, k, n - 1, e)) & 0xFFFFFFFF
        rounds -= 1
    return v


def _words(d):
    n = len(d) // 4
    return list(struct.unpack("<%dI" % n, d[:n * 4])), d[n * 4:]


def dec_bytes(d):
    v, tail = _words(d)
    return struct.pack("<%dI" % len(v), *decrypt(v)) + tail


def enc_bytes(d):
    v, tail = _words(d)
    return struct.pack("<%dI" % len(v), *encrypt(v)) + tail


MAX_SRC = "_devcfg_max.json"
MAX_DST = ("Angry+Birds-29100-2.9.1/assets/data/deviceconfigs/"
           "android-generic_extrahigh.json")

if __name__ == "__main__":
    if sys.argv[1] == "max":
        plain = open(MAX_SRC, "rb").read().replace(b"\r\n", b"\n")
        plain += b" " * (-len(plain) % 4)   # XXTEA covers whole words; a tail stays plaintext
        assert len(plain) < 2000, "LoadDeviceConfigFileJson reads at most 2047 bytes"
        open(MAX_DST, "wb").write(enc_bytes(plain))
        assert dec_bytes(open(MAX_DST, "rb").read()) == plain, "round trip failed"
        print("[+] %s -> %s (%d bytes)" % (MAX_SRC, MAX_DST, len(plain)))
    elif sys.argv[1] == "d":
        out = dec_bytes(open(sys.argv[2], "rb").read())
        if len(sys.argv) > 3:
            open(sys.argv[3], "wb").write(out)      # binary: stdout would eat the \n
        else:
            sys.stdout.buffer.write(out)
    else:
        open(sys.argv[3], "wb").write(enc_bytes(open(sys.argv[2], "rb").read()))
