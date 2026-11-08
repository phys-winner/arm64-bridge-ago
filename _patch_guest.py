"""Build the patched guest libABK.so from the original Rovio APK.

Every byte the mod changes in lib/armeabi-v7a/libABK.so is listed in PATCHES below, with the
exact original bytes it replaces. The table was generated from a byte diff of the original
library against the shipped mod (616 differing bytes, all covered, no overlaps) and each
entry was traced to its function in the original image. Nothing is written unless the
original bytes match first.

Two groups:

  base   offline, compatibility, graphics and audio fixes -- ads off, no "no connection"
         popups, uncapped present, performance tier 2 + LoadDeviceSpecific, anisotropic
         filtering, the extrahigh profile name fix, 48 kHz decode, the OpenSL refill cave.
  cheat  everything that changes earned currency or progression -- see the comment on each.

    python _patch_guest.py full    <out.so>   every patch; reproduces the tree's assets/libABK.so
    python _patch_guest.py vanilla <out.so>   base patches only (the "vanilla economy" build)
    python _patch_guest.py list               print the table

The input is always the original APK in the game root, verified by SHA-256, so neither variant
can silently inherit a patch from whatever library happens to be in the tree. Both outputs are
pinned by SHA-256 as well.

CSmokeTest::HandleCommandLineArgs (0x2B9DF8) has no callers in the image, so the mod uses its
body as a code cave. The cave holds four pieces: the unlock-all hook on CMapScreen::Process
and the coin->gem helpers (cheat), the OpenSL buffer-queue refill and the performance-tier-2
config loader (base). The vanilla build keeps only the last two; the cheat part of the cave is
left as the original bytes, and nothing branches into it.
"""
import hashlib, sys, zipfile
from collections import namedtuple

APK = "Angry+Birds-29100-2.9.1.apk"
APK_ENTRY = "lib/armeabi-v7a/libABK.so"
ORIG_SHA256 = "c1cc09c47a66da7ab419720e460fa577f2f429c40e8cc05161ced0269cba66ff"
OUT_SHA256 = {
    "full":    "5e0fec3a933426e26f32870dd513fae994cd2efb2c9b659bfc8733e44dd36e42",
    "vanilla": "3861dc8931c4ee30f3b2b26cdaebc2cf9d59ba509ef27d8e7392eb5c9de74577",
}

# File offsets: the first PT_LOAD maps offset == vaddr, the second one is vaddr - 0x1000
# (only decode_sample_rate_48k lives there: .data vaddr 0xDA19C4).
Patch = namedtuple("Patch", "name group offset orig new")
PATCHES = [
    # CEnergySystem::GetEnergyLevel: BHS -> B, the meter always reads "full".
    Patch("energy_always_full",        "cheat", 0x0E48C4,
          "1900002a",
          "190000ea"),
    # CGame::Process: no per-frame PopupNoConnection; take the connected branch.
    Patch("game_process_offline",      "base",  0x106EE0,
          "3b03000a",
          "00f020e3"),
    # CInGameAdManager::IsCampaignActive -> 0.
    Patch("ingame_ad_campaign_off",    "base",  0x112960,
          "080090e5",
          "0000a0e3"),
    # CKartManager::GetHasKartForEvent / IsKartValidForEvent: debug bool 30 is
    # Block_Low_CC_Kart (DebugTweakables.xml); forcing it to 0 lets an under-powered kart
    # enter any event.
    Patch("block_low_cc_kart_has",     "cheat", 0x1159EC,
          "498306eb",
          "0000a0e3"),
    Patch("block_low_cc_kart_valid",   "cheat", 0x115B88,
          "e28206eb",
          "0000a0e3"),
    # CPlayerInfo::GetNextCampaignLevel: never stops at the first unfinished level, so the
    # campaign pointer jumps to the last one.
    Patch("next_campaign_level_last",  "cheat", 0x140A5C,
          "0a00000a",
          "00f020e3"),
    # CPlayerInfo::HasSeenRovioNewsToday -> 1 (the news feed is online-only).
    Patch("rovio_news_seen",           "base",  0x14323C,
          "10402de910d04de2",
          "0100a0e31eff2fe1"),
    # CPlayerInfo::CheckConnectivity -> 1, no PopupNoConnection.
    Patch("connectivity_ok",           "base",  0x143410,
          "10402de98a00a0e3",
          "0100a0e31eff2fe1"),
    # CSaveManager::LoadFromSaveBlock: the "bFirstTimeUser" attribute is the FTUE stage
    # (CPlayerInfo+0x42C); forced to 10 on every load = tutorial done, FTUE event locks gone.
    Patch("ftue_stage_forced_on_load", "cheat", 0x155F04,
          "7f7a05eb",
          "0a00a0e3"),
    # CCar::AddCoin: x10 per pickup (stock: x2 with the coin doubler) + 1 gem per pickup via
    # the cave helper at 0x2B9F98.
    Patch("coin_pickup_x10_gem",       "cheat", 0x1A0C54,
          "203490e5000053e30250a0130150a003",
          "cf6404eb00f020e30a50a0e300f020e3"),
    # CCar::AddCoins(n): x10 coins + n gems via the cave helper at 0x2B9FAC.
    Patch("coins_x10_gems",            "cheat", 0x1A0CA4,
          "203490e5000053e38140a011",
          "c06404eb011181e08140a0e1"),
    # CTokenGroup::Decrement: the spent count is never stored -- kart parts/materials and
    # gacha tickets are never used up.
    Patch("tokens_never_spent",        "cheat", 0x1FCC08,
          "0c3080a5",
          "00f020e3"),
    # CAdsManager: Process returns, IsAdShown / ShouldShowMainMenuAd / IsVideoAdShown -> 0.
    Patch("ads_process_off",           "base",  0x262AF0,
          "30402de9",
          "1eff2fe1"),
    Patch("ads_shown_off",             "base",  0x263034,
          "180190e5000090e2",
          "0000a0e31eff2fe1"),
    Patch("ads_main_menu_off",         "base",  0x263044,
          "383190e5000053e3",
          "0000a0e31eff2fe1"),
    Patch("ads_video_off",             "base",  0x2630B8,
          "183190e5010013e3",
          "0000a0e31eff2fe1"),
    # CApp::DoPresent: debug bools 79/80 (TARGET_30_FPS, TARGET_60_FPS_FE) read as 0.
    Patch("present_no_30fps_cap",      "base",  0x26CA74,
          "272701eb",
          "0000a0e3"),
    Patch("present_no_60fps_fe_cap",   "base",  0x26CB20,
          "fc2601eb",
          "0000a0e3"),
    # CApp::MainLoadingFunc: BL CDebugManager::Initialise -> BL cave_perf_tier2_init.
    Patch("init_via_perf_tier2_cave",  "base",  0x26DB70,
          "582f01eb",
          "1c3101eb"),
    # CApp::MainLoadingFunc: always EPerformance tier 2 (android-generic_extrahigh), and
    # DebugOutput -> CDebugManager::LoadDeviceSpecific so the profile reaches the debug table.
    Patch("perf_tier2_forced",         "base",  0x26DD28,
          "2a00000a580095e5ba38fbebfe2900ebf22c00eb",
          "00f020e3580095e50200a0e3fe2900eb792001eb"),
    # CDeviceConfig::UpdateRecommendedPerformance -> 0 (no runtime downgrade).
    Patch("recommended_perf_off",      "base",  0x278D20,
          "6c339fe503308fe0",
          "0000a0e31eff2fe1"),
    # Cave, cheat part (0x2B9DF8..0x2B9FBB): the CMapScreen::Process hook body -- every frame
    # completes the FTUE channel, calls CPlayerInfo::UnlockAllEpisodes, sets the coin doubler
    # (+0x420) and Jenga (+0xA10), raises all 14 characters, marks every kart owned (+0x9904
    # array, state 1), marks every event played with all stars -- then the two CCar::AddGems
    # helpers used by the coin patches.
    Patch("cave_unlock_all",           "cheat", 0x2B9DF8,
          "010050e31eff2fd1f04f2de90cd04de2a0329fe50070a0e19c829fe50160a0e103308fe094929fe5"
          "94a29fe508808fe090b29fe509908fe000308de50140a0e384329fe50aa08fe00bb08fe003308fe0"
          "04308de5170000ea70329fe503308fe0003093e5000053e30400000a60329fe503308fe0003093e5"
          "000053e30a00000a50129fe50000a0e34c229fe501c0a0e348329fe501108fe002208fe003308fe0"
          "00c081e5000082e5000083e5014084e2070054e11900000a0450b6e50810a0e11320a0e30500a0e1"
          "c162f7eb000050e3e0ffff0a0500a0e10910a0e11020a0e3bb62f7eb000050e30e00001af0319fe5"
          "03308fe0003093e5000053e3dfffff0ae0319fe503308fe0003093e5000053e3daffff1a014084e2"
          "070054e1e5ffff1a0cd08de2f08fbde80500a0e10a10a0e11020a0e3a662f7eb000050e31600001a"
          "a4319fe503308fe0003093e5000053e30400000a94319fe503308fe0003093e5030053e3d0ffff0a"
          "84119fe501c0a0e380219fe50300a0e37c319fe501108fe002208fe003308fe000c081e5000082e5"
          "0010a0e3001083e5c3ffffea0500a0e10b10a0e11220a0e38962f7eb000050e31500001a44319fe5"
          "03308fe0003093e5000053e3",
          "ff5f2de9883606eb000050e30700000a081090e5000051e30400000a042091e5010072e30100000a"
          "0100a0e1e13306eb64019fe500008fe0000090e5340090e50060a0e1580090e5000050e34f00000a"
          "0040a0e16306faeb0100a0e3100a84e5200484e54e1f84e20e20a0e3003091e5010053e3000081b5"
          "281081e2012052e2f9ffff1a993ca0e3033084e0041093e5082093e5000051e30500000a000052e3"
          "030000da0c0081e5481081e2012052e2fbffff1a300096e5000050e33300000ab06590e5b45590e5"
          "507094e5000057e32e00000a000056e32c0000da0080a0e3a400a0e3900801e0011085e004a091e5"
          "009091e51400a0e3900801e0011087e00cb091e500005be31d00000a00005ae31b0000da0020a0e3"
          "1800a0e3900201e001c089e008c09ce501108be00300a0e3000081e50100a0e3040081e5080081e5"
          "0c1091e5000051e30a00000a00005ce3080000da0330a0e3003081e50100a0e3040081e50a00a0e3"
          "100081e5381081e201c05ce2f7ffff1a012082e20a0052e1e4ffffba018088e2060058e1d3ffffba"
          "ff5fbde8f04f2de9e6df04ea9820af000f502de90400a0e10110a0e3589bfbeb0f90bde80f502de9"
          "0500a0e1549bfbeb0f90bde8"),
    # Cave, base part: OpenSL buffer-queue refill, entered by BLEQ from opensl_refill_hook.
    Patch("cave_opensl_refill",        "base",  0x2B9FBC,
          "0400000a34319fe503308fe0003093e5010053e3b3ffff0a24119fe501c0a0e320219fe50000a0e3"
          "1c319fe5",
          "0f402de9003095e5103013e5030085e0033095e7543093e533ff2fe1000050e30f40bde81eff2f11"
          "4b020cea"),
    # Cave, base part: LoadDeviceConfigByPerformance(2), then tail-call
    # CDebugManager::Initialise; entered from init_via_perf_tier2_cave.
    Patch("cave_perf_tier2_init",      "base",  0x2B9FE8,
          "01108fe002208fe003308fe000c081e500c082e5000083e5a7ffffea",
          "10402de90040a0e10200a0e34ef9feeb0400a0e11040bde834feffea"),
    # GameUI::CIcon::RenderImpl: MOVLT R1,#0 -> #2, icons keep the filtered sampler.
    Patch("icon_filtering",            "base",  0x3BF9BC,
          "0010a0b3",
          "0210a0b3"),
    # GameUI::CMapScreen::Process entry -> B cave_unlock_all.
    Patch("map_screen_unlock_hook",    "cheat", 0x3F1F2C,
          "f04f2de9",
          "b11ffbea"),
    # CXGSRenderDeviceOGL::PresentScene: BEQ -> B.
    Patch("present_scene_fix",         "base",  0x556CD4,
          "2500000a",
          "250000ea"),
    # CXGSRenderDeviceOGL::Create: VMOVNE.F32 S14,S13 -> NOP.
    Patch("render_device_create",      "base",  0x5580C0,
          "667ab01e",
          "00f020e3"),
    # XGSOGL_applyTexParams: anisotropic filtering for every filter mode, not just mode 2.
    Patch("aniso_filter_all",          "base",  0x55C284,
          "3a00001a",
          "00f020e3"),
    # CXGSSound_2DSound_OpenSL::AndroidSimpleBufferQueueCallback: BEQ -> BLEQ cave_opensl_refill.
    Patch("opensl_refill_hook",        "base",  0x5BA8E4,
          "0b00000a",
          "b4fdf30b"),
    # s_sFiles[2] is "android-generic_extrahighandroid-generic_extrahigh" in the original (a
    # missing comma in Rovio's table); terminate it after the first name.
    Patch("extrahigh_profile_name",    "base",  0xC995F4,
          "68616e64",
          "68006e64"),
    # (anonymous namespace)::s_uDecodeSampleRate: 24000 -> 48000.
    Patch("decode_sample_rate_48k",    "base",  0xDA09C4,
          "c05d0000",
          "80bb0000"),
]

GROUPS = {"full": ("base", "cheat"), "vanilla": ("base",)}


def load_original():
    data = zipfile.ZipFile(APK).read(APK_ENTRY)
    digest = hashlib.sha256(data).hexdigest()
    assert digest == ORIG_SHA256, "%s!%s is %s, expected the original %s" % (
        APK, APK_ENTRY, digest, ORIG_SHA256)
    return bytearray(data)


def build(variant):
    img = load_original()
    groups = GROUPS[variant]
    # Check every preimage before writing any of them.
    for p in PATCHES:
        orig, new = bytes.fromhex(p.orig), bytes.fromhex(p.new)
        assert len(orig) == len(new), p.name
        got = bytes(img[p.offset:p.offset + len(orig)])
        assert got == orig, "%s at 0x%X holds %s, expected %s" % (p.name, p.offset, got.hex(), p.orig)
    applied = [p for p in PATCHES if p.group in groups]
    for p in applied:
        img[p.offset:p.offset + len(p.new) // 2] = bytes.fromhex(p.new)
    return bytes(img), applied


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "list"
    if mode == "list":
        for p in PATCHES:
            print("%-6s 0x%06X %4d  %s" % (p.group, p.offset, len(p.orig) // 2, p.name))
    elif mode in GROUPS:
        out, applied = build(mode)
        digest = hashlib.sha256(out).hexdigest()
        pinned = OUT_SHA256[mode]
        assert pinned is None or digest == pinned, "%s output is %s, pinned %s" % (mode, digest, pinned)
        open(sys.argv[2], "wb").write(out)
        print("[+] %s: %d/%d patches -> %s (sha256 %s)" % (mode, len(applied), len(PATCHES),
                                                           sys.argv[2], digest))
    else:
        sys.exit(__doc__)
