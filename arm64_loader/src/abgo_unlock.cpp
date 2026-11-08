// Host-side implementation of the AbgoUnlock hooks. See the header for what and why.
//
// Everything here runs from inside a thunk (the guest JNI bridge), so guest code goes
// through RunFunctionNested -- the main Jit is mid-Run and cannot be re-entered. Guest
// memory writes are direct: the arena is host memory and the writes are data, not code.

#include "abgo_unlock.h"

#include <android/log.h>
#include <sys/system_properties.h>
#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"

#define LOG_TAG "ABGO_UNLOCK"
#include "bridge_log.h"

namespace {

// --- guest symbol and vaddr table (libABK.so 2.9.1) ----------------------------------------
// The mangled names are exports in .dynsym and FindSymbol resolves them; the vaddrs are the
// IDA-verified fallback if a future build strips or hides one.
struct GuestVaddrs {
    uint32_t unlock_all_episodes   = 0x13B7E0;  // CPlayerInfo::UnlockAllEpisodes()
    uint32_t unlock_kart           = 0x13D610;  // CPlayerInfo::UnlockKart(UNameTag, ETypeOfGain, PKc, f, PKc, PKc, PKc, i)
    uint32_t is_kart_owned         = 0x13D974;  // CPlayerInfo::IsKartOwned(UNameTag) const
    uint32_t request_save          = 0x14D6FC;  // CSaveManager::RequestSave(int)
    uint32_t cheat_add_gift        = 0x1100A8;  // CGiftManager::CheatAddActiveGift(EGiftType)
    uint32_t get_ftue_manager      = 0x447824;  // GetFTUEManager()
    uint32_t ftue_complete_all     = 0x447B8C;  // CFTUEManager::DebugCompleteAll()
    // Data locations: globals live at fixed vaddrs; nothing here is a real symbol.
    uint32_t g_p_application       = 0xDABECC;  // -> P; state = *(P+52)
};
constexpr GuestVaddrs kVaddr{};

// The UI manager is a data global (not a GOT slot).  CPopupManager lives at +0x410 in it.
constexpr uint32_t kUiManagerGlobal = 0xEA45C8;

// libABK imports this from libSkynestSDK through its PLT/GOT. Redirecting that one GOT cell
// keeps the entire workaround in the arm64 bridge and avoids calling the real offline payment
// implementation (which only starts an asynchronous request that can never complete).
constexpr uint32_t kRestorePurchasesGot = 0xD9BAE8;
constexpr char kRestorePurchasesSymbol[] =
    "_ZN3rcs7Payment16restorePurchasesERKSt8functionIFvRKSsEERKS1_IFvNS0_9ErrorCodeES3_EERKS1_IFvRKNS0_4InfoEEE";

struct KartCode { const char* code; };
// The full kart roster, taken from the KartUnlock_<code> analytics names baked into the
// binary (also the codes the seasonal-content cheat walks its own list with).
constexpr KartCode kKartCodes[] = {
    {"AGTR"}, {"ARLR"}, {"BBRN"}, {"BBUG"}, {"BCNT"}, {"BGBM"}, {"BRLR"}, {"CSTR"},
    {"CWGN"}, {"DRLR"}, {"HGRD"}, {"IBLT"}, {"KKYK"}, {"MMBL"}, {"MMKR"}, {"PBKR"},
    {"PBOX"}, {"PNXS"}, {"PTNK"}, {"RRCR"}, {"RSNT"}, {"SCSR"}, {"SHSL"}, {"SOUT"},
    {"STGY"}, {"TBAR"}, {"TTKR"}, {"TTMP"}, {"TTSH"}, {"WWND"},
};

struct UnlockState {
    ElfLoader* abk = nullptr;
    uint32_t unlock_all_episodes = 0;
    uint32_t unlock_kart = 0;
    uint32_t is_kart_owned = 0;
    uint32_t request_save = 0;
    uint32_t cheat_add_gift = 0;
    uint32_t get_ftue_manager = 0;
    uint32_t ftue_complete_all = 0;
    uint32_t str_episode_select = 0;
    uint32_t str_na = 0;
    uint32_t gift_scratch = 0;   // TGift staging for CheatAddActiveGift
    uint32_t tag_scratch = 0;    // UNameTag staging: MakeNameTag is strncpy(dst, src, 5)
    bool ready = false;
};
UnlockState g_u;
std::atomic<bool> g_unlock_pending{false};
std::atomic<bool> g_skip_pending{false};

uint32_t ReadGlobal(DynarmicHost& host, uint32_t vaddr) {
    return host.MemoryRead32(g_u.abk->GetBaseAddress() + vaddr);
}

uint32_t ResolveSym(DynarmicHost& host, const char* mangled, uint32_t fallback_vaddr) {
    if (const uint32_t a = host.FindSymbol(mangled)) return a;
    LOGI("symbol %s not in .dynsym, using libABK+0x%08X", mangled, fallback_vaddr);
    return g_u.abk->GetBaseAddress() + fallback_vaddr;
}

uint32_t AllocGuestString(DynarmicHost& host, const char* s) {
    const uint32_t addr = host.GuestAlloc(strlen(s) + 1, 4);
    memcpy(host.GetGuestMemoryBase() + addr, s, strlen(s) + 1);
    return addr;
}

// --- the two hook actions -------------------------------------------------------------------

// What CSmokeTest::HandleCommandLineArgs does before it touches anything else: the full
// dev unlock. Episodes through the real function, characters/events/tiers through the same
// state writes the smoke test makes, then every kart, then a couple of gifts.
bool TryUnlockAll(DynarmicHost& host) {
    if (!g_u.ready) { LOGE("unlock: not initialised"); return false; }

    const uint32_t P          = ReadGlobal(host, kVaddr.g_p_application);
    const uint32_t app_state  = P ? host.MemoryRead32(P + 52) : 0;
    const uint32_t player     = app_state ? host.MemoryRead32(app_state + 88) : 0;
    if (!player) {
        static uint32_t wait_logs = 0;
        if ((++wait_logs % 120) == 1)
            LOGI("unlock: waiting for CPlayerInfo (g_pApplication=%08X)", P);
        return false;
    }
    LOGI("unlock: playerInfo=0x%08X, running the smoke-test unlock", player);

    // 1. Episodes: the real progression function, the same one the award-bundle path uses.
    host.RunFunctionNested(g_u.unlock_all_episodes, {player});

    // 2. Characters: 14 slots at player+312, stride 40 -- a name-level below 1 means
    // "never picked this character"; the smoke test raises every one to 1.
    for (int i = 0; i < 14; ++i) {
        const uint32_t a = player + 312u + 40u * i;
        if (static_cast<int32_t>(host.MemoryRead32(a)) < 1) host.MemoryWrite32(a, 1);
    }

    // 3. Per-event records the engine treats as "played and starred": state word 3,
    // two progress words 1, and every tier entry 3 / 1 / 10 stars, driven by the
    // episode definition table the same way the smoke test drives it.
    const uint32_t ev_mgr = app_state ? host.MemoryRead32(app_state + 48) : 0;
    if (ev_mgr) {
        const uint32_t ev_count = host.MemoryRead32(ev_mgr + 1456);
        const uint32_t ev_array = host.MemoryRead32(ev_mgr + 1460);
        const uint32_t pstates  = host.MemoryRead32(player + 80);
        if (pstates && ev_array) {
            for (uint32_t i = 0; i < ev_count; ++i) {
                const uint32_t ent      = ev_array + 164u * i;
                const uint32_t tiers    = host.MemoryRead32(ent);
                const uint32_t tc_count = host.MemoryRead32(ent + 4);
                const uint32_t ev_state = host.MemoryRead32(pstates + 20u * i + 12);
                if (!ev_state || tc_count == 0) continue;
                for (uint32_t j = 0; j < tc_count; ++j) {
                    const uint32_t slot = ev_state + 24u * j;
                    uint32_t tier_arr   = host.MemoryRead32(slot + 12);
                    host.MemoryWrite32(slot + 0, 3);
                    host.MemoryWrite32(slot + 4, 1);
                    host.MemoryWrite32(slot + 8, 1);
                    if (!tier_arr) continue;
                    uint32_t n = tiers ? host.MemoryRead32(tiers + 24u * j + 8) : 0;
                    while (n-- > 0) {
                        host.MemoryWrite32(tier_arr + 0, 3);
                        host.MemoryWrite32(tier_arr + 4, 1);
                        host.MemoryWrite32(tier_arr + 16, 10);
                        tier_arr += 56;
                    }
                }
            }
        }
    }
    LOGI("unlock: events and characters done");

    // 4. Karts. UNameTag is strncpy(dst, src, 5) -- a plain code word -- so the tag is
    // staged host-side and passed by value in r1:r2. IsKartOwned first: the engine's own
    // cheat does the same, and a re-press stays a no-op instead of duplicate entries.
    uint32_t unlocked = 0;
    for (const KartCode& k : kKartCodes) {
        uint8_t tag[8] = {};
        strncpy(reinterpret_cast<char*>(tag), k.code, 5);
        memcpy(host.GetGuestMemoryBase() + g_u.tag_scratch, tag, 8);
        const uint32_t lo = host.MemoryRead32(g_u.tag_scratch);
        const uint32_t hi = host.MemoryRead32(g_u.tag_scratch + 4);
        if (!host.RunFunctionNested(g_u.is_kart_owned, {player, lo, hi})) {
            host.RunFunctionNested(g_u.unlock_kart,
                                   {player, lo, hi, 12,                    // 12 = the gain type the engine's own cheat uses
                                    g_u.str_episode_select, 0, 0,
                                    g_u.str_na, 0, 0});
            ++unlocked;
        }
    }
    LOGI("unlock: %u/%zu karts newly unlocked", unlocked,
         sizeof(kKartCodes) / sizeof(kKartCodes[0]));

    // 5. Gifts from CGiftManager::CheatAddActiveGift: 5 lands 50-1000 coins, 6 lands
    // 5-30 gems (the two plain-currency cases in its switch). The gift materialises in
    // the gift box on the map screen, so the button has visible feedback.
    memset(host.GetGuestMemoryBase() + g_u.gift_scratch, 0, 32);
    host.RunFunctionNested(g_u.cheat_add_gift, {g_u.gift_scratch, 5});
    memset(host.GetGuestMemoryBase() + g_u.gift_scratch, 0, 32);
    host.RunFunctionNested(g_u.cheat_add_gift, {g_u.gift_scratch, 6});

    // 6. Save it the normal way.
    const uint32_t save_mgr = app_state ? host.MemoryRead32(app_state + 32) : 0;
    if (save_mgr) host.RunFunctionNested(g_u.request_save, {save_mgr, 0});
    LOGI("unlock: complete, save requested");
    return true;
}

// The connect button is handled outside the guest JIT. Calling the FTUE debug entry point from
// the landing-screen state-change function used to re-enter Dynarmic while its first JIT was
// still active; that made a null/half-built manager turn a harmless button press into a crash.
bool TrySkipTutorial(DynarmicHost& host) {
    if (!g_u.ready) { LOGE("skip-tutorial: not initialised"); return false; }
    if (host.IsJitRunning()) return false;

    const uint32_t mgr = host.RunFunctionNested(g_u.get_ftue_manager, {});
    if (!mgr) return false;

    // Same guard the smoke test uses: an already-completed channel stays completed.
    const uint32_t channel = host.MemoryRead32(mgr + 8);
    if (!channel) return false;
    if (host.MemoryRead32(channel + 4) != 0xFFFFFFFFu) {
        host.RunFunctionNested(g_u.ftue_complete_all, {mgr});   // requests the save itself
        LOGI("skip-tutorial: FTUE channel completed");
    } else {
        LOGI("skip-tutorial: FTUE already complete");
    }
    return true;
}

void InstallNativeRestoreHook(DynarmicHost& host) {
    if (!g_u.abk) return;
    const uint32_t restore_target = host.FindSymbol(kRestorePurchasesSymbol);
    if (!restore_target) {
        LOGE("restore hook: rcs::Payment::restorePurchases is not resolved");
        return;
    }

    host.GetThunkManager().RegisterThunk(
        "ABGO_RestorePurchases",
        [](Dynarmic::A32::Jit&, DynarmicHost&) {
            // This thunk has the native method's void ABI. Do not touch its std::function
            // arguments: they point into guest objects and are intentionally left alone.
            if (AbgoUnlock::kVanillaEconomy) {
                LOGI("native restorePurchases intercepted -> no-op (vanilla economy)");
                return;
            }
            g_unlock_pending.store(true, std::memory_order_release);
            LOGI("native restorePurchases intercepted -> full unlock queued");
        });
    const uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("ABGO_RestorePurchases");
    const uint32_t got = g_u.abk->GetBaseAddress() + kRestorePurchasesGot;
    const uint32_t current = host.MemoryRead32(got);
    if (current != restore_target && current != hook) {
        LOGE("restore hook: GOT 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
             got, current, restore_target);
        return;
    }
    if (current == hook) {
        LOGI("restore hook: native restorePurchases already redirected");
        return;
    }
    host.MemoryWrite32(got, hook);
    host.InvalidateGuestCode(got, 4);
    LOGI("restore hook: native restorePurchases GOT 0x%08X -> thunk 0x%08X",
         got, hook);
}

// --- the hook table --------------------------------------------------------------------------

constexpr int kHookNone = 0;
constexpr int kHookRestorePurchases = 1;   // settings -> Restore IAPs
constexpr int kHookServiceLogin = 2;       // landing -> account connect

std::mutex g_hooks_mutex;
std::unordered_map<uint32_t, int> g_method_hooks;

int HookKindForName(const char* name) {
    if (!name) return kHookNone;
    if (strcmp(name, "restorePurchases") == 0) return kHookRestorePurchases;
    if (strcmp(name, "serviceLogin") == 0) return kHookServiceLogin;
    return kHookNone;
}

}  // namespace

namespace AbgoUnlock {

void Init(DynarmicHost& host) {
    g_u = UnlockState{};
    g_u.abk = host.FindModule("libABK.so");
    if (!g_u.abk) {
        LOGE("unlock: libABK.so is not mapped -- hooks disabled");
        return;
    }
    g_u.unlock_all_episodes = ResolveSym(host, "_ZN11CPlayerInfo17UnlockAllEpisodesEv", kVaddr.unlock_all_episodes);
    g_u.unlock_kart         = ResolveSym(host, "_ZN11CPlayerInfo10UnlockKartE8UNameTag11ETypeOfGainPKcfS3_S3_S3_i", kVaddr.unlock_kart);
    g_u.is_kart_owned       = ResolveSym(host, "_ZNK11CPlayerInfo11IsKartOwnedE8UNameTag", kVaddr.is_kart_owned);
    g_u.request_save        = ResolveSym(host, "_ZN12CSaveManager11RequestSaveEi", kVaddr.request_save);
    g_u.cheat_add_gift      = ResolveSym(host, "_ZN12CGiftManager18CheatAddActiveGiftE9EGiftType", kVaddr.cheat_add_gift);
    g_u.get_ftue_manager    = ResolveSym(host, "_Z14GetFTUEManagerv", kVaddr.get_ftue_manager);
    g_u.ftue_complete_all   = ResolveSym(host, "_ZN12CFTUEManager16DebugCompleteAllEv", kVaddr.ftue_complete_all);

    g_u.str_episode_select = AllocGuestString(host, "EpisodeSelect");
    g_u.str_na             = AllocGuestString(host, "NA");
    g_u.gift_scratch       = host.GuestAlloc(32, 8);
    g_u.tag_scratch        = host.GuestAlloc(8, 8);

    g_u.ready = g_u.unlock_all_episodes && g_u.unlock_kart && g_u.is_kart_owned &&
                g_u.request_save && g_u.cheat_add_gift && g_u.get_ftue_manager &&
                g_u.ftue_complete_all && g_u.str_episode_select && g_u.str_na &&
                g_u.gift_scratch && g_u.tag_scratch;
    LOGI("unlock hooks %s (restore=%s skip-tutorial=%s)",
         g_u.ready ? "armed" : "DISABLED -- missing symbols",
         g_u.unlock_all_episodes ? "ok" : "missing",
         g_u.get_ftue_manager ? "ok" : "missing");
    if (!g_u.ready) return;

    // The shipped Java provider is a no-op and the settings screen calls the native rcs
    // payment object directly, so the Java method-ID hook is not guaranteed to see the click.
    // Arm both the exact native path and a one-shot startup fallback; either way the operation
    // waits until CPlayerInfo exists and runs on the frame-safe side of the bridge.
    InstallNativeRestoreHook(host);
    if (kVanillaEconomy) {
        LOGI("unlock hooks: vanilla economy build -- restore/connect are no-ops, nothing queued");
        return;
    }
    g_unlock_pending.store(true, std::memory_order_release);
    g_skip_pending.store(true, std::memory_order_release);
    LOGI("unlock hooks: frame-safe startup unlock and FTUE skip queued");
}

void OnMethodResolved(uint32_t guest_method_handle, const char* name) {
    const int kind = HookKindForName(name);
    if (kind == kHookNone) return;
    std::lock_guard<std::mutex> lock(g_hooks_mutex);
    g_method_hooks[guest_method_handle] = kind;
    LOGI("intercepting Java method '%s' (handle %u)", name, guest_method_handle);
}

bool RunMethodHook(DynarmicHost& host, uint32_t guest_method_handle) {
    int kind = kHookNone;
    {
        std::lock_guard<std::mutex> lock(g_hooks_mutex);
        const auto it = g_method_hooks.find(guest_method_handle);
        if (it == g_method_hooks.end()) return false;
        kind = it->second;
    }
    // Both hooked methods return void; the vanilla economy build answers them with nothing.
    if (kVanillaEconomy) {
        LOGI("hooked Java method (kind %d) -> no-op (vanilla economy)", kind);
        return true;
    }
    switch (kind) {
        case kHookRestorePurchases:
            LOGI("Restore IAPs pressed -> full unlock queued");
            g_unlock_pending.store(true, std::memory_order_release);
            return true;
        case kHookServiceLogin:
            LOGI("account connect pressed -> FTUE skip queued");
            g_skip_pending.store(true, std::memory_order_release);
            return true;
        default:
            return false;
    }
}

void Tick(DynarmicHost& host) {
    // The vanilla economy build never queues anything and has no adb triggers.
    if (kVanillaEconomy || !g_u.ready || host.IsJitRunning()) return;

    // Pending actions are cheap to test, but must be retried every frame: the first few frames
    // can legitimately have an application object without its player info attached yet.
    if (g_unlock_pending.load(std::memory_order_acquire) && TryUnlockAll(host))
        g_unlock_pending.store(false, std::memory_order_release);
    if (g_skip_pending.load(std::memory_order_acquire) && TrySkipTutorial(host))
        g_skip_pending.store(false, std::memory_order_release);
    static uint32_t property_frames = 0;
    if (++property_frames % 60) return;
    char value[PROP_VALUE_MAX] = {};
    __system_property_get("debug.abgo.unlock", value);
    if (value[0] == '1') {
        __system_property_set("debug.abgo.unlock", "0");
        LOGI("trigger: debug.abgo.unlock=1");
        g_unlock_pending.store(true, std::memory_order_release);
    }
    value[0] = '\0';
    __system_property_get("debug.abgo.skipftue", value);
    if (value[0] == '1') {
        __system_property_set("debug.abgo.skipftue", "0");
        LOGI("trigger: debug.abgo.skipftue=1");
        g_skip_pending.store(true, std::memory_order_release);
    }
}

}  // namespace AbgoUnlock
