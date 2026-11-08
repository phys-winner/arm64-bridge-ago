// Angry Birds Go! 2.9.1 -- ARM64 bridge bootstrap.
//
// Maps and relocates the three guest ELFs, applies runtime fixes, and runs their static
// initialisers. jni_exports_abgo.cpp forwards Java native calls through guest_jnienv.cpp.
//
// Guest load order is gnustl_shared -> SkynestSDK -> ABK, matching what the Java side does
// (AngryBirdsGoActivity.onCreate loads gnustl_shared then SkynestSDK, ExientActivity loads
// ABK). It has to match, because libABK.so and libgnustl_shared.so both export _Znwj /
// _ZdlPv / _Znaj / _ZdaPv and bionic is first-loaded-wins -- get the order wrong and
// allocations land in one heap while frees go to another.

#include <jni.h>
#include <android/log.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "dynarmic_host.h"
#include "elf_loader.h"
#include "guest_jni.h"
#include "thunk_manager.h"
#include "abgo_unlock.h"

#define LOG_TAG "ABGO_BRIDGE"
#include "bridge_log.h"

std::unique_ptr<DynarmicHost> g_host;
static JavaVM* g_vm = nullptr;
static std::string g_apk_path;

extern "C" int IndexApk(const char* apk_path);

// thunk_manager.cpp reaches back for these.
JavaVM* GetHostJavaVM() { return g_vm; }
// ponytail: "Kaamo VIP" is a Galaxy on Fire 2 add-on. ABGo has no equivalent, so the
// thunk_manager call sites stay compiled but always take the disabled branch.
bool IsVipAddonEnabled() { return false; }
void SetVipAddonEnabled(bool) {}

// --- minimal zip reader ---------------------------------------------------------------
// The guest .so files are shipped as STORED entries under assets/, so the inflate path is
// only a fallback for a mis-packed build.
static bool ExtractFromApk(const std::string& apk_path,
                           const std::vector<std::string>& candidates,
                           std::vector<uint8_t>& out) {
    if (apk_path.empty()) return false;
    int fd = open(apk_path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOGE("cannot open APK %s", apk_path.c_str());
        return false;
    }
    struct FdGuard { int fd; ~FdGuard() { close(fd); } } guard{fd};

    const off_t file_len = lseek(fd, 0, SEEK_END);
    if (file_len < 22) return false;

    const off_t search_len = file_len < 65536 + 22 ? file_len : 65536 + 22;
    const off_t search_start = file_len - search_len;
    std::vector<uint8_t> tail(static_cast<size_t>(search_len));
    if (pread(fd, tail.data(), tail.size(), search_start) != static_cast<ssize_t>(tail.size()))
        return false;

    off_t eocd = -1;
    for (ssize_t i = static_cast<ssize_t>(search_len) - 22; i >= 0; --i) {
        if (tail[i] == 0x50 && tail[i + 1] == 0x4b && tail[i + 2] == 0x05 && tail[i + 3] == 0x06) {
            eocd = search_start + i;
            break;
        }
    }
    if (eocd < 0) return false;

    uint8_t hdr[22];
    pread(fd, hdr, sizeof(hdr), eocd);
    uint16_t entries; uint32_t cd_size, cd_off;
    memcpy(&entries, hdr + 10, 2);
    memcpy(&cd_size, hdr + 12, 4);
    memcpy(&cd_off,  hdr + 16, 4);

    std::vector<uint8_t> cd(cd_size);
    if (pread(fd, cd.data(), cd_size, cd_off) != static_cast<ssize_t>(cd_size)) return false;

    uint32_t pos = 0;
    for (uint16_t i = 0; i < entries && pos + 46 <= cd_size; ++i) {
        uint32_t sig; memcpy(&sig, cd.data() + pos, 4);
        if (sig != 0x02014b50) break;
        uint16_t method, fn_len, extra_len, comm_len;
        uint32_t csize, usize, local_off;
        memcpy(&method,    cd.data() + pos + 10, 2);
        memcpy(&csize,     cd.data() + pos + 20, 4);
        memcpy(&usize,     cd.data() + pos + 24, 4);
        memcpy(&fn_len,    cd.data() + pos + 28, 2);
        memcpy(&extra_len, cd.data() + pos + 30, 2);
        memcpy(&comm_len,  cd.data() + pos + 32, 2);
        memcpy(&local_off, cd.data() + pos + 42, 4);
        const std::string name(reinterpret_cast<char*>(cd.data() + pos + 46), fn_len);

        for (const auto& cand : candidates) {
            if (name != cand) continue;
            uint8_t lh[30];
            pread(fd, lh, sizeof(lh), local_off);
            uint16_t l_fn, l_extra;
            memcpy(&l_fn,    lh + 26, 2);
            memcpy(&l_extra, lh + 28, 2);
            const off_t data_off = local_off + 30 + l_fn + l_extra;

            if (method == 0) {
                out.resize(usize);
                if (pread(fd, out.data(), usize, data_off) != static_cast<ssize_t>(usize)) return false;
            } else {
                std::vector<uint8_t> comp(csize);
                if (pread(fd, comp.data(), csize, data_off) != static_cast<ssize_t>(csize)) return false;
                out.resize(usize);
                z_stream zs{};
                if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) return false;
                zs.next_in = comp.data();  zs.avail_in = csize;
                zs.next_out = out.data();  zs.avail_out = usize;
                const int rc = inflate(&zs, Z_FINISH);
                inflateEnd(&zs);
                if (rc != Z_STREAM_END) {
                    LOGE("inflate failed for %s (%d)", name.c_str(), rc);
                    return false;
                }
            }
            LOGI("extracted %s (%u bytes, method %u)", name.c_str(), usize, method);
            return true;
        }
        pos += 46 + fn_len + extra_len + comm_len;
    }
    return false;
}

// ActivityThread.currentApplication().getApplicationInfo().sourceDir
static std::string QueryApkPath(JNIEnv* env) {
    jclass at = env->FindClass("android/app/ActivityThread");
    if (!at) { env->ExceptionClear(); return {}; }
    jmethodID cur = env->GetStaticMethodID(at, "currentApplication", "()Landroid/app/Application;");
    if (!cur) { env->ExceptionClear(); return {}; }
    jobject app = env->CallStaticObjectMethod(at, cur);
    if (!app) { env->ExceptionClear(); return {}; }

    jclass ctx = env->GetObjectClass(app);
    jmethodID gai = env->GetMethodID(ctx, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    jobject info = env->CallObjectMethod(app, gai);
    if (!info) { env->ExceptionClear(); return {}; }

    jclass ai = env->GetObjectClass(info);
    jfieldID src = env->GetFieldID(ai, "sourceDir", "Ljava/lang/String;");
    auto jstr = static_cast<jstring>(env->GetObjectField(info, src));
    if (!jstr) return {};

    const char* c = env->GetStringUTFChars(jstr, nullptr);
    std::string path = c ? c : "";
    env->ReleaseStringUTFChars(jstr, c);
    return path;
}

// --- guest patch: synchronous file IO ---------------------------------------------------
// CXGSFile_Buffered::FillBuffer (libABK 0x63E744) marks a buffer pending and hands the read to
// CXGSFile::ReadAsync; CXGSFile_Buffered::Read (0x63EFAC) then spins on that flag calling
// XGSThread::YieldThread until a CXGSFile_AsyncQueue worker thread clears it. This bridge has
// no guest threads -- pthread_create only records (start_func, arg) -- so the flag never
// clears and the engine wedges on the first CXmlUtil::LoadXmlDocument, with the watchdog
// naming libABK+0x63F0B0, i.e. the instruction after that BL.
//
// The engine already ships the synchronous handler. CXGSFile_AsyncImmediate::ReadAsync
// (0x50E58C) does the Seek+Read inline and calls CXGSAsyncEvent::Complete itself; Complete was
// built with callback-under-lock set, so it runs CXGSFile_Buffered::ReadCallback on the
// calling thread and clears the pending flag before FillBuffer even returns. CXGSFile_ROM uses
// it already (GetAsyncHandler -> &g_tXGSFile_AsyncImmediate).
//
// Both classes implement the same IXGSFileAsyncHandler vtable, so redirecting the queue's
// ReadAsync/WriteAsync slots covers every filesystem that asks for the async queue -- POSIX,
// Network, ZLib, LZ4 -- in two words, with no thread scheduler and no second Jit. The queue
// object is still constructed and still owns its own destructor slots; only the two dispatch
// entries move.
static void PatchGuestSyncFileIO(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("sync-file-io patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();

    // vtable of CXGSFile_AsyncQueue starts at 0xD903A8 (slot 0/1 = destructors).
    struct Slot {
        const char* name;
        uint32_t vtable_entry;   // file vaddr of the vtable slot
        uint32_t expect;         // file vaddr the slot must currently hold
        uint32_t want;           // file vaddr of the CXGSFile_AsyncImmediate implementation
    };
    static const Slot kSlots[] = {
        {"ReadAsync",  0xD903B0, 0x50E994, 0x50E58C},
        {"WriteAsync", 0xD903B4, 0x50EDA0, 0x50E648},
    };

    // Verify every slot before touching any of them, so a layout mismatch cannot leave the
    // vtable half-patched (same rule as patch_offline.py: check the opcode, then write).
    for (const Slot& s : kSlots) {
        const uint32_t cur = host.MemoryRead32(base + s.vtable_entry);
        if (cur != base + s.expect) {
            LOGE("sync-file-io patch: CXGSFile_AsyncQueue::%s slot at 0x%08X holds 0x%08X, "
                 "expected 0x%08X -- patch skipped entirely",
                 s.name, base + s.vtable_entry, cur, base + s.expect);
            return;
        }
    }
    for (const Slot& s : kSlots) {
        host.MemoryWrite32(base + s.vtable_entry, base + s.want);
        LOGI("sync-file-io patch: CXGSFile_AsyncQueue::%s -> CXGSFile_AsyncImmediate::%s "
             "(0x%08X = 0x%08X)", s.name, s.name, base + s.vtable_entry, base + s.want);
    }
}

// --- guest patch: skip the Skynest half of the game update ------------------------------
// CBasicDownloadScreen parks on "CHECKING_UPDATE_AVAILABLE" until somebody calls its
// OnGameUpdateComplete, and with CGameUpdater_Skynest in the way nobody ever does.
// CGameUpdater_Skynest::DownloadUpdate (0x283B88) hands the work to
// SkynestDownloadUpdateThread, whose first act is CGameUpdater_Skynest::GetSkynestMetadata --
// which posts an asynchronous metadata request to libSkynestSDK and then waits for
// libSkynestSDK's *own* pthreads to answer. Those threads do not exist here (pthread_create
// only records its arguments), so the wait never ends: the watchdog catches it spinning on
// gettimeofday inside libSkynestSDK+0x411DC8, six seconds deep, and airplane mode makes no
// difference because the wait is on a thread, not on a socket.
//
// The engine already ships the non-Skynest route and even keeps a named entry point for it:
// CGameUpdater_Skynest::RunSkynestBaseDownloadUpdate (0x288E88) is one instruction, a branch
// straight to CXGSGameUpdater::DownloadUpdate. That implementation is synchronous where it
// matters -- with no connection it calls the listener's OnGameUpdateComplete on the spot, and
// with one it posts a CXGSJob, which the job pump runs. Either way the screen gets its
// callback and CBasicDownloadScreen::ms_bDownloadComplete gets set.
//
// The vtable pointer stored in the object is &_ZTV20CGameUpdater_Skynest + 8, so slot 3 --
// the one CBasicDownloadScreen::Process calls as `updater->vtable[12]` -- is at 0xD85954.
static void PatchGuestSkipSkynestUpdate(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("skynest-update patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kSlot   = 0xD85954;   // CGameUpdater_Skynest vtable, DownloadUpdate
    constexpr uint32_t kExpect = 0x283B88;   // CGameUpdater_Skynest::DownloadUpdate
    constexpr uint32_t kWant   = 0x288E88;   // CGameUpdater_Skynest::RunSkynestBaseDownloadUpdate

    const uint32_t cur = host.MemoryRead32(base + kSlot);
    if (cur != base + kExpect) {
        LOGE("skynest-update patch: slot at 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
             base + kSlot, cur, base + kExpect);
        return;
    }
    host.MemoryWrite32(base + kSlot, base + kWant);
    LOGI("skynest-update patch: CGameUpdater_Skynest::DownloadUpdate -> "
         "RunSkynestBaseDownloadUpdate (0x%08X = 0x%08X)", base + kSlot, base + kWant);
}

// --- guest patch: no Skynest cloud-asset metadata ----------------------------------------
// The last thing holding the boot on CBasicDownloadScreen. CApp::ProcessFrame leaves its
// state 2 either straight to state 4 (tear the screen down, BeginLoad(CoreLoadingFunc)) or
// into state 3, and state 3 only ever ends through the GDPR dialog's fade -- which needs a
// dialog that only appears with a live Skynest session. The 2 -> 4 shortcut is the normal
// path, and it is taken when CBasicDownloadScreen's "forced update checked" word is set, which
// happens when CLiveUpdateManager::CheckForForcedUpdateBlocker's callback runs.
//
// That callback comes from CCloudAssetManager::LoadMetaData, which has exactly two branches:
//     if (m_pSkynestAssets) { rcs::Assets::loadMetadata(...); return; }   // async, never
//     onFailure(names, {}, -1, "Skynest Assets Pointer Invalid");         // synchronous
// The async branch posts the request into libSkynestSDK and waits for libSkynestSDK's own
// pthreads to answer it; those do not exist under the bridge, so the callback never fires and
// the boot sits on the loading screen forever. The synchronous branch is the engine's own
// no-cloud path: CLiveUpdateManager::ForcedUpdateMetadataFailure sets exactly the same flag
// ForcedUpdateSet would have, so the boot continues with the packaged assets.
//
// One instruction: load of m_pSkynestAssets -> constant 0, so the CMP that follows always
// takes the synchronous branch. Narrower than disabling CCloudAssetManager::Initialise, and
// aimed at the one call that measurably hangs.
static void PatchGuestNoCloudMetadata(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("cloud-metadata patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kSite   = 0x273558;      // CCloudAssetManager::LoadMetaData + 8
    constexpr uint32_t kExpect = 0xE590C004;    // LDR  R12, [R0,#4]
    constexpr uint32_t kWant   = 0xE3A0C000;    // MOV  R12, #0

    const uint32_t cur = host.MemoryRead32(base + kSite);
    if (cur != kExpect) {
        LOGE("cloud-metadata patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
             base + kSite, cur, kExpect);
        return;
    }
    host.MemoryWrite32(base + kSite, kWant);
    host.InvalidateGuestCode(base + kSite, 4);
    LOGI("cloud-metadata patch: CCloudAssetManager::LoadMetaData always reports "
         "\"Skynest Assets Pointer Invalid\" (0x%08X)", base + kSite);
}

// --- guest patch: no Skynest GDPR/TOS dialogs -------------------------------------------
// CXGSFE_SplashScreen::Process only moves on to "FrontendLoadingScreen" when
// CSkynestGDPRDialogs::CheckAndShowDialog() is true, and that is `ms_ptInstance[+16] == 3`,
// i.e. "every consent question has been answered". CheckAndInit computes it from the TOS and
// consent sub-states at +24 and +28, and both sit at 1 -- "asked, waiting" -- because the
// answer comes from a Skynest session that does not exist here. Measured on the device: the
// splash screen holds forever with `gdpr dlg=0 [+24]=1 [+28]=1`.
//
// Both entry points open with the same line: `if (!ms_ptInstance) ...` -- CheckAndShowDialog
// returns 1 and CheckAndInit does nothing. A null instance is the engine's own way of saying
// "this build has no consent subsystem", which for a restoration with no Skynest backend is
// simply true. So drop the one store that publishes the singleton; the object is still
// constructed, just never registered, and the six functions that touch ms_ptInstance all
// null-check it (the two popup callbacks can only run after a popup was shown).
static void PatchGuestNoGdprDialogs(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("gdpr patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kSite   = 0x3D978C;   // CSkynestGDPRDialogs::CSkynestGDPRDialogs + 0x58
    constexpr uint32_t kExpect = 0xE5820000; // STR  R0, [R2]   (ms_ptInstance = this)
    constexpr uint32_t kWant   = 0xE1A00000; // MOV  R0, R0     (nop)

    const uint32_t cur = host.MemoryRead32(base + kSite);
    if (cur != kExpect) {
        LOGE("gdpr patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
             base + kSite, cur, kExpect);
        return;
    }
    host.MemoryWrite32(base + kSite, kWant);
    host.InvalidateGuestCode(base + kSite, 4);
    LOGI("gdpr patch: CSkynestGDPRDialogs::ms_ptInstance stays null (0x%08X)", base + kSite);
}

// --- guest patch: the frontend's screen event must not be thrown away ---------------------
// The frontend is opened by an event, not by a call. CApp::FrontendLoadingFunc finishes and
// sends UI::CManager::SendStateChange(nullptr, "landingScreen"); the coordinator's listener
// finds "landingScreen" in its state->event table and pushes a clone onto the queue at
// coordinator+32. GameUI::CGameUICoordinator::Process then pops the head event *first* and only
// afterwards asks whether it may run it:
//
//     STR R3, [R0,#0x24]        ; count = count - 1   <- the pop is already committed
//     LDR R2, [R3,#0xCC]        ; CGame::m_ePendingState
//     ... if (pending != 0 && pending != 10 && pending != 3) -> return, event destroyed
//
// so an event that arrives while a CGame state change is pending is silently dropped. On the
// device that window is a fraction of a frame, because FrontendLoadingFunc runs on a worker
// thread and finishes long before the main thread requests FrontendLoading -> Frontend. Here it
// is a job the pump runs *inside* a frame (see guest_jobs.cpp), so it lands in the middle of
// that transition every time. Measured: "queue=1 CGame state=1 pending=2" on the frame the
// event is posted, "queue=0 CGame state=2 pending=0" ~98 ms later -- popped and discarded,
// which is exactly the black frontend: everything else about GameUI is verifiably fine, and
// calling GotoScreen("CLandingScreen") by hand draws the screen in full.
//
// One opcode: read 0 instead of the pending state, so a dequeued event is always processed
// rather than dropped. This does not change *which* events exist or their order, only that the
// engine stops discarding one it already committed to removing.
static void PatchGuestKeepUIEvents(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("ui-event patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kSite   = 0x3B7974;   // GameUI::CGameUICoordinator::Process + 0x68
    constexpr uint32_t kExpect = 0xE59320CC; // LDR  R2, [R3,#0xCC]
    constexpr uint32_t kWant   = 0xE3A02000; // MOV  R2, #0

    const uint32_t cur = host.MemoryRead32(base + kSite);
    if (cur != kExpect) {
        LOGE("ui-event patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
             base + kSite, cur, kExpect);
        return;
    }
    host.MemoryWrite32(base + kSite, kWant);
    host.InvalidateGuestCode(base + kSite, 4);
    LOGI("ui-event patch: CGameUICoordinator::Process runs dequeued events regardless of "
         "CGame's pending state (0x%08X)", base + kSite);
}

// --- guest patch: the periodic cloud save must not spin forever ---------------------------
// About a minute into the frontend the engine posts CIdentityManager::SaveToCloud_Callback as a
// job, and CCloudSaveManager::SaveToCloud hands the save block to rcs::Storage::set in
// libSkynestSDK and then waits for the answer:
//
//     ms_iSetResult = 1;
//     rcs::Storage::set(..., CloudSetSuccessCalback, CloudSetFailCalback, ...);
//     while (ms_iSetResult == 1) XGSThread::SleepThread(1);
//
// Only a Skynest callback moves that word, and there is no Skynest session here, so the job
// never returns. Because the job pump runs jobs inside a frame, the whole render loop stops
// with it: measured as frames ending at exactly 7200 in every run long enough to reach it --
// including the ones from before this session, so this is old and simply never diagnosed. No
// crash, no watchdog line (the guest is sleeping, not looping), just a surface that stops
// committing buffers while the process stays alive.
//
// The engine already ships the offline branch, guarded by a debug flag:
//
//     if (CDebugManager::GetDebugBool(142)) CloudSetFailCalback(name, 3);   // synchronous
//     else                                  rcs::Storage::set(...);        // asynchronous
//
// and CloudSetFailCalback just sets ms_iSetResult = 3, which the code after the wait already
// handles as "cloud save failed, carry on". Flag 142 is CCloudSaveManager's own "there is no
// cloud storage here" switch: every one of its eight call sites picks between a Skynest round
// trip and a synchronous local answer, and all eight sit in that one class. Patching only the
// one in SaveToCloud was not enough -- SaveToCloud calls CheckForSaveConflict first, which
// spins on ms_iCheckForConflictResult in exactly the same way (measured: the spin detector
// named libABK+0x20AB6C). So take the offline branch at all eight, the way the ARM32 build
// handles Block_Low_CC_Kart and the fps caps: patch the call sites, never the flag array --
// SetDefaults fills that from XML at runtime and any static edit is overwritten.
static void PatchGuestNoCloudSave(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("cloud-save patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kWant = 0xE3A00001;   // MOV R0, #1
    // Every `MOV R0,#0x8E; BL CDebugManager::GetDebugBool` in the image, with the BL word each
    // site actually holds (they differ: the branch offset is relative).
    struct Site { uint32_t vaddr, expect; const char* fn; };
    static constexpr Site kSites[] = {
        {0x209BC0, 0xEB02B2D4, "LoadXMLFromCloud"},
        {0x20A920, 0xEB02AF7C, "CheckForSaveConflict"},
        {0x20B4B4, 0xEB02AC97, "CheckForSaveConflict"},
        {0x20B834, 0xEB02ABB7, "CheckForSaveConflict"},
        {0x20BCA0, 0xEB02AA9C, "SaveToCloud"},
        {0x20C76C, 0xEB02A7E9, "MigrateFromCloudSave"},
        {0x20D170, 0xEB02A568, "AccountHasProgress"},
        {0x20DA8C, 0xEB02A321, "CloudConflictCheckFailCallback"},
    };
    int done = 0;
    for (const Site& s : kSites) {
        const uint32_t cur = host.MemoryRead32(base + s.vaddr);
        if (cur != s.expect) {
            LOGE("cloud-save patch: 0x%08X (%s) holds 0x%08X, expected 0x%08X -- skipped",
                 base + s.vaddr, s.fn, cur, s.expect);
            continue;
        }
        host.MemoryWrite32(base + s.vaddr, kWant);
        host.InvalidateGuestCode(base + s.vaddr, 4);
        ++done;
    }
    LOGI("cloud-save patch: %d/%zu CCloudSaveManager sites take the synchronous "
         "\"no cloud storage\" branch", done, sizeof(kSites) / sizeof(kSites[0]));
}

// Energy is the free-to-play meter that gates starting a race: 5 for a daily, 20 for a
// campaign event, one point back every four minutes, and it was written to be topped up with
// gems or a rewarded advert. Neither of those works here -- the gem refill goes through
// Skynest and the advert needs the ad SDK, both of which this bridge answers offline -- so an
// empty meter is a dead end that no amount of playing can clear.
//
// GameUI::CMapScreenContextualPanel::GotoEvent is the single gate: it asks
// CPlayerInfo::GetRaceEnergyCost and then
//
//     if (!CEnergySystem::SpendEnergy(..., cost)) return 3;   // 3 == "out of energy" popup
//
// and CResultsScreen calls the same function for a restart. Patch the callee, not the four
// call sites: every one of them treats a nonzero return as "paid", so a function that always
// answers 1 and spends nothing removes the meter everywhere at once and leaves the counter,
// its recharge timer and the shop UI untouched.
static void PatchGuestFreeEnergy(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("energy patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    // _ZN13CEnergySystem11SpendEnergyEi, ARM, at +0xE46A8.
    struct Word { uint32_t vaddr, expect, want; const char* what; };
    static constexpr Word kWords[] = {
        {0xE46A8, 0xE92D4FF0, 0xE3A00001, "PUSH {R4-R11,LR} -> MOV R0, #1"},
        {0xE46AC, 0xE1A04000, 0xE12FFF1E, "MOV R4, R0 -> BX LR"},
    };
    for (const Word& w : kWords) {
        const uint32_t cur = host.MemoryRead32(base + w.vaddr);
        if (cur != w.expect) {
            LOGE("energy patch: 0x%08X holds 0x%08X, expected 0x%08X (%s) -- skipped",
                 base + w.vaddr, cur, w.expect, w.what);
            return;                       // half a patched prologue is worse than none
        }
    }
    for (const Word& w : kWords) {
        host.MemoryWrite32(base + w.vaddr, w.want);
        host.InvalidateGuestCode(base + w.vaddr, 4);
    }
    LOGI("energy patch: CEnergySystem::SpendEnergy always succeeds -- races cost no energy");
}

// The landing screen's "returning player" button normally runs CIdentityManager::IsLoggedIn
// and, with no Skynest session here, enters an offline identity path that leaves the picture
// unchanged. The new-player branch already contains the complete offline-safe transition to
// GameplayLoading, so route the connect button through that existing path. FTUE completion is
// still queued and executed by AbgoUnlock::Tick outside the active guest JIT.
static void PatchGuestConnectToGameplay(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("connect patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kBranch = 0x4518F8;       // CLandingScreen::OnStateChange, connect branch
    constexpr uint32_t kGameplayPath = 0x4517E0; // the function's new-player gameplay path

    // The four instructions being replaced (CLandingScreen::OnStateChange + 0x168).
    static constexpr uint32_t kExpect[] = {0xE59F3068, 0xE7943003, 0xE5933000, 0xE593404C};
    for (size_t i = 0; i < std::size(kExpect); ++i) {
        const uint32_t cur = host.MemoryRead32(base + kBranch + 4u * i);
        if (cur != kExpect[i]) {
            LOGE("connect patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
                 static_cast<uint32_t>(base + kBranch + 4u * i), cur, kExpect[i]);
            return;
        }
    }

    const int32_t diff = static_cast<int32_t>(kGameplayPath - (kBranch + 8));
    const uint32_t branch_to_gameplay =
        0xEA000000u | (static_cast<uint32_t>(diff >> 2) & 0x00FFFFFFu);
    const uint32_t stub[4] = {
        branch_to_gameplay,
        0xE1A00000,                 // NOP; unreachable after the branch
        0xE1A00000,                 // NOP; unreachable after the branch
        0xE1A00000,                 // NOP; unreachable after the branch
    };
    for (size_t i = 0; i < 4; ++i) {
        host.MemoryWrite32(base + kBranch + 4u * i, stub[i]);
        host.InvalidateGuestCode(base + kBranch + 4u * i, 4);
    }
    LOGI("connect patch: landing CONNECT branch now enters GameplayLoading; "
         "FTUE completion is frame-safe");
}

// The settings screen exposes the same offline-unusable account action as the
// "Подключиться" button: its LoginRovio branch starts CIdentityManager::BeginTask,
// which has no completion path when the backend is intentionally unavailable.  The
// map is already the playable main page behind this modal, so reuse the engine's own
// dismiss-settings event and return there immediately.  This also makes the Rovio
// Account fallback deterministic without entering the identity task machinery.
static void PatchGuestSettingsConnectOffline(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("settings-connect patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kDismissPath = 0x41D7AC; // existing dismissSettingsScreen path
    struct Site { const char* name; uint32_t vaddr; uint32_t expect; };
    static constexpr Site kSites[] = {
        {"LoginRovio",   0x41D9A4, 0xE59F368C}, // LDR R3, [PC,#0x368C]
        {"LoginFacebook",0x41DA50, 0xE59F35E0}, // LDR R3, [PC,#0x35E0]
    };

    for (const Site& site : kSites) {
        const uint32_t cur = host.MemoryRead32(base + site.vaddr);
        if (cur != site.expect) {
            LOGE("settings-connect patch: %s at 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
                 site.name, base + site.vaddr, cur, site.expect);
            return;
        }
    }

    for (const Site& site : kSites) {
        const int32_t diff = static_cast<int32_t>(kDismissPath - (site.vaddr + 8));
        const uint32_t branch_to_dismiss =
            0xEA000000u | (static_cast<uint32_t>(diff >> 2) & 0x00FFFFFFu);
        host.MemoryWrite32(base + site.vaddr, branch_to_dismiss);
        host.InvalidateGuestCode(base + site.vaddr, 4);
    }
    LOGI("settings-connect patch: LoginFacebook and LoginRovio now return to the main game page "
         "through dismissSettingsScreen");
}

// CSettingsScreen::OnRestorePurchasesSelected performs two payment-provider checks before it
// ever reaches the native restore call. With networking deliberately disabled, that code only
// raises INTERNET_ERR_NO_CONNECTION. The payment manager already has the exact success handler
// used by a real restore; call it after the method's existing setup has loaded the manager into
// R0. It emits RestoreComplete and updates the manager state, while the arm64 bridge's deferred
// unlock has already made the content local and persistent.
static void PatchGuestRestoreOffline(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("restore UI patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kSite = 0x41E50C;       // after existing payment-manager load
    constexpr uint32_t kRestoreDone = 0x29A240; // CSkynestPaymentManager::onRestoreDone

    // Original instructions at kSite: load the payment-manager vtable, call IsSupported and
    // branch to the network/restricted error popup. The preceding instructions leave R0 as the
    // payment-manager object and establish the original stack frame/callee-saved registers.
    static constexpr uint32_t kExpect[] = {
        0xE5903000, // LDR R3, [R0]
        0xE593301C, // LDR R3, [R3,#0x1C]
        0xE12FFF33, // BLX R3
        0xE250C000, // SUBS R12, R0, #0
    };
    for (size_t i = 0; i < std::size(kExpect); ++i) {
        const uint32_t cur = host.MemoryRead32(base + kSite + 4u * i);
        if (cur != kExpect[i]) {
            LOGE("restore UI patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
                 static_cast<uint32_t>(base + kSite + 4u * i), cur, kExpect[i]);
            return;
        }
    }

    const int32_t diff = static_cast<int32_t>(kRestoreDone - (kSite + 8));
    const uint32_t call_restore_done =
        0xEB000000u | (static_cast<uint32_t>(diff >> 2) & 0x00FFFFFFu);
    const uint32_t stub[4] = {
        call_restore_done,          // BL CSkynestPaymentManager::onRestoreDone
        0xE3A00001,                 // MOV R0, #1
        0xE28DD01C,                 // ADD SP, SP, #0x1C
        0xE8BD8030,                 // POP {R4,R5,PC}
    };
    for (size_t i = 0; i < std::size(stub); ++i) {
        host.MemoryWrite32(base + kSite + 4u * i, stub[i]);
        host.InvalidateGuestCode(base + kSite + 4u * i, 4);
    }
    // The settings button normally reaches the same payment checks through
    // CSettingsScreen::HandleStateChange("RestorePurchasesSelected").  The
    // callback above is a legacy entry point and is not the path used by the
    // current XML behaviour, so patch that real branch as well.
    constexpr uint32_t kStateSite = 0x41DBD0;
    constexpr uint32_t kRestoreSuccess = 0x167F10; // CShopManager::ShowRestoreDialog(0)
    static constexpr uint32_t kStateExpect[] = {
        0xE12FFF33, // BLX R3: provider support check
        0xE250C000, // SUBS R12, R0, #0
        0x0A000079, // BEQ restricted/error path
    };
    for (size_t i = 0; i < std::size(kStateExpect); ++i) {
        const uint32_t cur = host.MemoryRead32(base + kStateSite + 4u * i);
        if (cur != kStateExpect[i]) {
            LOGE("restore state patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
                 static_cast<uint32_t>(base + kStateSite + 4u * i), cur, kStateExpect[i]);
            return;
        }
    }

    const int32_t state_call_diff = static_cast<int32_t>(kRestoreSuccess - (kStateSite + 4 + 8));
    const int32_t state_return_diff = static_cast<int32_t>(0x41D508 - (kStateSite + 12 + 8));
    const uint32_t state_stub[] = {
        0xE3A00000, // MOV R0, #0: ERestoreReturn::Restored
        0xEB000000u | (static_cast<uint32_t>(state_call_diff >> 2) & 0x00FFFFFFu),
        0xE3A03001, // MOV R3, #1: common handler return value
        0xEA000000u | (static_cast<uint32_t>(state_return_diff >> 2) & 0x00FFFFFFu),
    };
    for (size_t i = 0; i < std::size(state_stub); ++i) {
        host.MemoryWrite32(base + kStateSite + 4u * i, state_stub[i]);
        host.InvalidateGuestCode(base + kStateSite + 4u * i, 4);
    }
    LOGI("restore UI patch: offline Restore shows the standard success popup; "
         "network error paths bypassed");
}

// Save migration state 0 opens the one-time "Welcome Back" popup.  The content has already
// been awarded locally by the arm64 unlock bridge, and this popup is a stale migration UX
// that otherwise reappears on every offline entry.  Returning from the tiny popup wrapper
// lets CSaveMigrationData::PopupReward advance its state machine and persist the migration.
static void PatchGuestHideWelcomeBack(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("welcome-back patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kSite = 0x3C96D8;       // CPopupManager::PopupMigrationWelcome
    constexpr uint32_t kExpect = 0xE52DE004;  // PUSH {LR}
    constexpr uint32_t kWant = 0xE12FFF1E;    // BX LR
    const uint32_t cur = host.MemoryRead32(base + kSite);
    if (cur != kExpect) {
        LOGE("welcome-back patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
             base + kSite, cur, kExpect);
        return;
    }
    host.MemoryWrite32(base + kSite, kWant);
    host.InvalidateGuestCode(base + kSite, 4);
    LOGI("welcome-back patch: migration Welcome Back popup disabled");
}

// CPopupManager::PopupLanding is the recurring landing-screen daily-races welcome popup.  It
// is separate from both the migration popup and the map FTUE path, so disabling only those two
// still leaves this exact "WELCOME BACK" dialog on every cold start in the offline build.
static void PatchGuestDisableLandingPopup(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("landing-popup patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kSite = 0x3CBE6C;       // CPopupManager::PopupLanding
    constexpr uint32_t kExpect = 0xE92D40F0;  // PUSH {R4-R7,LR}
    constexpr uint32_t kWant = 0xE12FFF1E;    // BX LR
    const uint32_t cur = host.MemoryRead32(base + kSite);
    if (cur != kExpect) {
        LOGE("landing-popup patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
             base + kSite, cur, kExpect);
        return;
    }
    host.MemoryWrite32(base + kSite, kWant);
    host.InvalidateGuestCode(base + kSite, 4);
    LOGI("landing-popup patch: recurring daily-races WELCOME BACK popup disabled");
}

// CMapScreen::UpdateFTUE is the other source of the WELCOME_BACK_TITLE popup.  The bridge
// completes FTUE and unlocks all local content during startup; leaving this stale map-side
// tutorial loop active makes it show a daily-races welcome screen on every entry offline.
static void PatchGuestDisableMapFtue(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("map-ftue patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kSite = 0x3EFC60;       // CMapScreen::UpdateFTUE
    constexpr uint32_t kExpect = 0xE92D4FF0;  // PUSH {R4-R11,LR}
    constexpr uint32_t kWant = 0xE12FFF1E;    // BX LR
    const uint32_t cur = host.MemoryRead32(base + kSite);
    if (cur != kExpect) {
        LOGE("map-ftue patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
             base + kSite, cur, kExpect);
        return;
    }
    host.MemoryWrite32(base + kSite, kWant);
    host.InvalidateGuestCode(base + kSite, 4);
    LOGI("map-ftue patch: recurring WELCOME_BACK_TITLE tutorial popup disabled");
}

// Keep the guard at the popup boundary too.  The map update can enqueue the first FTUE
// request while the screen is being assembled; suppressing PopupFTUEText itself guarantees
// that a queued or alternate FTUE state cannot recreate the welcome overlay on a later entry.
static void PatchGuestDisableFtuePopups(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("ftue-popup patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kSite = 0x3CA688;       // CPopupManager::PopupFTUEText
    constexpr uint32_t kExpect = 0xE92D4FF0;  // PUSH {R4-R11,LR}
    constexpr uint32_t kWant = 0xE12FFF1E;    // BX LR
    const uint32_t cur = host.MemoryRead32(base + kSite);
    if (cur != kExpect) {
        LOGE("ftue-popup patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
             base + kSite, cur, kExpect);
        return;
    }
    host.MemoryWrite32(base + kSite, kWant);
    host.InvalidateGuestCode(base + kSite, 4);
    LOGI("ftue-popup patch: all FTUE text popups disabled");
}

// CApp::FrontendLoadingFunc, tutorial branch: after it has set up the next FTUE event it waits
// for the front end before asking for that race --
//
//     while (!CXGSFE_LandingScreen::ms_bLandingScreenActive) XGSThread::SleepThread(10);
//     game->RequestStateChange_FrontendToGameplayLoading();
//
// The flag is set by CXGSFE_LandingScreen::Process, i.e. by a frame. On the device this job
// runs on a loader thread while the render thread keeps drawing; here the job pump runs it
// inside a frame (guest_jobs.cpp), so the frame that would set the flag is the frame the loop
// blocks. Measured with stock progression: the first tutorial race ends, CGame goes 9 -> 1 and
// the guest spins at libABK+0x26C838 for good. The full mod completes the FTUE at startup and
// never takes this branch. Drop the wait: the request only stores CGame::m_ePendingState = 3,
// which the state machine picks up when front-end loading ends -- what Play does on the
// landing screen.
static void PatchGuestFtueFrontendWait(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("ftue-wait patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kSite = 0x26C840;       // BEQ back to the SleepThread(10) call
    constexpr uint32_t kExpect = 0x0AFFFFFA;  // BEQ 0x26C830
    constexpr uint32_t kWant = 0xE320F000;    // NOP
    const uint32_t cur = host.MemoryRead32(base + kSite);
    if (cur != kExpect) {
        LOGE("ftue-wait patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
             base + kSite, cur, kExpect);
        return;
    }
    host.MemoryWrite32(base + kSite, kWant);
    host.InvalidateGuestCode(base + kSite, 4);
    LOGI("ftue-wait patch: tutorial front-end load requests the next race without waiting "
         "for a frame (0x%08X)", base + kSite);
}

// CIdentityManager::AutoIdentityLogin (libABK+0x215C18) is the boot-time attempt to
// auto-login the Rovio account. Offline it goes down a path that throws a C++ exception,
// and exceptions cannot work under this bridge (EHABI unwinding is stubbed): the throw
// degrades into terminate/abort UB and a spam of abort() from the guest. The attempt is
// meaningless without a backend, so the function simply returns; the caller stores its
// own "no identity" state and boot proceeds exactly as it does on a failed login.
static void PatchGuestSkipAutoIdentityLogin(DynarmicHost& host) {
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) {
        LOGE("auto-identity patch: libABK.so is not mapped -- skipped");
        return;
    }
    const uint32_t base = abk->GetBaseAddress();
    constexpr uint32_t kSite  = 0x215C18;      // CIdentityManager::AutoIdentityLogin
    constexpr uint32_t kExpect = 0xE59F3DC8;   // ldr r3, [pc, #0xdc8]  (GOT load)
    constexpr uint32_t kWant   = 0xE12FFF1E;   // bx lr

    const uint32_t cur = host.MemoryRead32(base + kSite);
    if (cur != kExpect) {
        LOGE("auto-identity patch: 0x%08X holds 0x%08X, expected 0x%08X -- skipped",
             base + kSite, cur, kExpect);
        return;
    }
    host.MemoryWrite32(base + kSite, kWant);
    host.InvalidateGuestCode(base + kSite, 4);
    LOGI("auto-identity patch: CIdentityManager::AutoIdentityLogin returns immediately "
         "(0x%08X)", base + kSite);
}

static bool BootGuest(JNIEnv* env) {
    if (g_host) return true;

    g_apk_path = QueryApkPath(env);
    if (g_apk_path.empty()) {
        LOGE("could not determine APK path");
        return false;
    }
    LOGI("APK: %s", g_apk_path.c_str());
    IndexApk(g_apk_path.c_str());

    // Load order is load-bearing -- see the header comment.
    struct Want { const char* name; std::vector<std::string> candidates; };
    const Want wanted[] = {
        {"libgnustl_shared.so", {"assets/libgnustl_shared.so", "lib/armeabi-v7a/libgnustl_shared.so"}},
        {"libSkynestSDK.so",    {"assets/libSkynestSDK.so",    "lib/armeabi-v7a/libSkynestSDK.so"}},
        {"libABK.so",           {"assets/libABK.so",           "lib/armeabi-v7a/libABK.so"}},
    };

    // Buffers must outlive LoadModulesFromMemory.
    std::vector<std::vector<uint8_t>> blobs(std::size(wanted));
    std::vector<DynarmicHost::GuestModuleImage> images;
    for (size_t i = 0; i < std::size(wanted); ++i) {
        if (!ExtractFromApk(g_apk_path, wanted[i].candidates, blobs[i])) {
            LOGE("guest module %s not found in APK", wanted[i].name);
            return false;
        }
        images.push_back({wanted[i].name, blobs[i].data(), blobs[i].size()});
    }

    g_host = std::make_unique<DynarmicHost>();
    if (!g_host->Initialize()) {
        LOGE("DynarmicHost::Initialize failed");
        g_host.reset();
        return false;
    }
    // Before the modules, because their static initialisers already run guest code and any of
    // them may reach for JNI. Without this the guest keeps the stub table from
    // ThunkManager::SetupGuestJNIEnv, where FindClass always answers 0x3000.
    InstallGuestJNIEnv(*g_host);

    LOGI("host initialised, mapping %zu guest modules...", images.size());

    if (!g_host->LoadModulesFromMemory(images)) {
        LOGE("guest module load failed");
        g_host.reset();
        return false;
    }

    PatchGuestSyncFileIO(*g_host);
    PatchGuestSkipSkynestUpdate(*g_host);
    PatchGuestNoCloudMetadata(*g_host);
    PatchGuestNoGdprDialogs(*g_host);
    PatchGuestKeepUIEvents(*g_host);
    PatchGuestNoCloudSave(*g_host);
    // The vanilla economy build (abgo_unlock.h) keeps the stock energy meter and the stock
    // Restore IAPs answer, and it plays the tutorial from the start, so the map-side FTUE
    // driver and its text popups have to stay too.
    if (!AbgoUnlock::kVanillaEconomy) PatchGuestFreeEnergy(*g_host);
    PatchGuestConnectToGameplay(*g_host);
    PatchGuestSettingsConnectOffline(*g_host);
    if (!AbgoUnlock::kVanillaEconomy) PatchGuestRestoreOffline(*g_host);
    PatchGuestHideWelcomeBack(*g_host);
    PatchGuestDisableLandingPopup(*g_host);
    if (!AbgoUnlock::kVanillaEconomy) {
        PatchGuestDisableMapFtue(*g_host);
        PatchGuestDisableFtuePopups(*g_host);
    }
    PatchGuestFtueFrontendWait(*g_host);
    PatchGuestSkipAutoIdentityLogin(*g_host);

    // Stage the Restore-IAPs / connect-button hooks: symbol resolution and the guest
    // strings they hand to the engine's own cheat functions.
    AbgoUnlock::Init(*g_host);

    // libSkynestSDK.so exports JNI_OnLoad and that is where it caches the JavaVM. On a real
    // device the runtime calls it as part of System.loadLibrary; here the runtime only ever
    // sees the bridge, so nobody called it and Skynest's VM pointer stayed null -- which shows
    // up much later as java::jni::getJNIEnv dispatching through *(nullptr + 24) and jumping to
    // guest address 0 in the middle of CAppAndroid's constructor.
    if (const uint32_t on_load = g_host->FindSymbol("JNI_OnLoad")) {
        const uint32_t rc = g_host->RunFunction(on_load, {GetGuestJavaVMPtr(), 0});
        LOGI("guest JNI_OnLoad(vm=0x%08X) returned 0x%08X", GetGuestJavaVMPtr(), rc);
    } else {
        LOGE("no guest JNI_OnLoad found -- libSkynestSDK should export one");
    }

    LOGI("PHASE2-OK: %zu guest modules mapped, relocated and initialised",
         g_host->GetModuleCount());
    return true;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        LOGE("GetEnv failed");
        return JNI_VERSION_1_6;
    }
    LOGI("JNI_OnLoad: booting ARM32 guest under Dynarmic");
    if (!BootGuest(env)) {
        LOGE("guest boot failed -- see log above");
    }
    return JNI_VERSION_1_6;
}
