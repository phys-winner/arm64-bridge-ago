// Running the engine's CXGSJob work without guest threads.
//
// WHY
// ---
// The bridge has no guest threads: pthread_create only records (start_func, arg) and returns
// 0. Everything the engine hands to a job scheduler therefore sits in a linked list forever.
// That is what parks the boot on CBasicDownloadScreen: the screen calls
// CXGSGameUpdater::CheckForUpdate (0x56B35C), which builds a CXGSJob(CheckForUpdateThread),
// hands it to its own CXGSJobQueue and returns 3 straight away. The job is the only thing
// that ever calls CBasicDownloadScreen::CheckComplete, and CheckComplete is the only thing
// that sets ms_bDownloadComplete -- so the screen stays on "CHECKING_UPDATE_AVAILABLE" with
// the frame loop running cleanly around it. Airplane mode does not help, because the check
// itself never runs; there is no branch to take.
//
// Every later loading stage goes the same way: CApp::CoreLoadingFunc / MainLoadingFunc /
// FrontendLoadingFunc / LevelLoadingFunc, CFontManager::pfnFontManagerLoadFunc,
// CTextureAtlasManager::pfnLoadFunc and CEnvLoading::AsyncEnvLoad are all
// `void (CXGSJob*, void*)` entries posted to a scheduler.
//
// WHAT THIS DOES
// --------------
// Replays the worker loop on the host, from outside Jit::Run. CXGSNormalJobScheduler::
// JobSchedulerThreadFunc (0x4C97A8), CXGSJobQueue::JobQueueThreadFunc (0x4C9898) and
// CXGSGlobalJobScheduler::commonThreadEntry (0x4C855C) are the same five lines: wait on the
// semaphore, unlink the head job, call job->fn(job, job->arg), CXGSAsyncEvent::Complete, and
// push the job back on the free list if it came from the reserved pool. Drop the semaphore
// (single-threaded here) and that is a plain C++ loop over guest memory.
//
// The three classes share the field layout the loop needs, so one drain covers all of them:
//     scheduler +4  free list head      job +4  next
//     scheduler +8  job list head       job +8  fn
//     scheduler +12 tail slot (&head)   job +12 user arg
//     scheduler +20 semaphore           job +16 CXGSAsyncEvent*
//                                       job +20 came-from-pool flag
//
// Which objects to drain is not guessed: each scheduler creates its workers in its
// constructor, so the pthread_create thunk sees them all. XGSThread stores the real entry at
// +8 and its parameter at +12, and every guest thread enters through XGSThread::ThreadWrapper
// (0x520604), so the parameter of a recognised worker entry *is* the scheduler object.
//
// THREAD BODIES
// -------------
// Some of the engine's work is an XGSThread rather than a job, and the download screen needs
// exactly one of those: CGameUpdater_Skynest::DownloadUpdate hands the whole update to
// CGameUpdater_Skynest::SkynestDownloadUpdateThread. That body runs to completion -- fetch
// metadata, verify, call CXGSGameUpdater::DownloadUpdate, return -- so the pump can just call
// it, in the same place and for the same reason it calls a job.
//
// Only bodies verified to terminate get run; kRunnableThreads is that list. The rest are
// infinite worker loops (the job schedulers themselves, CXGSFile_AsyncQueue::AsyncThread,
// the breakpad handler) or pollers that wait on work another thread would do, and calling
// one would never come back. Every unrecognised entry is logged once so the list can grow on
// evidence rather than on guesses.
//
// Threads that will never run are marked exited (XGSThread+16 = 1) as soon as they are seen.
// XGSThread::GetExitCode reads that word, and CXGSGameUpdater::CheckForUpdate spins on it
// -- `while (!GetExitCode(m_pProgressThread, &code));` -- before starting a second check.
// Leaving those threads "still running" turns that into a hang the watchdog cannot explain.
//
// WHAT THIS DOES NOT DO
// ---------------------
// It does not make guest threads concurrent. A body queued here runs on the render thread,
// start to finish, in one go; two guest threads never overlap. Anything that genuinely needs
// to make progress *while* another thread runs -- CXGSGameUpdater::DownloadFileProgressThread
// polling byte counts for the progress bar -- still does not work.
//
// Jobs run between frames, not at the moment they are posted. Main-thread code that enqueues
// a job and then spins for its completion inside the same guest frame would still wedge --
// the watchdog names it if that ever happens. Nothing on the boot path does it today: the
// spin-waiters are the file subsystem (already synchronous, see PatchGuestSyncFileIO) and
// CLoadManager, which polls across frames.

#include <android/log.h>
#include <time.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

#include "dynarmic_host.h"
#include "elf_loader.h"
#include "guest_jni.h"
#include "guest_jobs.h"
#include "thunks_opensles.h"
#include "thunk_manager.h"
#include <memory>

// Rendering telemetry from thunks_gl.cpp.
extern uint64_t g_gl_draw_calls;
extern uint64_t g_gl_tex_uploads;
extern uint64_t g_gl_draw_to_fbo;
extern uint64_t g_gl_draw_to_screen;
extern uint64_t g_gl_fbo_binds;
extern uint32_t g_gl_last_fbo;
extern uint64_t g_bsearch_calls;
extern uint64_t g_bsearch_hits;

#define LOG_TAG "ABGO_BRIDGE"
#include "bridge_log.h"

namespace {

// File vaddrs in libABK.so; the module base is added once in Resolve(). Every STT_FUNC in
// this binary is ARM (zero Thumb symbols), so no interworking bit to carry.
constexpr uint32_t kThreadWrapper     = 0x520604;  // XGSThread::ThreadWrapper
constexpr uint32_t kJobSchedThreadFn  = 0x4C97A8;  // CXGSNormalJobScheduler::JobSchedulerThreadFunc
constexpr uint32_t kJobQueueThreadFn  = 0x4C9898;  // CXGSJobQueue::JobQueueThreadFunc
constexpr uint32_t kCommonThreadEntry = 0x4C855C;  // CXGSGlobalJobScheduler::commonThreadEntry
constexpr uint32_t kAsyncEventComplete= 0x4BB1BC;  // CXGSAsyncEvent::Complete

// CXGSGlobalJobScheduler's two owned schedulers, "GJQ_Frame" and "GJQ_Epic".
constexpr uint32_t kGlobalFrameSched = 36;
constexpr uint32_t kGlobalEpicSched  = 40;

// XGSThread: +8 entry, +12 parameter, +16 exit flag, +20 exit code.
constexpr uint32_t kThreadEntry    = 8;
constexpr uint32_t kThreadParam    = 12;
constexpr uint32_t kThreadExitFlag = 16;
constexpr uint32_t kThreadExitCode = 20;

// Thread bodies that terminate on their own, so the pump can run them like a job.
constexpr uint32_t kRunnableThreads[] = {
    0x288E8C,   // CGameUpdater_Skynest::SkynestDownloadUpdateThread
};

uint32_t g_base = 0;
std::vector<uint32_t> g_schedulers;
uint32_t g_scratch = 0;          // one guest word for CXGSAsyncEvent::Complete's by-ref arg
uint64_t g_jobs_run = 0;
uint64_t g_pump_frames = 0;   // frames the pump has seen; the spin detector's clock

struct PendingThread { uint32_t obj, entry, param; };
std::vector<PendingThread> g_pending_threads;
size_t g_next_thread = 0;        // index, not iterator: a running body may append more
std::vector<uint32_t> g_seen_thread_entries;

bool Resolve(DynarmicHost& host) {
    if (g_base) return true;
    ElfLoader* abk = host.FindModule("libABK.so");
    if (!abk) return false;
    g_base = abk->GetBaseAddress();
    return true;
}

void AddScheduler(uint32_t sched, const char* why) {
    if (!sched) return;
    for (uint32_t s : g_schedulers) if (s == sched) return;
    g_schedulers.push_back(sched);
    LOGI("job pump: scheduler #%zu at 0x%08X (%s)", g_schedulers.size(), sched, why);
}

// The body of JobSchedulerThreadFunc/JobQueueThreadFunc/commonThreadEntry, minus the wait.
void RunOneJob(DynarmicHost& host, uint32_t sched, uint32_t job) {
    const uint32_t fn     = host.MemoryRead32(job + 8);
    const uint32_t arg    = host.MemoryRead32(job + 12);
    const uint32_t event  = host.MemoryRead32(job + 16);
    const uint32_t pooled = host.MemoryRead32(job + 20);

    // Every distinct job function once, rather than the first N runs: CXGSSound's monitor job
    // re-posts itself every frame and used to swallow the whole quota before the interesting
    // ones (CApp::FrontendLoadingFunc and friends) ever appeared.
    static std::vector<uint32_t> seen_fns;
    bool first_time = true;
    for (uint32_t f : seen_fns) if (f == fn) { first_time = false; break; }
    if (first_time) {
        seen_fns.push_back(fn);
        LOGI("job pump: run #%llu job=0x%08X fn=libABK+0x%X arg=0x%08X event=0x%08X",
             static_cast<unsigned long long>(g_jobs_run), job,
             fn >= g_base ? fn - g_base : fn, arg, event);
    }
    ++g_jobs_run;

    if (fn) host.RunFunction(fn, {job, arg});

    // Complete() takes the job slot by reference and the worker re-reads it afterwards, so
    // it has to be a writable guest word, not a literal.
    uint32_t finished = job;
    if (event && g_scratch) {
        host.MemoryWrite32(g_scratch, job);
        host.RunFunction(g_base + kAsyncEventComplete, {event, g_scratch});
        finished = host.MemoryRead32(g_scratch);
    }

    if (pooled && finished) {          // CXGSNormalJobScheduler::ReturnPreAllocatedJob
        host.MemoryWrite32(finished + 4, host.MemoryRead32(sched + 4));
        host.MemoryWrite32(sched + 4, finished);
    }
}

// Probe. The update list is 59 core .pak files that live in the 345 MB OBB, and the OBB is a
// XPK archive whose header says it holds exactly 59 entries -- so the question is whether the
// guest can see inside it at all. CXGSFileSystemAndroidAPK::InitialiseExpansionFiles opens
// both expansion files through a POSIX filesystem and wraps each in a CXGSFileSystemPAK,
// keeping (pak, file) at this+12/+20 for the patch and this+16/+24 for the main one; a pak
// whose Initialise failed is nulled out. Then ask the engine to open one OBB-only file, with
// an APK-only file as the control.
void ProbeGuestFileSystem(DynarmicHost& host) {
    constexpr uint32_t kFsOpen = 0x50C73C;   // CXGSFileSystem::fopen(name, mode, heap)
    const uint32_t fs = host.MemoryRead32(g_base + 0xDE52F8);   // g_pXGSFileSystem
    LOGI("filesystem: g_pXGSFileSystem=0x%08X patch(pak=0x%08X file=0x%08X) "
         "main(pak=0x%08X file=0x%08X)", fs,
         fs ? host.MemoryRead32(fs + 12) : 0, fs ? host.MemoryRead32(fs + 20) : 0,
         fs ? host.MemoryRead32(fs + 16) : 0, fs ? host.MemoryRead32(fs + 24) : 0);

    for (const char* path : {"data\\smackables.pak", "data\\ui\\ui_core.pak"}) {
        const size_t len = std::strlen(path) + 1;
        const uint32_t p = host.GuestAlloc(len, 4);
        if (!p) return;
        std::memcpy(host.GetGuestMemoryBase() + p, path, len);

        const uint32_t file = host.RunFunction(g_base + kFsOpen, {p, 1, 0});
        uint32_t is_open = 0;
        if (file) {
            const uint32_t vt = host.MemoryRead32(file);
            is_open = host.RunFunction(host.MemoryRead32(vt + 8), {file});   // IsOpen
            host.RunFunction(host.MemoryRead32(vt + 4), {file});             // Close
        }
        LOGI("filesystem: fopen(\"%s\") -> 0x%08X isOpen=%u", path, file, is_open & 0xFF);
    }
}

// Probe. CXGSGameUpdater::AnyFilesToUpdate is what decides whether the boot has to download
// anything: it walks the list and answers yes if any entry's +12 flag is set. Everything
// downstream -- result 8 instead of 1, the download attempt, the failure screen -- follows
// from that one predicate, so print the entries that set it.
//   list +4 count, +8 head;  node [0] entry, [2] next;
//   entry +12 needs-update, +20 type (4 = dynamic), +24 name, inline.
void DumpUpdateFileList(DynarmicHost& host, uint32_t list) {
    const int count = static_cast<int>(host.MemoryRead32(list + 4));
    uint32_t node = host.MemoryRead32(list + 8);
    const auto* mem = host.GetGuestMemoryBase();

    int wanted = 0, dynamic_wanted = 0, printed = 0;
    for (int i = 0; i < count && node; ++i, node = host.MemoryRead32(node + 8)) {
        const uint32_t entry = host.MemoryRead32(node);
        if (!entry || !host.MemoryRead32(entry + 12)) continue;
        ++wanted;
        const uint32_t type = host.MemoryRead32(entry + 20);
        if (type == 4) ++dynamic_wanted;
        if (printed++ < 16)
            LOGI("update wants[%d]: type=%u %.120s", i, type,
                 reinterpret_cast<const char*>(mem + entry + 24));
    }
    LOGI("update list: %d files, %d flagged for update (%d of them dynamic)",
         count, wanted, dynamic_wanted);
}

// Probe. CApp::DoRenderXGSUI calls UI::CManager::Render (vptr+24), which sets the pass index and
// hands the whole frontend to CXGSFEWindow::Render on the manager's own root window at +36. That
// walk visits a child only when child[+184] (visible) is set, so a black frontend is one of two
// very different things: an empty tree (the screen never opened) or a populated tree whose
// windows are invisible or zero-sized. Print enough of both to tell them apart in one run.
//   UI::CManager: +36 root window, +112 screen count, +116 screen list head, +120 tail.
//   CXGSFEWindow: +80 child list head, +124 pos (2 floats), +132 size (2 floats), +184 visible;
//                 child node [0] window, [2] next.
void DumpUIWindowTree(DynarmicHost& host, uint32_t win, const char* what, int depth) {
    const auto f = [&](uint32_t off) {
        const uint32_t bits = host.MemoryRead32(win + off);
        float v; std::memcpy(&v, &bits, sizeof(v)); return v;
    };
    const uint32_t vt = host.MemoryRead32(win);
    int children = 0;
    for (uint32_t n = host.MemoryRead32(win + 80); n && children < 4096; n = host.MemoryRead32(n + 8))
        ++children;
    LOGI("uitree:%*s %s 0x%08X vt=libABK+0x%X vis=%u pos=(%.1f,%.1f) size=(%.1f,%.1f) children=%d",
         depth * 2, "", what, win, vt >= g_base ? vt - g_base : vt,
         host.MemoryRead8(win + 184), f(124), f(128), f(132), f(136), children);

    if (depth >= 2) return;
    int printed = 0;
    for (uint32_t n = host.MemoryRead32(win + 80); n && printed < 8; n = host.MemoryRead32(n + 8)) {
        const uint32_t child = host.MemoryRead32(n);
        if (!child) continue;
        ++printed;
        DumpUIWindowTree(host, child, "child", depth + 1);
    }
}

// Turn the GameUI call tracing below on when a screen does not appear. It costs one SVC per
// call on functions the frontend uses every frame, so it is off by default -- but it is what
// found the dropped "landingScreen" event, and the next missing screen will need it too.
constexpr bool kTraceGameUI = false;

void ProbeGameUI(DynarmicHost& host) {
    // Where the frontend's idea of the screen size comes from. XGSGLES_init2 fills s_egl_width /
    // s_egl_height from eglQuerySurface and may swap them for the configured orientation;
    // UI::CManager::ParseConfig copies the display's width/height (render device vtable+24 gives
    // the display, then its vtable+32/+36) into the CDimensions at manager+660, and every '%'
    // dimension in UI.xml is resolved against that.
    const uint32_t dev = host.MemoryRead32(g_base + 0xDE59A8);      // g_ptXGSRenderDevice
    const uint32_t disp = dev ? host.MemoryRead32(dev + 72) : 0;
    uint32_t dw = 0, dh = 0;
    if (disp) {
        const uint32_t vt = host.MemoryRead32(disp);
        dw = host.RunFunction(host.MemoryRead32(vt + 32), {disp});
        dh = host.RunFunction(host.MemoryRead32(vt + 36), {disp});
    }
    LOGI("uisize: egl=%ux%u camera=%ux%u dev=0x%08X display=0x%08X displaySize=%ux%u",
         host.MemoryRead32(g_base + 0xDE5FCC), host.MemoryRead32(g_base + 0xDE5FC4),
         host.MemoryRead32(g_base + 0xDE3FE4), host.MemoryRead32(g_base + 0xDE3F24),
         dev, disp, dw, dh);

    const uint32_t mgr = host.MemoryRead32(g_base + 0xEA45C8);   // UI::CManager::g_pUIManager
    if (!mgr) { LOGI("uitree: g_pUIManager is null"); return; }
    const auto f = [&](uint32_t a) {
        const uint32_t b = host.MemoryRead32(a); float v; std::memcpy(&v, &b, sizeof(v)); return v;
    };
    LOGI("uisize: manager CDimensions = (%g,%g)-(%g,%g)",
         f(mgr + 660), f(mgr + 664), f(mgr + 668), f(mgr + 672));

    const uint32_t head = host.MemoryRead32(mgr + 116);
    const uint32_t screen = head ? host.MemoryRead32(head) : 0;
    LOGI("uitree: mgr=0x%08X screens=%u head=0x%08X current=0x%08X",
         mgr, host.MemoryRead32(mgr + 112), head, screen);
    DumpUIWindowTree(host, mgr + 36, "root", 0);
    if (screen) DumpUIWindowTree(host, screen, "screen", 0);

    // The live window tree only holds three windows, so the question moves upstream: did UI.xml
    // parse into anything? UI::CManager::CreateScreen starts with
    // FindNodeData(manager[+640], name, 0) and returns null the moment that misses, so a screen
    // that never appears and an XML tree that never populated look identical from outside. Walk
    // the parser's own tree -- parser[0] is the root node, node[0] first child, node[8] next
    // sibling, node[16] a UI::CString with the name -- and name what is in it.
    const uint32_t parser = host.MemoryRead32(mgr + 640);
    const uint32_t xroot = parser ? host.MemoryRead32(parser) : 0;
    LOGI("uixml: parser=0x%08X root=0x%08X", parser, xroot);
    if (!xroot) return;

    constexpr uint32_t kGetString = 0x7BD9BC;      // UI::CString::GetString
    const auto name_of = [&](uint32_t node) -> const char* {
        const uint32_t str = host.MemoryRead32(node + 16);
        if (!str) return "(no name)";
        const uint32_t p = host.RunFunction(g_base + kGetString, {str});
        return p ? reinterpret_cast<const char*>(host.GetGuestMemoryBase()) + p : "(null)";
    };

    int total = 0;
    for (uint32_t n = host.MemoryRead32(xroot); n && total < 4096; n = host.MemoryRead32(n + 8)) ++total;
    LOGI("uixml: root \"%s\" has %d top-level nodes", name_of(xroot), total);

    // The XML names a class; UI::CClassFactory::CreateClassInstance turns that name into an
    // object through UI::CStaticTypeTree::FindEntry, and returns null when the name is not
    // registered -- which is exactly how RecurseAddElements ends up building an almost empty
    // screen without a single complaint. The tree is filled by ~200 static initialisers
    // (_GLOBAL__sub_I_<Widget>.cpp, each doing CStaticTypeTree::Add), so its entry count says
    // whether those ran. Layout: entries stride 24 from the base, name at entry+12, count at
    // +24576, and the function-local guard word right after the object.
    constexpr uint32_t kTypeTree = 0xDD6ECC;
    LOGI("uitypes: registered=%u guard=0x%08X",
         host.MemoryRead32(g_base + kTypeTree + 24576),
         host.MemoryRead32(g_base + kTypeTree + 24584));

    // And the direct questions, asked of the engine rather than inferred.
    for (const char* want : {"CLandingScreen", "CFoundationScreen"}) {
        const size_t len = std::strlen(want) + 1;
        const uint32_t p = host.GuestAlloc(len, 4);
        if (!p) break;
        std::memcpy(host.GetGuestMemoryBase() + p, want, len);
        LOGI("uixml: \"%s\": xmlNode=0x%08X staticType=0x%08X", want,
             host.RunFunction(g_base + 0x7CA4A0, {parser, p, 0}),          // CXMLParser::FindNodeData
             host.RunFunction(g_base + 0x7B96EC, {g_base + kTypeTree, p}));  // CStaticTypeTree::FindEntry
        host.GuestFree(p);
    }
}

// Call tracing for a guest function: which of them run, with what arguments, and called from
// where. The PatchGuest* patches change behaviour and that is all they need to do; answering
// "who opens the frontend screen" needs the original function to still run afterwards.
//
// The trick avoids touching PC. Dynarmic keeps executing the rest of the translated block after
// CallSVC returns, so rewriting R15 from inside a thunk is not reliable -- but nothing forces
// the hook to resume at the same instruction. Every function hooked here begins with
// `STMFD SP!, {reglist}` (verified before the patch is written, as always), so the thunk can
// perform that push itself against guest memory and simply return: execution continues at
// addr+4 with the exact state the real prologue would have produced. The hook stays installed
// and costs one SVC per call.
namespace {

struct GuestCallHook {
    uint32_t addr = 0;
    uint32_t push = 0;      // the displaced STMFD SP!, {reglist}
    int hits = 0;
    int max_log = 4;
    bool backtrace = true;
    const char* name = "";
    // Which argument registers hold a string, as a bitmask over r0..r3.
    uint32_t str_args = 0;
};

void RunDisplacedPush(Dynarmic::A32::Jit& jit, DynarmicHost& host, const GuestCallHook& h) {
    const uint32_t list = h.push & 0xFFFF;
    uint32_t sp = jit.Regs()[13];
    for (int r = 0; r < 16; ++r) if (list & (1u << r)) sp -= 4;
    uint32_t p = sp;
    for (int r = 0; r < 16; ++r) {
        if (!(list & (1u << r))) continue;
        host.MemoryWrite32(p, r == 15 ? h.addr + 8 : jit.Regs()[r]);
        p += 4;
    }
    jit.Regs()[13] = sp;
}

}  // namespace

// Returns false (and patches nothing) when the first instruction is not the expected push.
bool InstallGuestCallHook(DynarmicHost& host, uint32_t vaddr, const char* name,
                          uint32_t str_args = 0, int max_log = 4, bool backtrace = true) {
    const uint32_t addr = g_base + vaddr;
    const uint32_t orig = host.MemoryRead32(addr);
    if ((orig & 0xFFFF0000) != 0xE92D0000) {
        LOGE("hook %s: first instruction 0x%08X is not STMFD SP!, refusing", name, orig);
        return false;
    }
    auto h = std::make_shared<GuestCallHook>();
    h->addr = addr; h->push = orig; h->name = name;
    h->str_args = str_args; h->max_log = max_log; h->backtrace = backtrace;

    ThunkManager& tm = host.GetThunkManager();
    const std::string key = std::string("__hook_") + name;
    tm.RegisterThunk(key, [h](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (h->hits++ < h->max_log) {
            char args[4][80];
            for (int i = 0; i < 4; ++i) {
                const uint32_t v = jit.Regs()[i];
                if ((h->str_args & (1u << i)) && v > 0x1000 &&
                    static_cast<uint64_t>(v) + 64 <= host.GetGuestMemorySize())
                    snprintf(args[i], sizeof(args[i]), "\"%.48s\"",
                             reinterpret_cast<const char*>(host.GetGuestMemoryBase()) + v);
                else
                    snprintf(args[i], sizeof(args[i]), "0x%08X", v);
            }
            const uint32_t lr = jit.Regs()[14];
            LOGI("hook %s(%s, %s, %s, %s) from libABK+0x%X", h->name,
                 args[0], args[1], args[2], args[3], lr >= g_base ? lr - g_base : lr);
            if (h->backtrace)
                host.DumpGuestBacktrace(h->name, jit.Regs()[13], jit.Regs()[14]);
        }
        RunDisplacedPush(jit, host, *h);
    });
    const uint32_t tramp = tm.GetOrCreateThunkAddress(key);
    const uint32_t svc = host.MemoryRead32(tramp);      // the trampoline's own `SVC #id`
    host.MemoryWrite32(addr, svc);
    host.InvalidateGuestCode(addr, 4);
    LOGI("hook %s installed at 0x%08X (was 0x%08X, svc 0x%08X)", name, addr, orig, svc);
    return true;
}

// The engine does send the "landingScreen" state change and the coordinator does receive it, so
// the break is inside GameUI::CGameUICoordinator::OnStateChange. That function looks the state
// name up in a table of (CStringHandle, CEvent*) pairs at coord+8 (count +12, "is sorted" flag
// +29) and queues a clone of the matching event; a miss is silent. Both lookup paths -- the
// binary search when the flag is set and the "linear" one when it is not -- assume the table is
// ordered by CRC, and the linear path gives up the moment it sees a larger CRC. So print the
// table in order with its CRCs and say whether it is actually sorted.
void ProbeCoordinatorEvents(DynarmicHost& host, uint32_t coord) {
    const uint32_t arr = host.MemoryRead32(coord + 8);
    const int n = static_cast<int>(host.MemoryRead32(coord + 12));
    const uint32_t sorted = host.MemoryRead8(coord + 29);
    LOGI("uievents: table=0x%08X count=%d sorted=%u queued=%d", arr, n, sorted,
         static_cast<int>(host.MemoryRead32(coord + 36)));
    if (!arr || n <= 0 || n > 512) return;

    const auto* mem = reinterpret_cast<const char*>(host.GetGuestMemoryBase());
    uint32_t prev = 0;
    int inversions = 0;
    for (int i = 0; i < n; ++i) {
        const uint32_t h = arr + 8u * static_cast<uint32_t>(i);
        const uint32_t crc = host.RunFunction(g_base + 0x7A8C78, {h});   // CStringHandle::GetCRC
        if (i && crc < prev) ++inversions;
        prev = crc;
        if (kTraceGameUI) {
            const uint32_t s = host.RunFunction(g_base + 0x7A8C88, {h}); // CStringHandle::GetString
            LOGI("uievents: [%3d] crc=%08X ev=0x%08X \"%.40s\"", i, crc,
                 host.MemoryRead32(h + 4), s ? mem + s : "(null)");
        }
    }
    LOGI("uievents: %d entries, %d out of CRC order", n, inversions);
}

// Music looping in this engine is a playlist, not a loop flag on the voice. ABKSound plays a
// CXGSSCPlaylistInstance and CXGSSCPlaylistInstance::Update (0x5DBBC0) starts the next atom --
// wrapping the index back to 0, which is what "the menu track repeats" is -- as soon as
// CXGSSC::IsPlaying says the current atom stopped. Three links can break that and they need
// completely different fixes, so print which one it is:
//   upd  CXGSSC::Update is running at all      (ms_fGameStateTimer moves every call)
//   f52  the playlist instance is active       (Update does nothing when this word is 0)
//   auto CXGSSC::Update only reaches the playlist when IsMarkedForAutoRelease is true
//   atom the current atom still counts as playing
// On change only: this sits in the 2.5 s pulse and a line that repeats costs real diagnostics
// on a device whose log flow control drops the overflow silently.
void ProbeMusicPlaylist(DynarmicHost& host, uint32_t handle) {
    const int slot = static_cast<int>(handle) >> 16;
    if (handle == 0xFFFFFFFFu || slot < 0 || slot >= 127) return;
    const uint32_t inst = host.MemoryRead32(g_base + 0xEA0920 + 4u * static_cast<uint32_t>(slot));
    if (!inst) return;

    const uint32_t timer_bits = host.MemoryRead32(g_base + 0xDD6E4C);   // ms_fGameStateTimer
    static uint32_t last_timer = 0;
    const unsigned upd = (timer_bits != last_timer) ? 1u : 0u;
    last_timer = timer_bits;

    const uint32_t type = host.RunFunction(g_base + 0x5D5E48, {inst});  // GetType
    const uint32_t autorel = host.RunFunction(g_base + 0x5D5E78, {inst});
    const uint32_t atom = host.MemoryRead32(inst + 32);
    char now[224];
    snprintf(now, sizeof(now),
             "  sc: inst=0x%08X type=%u upd=%u autorel=%u canrel=%u f52=%u idx=%u/%u "
             "atom=0x%08X atomPlaying=%u listPlaying=%u active=%u",
             inst, type, upd, autorel,
             type == 3 ? host.RunFunction(g_base + 0x5DBE40, {inst}) : 0,
             host.MemoryRead32(inst + 52),
             host.MemoryRead32(inst + 36), host.MemoryRead32(inst + 28),
             atom, host.RunFunction(g_base + 0x5C793C, {atom}),
             host.RunFunction(g_base + 0x5C793C, {handle}),
             host.MemoryRead32(g_base + 0xEA08E8));
    static std::string last;
    if (last != now) { last = now; LOGI("%s", now); }
}

// Whether a stream keeps going at end-of-data is one word: CXGSSound_Sound_OpenSL_Stream::Watch
// asks CXGSSound_Sound::GetLoop() and either rewinds the stream or clears its own "keep feeding"
// flag, after which the queue drains and the buffer-queue callback stops the voice. So print
// GetLoop next to that flag for every sound on CXGSSound_Sound_OpenSL::ms_pWatchHead.
//
// The offsets are not guessed: the watch list holds the CXGSSound_Sound_OpenSL subobject (the
// vtable group whose +56 slot is the Watch thunk StreamMonitorJob calls), so this+84 is the
// feed flag and this+80 the state that Watch writes -- and the CXGSSound_Sound virtual base is
// found through the vtable's own vbase offset at vptr-12, exactly the way the guest finds it.
void ProbeWatchList(DynarmicHost& host) {
    uint32_t p = host.MemoryRead32(g_base + 0xEA06A8);   // ms_pWatchHead
    char buf[512];
    int n = 0, at = 0;
    at += snprintf(buf, sizeof(buf), "  streams:");
    for (; p && n < 4; ++n) {
        const uint32_t vptr = host.MemoryRead32(p);
        const int32_t vbase = static_cast<int32_t>(host.MemoryRead32(vptr - 12));
        const uint32_t snd = static_cast<uint32_t>(p + vbase);
        const uint32_t getloop = host.MemoryRead32(host.MemoryRead32(snd) + 84);
        // Decoded byte position against the buffer's total: how far through the track it is,
        // and -- since Watch wraps it back to 0 at the loop point -- whether it ever wrapped.
        const uint32_t bufobj = host.RunFunction(g_base + 0x5AFF6C, {snd});   // GetBuffer
        const uint32_t meta = bufobj
            ? host.RunFunction(host.MemoryRead32(host.MemoryRead32(bufobj) + 4), {bufobj}) : 0;
        // CXGSSound_Stream, via CXGSSound_Buffer vtable slot 4. Its +4 is the count of buffers
        // the guest believes are in flight: Watch tops it up while it is <= 1, and the
        // buffer-queue callback stops the voice the moment the decrement lands on 0.
        const uint32_t stream = bufobj
            ? host.RunFunction(host.MemoryRead32(host.MemoryRead32(bufobj) + 16), {bufobj}) : 0;
        // pos is the decoded sample position (48 kHz), and it is the one field that says
        // whether the loop point was reached at all: Watch wraps it back to 0 there.
        at += snprintf(buf + at, sizeof(buf) - at,
                       " [0x%08X loop=%u feed=%u state=%u inflight=%u pos=%u srcBytes=%u]",
                       p, host.RunFunction(getloop, {snd}),
                       host.MemoryRead32(p + 84), host.MemoryRead32(p + 80),
                       stream ? host.MemoryRead32(stream + 4) : 0,
                       host.MemoryRead32(p - 16), meta ? host.MemoryRead32(meta + 28) : 0);
        if (at >= static_cast<int>(sizeof(buf)) - 80) break;
        p = host.MemoryRead32(p + 92);
    }
    if (!n) return;
    static std::string last;
    if (last != buf) { last = buf; LOGI("%s", buf); }
}

// Probe, not machinery: says what the boot screen's state machine is doing, but only when it
// changes. CBasicDownloadScreen::Process switches on this[3079] and leaves the screen up
// until ms_bDownloadComplete is set; printing those two whenever they move is enough to tell
// a stuck download screen from a stuck GDPR dialog without another build.
void LogDownloadScreenState(DynarmicHost& host) {
    // One-time: trace the funnel every GameUI screen has to pass through, from the state change
    // that asks for it down to the window that gets built. Off by default (kTraceGameUI); this
    // is the set that answered "who opens the frontend", so it is left wired up.
    static bool hooked = false;
    if (kTraceGameUI && !hooked) {
        hooked = true;
        InstallGuestCallHook(host, 0x7B72E0, "UI::CManager::CreateScreen", 1u << 1, 8, false);
        InstallGuestCallHook(host, 0x3D43A8, "CScreenContainer::AddScreen", 1u << 2, 8, false);
        InstallGuestCallHook(host, 0x3BD39C, "CGameUIManager::SetScreenByType", 0, 6);
        InstallGuestCallHook(host, 0x7B5894, "UI::CManager::SetScreenByType", 0, 6, false);
        InstallGuestCallHook(host, 0x3BC33C, "CGameUIManager::FixupScreen", 0, 6);
        InstallGuestCallHook(host, 0x3B75F0, "CCoordinator::RegisterLatestScreen", 0, 6, false);
        // The event route: UI.xml behaviours -> SendStateChange -> the coordinator's listener ->
        // QueueEvent -> Process -> CEventGotoScreen::Process -> GotoScreen. If none of these fire
        // then nothing is asking for a screen at all, and the trigger is upstream of GameUI.
        InstallGuestCallHook(host, 0x7B6AC8, "UI::CManager::SendStateChange",
                             (1u << 1) | (1u << 2), 24, false);
        InstallGuestCallHook(host, 0x3B7318, "CCoordinator::OnStateChange", 0, 12, false);
        InstallGuestCallHook(host, 0x3B7BB4, "CCoordinator::QueueEvent(name)", 0, 12);
        InstallGuestCallHook(host, 0x3B7E48, "CCoordinator::QueueEvent(event)", 0, 12);
    }

    // Where the boot is, whether or not the download screen still exists. CApp::ProcessFrame
    // switches on g_pApplication+40 (4 = tear the screen down, 7 = main loading, 8 = frontend)
    // and CGame keeps its own state at +200.
    {
        const uint32_t app = host.MemoryRead32(g_base + 0xDABECC);
        const uint32_t game = app ? host.MemoryRead32(app + 52) : 0;
        const uint32_t appstate = app ? host.MemoryRead32(app + 40) : 0;
        const uint32_t gamestate = game ? host.MemoryRead32(game + 200) : 0;
        // CXGSFE_SplashScreen::Process leaves for FrontendLoadingScreen only when
        // CSkynestGDPRDialogs::CheckAndShowDialog() is true, and that is `ms_ptInstance[+16]
        // == 3`. Everything about this boot stage is in these few words.
        // Heartbeat: without it there is no way to tell "the frame loop is running and the
        // frontend simply draws nothing" from "the frame loop stopped".
        static uint64_t pumps = 0;
        // Every frame, not once per pulse: ABKSound::CMusicController::Play strlcpy's the track
        // name into ms_sMusicTrack, and the short stingers between the slingshot and the race
        // (ABY_music_pullback is 9 kB, about two seconds) come and go well inside the 2.5 s
        // pulse. Sampling on the pulse showed the transition into the race and nothing after,
        // which reads as "the music never changed" when it changed twice. One string compare
        // per frame; it still only prints when the value moves.
        {
            const char* track =
                reinterpret_cast<const char*>(host.GetGuestMemoryBase()) + g_base + 0xDD6C48;
            static std::string last_track;
            if (last_track != track) {
                last_track = track;
                LOGI("  music: handle=0x%08X track=\"%.48s\"",
                     host.MemoryRead32(g_base + 0xDD6C8C), track);
            }
        }
        if (++pumps % 300 == 0) {
            const uint32_t fe = host.MemoryRead32(g_base + 0xDC30AC);   // g_ptXGSFE
            static uint64_t last_draws = 0;
            const uint64_t draws = g_gl_draw_calls;
            const auto* mem = reinterpret_cast<const char*>(host.GetGuestMemoryBase());
            LOGI("frame %llu: CApp state=%u CGame state=%u screen=0x%08X \"%.40s\" pending "
                 "\"%.40s\"  draws +%llu fboBinds=%llu lastFbo=%u bsearch=%llu/%llu fboDraws=%llu screenDraws=%llu texUploads=%llu",
                 static_cast<unsigned long long>(pumps), appstate, gamestate,
                 fe ? host.RunFunction(g_base + 0x531DA8, {fe}) : 0,   // GetCurrentScreen
                 mem + g_base + 0xDD5658,      // s_cScreenNameCurrent
                 mem + g_base + 0xDD56A0,      // s_cScreenNamePending
                 static_cast<unsigned long long>(draws - last_draws),
                 static_cast<unsigned long long>(g_gl_fbo_binds), g_gl_last_fbo,
                 static_cast<unsigned long long>(g_bsearch_hits),
                 static_cast<unsigned long long>(g_bsearch_calls),
                 static_cast<unsigned long long>(g_gl_draw_to_fbo),
                 static_cast<unsigned long long>(g_gl_draw_to_screen),
                 static_cast<unsigned long long>(g_gl_tex_uploads));
            last_draws = draws;
            host.LogHeapStats("pulse");
            LogAudioStats();
            LogJniStats();
            // Music. The track name itself is sampled every frame above; here only the state
            // around it, which is slow-moving: whether the engine has music enabled at all,
            // and what the sound-container instance behind the current handle is doing.
            {
                const uint32_t handle = host.MemoryRead32(g_base + 0xDD6C8C);  // ms_iMusicTrack
                ProbeMusicPlaylist(host, handle);
                ProbeWatchList(host);
            }
            // CApp::DoRenderXGSUI draws the whole frontend and does nothing at all unless
            // g_ptBatchController and CApp::m_pUIManager (this+164) are both live.
            // Static as soon as the frontend exists, so only say it when it changes --
            // a line that repeats every 2.5 seconds is what pushes the useful ones out of
            // the device's log buffer.
            {
                const uint32_t bc = host.MemoryRead32(g_base + 0xEA462C);
                const uint32_t um = app ? host.MemoryRead32(app + 164) : 0;
                static uint32_t last_bc = 0xFFFFFFFF, last_um = 0xFFFFFFFF;
                if (bc != last_bc || um != last_um) {
                    last_bc = bc; last_um = um;
                    LOGI("  ui: batchCtrl=0x%08X xgs2d=0x%08X uiMgr=0x%08X uiManagerGlobal=0x%08X",
                         bc, host.MemoryRead32(g_base + 0xDDF4C8), um,
                         host.MemoryRead32(g_base + 0xEA45C8));
                }
            }

            // Once, after the frontend is up: does the engine's own filesystem actually hand
            // over the files the UI is built from? Same trick as the CHARSPEC probe -- ask the
            // guest instead of guessing.
            static bool probed_ui = false;
            if (!probed_ui && gamestate == 2) {
                probed_ui = true;
                for (const char* path : {"XMLUIPAK:UI.xml", "UIPAK:textures/uisharedatlas.atlas",
                                         "SCREENS:common_uncompressed_alpha_16.atlas",
                                         "UIADDITIONALPAK:UI.xml"}) {
                    const size_t len = std::strlen(path) + 1;
                    const uint32_t p = host.GuestAlloc(len, 4);
                    if (!p) break;
                    std::memcpy(host.GetGuestMemoryBase() + p, path, len);
                    const uint32_t f = host.RunFunction(g_base + 0x50C73C, {p, 1, 0});
                    if (f) {
                        const uint32_t vt = host.MemoryRead32(f);
                        host.RunFunction(host.MemoryRead32(vt + 4), {f});
                    }
                    LOGI("ui probe: fopen(\"%s\") -> 0x%08X", path, f);
                    host.GuestFree(p);
                }
                ProbeGameUI(host);
            }
        }

        // GameUI::CGameUICoordinator::Process pops the head event every frame but only *runs*
        // it when CGame's pending state (CGame+204) is 0, 3 or 10; any other value and the
        // event is dropped without a word. Watch the queue depth and the pending state together,
        // on change only, so a queued-then-discarded "landingScreen" is visible.
        {
            const uint32_t uimgr = host.MemoryRead32(g_base + 0xEA45C8);
            const uint32_t coord = uimgr ? host.MemoryRead32(uimgr + 1032) : 0;
            const uint32_t pending = game ? host.MemoryRead32(game + 204) : 0;
            const uint32_t q = coord ? host.MemoryRead32(coord + 36) : 0;
            static uint32_t last_q = 0xFFFFFFFF, last_pending = 0xFFFFFFFF;
            if (q != last_q || pending != last_pending) {
                last_q = q; last_pending = pending;
                LOGI("uievents: queue=%u CGame state=%u pending=%u", q, gamestate, pending);
            }
        }

        const uint32_t gd = host.MemoryRead32(g_base + 0xDDD304);
        const uint32_t dlg = gd ? host.MemoryRead32(gd + 16) : 0xFFFFFFFF;
        static uint32_t last_app = 0xFFFFFFFF, last_game = 0xFFFFFFFF, last_dlg = 0xFFFFFFFE;
        if (appstate != last_app || gamestate != last_game || dlg != last_dlg) {
            last_app = appstate; last_game = gamestate; last_dlg = dlg;
            LOGI("boot: CApp state=%u CGame state=%u gdpr dlg=%d [+20]=%u [+24]=%u [+28]=%u "
                 "[+32]=%u [+36]=%u [+40]=%u [+44]=%u [+48]=%u [+52]=%u [+64]=%u",
                 appstate, gamestate, static_cast<int>(dlg),
                 gd ? host.MemoryRead32(gd + 20) : 0, gd ? host.MemoryRead32(gd + 24) : 0,
                 gd ? host.MemoryRead32(gd + 28) : 0, gd ? host.MemoryRead32(gd + 32) : 0,
                 gd ? host.MemoryRead32(gd + 36) : 0, gd ? host.MemoryRead32(gd + 40) : 0,
                 gd ? host.MemoryRead32(gd + 44) : 0, gd ? host.MemoryRead32(gd + 48) : 0,
                 gd ? host.MemoryRead32(gd + 52) : 0, gd ? host.MemoryRead32(gd + 64) : 0);
        }
    }

    const uint32_t screen = host.MemoryRead32(g_base + 0xDD5840);   // ms_pDownloadScreen
    if (!screen) return;

    static bool probed_fs = false;
    if (!probed_fs) { probed_fs = true; ProbeGuestFileSystem(host); }

    // CEventDefinitionManager::LoadEvent opens "CHARSPEC:Boss_%03d.xml" and calls straight
    // through the result without a null check, so a miss is a jump to guest address 0. Watch
    // the pak until it answers, to tell "CHARSPEC never gets mounted" from "the index is
    // wrong". Bounded, and stops as soon as it succeeds.
    static int charspec_tries = 0;
    if (charspec_tries < 400) {
        ++charspec_tries;
        const uint32_t p = host.GuestAlloc(24, 4);
        if (p) {
            std::memcpy(host.GetGuestMemoryBase() + p, "CHARSPEC:boss_001.xml", 22);
            const uint32_t f = host.RunFunction(g_base + 0x50C73C, {p, 1, 0});
            static uint32_t last = 0xFFFFFFFF;
            const uint32_t ok = f ? 1u : 0u;
            if (ok != last) {
                last = ok;
                LOGI("filesystem: CHARSPEC:boss_001.xml -> 0x%08X (try %d)", f, charspec_tries);
            }
            if (f) {
                const uint32_t vt = host.MemoryRead32(f);
                host.RunFunction(host.MemoryRead32(vt + 4), {f});
                charspec_tries = 400;   // answered; stop probing
            }
            host.GuestFree(p);
        }
    }

    const uint32_t list = host.MemoryRead32(g_base + 0xDD5830);     // ms_pFileList
    static uint32_t dumped_list = 0;
    if (list && list != dumped_list) { dumped_list = list; DumpUpdateFileList(host, list); }

    const uint32_t state    = host.MemoryRead32(screen + 3079 * 4);
    const uint32_t complete = host.MemoryRead32(g_base + 0xDD5834); // ms_bDownloadComplete
    const uint32_t gdpr     = host.MemoryRead32(screen + 3087 * 4);
    // CApp::ProcessFrame's own state (g_pApplication+40): 2 = running the download screen,
    // 3 = fading it out, 4 = tear it down and CLoadManager::BeginLoad(CoreLoadingFunc).
    const uint32_t app      = host.MemoryRead32(g_base + 0xDABECC);
    const uint32_t appstate = app ? host.MemoryRead32(app + 40) : 0;
    static uint32_t last_state = 0xFFFFFFFF, last_complete = 0xFFFFFFFF, last_gdpr = 0xFFFFFFFF,
                    last_app = 0xFFFFFFFF;
    if (state == last_state && complete == last_complete && gdpr == last_gdpr &&
        appstate == last_app) return;
    last_state = state; last_complete = complete; last_gdpr = gdpr; last_app = appstate;

    // CSkynestGDPRDialogs::ms_ptInstance+16 is what IsShowingADialog tests (1 or 2 = showing),
    // and CApp will not leave state 2 while it says yes.
    const uint32_t gd = host.MemoryRead32(g_base + 0xDDD304);
    LOGI("app state=%u  gdpr dialogs=0x%08X showing=%u [4]=%u [5]=%u [6]=%u [7]=%u [8]=%u "
         "[9]=%u [16]=%u  identity=0x%08X", appstate, gd,
         gd ? host.MemoryRead32(gd + 16) : 0,
         gd ? host.MemoryRead32(gd + 16) : 0, gd ? host.MemoryRead32(gd + 20) : 0,
         gd ? host.MemoryRead32(gd + 24) : 0, gd ? host.MemoryRead32(gd + 28) : 0,
         gd ? host.MemoryRead32(gd + 32) : 0, gd ? host.MemoryRead32(gd + 36) : 0,
         gd ? host.MemoryRead32(gd + 64) : 0,
         app ? host.MemoryRead32(app + 76) : 0);

    LOGI("download screen: state=%u complete=%u fileList=0x%08X gdpr(init=%u done=%u "
         "fadeOut=%u fadeIn=%u blocked=%u) audioConverted=%u pendingStart=%u files=%u %u/%u",
         state, complete, host.MemoryRead32(g_base + 0xDD5830),
         host.MemoryRead32(screen + 3085 * 4), gdpr,
         host.MemoryRead32(screen + 3090 * 4), host.MemoryRead32(screen + 3091 * 4),
         host.MemoryRead32(screen + 3086 * 4), host.MemoryRead32(screen + 3216 * 4),
         host.MemoryRead32(screen + 18279 * 4), host.MemoryRead32(screen + 3081 * 4),
         host.MemoryRead32(screen + 3082 * 4), host.MemoryRead32(screen + 3083 * 4));
}

}  // namespace

void RegisterGuestThread(DynarmicHost& host, uint32_t start_func, uint32_t arg) {
    if (!Resolve(host) || !arg) return;
    if (start_func != g_base + kThreadWrapper) return;   // not an XGSThread

    const uint32_t entry = host.MemoryRead32(arg + kThreadEntry);
    const uint32_t param = host.MemoryRead32(arg + kThreadParam);
    if (entry == g_base + kJobSchedThreadFn) {
        AddScheduler(param, "CXGSNormalJobScheduler");
    } else if (entry == g_base + kJobQueueThreadFn) {
        AddScheduler(param, "CXGSJobQueue");
    } else if (entry == g_base + kCommonThreadEntry) {
        // The global scheduler's workers steal from the two schedulers it owns, not from a
        // list of its own, so register those instead of the global object.
        AddScheduler(host.MemoryRead32(param + kGlobalFrameSched), "GJQ_Frame");
        AddScheduler(host.MemoryRead32(param + kGlobalEpicSched),  "GJQ_Epic");
    }

    bool runnable = false;
    for (uint32_t r : kRunnableThreads) runnable |= (entry == g_base + r);
    if (runnable) {
        g_pending_threads.push_back({arg, entry, param});
        return;
    }

    // Never going to run: say so in the object, because GetExitCode is polled in a spin loop.
    host.MemoryWrite32(arg + kThreadExitFlag, 1);
    host.MemoryWrite32(arg + kThreadExitCode, 0);

    const uint32_t off = entry >= g_base ? entry - g_base : entry;
    for (uint32_t seen : g_seen_thread_entries) if (seen == entry) return;
    g_seen_thread_entries.push_back(entry);
    LOGI("guest thread body not run: libABK+0x%X (marked exited)", off);
}

// The guest's cooperative yield point.
//
// CApp::MainLoadingFunc finishes with
//     while (!saveMgr[260]) { if (ms_bPermanentlyDisabled) break; XGSThread::SleepThread(1); }
// and saveMgr[260] is set only by CSaveManager::Update, which CApp::ProcessFrame calls once a
// frame. On the device MainLoadingFunc is a job on a worker thread, so the render thread keeps
// calling Update while it waits. Here the job runs *on* the render thread, so the frame that
// would advance the save state machine is the frame the loop is blocking -- a deadlock that no
// amount of sleeping resolves.
//
// SleepThread lands in the usleep thunk, which is exactly where a cooperative scheduler gets
// its turn. Advance the save state machine there, on the nested Jit (we are inside Jit::Run).
// Guarded against re-entry: nesting is one level deep.
void OnGuestYield(DynarmicHost& host, uint32_t lr) {
    if (!g_base) return;
    static bool in_yield = false;
    if (in_yield) return;

    // The watchdog's blind spot. It trips when RunFunction stops advancing m_run_seq, but a
    // guest spin of the shape `while (flag) XGSThread::SleepThread(1)` arrives here every
    // iteration and the nested CSaveManager::Update below bumps m_run_seq each time -- so the
    // wedge looks like healthy progress and nothing is ever printed. That is how a job that
    // waits for a Skynest callback stopped the render loop with no crash, no watchdog line and
    // no ANR. Frames are the honest clock: if the pump has not run a frame for seconds while
    // yields keep coming, name the guest address that is spinning.
    {
        static uint64_t last_frame = 0;
        static struct timespec since = {0, 0};
        static int reported = 0;
        struct timespec t{};
        clock_gettime(CLOCK_MONOTONIC, &t);
        if (g_pump_frames != last_frame) {
            last_frame = g_pump_frames;
            since = t;
            reported = 0;
        } else if (since.tv_sec) {
            const int64_t sec = t.tv_sec - since.tv_sec;
            if (sec >= 3 && sec / 10 >= reported) {
                reported = static_cast<int>(sec / 10) + 1;
                LOGE("guest spin: no frame for %lld s, yield from libABK+0x%X",
                     static_cast<long long>(sec), lr >= g_base ? lr - g_base : lr);
            }
        }
    }

    // The guest asks to sleep a millisecond at a time and usleep is a no-op here, so a spin
    // loop reaches this thousands of times per frame. CSaveManager::Update is not cheap -- it
    // walks DOCS: and can serialise the whole save -- so run it at the rate the frame loop
    // would have, not at the rate of the spin.
    static struct timespec last = {0, 0};
    struct timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    const int64_t elapsed_us = (now.tv_sec - last.tv_sec) * 1000000LL +
                               (now.tv_nsec - last.tv_nsec) / 1000;
    if (elapsed_us < 4000) return;
    last = now;

    in_yield = true;

    constexpr uint32_t kSaveManagerUpdate = 0x158DA0;
    constexpr uint32_t kDt = 0x3C888889;      // 0.016666f, softfp: the bits go in r1
    const uint32_t app  = host.MemoryRead32(g_base + 0xDABECC);          // g_pApplication
    const uint32_t game = app ? host.MemoryRead32(app + 52) : 0;         // CApp::m_pGame
    const uint32_t save = game ? host.MemoryRead32(game + 32) : 0;       // CGame::m_pSaveManager
    if (save) host.RunFunctionNested(g_base + kSaveManagerUpdate, {save, kDt});

    in_yield = false;
}

void PumpGuestJobs(DynarmicHost& host) {
    ++g_pump_frames;
    if (!g_base || g_schedulers.empty()) return;
    if (!g_scratch) {
        g_scratch = host.GuestAlloc(4, 4);
        if (!g_scratch) { LOGE("job pump: no guest word for the completion slot"); return; }
    }

    // One sweep per frame, over the jobs that were pending when the sweep started. The whole
    // list is detached first, so work posted *by* these jobs lands in a now-empty list and is
    // picked up next frame. Draining re-posted jobs in the same pass is what a real worker
    // thread would never do either: CXGSSound::StreamMonitorJob re-queues itself every time it
    // runs, so it looped 256 times per frame until the budget cut it off.
    int budget = 4096;
    for (size_t i = 0; i < g_schedulers.size() && budget > 0; ++i) {
        const uint32_t sched = g_schedulers[i];
        uint32_t job = host.MemoryRead32(sched + 8);
        if (!job) continue;
        host.MemoryWrite32(sched + 8, 0);            // detach the whole chain at once
        host.MemoryWrite32(sched + 12, sched + 8);

        while (job && budget-- > 0) {
            const uint32_t next = host.MemoryRead32(job + 4);
            RunOneJob(host, sched, job);
            job = next;
        }
    }
    if (g_next_thread < g_pending_threads.size()) {
        const PendingThread t = g_pending_threads[g_next_thread++];
        LOGI("guest thread body: running libABK+0x%X(0x%08X)",
             t.entry >= g_base ? t.entry - g_base : t.entry, t.param);
        const uint32_t rc = host.RunFunction(t.entry, {t.param, 0});
        // What XGSThread::ThreadWrapper does on the way out, minus the JNI detach: this is the
        // render thread and it must stay attached to the VM.
        host.MemoryWrite32(t.obj + kThreadExitCode, rc);
        host.MemoryWrite32(t.obj + kThreadExitFlag, 1);
    }
    if (budget <= 0) {
        static int reported = 0;
        if (reported++ < 4) LOGE("job pump: hit the job budget in one frame");
    }

    LogDownloadScreenState(host);
}
