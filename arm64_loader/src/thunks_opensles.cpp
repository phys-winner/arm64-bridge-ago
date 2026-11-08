#include "thunks_opensles.h"
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include "guest_jobs.h"

#include <SLES/OpenSLES.h>
#include <SLES/OpenSLES_Android.h>
#include <android/log.h>
#include <cstring>
#include <vector>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <set>
#include <tuple>
#include <algorithm>
#include <deque>

#if defined(__ANDROID__)
#include <sys/resource.h>
#endif

#define LOG_TAG "GOF2_OpenSLES"
#include "bridge_log.h"

namespace {

DynarmicHost* g_opensles_host = nullptr;

// Host OpenSL ES global state
SLObjectItf g_hostEngineObject = nullptr;
SLEngineItf g_hostEngineEngine = nullptr;
SLObjectItf g_hostOutputMixObject = nullptr;
SLObjectItf g_hostPlayerObject = nullptr;
SLPlayItf g_hostPlayerPlay = nullptr;
SLAndroidSimpleBufferQueueItf g_hostPlayerBufferQueue = nullptr;
SLVolumeItf g_hostPlayerVolume = nullptr;

// Guest addresses for objects & vtables
uint32_t g_guestEngineObjectAddr = 0;
uint32_t g_guestEngineVtblAddr = 0;
uint32_t g_guestEngineInterfaceAddr = 0;
uint32_t g_guestEngineInterfaceVtblAddr = 0;

uint32_t g_guestOutputMixObjectAddr = 0;
uint32_t g_guestOutputMixVtblAddr = 0;

uint32_t g_guestPlayerObjectAddr = 0;
uint32_t g_guestPlayerVtblAddr = 0;
uint32_t g_guestPlayInterfaceAddr = 0;
uint32_t g_guestPlayInterfaceVtblAddr = 0;
uint32_t g_guestBufferQueueInterfaceAddr = 0;
uint32_t g_guestBufferQueueInterfaceVtblAddr = 0;
uint32_t g_guestVolumeInterfaceAddr = 0;
uint32_t g_guestVolumeInterfaceVtblAddr = 0;

// A guest vtable here is 64 slots of raw heap and only the handful of methods below get
// written, so any other slot the engine calls is whatever the block last held. That used to
// read as zero (fresh arena is zero-filled) and now reads as recycled junk, but both jump the
// guest somewhere arbitrary and hang it until the watchdog fires. Point every slot at one
// loud stub first and let the real methods overwrite it: an unimplemented call then returns
// FEATURE_UNSUPPORTED and prints the guest LR that made it, which names the call site exactly.
// The stub itself is registered once from RegisterOpenSLESThunks, never from here: every
// vtable is built inside a running thunk, and ThunkManager::RegisterThunk ends in
// InvalidateGuestCode -> Jit::InvalidateCacheRange, which must not be called while Jit::Run
// is on the stack (HaltExecution is the only safe call). Doing it lazily froze the boot the
// moment slCreateEngine ran: the thunk never finished and the guest sat on the splash screen.
void FillGuestVtableWithStubs(DynarmicHost& host, uint32_t vtbl) {
    const uint32_t stub = host.GetThunkManager().GetOrCreateThunkAddress("SL_UnimplementedMethod");
    for (int i = 0; i < 64; ++i) host.MemoryWrite32(vtbl + i * 4, stub);
}

static constexpr size_t BUFFER_QUEUE_COUNT = 32;
static constexpr size_t MAX_BUFFER_SIZE = 16384;
static std::mutex g_audioMutex;

// One host audio player per guest audio player.
//
// This used to be a single set of globals shared by every CreateAudioPlayer, which is wrong
// for this engine: the ARM32 build runs ~29 AudioTracks during a race, one per voice plus the
// music stream. Sharing one host player meant each new sound overwrote the previous one's
// buffer-queue callback, and a Clear() or SetPlayState(STOPPED) on any voice cut whatever was
// actually playing. Interface vtables stay shared (they hold no state); what becomes
// per-player is the guest object block, so `self` in each thunk identifies the voice.
struct GuestPlayer {
    uint32_t obj = 0;         // guest SLObjectItf
    uint32_t play_itf = 0;
    uint32_t bq_itf = 0;
    uint32_t vol_itf = 0;
    uint32_t cfg_itf = 0;

    SLObjectItf hobj = nullptr;
    SLPlayItf hplay = nullptr;
    SLAndroidSimpleBufferQueueItf hbq = nullptr;
    SLVolumeItf hvol = nullptr;

    uint32_t cb_fn = 0, cb_ctx = 0;
    std::atomic<int> pending{0};

    // A one-shot SFX destroys its player from inside its own buffer-queue callback. The
    // delivery lock plus this flag let that teardown happen while PumpOpenSLESCallbacks
    // stands in its delivery loop: the pump keeps the shared_ptr alive, refuses new
    // deliveries once destroyed is set, and never iterates a container being mutated.
    std::atomic<bool> destroyed{false};
    std::recursive_mutex delivery_mutex;

    // Set by PauseAudioPlayback: only voices that were actually playing come back on
    // Resume, instead of force-starting everything including deliberately stopped ones.
    bool resume_after_pause = false;

    // CXGSSound_2DSound_OpenSL::Flush re-applies volume and stereo position to every live 2D
    // sound on every frame, and each host SetVolumeLevel makes AudioTrack print a line. With a
    // dozen voices in a race that is ~1000 lines/s charged to this process, well past the
    // firmware's ~300 lines/s flow-control quota -- which then drops the bridge's own
    // diagnostics silently. The values almost never actually change, so remember them and only
    // call through on a real change. Sentinels are out of range for millibels and permille.
    int32_t last_vol = INT32_MIN;
    int32_t last_pan = INT32_MIN;
    int last_mute = -1, last_stereo_on = -1;

    // Same idea for the transport. SetPlayState is a synchronous AudioTrack call whether or
    // not it changes anything, ~2.5 ms of it on this device, and the engine stops voices that
    // are already stopped -- AudioTrack logs "stop(): prior state:STATE_STOPPED" for every
    // one. A fresh player is STOPPED, and so is one taken back out of the pool.
    SLuint32 last_state = SL_PLAYSTATE_STOPPED;

    // What this voice was built for, so a released host player can be matched to the next
    // request. The engine only ever asks for mono and stereo 48 kHz.
    SLuint32 fmt_channels = 0, fmt_rate = 0, fmt_mask = 0;

    // Telemetry. "The sound stopped" has three very different causes -- the guest stopped
    // enqueuing, we rejected what it enqueued, or the hardware stopped completing buffers --
    // and these three counters say which one it was without another build.
    uint64_t enq_ok = 0, enq_full = 0, enq_error = 0, cbs = 0, callbacks_dropped = 0, bytes = 0;

    // Host-side copies of what the guest enqueued. One vector per queue slot, grown to fit
    // whatever arrives: the music stream hands over 17952- and 19200-byte blocks and a fixed
    // 16384-byte slot silently dropped the tail of every one of them, which is what made the
    // music run fast -- roughly 15% of each buffer never reached the mixer.
    std::vector<std::vector<uint8_t>> ring{BUFFER_QUEUE_COUNT};
    size_t ring_idx = 0;
    uint32_t max_seen = 0;
};

static std::vector<std::shared_ptr<GuestPlayer>> g_players;
static std::unordered_map<uint32_t, GuestPlayer*> g_itf_owner;   // any guest itf/obj -> player
// Android will not hand out unlimited AudioTracks; past this the engine gets a clean
// resource error for the extra voice instead of a failed allocation deeper in.
static constexpr size_t kMaxHostPlayers = 32;   // the ARM32 build peaks at ~29 voices

// Host players that SLObject_Destroy parked instead of destroying, ready for the next
// CreateAudioPlayer of the same PCM format.
//
// Building one costs 14-18 ms on this device: CreateAudioPlayer + Realize is a synchronous
// round trip into AudioFlinger that allocates an AudioTrack and walks the vendor effect
// chain (this firmware hangs Dolby, AudioBoost and DetectScene off every track). The engine
// builds one player per sound effect and destroys it when the sound ends, so a collision --
// which fires one or two impact SFX in a single frame -- cost 14-37 ms inside the frame and
// dropped 2 to 4 vsyncs. Recycling is free: only the buffer contents and the callback
// context belonged to the old voice, and both are reset on the way in.
// Entries are the whole GuestPlayer, not just the host handles -- see SLObject_Destroy.
static std::vector<std::shared_ptr<GuestPlayer>> g_player_pool;
// Live voices peak at ~8 across two formats, so this is slack, not a target. A parked track
// still holds an AudioTrack open, which is why it is bounded at all.
// live (peaks at ~8) + pooled stays under kMaxHostPlayers, which is the real ceiling.
static constexpr size_t kMaxPooledPlayers = 16;
// Spares built the first time a format is asked for, so a race start does not have to build
// its voices one 14 ms stall at a time. Sized from what starved in a race, not from the
// steady-state voice count: the engine opens several sound effects before it closes any, so
// a pool that only matches the average still misses at exactly the wrong moment.
static constexpr size_t kPrewarmPerFormat = 8;

static GuestPlayer* PlayerFor(uint32_t guest_addr) {
    auto it = g_itf_owner.find(guest_addr);
    return it == g_itf_owner.end() ? nullptr : it->second;
}

// Put the guest's transport state on the host player, mapping STOPPED to PAUSED.
//
// AudioTrack::stop() drains the mixer before it returns; pausing is a flag in the shared
// control block. The engine stops a voice and starts it again for every sound effect it
// plays, so that drain landed in the frame a collision happened in, several times over.
//
// Only the stop side is avoidable. Leaving the track PLAYING with an empty queue instead was
// measured and is worse: AudioFlinger disables an underrunning track, and the client then
// restarts it from inside the next Enqueue -- the same 6 ms, moved onto a call the guest
// makes more often. The start itself (5-10 ms here: AudioPolicy startOutput plus this
// firmware's Dolby/AudioBoost/DetectScene chain) has to be paid somewhere on this thread.
//
// Nothing the guest can observe changes: a buffer-queue player has no playhead for STOPPED to
// rewind, the queue survives STOPPED by spec either way, and the engine empties it with an
// explicit Clear when it wants it empty. SLPlay_GetPlayState answers from last_state, so a
// read-back still returns the state the guest asked for, not the one the track is in.
//
// And it is handed to a worker rather than run here. The guest cannot see the difference --
// GetPlayState is answered from last_state and nothing else reads the transport -- but the
// render thread stops paying for it, which is the whole point: a collision starts four to
// nine voices in one frame and that was 13-27 ms of a 35-53 ms frame after everything else
// had been dealt with.
//
// Ordering is the one thing that must hold, so every transport call for every player goes
// through one queue in the order the guest issued it. Enqueue and Clear stay synchronous;
// they are cheap and they must stay ordered against each other. A start that overtakes a
// Clear can only end in silence on a voice the guest was silencing anyway.
struct PlayStateOp { GuestPlayer* p; SLuint32 state; };
std::deque<PlayStateOp> g_play_ops;
std::mutex g_play_mutex;
std::condition_variable g_play_cv;
std::atomic<bool> g_play_worker_running{false};
size_t g_play_in_flight = 0;               // popped but not yet applied

void PlayStateWorker() {
    for (;;) {
        PlayStateOp op;
        {
            std::unique_lock<std::mutex> lock(g_play_mutex);
            g_play_cv.wait(lock, [] { return !g_play_ops.empty(); });
            op = g_play_ops.front();
            g_play_ops.pop_front();
            ++g_play_in_flight;
        }
        // Deliberately not under g_audioMutex: the render thread drains this queue while
        // holding it, and Android locks each OpenSL object internally anyway, so a transport
        // call needs no lock of ours to be safe against a concurrent Enqueue or Clear.
        if (op.p->hplay) (*op.p->hplay)->SetPlayState(op.p->hplay, op.state);
        {
            std::lock_guard<std::mutex> lock(g_play_mutex);
            --g_play_in_flight;
        }
        g_play_cv.notify_all();                     // for DrainPlayStateOps
    }
}

// Block until every queued transport call has been applied. Needed wherever a player is about
// to stop existing or the whole engine has to be quiet by the time we return.
void DrainPlayStateOps() {
    if (!g_play_worker_running.load(std::memory_order_relaxed)) return;
    std::unique_lock<std::mutex> lock(g_play_mutex);
    g_play_cv.wait(lock, [] { return g_play_ops.empty() && g_play_in_flight == 0; });
}

static void SetHostPlayState(GuestPlayer* p, SLuint32 logical) {
    if (!p || !p->hplay) return;
    const SLuint32 want = (logical == SL_PLAYSTATE_STOPPED) ? SL_PLAYSTATE_PAUSED : logical;
    if (!g_play_worker_running.exchange(true)) std::thread(PlayStateWorker).detach();
    {
        std::lock_guard<std::mutex> lock(g_play_mutex);
        g_play_ops.push_back({p, want});
    }
    g_play_cv.notify_one();
}

static uint32_t g_guestConfigInterfaceAddr = 0;
static uint32_t g_guestConfigInterfaceVtblAddr = 0;

static std::unordered_map<std::string, uint32_t> g_iid_pointer_map;
static std::atomic<int> g_bqCallbackPending{0};

// Background Audio Thread synchronization
static std::atomic<bool> g_audioThreadRunning{false};
static std::atomic<bool> g_audioPaused{false};
static std::mutex g_audioCvMutex;
static std::condition_variable g_audioCv;
static std::unique_ptr<std::thread> g_audioThread;

// Host OpenSL ES Buffer Queue Callback (fired on real-time audio thread by Android HAL).
// Only counts: the guest callback it stands for has to run on the thread that owns the JIT.
static void HostBqPlayerCallback(SLAndroidSimpleBufferQueueItf bq, void *context) {
    auto* p = static_cast<GuestPlayer*>(context);
    if (!p || p->destroyed.load(std::memory_order_acquire)) return;
    p->pending.fetch_add(1, std::memory_order_relaxed);
    g_bqCallbackPending.fetch_add(1, std::memory_order_relaxed);
    g_audioCv.notify_one();
}

bool IID_Matches(DynarmicHost& host, uint32_t iid_ptr, const SLInterfaceID host_iid) {
    if (iid_ptr == 0 || !host_iid) return false;
    const void* pStruct = host_iid;

    if (iid_ptr + sizeof(struct SLInterfaceID_) <= host.GetGuestMemorySize()) {
        const void* guest1 = host.GetGuestMemoryBase() + iid_ptr;
        if (memcmp(guest1, pStruct, sizeof(struct SLInterfaceID_)) == 0) return true;
    }

    if (iid_ptr + 4 <= host.GetGuestMemorySize()) {
        uint32_t deref = host.MemoryRead32(iid_ptr);
        if (deref != 0 && deref + sizeof(struct SLInterfaceID_) <= host.GetGuestMemorySize()) {
            const void* guest2 = host.GetGuestMemoryBase() + deref;
            if (memcmp(guest2, pStruct, sizeof(struct SLInterfaceID_)) == 0) return true;
        }
    }
    return false;
}

static uint32_t AllocAndRegisterIID(ThunkManager& manager, DynarmicHost& host, const std::string& name, const SLInterfaceID host_iid) {
    // 1. Allocate 16 bytes for struct SLInterfaceID_
    uint32_t struct_addr = host.GuestAlloc(sizeof(struct SLInterfaceID_), 4);
    if (host_iid) {
        memcpy(host.GetGuestMemoryBase() + struct_addr, host_iid, sizeof(struct SLInterfaceID_));
    }

    // 2. Allocate 4 bytes for pointer to struct
    uint32_t ptr_addr = host.GuestAlloc(4, 4);
    host.MemoryWrite32(ptr_addr, struct_addr);

    // 3. Register in ThunkManager and map
    manager.RegisterSymbol(name, ptr_addr);
    g_iid_pointer_map[name] = ptr_addr;

    return ptr_addr;
}

} // namespace

bool HasPendingAudioCallbacks() {
    return g_bqCallbackPending.load(std::memory_order_relaxed) > 0;
}

void PumpOpenSLESCallbacks(DynarmicHost& host) {
    if (g_audioPaused.load(std::memory_order_relaxed)) return;
    if (host.IsJitRunning()) return;

    // Work on a snapshot: the guest callback below may destroy its own player (the
    // one-shot SFX pattern), which erases from g_players while this loop is walking it.
    // shared_ptr keeps the object alive for the rest of the pass.
    std::vector<std::shared_ptr<GuestPlayer>> snapshot;
    {
        std::lock_guard<std::mutex> lock(g_audioMutex);
        snapshot.assign(g_players.begin(), g_players.end());
    }

    // Exactly as many callbacks as the hardware actually completed -- one short and the
    // stream underruns, one extra and the guest produces a buffer with nowhere to go.
    // Subtracting what was consumed (instead of wiping the global counter) keeps
    // g_bqCallbackPending == sum(pending) even with this pump and the audio thread's
    // pump both draining.
    int delivered = 0;
    for (auto& sp : snapshot) {
        GuestPlayer* p = sp.get();
        std::lock_guard<std::recursive_mutex> delivery_lock(p->delivery_mutex);
        if (p->destroyed.load(std::memory_order_acquire)) {
            delivered += p->pending.exchange(0, std::memory_order_acq_rel);
            continue;
        }
        if (!p->cb_fn) {
            delivered += p->pending.exchange(0, std::memory_order_relaxed);
            continue;
        }
        const int n = p->pending.exchange(0, std::memory_order_acq_rel);
        delivered += n;
        for (int i = 0; i < n; ++i) {
            // Do not cap this at BUFFER_QUEUE_COUNT. A busy render frame can let more than
            // one queue's worth of completions accumulate; dropping the rest loses the
            // guest refill callbacks and makes otherwise healthy voices go silent.
            if (p->destroyed.load(std::memory_order_acquire)) {
                p->callbacks_dropped += static_cast<uint64_t>(n - i);
                break;
            }
            ++p->cbs;
            host.RunFunction(p->cb_fn, {p->bq_itf, p->cb_ctx});
        }
    }
    if (delivered > 0)
        g_bqCallbackPending.fetch_sub(delivered, std::memory_order_acq_rel);
}

void PumpAudioWorkers(DynarmicHost& host) {
    if (g_audioPaused.load(std::memory_order_relaxed)) return;
    const auto& workers = GetGuestThreadWorkers();
    for (size_t wi = 0; wi < workers.size(); ++wi) {
        const auto& worker = workers[wi];
        if (worker.arg) {
            host.MemoryWrite8(worker.arg + 0x10c, 1);
            host.MemoryWrite8(worker.arg + 0x134, 1);
            uint32_t worker_func = host.MemoryRead32(worker.arg + 0x120);
            uint32_t worker_arg = host.MemoryRead32(worker.arg + 0x110);
            if (!worker_func) {
                uint32_t vtable = host.MemoryRead32(worker.arg);
                if (vtable) {
                    worker_func = host.MemoryRead32(vtable);
                    worker_arg = worker.arg;
                }
            }
            if (worker_arg && worker_arg != worker.arg) {
                host.MemoryWrite8(worker_arg + 0x10c, 1);
                host.MemoryWrite8(worker_arg + 0x134, 1);
            }
            if (worker_func) {
                host.RunFunction(worker_func, {worker_arg});
            }
        }
    }
}

static void AudioThreadLoop(DynarmicHost* host) {
    LOGI("GOF2 Dedicated Audio Thread started with high priority!");
#if defined(__ANDROID__)
    setpriority(PRIO_PROCESS, 0, -16); // High priority audio thread
#endif

    while (g_audioThreadRunning.load(std::memory_order_relaxed)) {
        {
            std::unique_lock<std::mutex> lock(g_audioCvMutex);
            g_audioCv.wait_for(lock, std::chrono::milliseconds(5), []() {
                return !g_audioThreadRunning.load(std::memory_order_relaxed) ||
                       g_bqCallbackPending.load(std::memory_order_relaxed) > 0;
            });
        }

        if (!g_audioThreadRunning.load(std::memory_order_relaxed)) break;
        if (!host || g_audioPaused.load(std::memory_order_relaxed)) continue;

        if (g_bqCallbackPending.load(std::memory_order_relaxed) > 0) {
            TraceEvent("AUD_PUMP_ENTER", static_cast<uint32_t>(reinterpret_cast<uintptr_t>(host)));
            std::lock_guard<std::recursive_mutex> lock(host->GetMutex());
            // The music refill the guest runs from its buffer-queue callback waits on the
            // engine's own stream job (CXGSSound::StreamMonitorJob re-queues itself every
            // pass), and with no guest threads only the job pump advances those. The pump
            // otherwise lives on GLThread -- which is blocked on this very mutex while we
            // are delivering -- so a refill that needs one pass of the stream job would
            // spin here forever, holding the JIT: no frames, no watchdog, frozen surface.
            // Run the pending jobs before the callbacks, exactly like nativeDrawFrame does.
            PumpGuestJobs(*host);
            PumpOpenSLESCallbacks(*host);
            TraceEvent("AUD_PUMP_EXIT", 0, 0);
        }
    }

    LOGI("GOF2 Dedicated Audio Thread stopped.");
}

void StartAudioThread(DynarmicHost* host) {
    if (g_audioThreadRunning.load(std::memory_order_relaxed)) return;
    if (!host) return;
    g_audioThreadRunning.store(true, std::memory_order_relaxed);
    g_audioPaused.store(false, std::memory_order_relaxed);
    g_audioThread = std::make_unique<std::thread>(AudioThreadLoop, host);
    LOGI("Audio thread launched successfully!");
}

void StopAudioThread() {
    if (!g_audioThreadRunning.load(std::memory_order_relaxed)) return;
    g_audioThreadRunning.store(false, std::memory_order_relaxed);
    g_audioCv.notify_all();
    if (g_audioThread && g_audioThread->joinable()) {
        g_audioThread->join();
    }
    g_audioThread.reset();
}

void PauseAudioPlayback() {
    LOGI("PauseAudioPlayback requested");
    g_audioPaused.store(true, std::memory_order_release);
    // The audio thread's pump walks this same set under the host mutex; the caller (the
    // platform thread delivering nativePause) holds nothing, so take it here too.
    if (g_opensles_host) {
        std::lock_guard<std::recursive_mutex> host_lock(g_opensles_host->GetMutex());
        // Parked players are already paused, so g_players is the whole live set. Straight to
        // the host and then drain: the app is going to the background and everything queued
        // behind this would otherwise start a voice after we said we were quiet.
        for (auto& p : g_players)
            if (p->hplay) {
                p->resume_after_pause = (p->last_state == SL_PLAYSTATE_PLAYING);
                p->last_state = SL_PLAYSTATE_PAUSED;   // keep SLPlay_SetPlayState's cache honest
                SetHostPlayState(p.get(), SL_PLAYSTATE_PAUSED);
            }
        DrainPlayStateOps();
    }
}

void ResumeAudioPlayback() {
    LOGI("ResumeAudioPlayback requested");
    g_audioPaused.store(false, std::memory_order_release);
    if (g_opensles_host) {
        std::lock_guard<std::recursive_mutex> host_lock(g_opensles_host->GetMutex());
        // Only what was actually playing comes back. Force-starting every voice also
        // force-started ones the guest had deliberately stopped, with empty queues.
        for (auto& p : g_players)
            if (p->hplay && p->resume_after_pause) {
                p->resume_after_pause = false;
                p->last_state = SL_PLAYSTATE_PLAYING;
                SetHostPlayState(p.get(), SL_PLAYSTATE_PLAYING);
            }
    }
}

// One line, not one per voice: a race runs a dozen players and this fires every 300 frames,
// which on this device's log flow control pushes real diagnostics out of the buffer.
// kAudioVerbose breaks it back out per player when a specific voice is under investigation.
constexpr bool kAudioVerbose = false;

void LogAudioStats() {
    if (g_players.empty()) return;
    size_t playing = 0, queued = 0;
    uint64_t enq = 0, full = 0, errors = 0, cbs = 0, dropped = 0;
    for (size_t i = 0; i < g_players.size(); ++i) {
        GuestPlayer* p = g_players[i].get();
        SLAndroidSimpleBufferQueueState st = {0, 0};
        if (p->hbq) (*p->hbq)->GetState(p->hbq, &st);
        SLuint32 ps = 0;
        if (p->hplay) (*p->hplay)->GetPlayState(p->hplay, &ps);
        if (ps == SL_PLAYSTATE_PLAYING) ++playing;
        queued += st.count;
        enq += p->enq_ok; full += p->enq_full; errors += p->enq_error;
        cbs += p->cbs; dropped += p->callbacks_dropped;
        if (kAudioVerbose)
            LOGI("  audio[%zu] obj=0x%08X play=%u queued=%u enq=%llu full=%llu err=%llu cb=%llu drop=%llu",
                 i, p->obj, ps, st.count,
                 static_cast<unsigned long long>(p->enq_ok),
                 static_cast<unsigned long long>(p->enq_full),
                 static_cast<unsigned long long>(p->enq_error),
                 static_cast<unsigned long long>(p->cbs),
                 static_cast<unsigned long long>(p->callbacks_dropped));
    }
    LOGI("  audio: %zu players (%zu playing) queued=%zu enq=%llu full=%llu err=%llu cb=%llu drop=%llu",
         g_players.size(), playing, queued,
         static_cast<unsigned long long>(enq),
         static_cast<unsigned long long>(full),
         static_cast<unsigned long long>(errors),
         static_cast<unsigned long long>(cbs),
         static_cast<unsigned long long>(dropped));
}

uint32_t GetOpenSLESInterfacePointer(const std::string& name) {
    auto it = g_iid_pointer_map.find(name);
    if (it != g_iid_pointer_map.end()) {
        return it->second;
    }
    return 0;
}

void RegisterOpenSLESThunks(ThunkManager& manager, DynarmicHost& host) {
    g_opensles_host = &host;
    LOGI("Registering OpenSL ES guest bridge thunks...");

    // Backstop for every vtable slot no interface below fills in; see FillGuestVtableWithStubs.
    manager.RegisterThunk("SL_UnimplementedMethod", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        static int hits = 0;
        if (hits++ < 8)
            LOGE("OpenSL: unimplemented interface method, self=0x%08X called from libABK LR 0x%08X",
                 jit.Regs()[0], jit.Regs()[14]);
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });

    // Register all standard OpenSL ES interface IDs
    AllocAndRegisterIID(manager, host, "SL_IID_ENGINE", SL_IID_ENGINE);
    AllocAndRegisterIID(manager, host, "SL_IID_ANDROIDSIMPLEBUFFERQUEUE", SL_IID_ANDROIDSIMPLEBUFFERQUEUE);
    AllocAndRegisterIID(manager, host, "SL_IID_ANDROIDCONFIGURATION", SL_IID_ANDROIDCONFIGURATION);
    AllocAndRegisterIID(manager, host, "SL_IID_PLAY", SL_IID_PLAY);
    AllocAndRegisterIID(manager, host, "SL_IID_VOLUME", SL_IID_VOLUME);
    AllocAndRegisterIID(manager, host, "SL_IID_OUTPUTMIX", SL_IID_OUTPUTMIX);
    AllocAndRegisterIID(manager, host, "SL_IID_BUFFERQUEUE", SL_IID_BUFFERQUEUE);
    AllocAndRegisterIID(manager, host, "SL_IID_RECORD", SL_IID_RECORD);
    // libABK's .dynsym imports these three as STT_OBJECT and nothing provided them, so the
    // resolver fell back to a thunk trampoline and the guest passed *that* to GetInterface --
    // which is why the log showed an "IID" of 0xEF000329, an SVC opcode word. Registering
    // them does not implement them; GetInterface still answers FEATURE_UNSUPPORTED, which is
    // the honest answer and the one the engine already handles.
    AllocAndRegisterIID(manager, host, "SL_IID_PLAYBACKRATE", SL_IID_PLAYBACKRATE);
    AllocAndRegisterIID(manager, host, "SL_IID_SEEK", SL_IID_SEEK);
    AllocAndRegisterIID(manager, host, "SL_IID_ENGINECAPABILITIES", SL_IID_ENGINECAPABILITIES);

    // 1. slCreateEngine
    manager.RegisterThunk("slCreateEngine", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        uint32_t pEngine = jit.Regs()[0];
        LOGI("slCreateEngine called! pEngine=0x%08X", pEngine);

        // Initialize Host OpenSL ES
        if (!g_hostEngineObject) {
            SLresult result = slCreateEngine(&g_hostEngineObject, 0, nullptr, 0, nullptr, nullptr);
            if (result != SL_RESULT_SUCCESS) {
                LOGE("Host slCreateEngine failed: %u", result);
                jit.Regs()[0] = result;
                return;
            }

            result = (*g_hostEngineObject)->Realize(g_hostEngineObject, SL_BOOLEAN_FALSE);
            if (result != SL_RESULT_SUCCESS) {
                LOGE("Host Engine Realize failed: %u", result);
                jit.Regs()[0] = result;
                return;
            }

            result = (*g_hostEngineObject)->GetInterface(g_hostEngineObject, SL_IID_ENGINE, &g_hostEngineEngine);
            if (result != SL_RESULT_SUCCESS) {
                LOGE("Host Engine GetInterface failed: %u", result);
                jit.Regs()[0] = result;
                return;
            }

            // Create Host OutputMix
            result = (*g_hostEngineEngine)->CreateOutputMix(g_hostEngineEngine, &g_hostOutputMixObject, 0, nullptr, nullptr);
            if (result == SL_RESULT_SUCCESS) {
                (*g_hostOutputMixObject)->Realize(g_hostOutputMixObject, SL_BOOLEAN_FALSE);
            }
        }

        // Allocate Guest Engine Object structure
        if (g_guestEngineObjectAddr == 0) {
            g_guestEngineVtblAddr = host.GuestAlloc(64 * 4, 8);
            FillGuestVtableWithStubs(host, g_guestEngineVtblAddr);
            g_guestEngineObjectAddr = host.GuestAlloc(16, 8);
            host.MemoryWrite32(g_guestEngineObjectAddr, g_guestEngineVtblAddr);

            // Populate VTable with thunk addresses
            host.MemoryWrite32(g_guestEngineVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Realize"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 1 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Resume"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 2 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_GetState"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 3 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLEngine_GetInterface"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 4 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_RegisterCallback"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 5 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_AbortAsyncOperation"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 6 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Destroy"));
        }

        if (pEngine) {
            host.MemoryWrite32(pEngine, g_guestEngineObjectAddr);
        }

        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 2. Generic SLObject Thunks
    manager.RegisterThunk("SLObject_Realize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_Resume", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_GetState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t pState = jit.Regs()[1];
        if (pState) host.MemoryWrite32(pState, SL_OBJECT_STATE_REALIZED);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_RegisterCallback", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_AbortAsyncOperation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
    });

    manager.RegisterThunk("SLObject_Destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t self = jit.Regs()[0];
        GuestPlayer* p = PlayerFor(self);
        if (!p) return;              // engine or output mix: those live for the process
        // A one-shot SFX destroys its player from inside its own callback, i.e. from inside
        // PumpOpenSLESCallbacks holding this same recursive mutex. Taking it first (and
        // flagging) means the pump can never deliver another callback to a teardown that
        // has already started, and a re-entrant self-destroy does not deadlock.
        std::lock_guard<std::recursive_mutex> delivery_lock(p->delivery_mutex);
        if (p->destroyed.exchange(true, std::memory_order_acq_rel)) return;
        p->cb_fn = 0; p->cb_ctx = 0;
        // Keep the global accounting exact: whatever this player had queued up for
        // delivery is never going to be delivered.
        g_bqCallbackPending.fetch_sub(p->pending.exchange(0, std::memory_order_acq_rel),
                                      std::memory_order_acq_rel);
        // Whatever happens to the host player, the guest handles stop resolving now: a guest
        // that keeps calling methods on a destroyed player must reach no voice at all.
        for (uint32_t a : {p->obj, p->play_itf, p->bq_itf, p->vol_itf, p->cfg_itf})
            if (a) g_itf_owner.erase(a);

        {
            std::lock_guard<std::mutex> lock(g_audioMutex);
            // Park it for the next voice of this format rather than tearing the AudioTrack
            // down -- see g_player_pool. Stop it and drop what is still queued; the guest
            // identity is rebuilt on the way back out.
            const bool parked = p->hobj && p->hplay && p->hbq &&
                                g_player_pool.size() < kMaxPooledPlayers;
            if (parked) {
                // Parked paused, not stopped -- see SetHostPlayState.
                if (p->last_state != SL_PLAYSTATE_STOPPED)
                    SetHostPlayState(p, SL_PLAYSTATE_STOPPED);
                (*p->hbq)->Clear(p->hbq);
                p->cb_fn = 0; p->cb_ctx = 0;
                p->pending.store(0, std::memory_order_relaxed);
                p->last_state = SL_PLAYSTATE_STOPPED;
                p->last_vol = INT32_MIN; p->last_pan = INT32_MIN;
                p->last_mute = -1; p->last_stereo_on = -1;
                p->enq_ok = p->enq_full = p->enq_error = p->cbs = p->callbacks_dropped = p->bytes = 0;
                p->ring_idx = 0;
            } else {
                // The worker may still hold a queued SetPlayState for this player, and the
                // object is about to go away under it.
                DrainPlayStateOps();
                if (p->hobj) (*p->hobj)->Destroy(p->hobj);  // blocks until callbacks are done
                p->hobj = nullptr; p->hplay = nullptr; p->hbq = nullptr; p->hvol = nullptr;
                p->cb_fn = 0;
                p->pending.store(0, std::memory_order_relaxed);
            }
            for (auto it = g_players.begin(); it != g_players.end(); ++it) {
                if (it->get() != p) continue;
                // Moved whole, not just its host handles. HostBqPlayerCallback's context is
                // this object's address, and Android only accepts RegisterCallback while the
                // track is SL_PLAYSTATE_STOPPED -- a parked track is deliberately PAUSED, so
                // it can never be re-pointed at a replacement. Keeping the object means it
                // never has to be.
                if (parked) g_player_pool.push_back(std::move(*it));
                g_players.erase(it);
                break;
            }
        }
    });

    // 3. SLEngine_GetInterface
    manager.RegisterThunk("SLEngine_GetInterface", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        uint32_t self = jit.Regs()[0];
        uint32_t iid_ptr = jit.Regs()[1];
        uint32_t pInterface = jit.Regs()[2];


        if (IID_Matches(host, iid_ptr, SL_IID_ENGINE)) {
            if (g_guestEngineInterfaceAddr == 0) {
                g_guestEngineInterfaceVtblAddr = host.GuestAlloc(64 * 4, 8);
                FillGuestVtableWithStubs(host, g_guestEngineInterfaceVtblAddr);
                g_guestEngineInterfaceAddr = host.GuestAlloc(16, 8);
                host.MemoryWrite32(g_guestEngineInterfaceAddr, g_guestEngineInterfaceVtblAddr);

                // Populate SLEngineItf VTable
                host.MemoryWrite32(g_guestEngineInterfaceVtblAddr + 2 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLEngine_CreateAudioPlayer"));
                host.MemoryWrite32(g_guestEngineInterfaceVtblAddr + 7 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLEngine_CreateOutputMix"));
            }

            if (pInterface) {
                host.MemoryWrite32(pInterface, g_guestEngineInterfaceAddr);
            }
            jit.Regs()[0] = SL_RESULT_SUCCESS;
            return;
        }

        LOGI("SLEngine_GetInterface: unsupported IID 0x%08X", iid_ptr);
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });

    // 4. SLEngine_CreateOutputMix
    manager.RegisterThunk("SLEngine_CreateOutputMix", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        uint32_t pMix = jit.Regs()[1];
        LOGI("SLEngine_CreateOutputMix called! pMix=0x%08X", pMix);

        if (g_guestOutputMixObjectAddr == 0) {
            g_guestOutputMixVtblAddr = host.GuestAlloc(64 * 4, 8);
            FillGuestVtableWithStubs(host, g_guestOutputMixVtblAddr);
            g_guestOutputMixObjectAddr = host.GuestAlloc(16, 8);
            host.MemoryWrite32(g_guestOutputMixObjectAddr, g_guestOutputMixVtblAddr);

            host.MemoryWrite32(g_guestOutputMixVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Realize"));
            host.MemoryWrite32(g_guestOutputMixVtblAddr + 6 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Destroy"));
        }

        if (pMix) {
            host.MemoryWrite32(pMix, g_guestOutputMixObjectAddr);
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 5. SLEngine_CreateAudioPlayer
    manager.RegisterThunk("SLEngine_CreateAudioPlayer", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        uint32_t self = jit.Regs()[0];
        uint32_t pPlayer = jit.Regs()[1];
        uint32_t pAudioSrc = jit.Regs()[2];
        uint32_t pAudioSnk = jit.Regs()[3];
        uint32_t numInterfaces = jit.Regs()[4];
        LOGI("SLEngine_CreateAudioPlayer called! pPlayer=0x%08X, pAudioSrc=0x%08X, pAudioSnk=0x%08X",
             pPlayer, pAudioSrc, pAudioSnk);

        // Parse PCM parameters from guest
        SLuint32 numChannels = 2;
        SLuint32 sampleRate = SL_SAMPLINGRATE_44_1;
        SLuint32 channelMask = SL_SPEAKER_FRONT_LEFT | SL_SPEAKER_FRONT_RIGHT;

        if (pAudioSrc) {
            uint32_t pFormat = host.MemoryRead32(pAudioSrc + 4);
            if (pFormat) {
                const SLDataFormat_PCM* gfmt = reinterpret_cast<const SLDataFormat_PCM*>(
                    GuestToHost(host.GetGuestMemoryBase(), pFormat));
                if (gfmt && gfmt->formatType == SL_DATAFORMAT_PCM) {
                    numChannels = gfmt->numChannels;
                    sampleRate = gfmt->samplesPerSec;
                    channelMask = gfmt->channelMask;
                    LOGI("Extracted PCM format from guest: %u channels, %u mHz sampleRate", numChannels, sampleRate);
                }
            }
        }

        // Setup host OpenSL ES Audio Player
        SLDataLocator_AndroidSimpleBufferQueue loc_bufq = {
            SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE,
            static_cast<SLuint32>(BUFFER_QUEUE_COUNT)
        };

        SLDataFormat_PCM format_pcm = {
            SL_DATAFORMAT_PCM,
            numChannels,
            sampleRate,
            SL_PCMSAMPLEFORMAT_FIXED_16,
            SL_PCMSAMPLEFORMAT_FIXED_16,
            channelMask,
            SL_BYTEORDER_LITTLEENDIAN
        };

        SLDataSource audioSrc = { &loc_bufq, &format_pcm };

        SLDataLocator_OutputMix loc_outmix = {
            SL_DATALOCATOR_OUTPUTMIX,
            g_hostOutputMixObject
        };
        SLDataSink audioSnk = { &loc_outmix, nullptr };

        const SLInterfaceID ids[4] = { SL_IID_ANDROIDSIMPLEBUFFERQUEUE, SL_IID_PLAY, SL_IID_VOLUME, SL_IID_ANDROIDCONFIGURATION };
        const SLboolean req[4] = { SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE };

        if (!g_hostEngineEngine) {
            LOGE("CreateAudioPlayer before the engine exists");
            jit.Regs()[0] = SL_RESULT_RESOURCE_ERROR;
            return;
        }

        // Scoped: the guest allocations below must not run holding the audio lock. Everything
        // that touches a host interface the HAL callback can also see does.
        std::unique_lock<std::mutex> audio_lock(g_audioMutex);
        // A player of this format that a previous voice finished with costs nothing to take
        // back; building a new one costs 14-18 ms in the middle of the frame. See
        // g_player_pool.
        auto pooled = std::find_if(g_player_pool.begin(), g_player_pool.end(),
                                   [&](const std::shared_ptr<GuestPlayer>& e) {
                                       return e->fmt_channels == numChannels &&
                                              e->fmt_rate == sampleRate &&
                                              e->fmt_mask == channelMask;
                                   });
        std::shared_ptr<GuestPlayer> pl;
        const bool from_pool = pooled != g_player_pool.end();
        if (from_pool) {
            pl = std::move(*pooled);
            g_player_pool.erase(pooled);
            // Everything the previous voice set on the track has to go back to what a freshly
            // realized player would have, or a recycled voice inherits its pan and mute. The
            // buffer-queue callback is not re-registered -- it still points at this same
            // object, which is why the object was pooled rather than just its handles.
            std::lock_guard<std::recursive_mutex> delivery_lock(pl->delivery_mutex);
            // SLObject_Destroy marks the object dead before parking it. The old value was
            // never cleared on reuse, so HostBqPlayerCallback silently discarded every
            // completion for recycled voices: short SFX worked once, then later sounds were
            // truncated or never refilled. Re-arm the callback gate before exposing the player
            // to the guest again.
            pl->destroyed.store(false, std::memory_order_release);
            pl->cb_fn = 0;
            pl->cb_ctx = 0;
            pl->resume_after_pause = false;
            pl->last_state = SL_PLAYSTATE_STOPPED;
            pl->last_vol = INT32_MIN;
            pl->last_pan = INT32_MIN;
            pl->last_mute = -1;
            pl->last_stereo_on = -1;
            pl->ring_idx = 0;
            pl->max_seen = 0;
            if (pl->hvol) {
                (*pl->hvol)->SetMute(pl->hvol, SL_BOOLEAN_FALSE);
                (*pl->hvol)->EnableStereoPosition(pl->hvol, SL_BOOLEAN_FALSE);
            }
            pl->pending.store(0, std::memory_order_relaxed);
        } else {
            // Both the live voices and the parked ones hold an AudioTrack, so the platform
            // limit applies to the sum.
            const auto build = [&]() -> std::shared_ptr<GuestPlayer> {
                if (g_players.size() + g_player_pool.size() >= kMaxHostPlayers) return nullptr;
                auto np = std::make_shared<GuestPlayer>();
                np->fmt_channels = numChannels;
                np->fmt_rate = sampleRate;
                np->fmt_mask = channelMask;
                if ((*g_hostEngineEngine)->CreateAudioPlayer(
                        g_hostEngineEngine, &np->hobj, &audioSrc, &audioSnk, 4, ids, req)
                    != SL_RESULT_SUCCESS) {
                    return nullptr;
                }
                // Android stream type has to be set before Realize.
                SLAndroidConfigurationItf configItf = nullptr;
                if ((*np->hobj)->GetInterface(np->hobj, SL_IID_ANDROIDCONFIGURATION, &configItf) == SL_RESULT_SUCCESS) {
                    SLint32 streamType = SL_ANDROID_STREAM_MEDIA;
                    (*configItf)->SetConfiguration(configItf, SL_ANDROID_KEY_STREAM_TYPE, &streamType, sizeof(SLint32));
                }
                // A half-realized player used to pass as valid: Enqueue then answered SUCCESS
                // for it forever, so after any audio-server hiccup every later voice was
                // silently dead while the guest believed it was playing. Fail honestly instead
                // and hand the track back.
                if ((*np->hobj)->Realize(np->hobj, SL_BOOLEAN_FALSE) != SL_RESULT_SUCCESS) {
                    LOGE("Host AudioTrack Realize failed (%u ch @ %u mHz)", numChannels, sampleRate);
                    (*np->hobj)->Destroy(np->hobj);
                    np->hobj = nullptr;
                    return nullptr;
                }
                (*np->hobj)->GetInterface(np->hobj, SL_IID_PLAY, &np->hplay);
                (*np->hobj)->GetInterface(np->hobj, SL_IID_ANDROIDSIMPLEBUFFERQUEUE, &np->hbq);
                (*np->hobj)->GetInterface(np->hobj, SL_IID_VOLUME, &np->hvol);
                if (!np->hplay || !np->hbq) {
                    LOGE("Host AudioTrack missing interfaces: play=%p bq=%p",
                         static_cast<const void*>(np->hplay), static_cast<const void*>(np->hbq));
                    (*np->hobj)->Destroy(np->hobj);
                    np->hobj = nullptr; np->hplay = nullptr; np->hbq = nullptr;
                    return nullptr;
                }
                // Once, here, while the track is still SL_PLAYSTATE_STOPPED: Android rejects
                // RegisterCallback in any other state, and this player never returns to
                // STOPPED once it has been used (see SetHostPlayState).
                (*np->hbq)->RegisterCallback(np->hbq, HostBqPlayerCallback, np.get());
                return np;
            };

            pl = build();
            if (!pl) {
                LOGE("CreateAudioPlayer failed (%zu live + %zu pooled, limit %zu)",
                     g_players.size(), g_player_pool.size(), kMaxHostPlayers);
                jit.Regs()[0] = SL_RESULT_RESOURCE_ERROR;
                return;
            }

            // The first voice of a format pays for its track; the ones behind it in the same
            // race must not. Recycling alone does not cover a race start, where the engine
            // brings up several voices before it has finished with any -- the pool is still
            // empty and every one of those costs 14 ms inside a frame. Build the spares now,
            // at level-load time, where a stall is invisible.
            static std::set<std::tuple<SLuint32, SLuint32, SLuint32>> s_prewarmed;
            if (s_prewarmed.insert({numChannels, sampleRate, channelMask}).second) {
                size_t made = 0;
                while (made < kPrewarmPerFormat && g_player_pool.size() < kMaxPooledPlayers) {
                    auto spare = build();
                    if (!spare) break;
                    g_player_pool.push_back(std::move(spare));
                    ++made;
                }
                LOGI("pre-warmed %zu spare players for %u ch @ %u mHz",
                     made, numChannels, sampleRate);
            }
        }
        if (pl->hvol) (*pl->hvol)->SetVolumeLevel(pl->hvol, 0);   // 0 mB = unattenuated
        audio_lock.unlock();

        // Shared, stateless vtables; built once.
        if (g_guestPlayerVtblAddr == 0) {
            g_guestPlayerVtblAddr = host.GuestAlloc(64 * 4, 8);
            FillGuestVtableWithStubs(host, g_guestPlayerVtblAddr);
            host.MemoryWrite32(g_guestPlayerVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Realize"));
            host.MemoryWrite32(g_guestPlayerVtblAddr + 1 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Resume"));
            host.MemoryWrite32(g_guestPlayerVtblAddr + 2 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_GetState"));
            host.MemoryWrite32(g_guestPlayerVtblAddr + 3 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLPlayer_GetInterface"));
            host.MemoryWrite32(g_guestPlayerVtblAddr + 4 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_RegisterCallback"));
            host.MemoryWrite32(g_guestPlayerVtblAddr + 5 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_AbortAsyncOperation"));
            host.MemoryWrite32(g_guestPlayerVtblAddr + 6 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Destroy"));
        }

        // Per-player object block: this is what the guest passes back as `self`. A recycled
        // player still owns the blocks it was given last time -- reusing them keeps the guest
        // heap from growing by one object and four interfaces per sound effect played.
        if (!pl->obj) pl->obj = host.GuestAlloc(16, 8);
        host.MemoryWrite32(pl->obj, g_guestPlayerVtblAddr);
        GuestPlayer* raw = pl.get();
        for (uint32_t a : {pl->obj, pl->play_itf, pl->bq_itf, pl->vol_itf, pl->cfg_itf})
            if (a) g_itf_owner[a] = raw;
        g_players.push_back(std::move(pl));
        LOGI("audio player #%zu (%s): guest obj 0x%08X, %u ch @ %u mHz, %zu pooled",
             g_players.size(), from_pool ? "pooled" : "FRESH", raw->obj,
             numChannels, sampleRate, g_player_pool.size());
        g_guestPlayerObjectAddr = raw->obj;

        if (pPlayer) {
            host.MemoryWrite32(pPlayer, g_guestPlayerObjectAddr);
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 6. SLPlayer_GetInterface
    manager.RegisterThunk("SLPlayer_GetInterface", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        uint32_t self = jit.Regs()[0];
        uint32_t iid_ptr = jit.Regs()[1];
        uint32_t pInterface = jit.Regs()[2];

        GuestPlayer* p = PlayerFor(self);
        if (!p) {
            // No fallback to "whatever is player zero": a stale self silently bound to a live
            // voice would route the next Stop or SetVolumeLevel for a dead sound into an
            // audible one.
            LOGE("SLPlayer_GetInterface: self=0x%08X belongs to no player", self);
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }

        // Shared vtable (stateless), per-player interface block. `self` in every method below
        // then identifies the voice, which is the whole point of the rewrite.
        const auto give = [&](uint32_t& vtbl, uint32_t& itf,
                              std::initializer_list<const char*> methods) {
            if (vtbl == 0) {
                vtbl = host.GuestAlloc(64 * 4, 8);
                FillGuestVtableWithStubs(host, vtbl);
                int i = 0;
                for (const char* m : methods)
                    host.MemoryWrite32(vtbl + (i++) * 4,
                                       host.GetThunkManager().GetOrCreateThunkAddress(m));
            }
            if (itf == 0) {
                itf = host.GuestAlloc(16, 8);
                host.MemoryWrite32(itf, vtbl);
                g_itf_owner[itf] = p;
            }
            if (pInterface) host.MemoryWrite32(pInterface, itf);
            jit.Regs()[0] = SL_RESULT_SUCCESS;
        };

        if (IID_Matches(host, iid_ptr, SL_IID_PLAY)) {
            give(g_guestPlayInterfaceVtblAddr, p->play_itf,
                 {"SLPlay_SetPlayState", "SLPlay_GetPlayState"});
            return;
        }
        if (IID_Matches(host, iid_ptr, SL_IID_ANDROIDSIMPLEBUFFERQUEUE) ||
            IID_Matches(host, iid_ptr, SL_IID_BUFFERQUEUE)) {
            give(g_guestBufferQueueInterfaceVtblAddr, p->bq_itf,
                 {"SLBufferQueue_Enqueue", "SLBufferQueue_Clear",
                  "SLBufferQueue_GetState", "SLBufferQueue_RegisterCallback"});
            return;
        }
        if (IID_Matches(host, iid_ptr, SL_IID_VOLUME)) {
            give(g_guestVolumeInterfaceVtblAddr, p->vol_itf,
                 {"SLVolume_SetVolumeLevel", "SLVolume_GetVolumeLevel",
                  "SLVolume_GetMaxVolumeLevel", "SLVolume_SetMute", "SLVolume_GetMute",
                  "SLVolume_EnableStereoPosition", "SLVolume_IsEnabledStereoPosition",
                  "SLVolume_SetStereoPosition", "SLVolume_GetStereoPosition"});
            return;
        }
        if (IID_Matches(host, iid_ptr, SL_IID_ANDROIDCONFIGURATION)) {
            give(g_guestConfigInterfaceVtblAddr, p->cfg_itf,
                 {"SLConfig_SetConfiguration", "SLConfig_GetConfiguration"});
            return;
        }

        static int unsupported = 0;
        if (unsupported++ < 4)
            LOGI("SLPlayer_GetInterface: unsupported IID 0x%08X", iid_ptr);
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });

    manager.RegisterThunk("SLConfig_SetConfiguration", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLConfig_GetConfiguration", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 7. SLPlay Thunks
    manager.RegisterThunk("SLPlay_SetPlayState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GuestPlayer* p = PlayerFor(jit.Regs()[0]);
        const uint32_t state = jit.Regs()[1];
        // A stream that stops on its own is the difference between "we starved it" and "the
        // engine asked for it"; name the caller so the next step is not a guess.
        if (state == SL_PLAYSTATE_STOPPED && p) {
            static int stops = 0;
            if (stops++ < 6) {
                LOGI("SLPlay_SetPlayState(STOPPED) on player 0x%08X after enq=%llu cb=%llu,"
                     " from guest LR 0x%08X", p->obj,
                     static_cast<unsigned long long>(p->enq_ok),
                     static_cast<unsigned long long>(p->cbs), jit.Regs()[14]);
                host.DumpGuestBacktrace("SLPlay_SetPlayState(STOPPED)", jit.Regs()[13], jit.Regs()[14]);
            }
        }
        // Only on a real change. The engine stops voices that are already stopped -- every one
        // of those is a synchronous AudioTrack call, ~2.5 ms of it here, and the profiler
        // charged five of them to a single 71 ms frame. Same rule as the volume cache above.
        if (p && p->hplay && static_cast<SLuint32>(state) != p->last_state) {
            p->last_state = static_cast<SLuint32>(state);
            SetHostPlayState(p, static_cast<SLuint32>(state));
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLPlay_GetPlayState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GuestPlayer* p = PlayerFor(jit.Regs()[0]);
        uint32_t pState = jit.Regs()[1];
        if (pState) {
            // The state the guest asked for, not the one the track is in: STOPPED is served
            // as a host PAUSE (see SetHostPlayState), and reading the host back would report
            // that PAUSE to a guest that never requested it. A dead voice reads as stopped --
            // PLAYING here made the engine wait on a sound nothing would ever advance.
            host.MemoryWrite32(pState, p ? p->last_state : SL_PLAYSTATE_STOPPED);
        }
        jit.Regs()[0] = p ? SL_RESULT_SUCCESS : SL_RESULT_PRECONDITIONS_VIOLATED;
    });

    // 8. SLBufferQueue Thunks
    manager.RegisterThunk("SLBufferQueue_RegisterCallback", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GuestPlayer* p = PlayerFor(jit.Regs()[0]);
        if (p) {
            p->cb_fn = jit.Regs()[1];
            p->cb_ctx = jit.Regs()[2];
            LOGI("SLBufferQueue_RegisterCallback: player 0x%08X cb=0x%08X ctx=0x%08X",
                 p->obj, p->cb_fn, p->cb_ctx);
            // Deliberately NOT starting a dedicated delivery thread here (the upstream
            // bridge does). Under this bridge the guest is single-threaded by design:
            // running guest callbacks -- or the job pump a music refill waits on -- from
            // a second thread races guest-internal state (scheduler registration, the
            // screen stack) and crashes far from the cause. PumpOpenSLESCallbacks on the
            // frame loop is the delivery path, and with the exact accounting above it
            // drains whatever the hardware completed.
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLBufferQueue_Clear", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GuestPlayer* p = PlayerFor(jit.Regs()[0]);
        if (p && p->hbq) {
            std::lock_guard<std::mutex> lock(g_audioMutex);
            (*p->hbq)->Clear(p->hbq);
            // Cleared completions are never delivered; take them off the global counter
            // so the audio thread's wake predicate cannot strand on a stale count.
            g_bqCallbackPending.fetch_sub(p->pending.exchange(0, std::memory_order_acq_rel),
                                          std::memory_order_acq_rel);
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLBufferQueue_GetState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GuestPlayer* p = PlayerFor(jit.Regs()[0]);
        uint32_t pState = jit.Regs()[1];
        if (pState) {
            SLAndroidSimpleBufferQueueState state = {0, 0};
            if (p && p->hbq) (*p->hbq)->GetState(p->hbq, &state);
            host.MemoryWrite32(pState + 0, state.count);
            host.MemoryWrite32(pState + 4, state.index);
        }
        jit.Regs()[0] = p ? SL_RESULT_SUCCESS : SL_RESULT_PRECONDITIONS_VIOLATED;
    });

    manager.RegisterThunk("SLBufferQueue_Enqueue", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GuestPlayer* p = PlayerFor(jit.Regs()[0]);
        uint32_t pBuffer = jit.Regs()[1];
        uint32_t size = jit.Regs()[2];

        // A dead handle or a bogus buffer used to fall through to SUCCESS, which told the
        // guest its block was accepted and let it advance its decode position past audio
        // that never reached the mixer.
        if (!p || !p->hbq) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        if (size == 0 || pBuffer == 0) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }
        const void* guest_buf = GuestToHost(host.GetGuestMemoryBase(), pBuffer);
        if (!guest_buf ||
            static_cast<uint64_t>(pBuffer) + size > host.GetGuestMemorySize() ||
            size > 16 * 1024 * 1024) {
            LOGE("SLBufferQueue_Enqueue: guest buffer 0x%08X+%u outside the arena", pBuffer, size);
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_audioMutex);
            // A full queue must be reported as full. Answering SUCCESS instead makes the
            // guest believe the block was accepted, so it advances its decode position and
            // the audio it just produced is never heard -- which is what "the music plays
            // too fast" is: the stream skipping forward a buffer at a time. It also stops
            // the ring below from wrapping onto a slot the hardware is still reading.
            SLAndroidSimpleBufferQueueState st = {0, 0};
            (*p->hbq)->GetState(p->hbq, &st);
            if (st.count >= BUFFER_QUEUE_COUNT) {
                ++p->enq_full;
                jit.Regs()[0] = SL_RESULT_BUFFER_INSUFFICIENT;
                return;
            }
            // The guest reuses its own buffer as soon as the callback fires, so the data
            // has to be copied into storage this player owns for as long as the queue
            // holds it. Copied whole -- never truncated; a short copy is silent data loss
            // that surfaces as the stream running fast, nowhere near this line.
            std::vector<uint8_t>& slot = p->ring[p->ring_idx];
            if (slot.size() < size) slot.resize(size);
            memcpy(slot.data(), guest_buf, size);
            const SLresult result = (*p->hbq)->Enqueue(
                p->hbq, slot.data(), static_cast<SLuint32>(size));
            if (result == SL_RESULT_SUCCESS) {
                p->ring_idx = (p->ring_idx + 1) % BUFFER_QUEUE_COUNT;
                ++p->enq_ok;
                p->bytes += size;
                if (size > p->max_seen) p->max_seen = size;
            } else {
                ++p->enq_error;
                static int enqueue_errors_logged = 0;
                if (enqueue_errors_logged++ < 16)
                    LOGE("SLBufferQueue_Enqueue: host result=%u player=0x%08X size=%u queue=%u",
                         result, p->obj, size, st.count);
            }
            jit.Regs()[0] = result;
        }
    });

    // 9. SLVolume Thunk
    manager.RegisterThunk("SLVolume_SetVolumeLevel", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GuestPlayer* p = PlayerFor(jit.Regs()[0]);
        // SLmillibel is a signed 16-bit; it arrives zero-extended in r1.
        const int32_t level = static_cast<int16_t>(jit.Regs()[1] & 0xFFFF);
        if (p && p->hvol && level != p->last_vol) {
            p->last_vol = level;
            (*p->hvol)->SetVolumeLevel(p->hvol, level);
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // Slot 2 of SLVolumeItf. CXGSSound_2DSound_OpenSL::CreateSL calls it on every sound it
    // builds and stores the answer, so leaving the slot unfilled wedged the guest for the six
    // seconds it took the watchdog to notice -- three times per run, once per audio player.
    // Android's own implementation answers SL_MILLIBEL_MAX, which is 0.
    manager.RegisterThunk("SLVolume_GetMaxVolumeLevel", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        SLmillibel max = 0;
        if (GuestPlayer* p = PlayerFor(jit.Regs()[0])) if (p->hvol)
            (*p->hvol)->GetMaxVolumeLevel(p->hvol, &max);
        if (jit.Regs()[1]) host.MemoryWrite16(jit.Regs()[1], static_cast<uint16_t>(max));
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLVolume_GetVolumeLevel", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        SLmillibel level = 0;
        if (GuestPlayer* p = PlayerFor(jit.Regs()[0])) if (p->hvol)
            (*p->hvol)->GetVolumeLevel(p->hvol, &level);
        if (jit.Regs()[1]) host.MemoryWrite16(jit.Regs()[1], static_cast<uint16_t>(level));
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // Slots 3..8. CXGSSound_2DSound_OpenSL::Flush pans every 2D sound with
    // EnableStereoPosition + SetStereoPosition, which is what the vtable stub was catching.
    manager.RegisterThunk("SLVolume_SetMute", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const int on = jit.Regs()[1] ? 1 : 0;
        if (GuestPlayer* p = PlayerFor(jit.Regs()[0])) if (p->hvol && on != p->last_mute) {
            p->last_mute = on;
            (*p->hvol)->SetMute(p->hvol, on ? SL_BOOLEAN_TRUE : SL_BOOLEAN_FALSE);
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
    manager.RegisterThunk("SLVolume_GetMute", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        SLboolean mute = SL_BOOLEAN_FALSE;
        if (GuestPlayer* p = PlayerFor(jit.Regs()[0])) if (p->hvol) (*p->hvol)->GetMute(p->hvol, &mute);
        if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], mute);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
    manager.RegisterThunk("SLVolume_EnableStereoPosition", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const int on = jit.Regs()[1] ? 1 : 0;
        if (GuestPlayer* p = PlayerFor(jit.Regs()[0])) if (p->hvol && on != p->last_stereo_on) {
            p->last_stereo_on = on;
            (*p->hvol)->EnableStereoPosition(p->hvol, on ? SL_BOOLEAN_TRUE : SL_BOOLEAN_FALSE);
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
    manager.RegisterThunk("SLVolume_IsEnabledStereoPosition", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        SLboolean on = SL_BOOLEAN_FALSE;
        if (GuestPlayer* p = PlayerFor(jit.Regs()[0])) if (p->hvol)
            (*p->hvol)->IsEnabledStereoPosition(p->hvol, &on);
        if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], on);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
    manager.RegisterThunk("SLVolume_SetStereoPosition", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        // SLpermille is a signed 16-bit -1000..1000; it arrives zero-extended in r1.
        const SLpermille pos = static_cast<SLpermille>(static_cast<int16_t>(jit.Regs()[1] & 0xFFFF));
        if (GuestPlayer* p = PlayerFor(jit.Regs()[0])) if (p->hvol && pos != p->last_pan) {
            p->last_pan = pos;
            (*p->hvol)->SetStereoPosition(p->hvol, pos);
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
    manager.RegisterThunk("SLVolume_GetStereoPosition", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        SLpermille pos = 0;
        if (GuestPlayer* p = PlayerFor(jit.Regs()[0])) if (p->hvol) (*p->hvol)->GetStereoPosition(p->hvol, &pos);
        if (jit.Regs()[1]) host.MemoryWrite16(jit.Regs()[1], static_cast<uint16_t>(pos));
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });
}
