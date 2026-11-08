// libandroid: the asset API, plus the one ANativeWindow call libABK.so imports.
//
// This is what stood between "the guest boots" and "the guest runs": with
// AAssetManager_fromJava stubbed to 0 the engine's asset system failed to initialise and
// CApp::Shutdown called exit(0) three frames into nativeInitialize.
//
// The host process is the one with a real AssetManager, so every call here is a passthrough.
// The only real work is the boundary: an AAsset*/AAssetDir*/AAssetManager* is a 64-bit host
// pointer and the guest holds 32 bits, so they cross as table indices; and AAsset_getBuffer
// hands back a pointer the guest will dereference, so the bytes have to be copied into guest
// memory rather than the address handed over.

#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include "guest_jni.h"

#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>
#include <android/native_window.h>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#define LOG_TAG "ABGO_ASSET"
#include "bridge_log.h"

namespace {

using Jit = Dynarmic::A32::Jit;

std::mutex g_lock;
std::vector<void*> g_handles{nullptr};                 // index 0 == null
std::unordered_map<void*, uint32_t> g_index;
// AAsset_getBuffer is idempotent in the real API, so the guest copy is cached per asset and
// freed with the asset. Without this a guest that re-reads a 7 MB pak walks the bump heap.
std::unordered_map<void*, uint32_t> g_buffers;

uint32_t Tok(void* p) {
    if (!p) return 0;
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_index.find(p);
    if (it != g_index.end()) return it->second;
    g_handles.push_back(p);
    const uint32_t h = static_cast<uint32_t>(g_handles.size() - 1);
    g_index[p] = h;
    return h;
}

void* Ptr(uint32_t tok) {
    if (tok == 0) return nullptr;
    std::lock_guard<std::mutex> guard(g_lock);
    if (tok >= g_handles.size()) {
        LOGE("bad asset handle %u", tok);
        return nullptr;
    }
    return g_handles[tok];
}

void Forget(void* p) {
    if (!p) return;
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_index.find(p);
    if (it != g_index.end()) {
        g_handles[it->second] = nullptr;
        g_index.erase(it);
    }
    g_buffers.erase(p);
}

}  // namespace

void RegisterAndroidThunks(ThunkManager& tm, DynarmicHost& host) {
    tm.RegisterThunk("AAssetManager_fromJava", [](Jit& jit, DynarmicHost&) {
        // r0 is the guest's fake JNIEnv, which is no use to the host; r1 is a handle into the
        // JNI reference table. The real env is this thread's host env.
        JNIEnv* env = HostEnv();
        jobject mgr_obj = HostRefFromGuest(jit.Regs()[1]);
        if (!env || !mgr_obj) {
            LOGE("AAssetManager_fromJava: env=%p obj handle=%u -> null", env, jit.Regs()[1]);
            jit.Regs()[0] = 0;
            return;
        }
        AAssetManager* mgr = AAssetManager_fromJava(env, mgr_obj);
        if (!mgr) LOGE("AAssetManager_fromJava returned null for handle %u", jit.Regs()[1]);
        else      LOGI("AAssetManager_fromJava -> %p", mgr);
        jit.Regs()[0] = Tok(mgr);
    });

    tm.RegisterThunk("AAssetManager_open", [](Jit& jit, DynarmicHost& h) {
        auto* mgr = static_cast<AAssetManager*>(Ptr(jit.Regs()[0]));
        const char* name = static_cast<const char*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[1]));
        if (!mgr || !name) { jit.Regs()[0] = 0; return; }
        AAsset* a = AAssetManager_open(mgr, name, static_cast<int>(jit.Regs()[2]));
        // One line per distinct name, hit or miss. The engine probes _atc/_etc variants of
        // every pak and most of those misses are expected, so the interesting signal is
        // which names DO resolve here versus fall through to the OBB pak filesystem.
        // Bounded by the name set, so it cannot trip the device's log flow control.
        static std::set<std::string> seen;
        if (seen.insert(name).second) {
            if (a) LOGI("AAssetManager_open('%s') ok (%lld bytes)", name,
                        static_cast<long long>(AAsset_getLength64(a)));
            // Expected: the engine probes texture-format variants (_atc/_dxt/_etc) that
            // legitimately do not exist. Not an error -- keep it out of the release log.
            else   LOGI("AAssetManager_open('%s') failed", name);
        }
        jit.Regs()[0] = Tok(a);
    });

    tm.RegisterThunk("AAsset_getLength", [](Jit& jit, DynarmicHost&) {
        auto* a = static_cast<AAsset*>(Ptr(jit.Regs()[0]));
        jit.Regs()[0] = a ? static_cast<uint32_t>(AAsset_getLength(a)) : 0;
    });

    tm.RegisterThunk("AAsset_getLength64", [](Jit& jit, DynarmicHost&) {
        auto* a = static_cast<AAsset*>(Ptr(jit.Regs()[0]));
        const uint64_t len = a ? static_cast<uint64_t>(AAsset_getLength64(a)) : 0;
        jit.Regs()[0] = static_cast<uint32_t>(len);
        jit.Regs()[1] = static_cast<uint32_t>(len >> 32);
    });

    tm.RegisterThunk("AAsset_getBuffer", [](Jit& jit, DynarmicHost& h) {
        auto* a = static_cast<AAsset*>(Ptr(jit.Regs()[0]));
        if (!a) { jit.Regs()[0] = 0; return; }
        {
            std::lock_guard<std::mutex> guard(g_lock);
            auto it = g_buffers.find(a);
            if (it != g_buffers.end()) { jit.Regs()[0] = it->second; return; }
        }
        const void* src = AAsset_getBuffer(a);
        const off_t len = AAsset_getLength(a);
        if (!src || len <= 0) { jit.Regs()[0] = 0; return; }
        const uint32_t g = h.GuestAlloc(static_cast<size_t>(len), 8);
        if (!g) { LOGE("AAsset_getBuffer: no guest heap for %ld bytes", static_cast<long>(len)); jit.Regs()[0] = 0; return; }
        std::memcpy(GuestToHost(h.GetGuestMemoryBase(), g), src, static_cast<size_t>(len));
        {
            std::lock_guard<std::mutex> guard(g_lock);
            g_buffers[a] = g;
        }
        jit.Regs()[0] = g;
    });

    tm.RegisterThunk("AAsset_close", [](Jit& jit, DynarmicHost&) {
        auto* a = static_cast<AAsset*>(Ptr(jit.Regs()[0]));
        if (!a) return;
        Forget(a);
        AAsset_close(a);
    });

    tm.RegisterThunk("AAsset_openFileDescriptor", [](Jit& jit, DynarmicHost& h) {
        // The fd is a real host fd and the guest's read/lseek thunks pass fds straight
        // through, so it works unchanged on the other side.
        auto* a = static_cast<AAsset*>(Ptr(jit.Regs()[0]));
        if (!a) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        off64_t start = 0, len = 0;
        const int fd = AAsset_openFileDescriptor64(a, &start, &len);
        // The guest imports the 32-bit off_t form, so the out-parameters are single words.
        if (jit.Regs()[1]) h.MemoryWrite32(jit.Regs()[1], static_cast<uint32_t>(start));
        if (jit.Regs()[2]) h.MemoryWrite32(jit.Regs()[2], static_cast<uint32_t>(len));
        jit.Regs()[0] = static_cast<uint32_t>(fd);
    });

    tm.RegisterThunk("AAssetManager_openDir", [](Jit& jit, DynarmicHost& h) {
        auto* mgr = static_cast<AAssetManager*>(Ptr(jit.Regs()[0]));
        const char* name = static_cast<const char*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[1]));
        if (!mgr || !name) { jit.Regs()[0] = 0; return; }
        jit.Regs()[0] = Tok(AAssetManager_openDir(mgr, name));
    });

    tm.RegisterThunk("AAssetDir_getNextFileName", [](Jit& jit, DynarmicHost& h) {
        auto* d = static_cast<AAssetDir*>(Ptr(jit.Regs()[0]));
        if (!d) { jit.Regs()[0] = 0; return; }
        const char* name = AAssetDir_getNextFileName(d);
        if (!name) { jit.Regs()[0] = 0; return; }
        // The real API owns this string until the next call, so one reusable guest buffer per
        // directory matches the contract and does not grow the heap per entry.
        static std::mutex name_lock;
        static std::unordered_map<void*, uint32_t> name_buf;
        std::lock_guard<std::mutex> guard(name_lock);
        uint32_t& buf = name_buf[d];
        if (!buf) buf = h.GuestAlloc(512, 4);
        if (!buf) { jit.Regs()[0] = 0; return; }
        std::snprintf(static_cast<char*>(GuestToHost(h.GetGuestMemoryBase(), buf)), 512, "%s", name);
        jit.Regs()[0] = buf;
    });

    tm.RegisterThunk("AAssetDir_close", [](Jit& jit, DynarmicHost&) {
        auto* d = static_cast<AAssetDir*>(Ptr(jit.Regs()[0]));
        if (!d) return;
        Forget(d);
        AAssetDir_close(d);
    });

    tm.RegisterThunk("ANativeWindow_setBuffersGeometry", [](Jit& jit, DynarmicHost&) {
        // The window belongs to GLSurfaceView on the Java side; the guest never has a real
        // ANativeWindow to pass. Report success so it does not treat this as a fatal error.
        LOGI("guest ANativeWindow_setBuffersGeometry(%u, %u, %u) ignored -- Java owns the surface",
             jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
        jit.Regs()[0] = 0;
    });

    (void)host;
}
