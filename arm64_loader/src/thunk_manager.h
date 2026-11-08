#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace Dynarmic::A32 {
    class Jit;
}

class DynarmicHost;

using ThunkHandler = std::function<void(Dynarmic::A32::Jit& jit, DynarmicHost& host)>;

class ThunkManager {
public:
    ThunkManager(DynarmicHost& host);
    ~ThunkManager();

    void RegisterAllThunks();
    void RegisterThunk(const std::string& name, ThunkHandler handler);
    void RegisterSymbol(const std::string& name, uint32_t address);

    // Dispatch ids are dense (1..N in registration order), so the hot SVC path resolves
    // the handler by direct index instead of an unordered_map lookup. Slots are written
    // exactly once at registration -- before the matching trampoline can ever execute --
    // so the read path needs no lock. Ids past the table fall back to the id map.
    static constexpr uint32_t kDispatchTableSize = 16384;

    uint32_t GetOrCreateThunkAddress(const std::string& name);
    void DispatchThunk(uint32_t thunk_id, Dynarmic::A32::Jit& jit);
    // "" when the id was never handed out. A trampoline address in a crash or watchdog
    // report is useless without it.
    const char* GetThunkName(uint32_t thunk_id) const;

    const std::unordered_map<std::string, uint32_t>& GetThunkSymbolTable() const {
        return m_symbol_to_address;
    }

    void SetupGuestJNIEnv();
    uint32_t GetGuestJNIEnv() const { return m_guest_jni_env; }

    static uint32_t s_screenWidth;
    static uint32_t s_screenHeight;
    static uint32_t s_forced_dpi;
    static uint32_t s_ui_inset;

private:
    void RegisterGLThunks();
    void RegisterLibcThunks();
    void RegisterNFCThunks();
    DynarmicHost& m_host;
    uint32_t m_next_thunk_addr = 0x00010000; // Base address for thunk trampolines
    uint32_t m_guest_jni_env = 0;
    std::unordered_map<std::string, uint32_t> m_symbol_to_address;
    std::unordered_map<uint32_t, ThunkHandler> m_id_to_handler;
    std::unordered_map<uint32_t, std::string> m_id_to_name;
    ThunkHandler m_dispatch[kDispatchTableSize] = {};
};

struct GuestThreadWorker {
    uint32_t start_func;
    uint32_t arg;
};

const std::vector<GuestThreadWorker>& GetGuestThreadWorkers();
void AddGuestThreadWorker(uint32_t start_func, uint32_t arg);

bool IsVipAddonEnabled();
void SetVipAddonEnabled(bool enabled);

// --- frame profiler (thunk_manager.cpp) ---------------------------------------------------
// The engine is single-threaded under the JIT: physics, GL and the audio pump all run on
// GLThread, so "the frame ran long" is the only symptom any of them has. These record which
// thunks one frame paid for and name them when it overruns.
//
// Off unless `setprop debug.abgo.profile 1` before the process starts -- two clock_gettime
// calls per thunk is not free at the rate this guest calls them.
void ThunkProfileFrameBegin();
void ThunkProfileFrameEnd(double frame_ms);

// --- stall trace ring (thunk_manager.cpp) --------------------------------------------------
// The guest entry points that can block record enter/exit here; when the frame loop stalls,
// TraceDump prints the last events so the blocking call names itself. Cheap: two stores.
void TraceEvent(const char* what, uint32_t a = 0, uint32_t b = 0);
void TraceDump(const char* why);

// Asset overriding from <externalFilesDir>/... (thunks_libc.cpp)
void SetAssetOverrideRoot(const std::string& root);
bool HasAssetOverride(const char* entry_name);
void InstallAssetOverrideHook(DynarmicHost& host);
