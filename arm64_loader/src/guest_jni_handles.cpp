#include "guest_jni.h"
#include "dynarmic_host.h"
#include "elf_loader.h"

#include <android/log.h>
#include <cstring>
#include <mutex>
#include <unordered_map>

#define LOG_TAG "ABGO_JNI"
#include "bridge_log.h"

extern std::unique_ptr<DynarmicHost> g_host;
JavaVM* GetHostJavaVM();

// --- host JNIEnv per thread --------------------------------------------------------------
// Guest worker threads become host threads here, so they have to attach. Detaching is left
// to thread exit; the process is single-purpose and the VM cleans up.
JNIEnv* HostEnv() {
    JavaVM* vm = GetHostJavaVM();
    if (!vm) return nullptr;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) return env;
    if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK) return env;
    LOGE("AttachCurrentThread failed");
    return nullptr;
}

// --- handle tables -----------------------------------------------------------------------
namespace {

std::mutex g_lock;

// Slot 0 is reserved so handle 0 can mean null.
std::vector<jobject>   g_refs{nullptr};
std::vector<uint32_t>  g_free_refs;
std::vector<jmethodID> g_methods{nullptr};
std::vector<jfieldID>  g_fields{nullptr};

// Method/field IDs are stable for the life of the class, so cache them rather than growing
// the table every time the guest asks for the same one.
std::unordered_map<const void*, uint32_t> g_method_index;
std::unordered_map<const void*, uint32_t> g_field_index;

// Every guest reference is a host global ref, and ART caps those at 51200 process-wide.
// A guest that forgets one DeleteLocalRef in a per-frame path therefore kills the process
// minutes later, nowhere near the cause -- so keep the count visible.
uint64_t g_refs_made = 0, g_refs_freed = 0;

}  // namespace

void LogJniStats() {
    std::lock_guard<std::mutex> guard(g_lock);
    LOGI("  jni: liveRefs=%llu (made %llu, freed %llu) slots=%zu free=%zu methods=%zu fields=%zu",
         static_cast<unsigned long long>(g_refs_made - g_refs_freed),
         static_cast<unsigned long long>(g_refs_made),
         static_cast<unsigned long long>(g_refs_freed),
         g_refs.size(), g_free_refs.size(), g_methods.size(), g_fields.size());
}

uint32_t GuestRefFromHost(jobject obj) {
    if (!obj) return 0;
    JNIEnv* env = HostEnv();
    if (!env) return 0;
    jobject global = env->NewGlobalRef(obj);
    if (!global) return 0;

    std::lock_guard<std::mutex> guard(g_lock);
    ++g_refs_made;
    if (!g_free_refs.empty()) {
        const uint32_t h = g_free_refs.back();
        g_free_refs.pop_back();
        g_refs[h] = global;
        return h;
    }
    g_refs.push_back(global);
    return static_cast<uint32_t>(g_refs.size() - 1);
}

jobject HostRefFromGuest(uint32_t handle) {
    if (handle == 0) return nullptr;
    std::lock_guard<std::mutex> guard(g_lock);
    if (handle >= g_refs.size()) {
        LOGE("bad guest ref handle %u (table size %zu)", handle, g_refs.size());
        return nullptr;
    }
    return g_refs[handle];
}

void GuestRefDelete(uint32_t handle) {
    if (handle == 0) return;
    jobject global = nullptr;
    {
        std::lock_guard<std::mutex> guard(g_lock);
        if (handle >= g_refs.size() || !g_refs[handle]) return;
        global = g_refs[handle];
        g_refs[handle] = nullptr;
        g_free_refs.push_back(handle);
        ++g_refs_freed;
    }
    if (JNIEnv* env = HostEnv()) env->DeleteGlobalRef(global);
}

uint32_t GuestMethodId(jmethodID id) {
    if (!id) return 0;
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_method_index.find(id);
    if (it != g_method_index.end()) return it->second;
    g_methods.push_back(id);
    const uint32_t h = static_cast<uint32_t>(g_methods.size() - 1);
    g_method_index[id] = h;
    return h;
}

jmethodID HostMethodId(uint32_t handle) {
    if (handle == 0) return nullptr;
    std::lock_guard<std::mutex> guard(g_lock);
    if (handle >= g_methods.size()) {
        LOGE("bad guest methodID handle %u", handle);
        return nullptr;
    }
    return g_methods[handle];
}

uint32_t GuestFieldId(jfieldID id) {
    if (!id) return 0;
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_field_index.find(id);
    if (it != g_field_index.end()) return it->second;
    g_fields.push_back(id);
    const uint32_t h = static_cast<uint32_t>(g_fields.size() - 1);
    g_field_index[id] = h;
    return h;
}

jfieldID HostFieldId(uint32_t handle) {
    if (handle == 0) return nullptr;
    std::lock_guard<std::mutex> guard(g_lock);
    if (handle >= g_fields.size()) {
        LOGE("bad guest fieldID handle %u", handle);
        return nullptr;
    }
    return g_fields[handle];
}

// --- calling into the guest ---------------------------------------------------------------
uint32_t CallGuestJni(const char* symbol, const std::vector<uint32_t>& args) {
    if (!g_host) {
        LOGE("CallGuestJni(%s) with no host", symbol);
        return 0;
    }
    const uint32_t pc = g_host->FindSymbol(symbol);
    if (pc == 0) {
        // Once per symbol is enough; a hot-path miss would otherwise flood the log.
        static std::unordered_map<std::string, bool> reported;
        std::lock_guard<std::mutex> guard(g_lock);
        if (!reported[symbol]) {
            reported[symbol] = true;
            LOGE("guest symbol not found: %s", symbol);
        }
        return 0;
    }
    return g_host->RunFunction(pc, args);
}

// --- softfp argument helpers ----------------------------------------------------------------
uint32_t FloatBits(float f) {
    uint32_t bits;
    std::memcpy(&bits, &f, sizeof(bits));
    return bits;
}

void PushDouble(std::vector<uint32_t>& args, double d) {
    if (args.size() & 1u) args.push_back(0);   // AAPCS: 64-bit values start on an even slot
    uint64_t bits;
    std::memcpy(&bits, &d, sizeof(bits));
    args.push_back(static_cast<uint32_t>(bits));
    args.push_back(static_cast<uint32_t>(bits >> 32));
}

void PushLong(std::vector<uint32_t>& args, int64_t v) {
    if (args.size() & 1u) args.push_back(0);
    args.push_back(static_cast<uint32_t>(static_cast<uint64_t>(v)));
    args.push_back(static_cast<uint32_t>(static_cast<uint64_t>(v) >> 32));
}
