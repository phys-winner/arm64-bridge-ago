// The guest-facing JNIEnv.
//
// The guest reaches JNI through a table of 233 function pointers whose layout is fixed by
// struct JNINativeInterface. It indexes that table by *position*, so every slot number here
// was derived mechanically from the NDK header
//   ndk/27.2.12479018/.../sysroot/usr/include/jni.h
// as offsetof(JNINativeInterface, fn)/sizeof(void*) -- note the FOUR reserved pointers at the
// top, which is why GetVersion is 4 and not 0. A wrong index does not crash: it calls a
// different JNI function with the wrong arguments and looks like data corruption later.
//
// Everything the guest sees is a 32-bit handle from guest_jni_handles.cpp, never a host
// pointer, and every argument is read out of the core registers because the guest is softfp
// (lesson 2.1) -- a jfloat is just its bit pattern in one word.

#include "guest_jni.h"
#include "dynarmic_host.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include "abgo_unlock.h"

#include <android/log.h>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#define LOG_TAG "ABGO_JNIENV"
#include "bridge_log.h"

namespace {

using Jit = Dynarmic::A32::Jit;

// sizeof(struct JNINativeInterface)/sizeof(void*) in the NDK 27 header.
constexpr uint32_t kSlotCount = 233;

// Slot indices. The number next to each name is what a reviewer should re-derive from jni.h.
enum : uint32_t {
    kReserved0 = 0, kReserved1 = 1, kReserved2 = 2, kReserved3 = 3,

    kGetVersion = 4,
    kFindClass = 6,
    kGetSuperclass = 10,
    kIsAssignableFrom = 11,
    kThrow = 13,
    kThrowNew = 14,
    kExceptionOccurred = 15,
    kExceptionDescribe = 16,
    kExceptionClear = 17,
    kFatalError = 18,
    kPushLocalFrame = 19,
    kPopLocalFrame = 20,
    kNewGlobalRef = 21,
    kDeleteGlobalRef = 22,
    kDeleteLocalRef = 23,
    kIsSameObject = 24,
    kNewLocalRef = 25,
    kEnsureLocalCapacity = 26,
    kAllocObject = 27,
    kNewObject = 28,
    kNewObjectV = 29,
    kNewObjectA = 30,
    kGetObjectClass = 31,
    kIsInstanceOf = 32,
    kGetMethodID = 33,

    kCallObjectMethod = 34,  kCallObjectMethodV = 35,  kCallObjectMethodA = 36,
    kCallBooleanMethod = 37, kCallBooleanMethodV = 38, kCallBooleanMethodA = 39,
    kCallByteMethod = 40,    kCallByteMethodV = 41,    kCallByteMethodA = 42,
    kCallCharMethod = 43,    kCallCharMethodV = 44,    kCallCharMethodA = 45,
    kCallShortMethod = 46,   kCallShortMethodV = 47,   kCallShortMethodA = 48,
    kCallIntMethod = 49,     kCallIntMethodV = 50,     kCallIntMethodA = 51,
    kCallLongMethod = 52,    kCallLongMethodV = 53,    kCallLongMethodA = 54,
    kCallFloatMethod = 55,   kCallFloatMethodV = 56,   kCallFloatMethodA = 57,
    kCallDoubleMethod = 58,  kCallDoubleMethodV = 59,  kCallDoubleMethodA = 60,
    kCallVoidMethod = 61,    kCallVoidMethodV = 62,    kCallVoidMethodA = 63,

    kGetFieldID = 94,
    kGetObjectField = 95,
    kGetBooleanField = 96,
    kGetByteField = 97,
    kGetCharField = 98,
    kGetShortField = 99,
    kGetIntField = 100,
    kGetLongField = 101,
    kGetFloatField = 102,
    kGetDoubleField = 103,
    kSetObjectField = 104,
    kSetBooleanField = 105,
    kSetByteField = 106,
    kSetCharField = 107,
    kSetShortField = 108,
    kSetIntField = 109,
    kSetLongField = 110,
    kSetFloatField = 111,
    kSetDoubleField = 112,

    kGetStaticMethodID = 113,
    kCallStaticObjectMethod = 114,  kCallStaticObjectMethodV = 115,  kCallStaticObjectMethodA = 116,
    kCallStaticBooleanMethod = 117, kCallStaticBooleanMethodV = 118, kCallStaticBooleanMethodA = 119,
    kCallStaticByteMethod = 120,    kCallStaticByteMethodV = 121,    kCallStaticByteMethodA = 122,
    kCallStaticCharMethod = 123,    kCallStaticCharMethodV = 124,    kCallStaticCharMethodA = 125,
    kCallStaticShortMethod = 126,   kCallStaticShortMethodV = 127,   kCallStaticShortMethodA = 128,
    kCallStaticIntMethod = 129,     kCallStaticIntMethodV = 130,     kCallStaticIntMethodA = 131,
    kCallStaticLongMethod = 132,    kCallStaticLongMethodV = 133,    kCallStaticLongMethodA = 134,
    kCallStaticFloatMethod = 135,   kCallStaticFloatMethodV = 136,   kCallStaticFloatMethodA = 137,
    kCallStaticDoubleMethod = 138,  kCallStaticDoubleMethodV = 139,  kCallStaticDoubleMethodA = 140,
    kCallStaticVoidMethod = 141,    kCallStaticVoidMethodV = 142,    kCallStaticVoidMethodA = 143,

    kGetStaticFieldID = 144,
    kGetStaticObjectField = 145,
    kGetStaticBooleanField = 146,
    kGetStaticByteField = 147,
    kGetStaticCharField = 148,
    kGetStaticShortField = 149,
    kGetStaticIntField = 150,
    kGetStaticLongField = 151,
    kGetStaticFloatField = 152,
    kGetStaticDoubleField = 153,
    kSetStaticObjectField = 154,
    kSetStaticBooleanField = 155,
    kSetStaticByteField = 156,
    kSetStaticCharField = 157,
    kSetStaticShortField = 158,
    kSetStaticIntField = 159,
    kSetStaticLongField = 160,
    kSetStaticFloatField = 161,
    kSetStaticDoubleField = 162,

    kNewString = 163,
    kGetStringLength = 164,
    kGetStringChars = 165,
    kReleaseStringChars = 166,
    kNewStringUTF = 167,
    kGetStringUTFLength = 168,
    kGetStringUTFChars = 169,
    kReleaseStringUTFChars = 170,
    kGetArrayLength = 171,
    kNewObjectArray = 172,
    kGetObjectArrayElement = 173,
    kSetObjectArrayElement = 174,
    kNewByteArray = 176,
    kNewIntArray = 179,
    kGetByteArrayElements = 184,
    kReleaseByteArrayElements = 192,
    kGetByteArrayRegion = 200,
    kSetByteArrayRegion = 208,
    kGetIntArrayElements = 187,
    kReleaseIntArrayElements = 195,
    kGetIntArrayRegion = 203,
    kSetIntArrayRegion = 211,
    kRegisterNatives = 215,
    kUnregisterNatives = 216,
    kMonitorEnter = 217,
    kMonitorExit = 218,
    kGetJavaVM = 219,
    kGetStringRegion = 220,
    kGetStringUTFRegion = 221,
    kGetPrimitiveArrayCritical = 222,
    kReleasePrimitiveArrayCritical = 223,
    kNewWeakGlobalRef = 226,
    kDeleteWeakGlobalRef = 227,
    kExceptionCheck = 228,
    kNewDirectByteBuffer = 229,
    kGetDirectBufferAddress = 230,
    kGetDirectBufferCapacity = 231,
    kGetObjectRefType = 232,
};

// JNIInvokeInterface slots, same derivation. Three reserved pointers here, not four.
enum : uint32_t {
    kDestroyJavaVM = 3,
    kAttachCurrentThread = 4,
    kDetachCurrentThread = 5,
    kGetEnv = 6,
    kAttachCurrentThreadAsDaemon = 7,
    kInvokeSlotCount = 8,
};

uint32_t g_env_ptr = 0;   // guest JNIEnv*  -> cell holding the function table address
uint32_t g_vm_ptr = 0;    // guest JavaVM*

// --- register helpers ---------------------------------------------------------------------
inline uint32_t Arg(Jit& jit, uint32_t n) { return jit.Regs()[n]; }
inline void SetRet(Jit& jit, uint32_t v) { jit.Regs()[0] = v; }
inline void SetRet64(Jit& jit, uint64_t v) {
    jit.Regs()[0] = static_cast<uint32_t>(v);
    jit.Regs()[1] = static_cast<uint32_t>(v >> 32);
}
// Non-variadic slots with more than four arguments (Get/SetByteArrayRegion) spill to the
// caller's stack, and the trampoline has no prologue, so SP still points at argument 5.
inline uint32_t StackArg(Jit& jit, DynarmicHost& host, uint32_t index) {
    return host.MemoryRead32(jit.Regs()[13] + index * 4);
}
inline const char* GuestStr(DynarmicHost& host, uint32_t gaddr) {
    return static_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), gaddr));
}

// --- exception shadow ----------------------------------------------------------------------
// A pending host exception makes the very next host JNI call abort the process at a place
// unrelated to the cause, so it is taken off the host env immediately and parked here where
// ExceptionOccurred/ExceptionCheck/ExceptionClear can still see it.
thread_local uint32_t t_pending_exc = 0;

void CaptureException(JNIEnv* env, const char* what) {
    if (!env || !env->ExceptionCheck()) return;
    jthrowable e = env->ExceptionOccurred();
    env->ExceptionDescribe();   // logs and clears
    env->ExceptionClear();
    LOGE("host JNI exception during %s -- parked for the guest", what);
    if (t_pending_exc) GuestRefDelete(t_pending_exc);
    t_pending_exc = GuestRefFromHost(e);
    if (e) env->DeleteLocalRef(e);
}

// Objects come back from the host as local refs; the guest only ever holds our handles, so the
// local ref is dropped right away rather than piling up in the host frame.
uint32_t Publish(JNIEnv* env, jobject local) {
    const uint32_t h = GuestRefFromHost(local);
    if (local) env->DeleteLocalRef(local);
    return h;
}

// --- guest block recycling -------------------------------------------------------------------
// ponytail: DynarmicHost::GuestFree is a no-op bump allocator, so Release{StringUTFChars,
// ByteArrayElements} recycles here instead. Without it a guest that calls GetStringUTFChars in
// a loop walks the heap straight into the guest stack.
std::mutex g_block_lock;
std::map<uint32_t, uint32_t> g_block_size;        // live block -> capacity
std::multimap<uint32_t, uint32_t> g_block_free;   // capacity -> block

uint32_t BlockAlloc(DynarmicHost& host, uint32_t size) {
    if (size == 0) size = 1;
    {
        std::lock_guard<std::mutex> guard(g_block_lock);
        auto it = g_block_free.lower_bound(size);
        if (it != g_block_free.end()) {
            const uint32_t addr = it->second;
            g_block_size[addr] = it->first;
            g_block_free.erase(it);
            return addr;
        }
    }
    const uint32_t addr = host.GuestAlloc(size, 8);
    if (!addr) return 0;
    std::lock_guard<std::mutex> guard(g_block_lock);
    g_block_size[addr] = size;
    return addr;
}

void BlockFree(uint32_t addr) {
    if (!addr) return;
    std::lock_guard<std::mutex> guard(g_block_lock);
    auto it = g_block_size.find(addr);
    if (it == g_block_size.end()) {
        LOGE("release of unknown guest block 0x%08X", addr);
        return;
    }
    g_block_free.emplace(it->second, addr);
    g_block_size.erase(it);
}

// Pinned primitive arrays: the guest pointer plus how much to copy back on release.
std::mutex g_pin_lock;
std::unordered_map<uint32_t, jsize> g_pin_len;

// --- method signatures -------------------------------------------------------------------
// Unpacking a call needs the argument types, and a jmethodID does not carry them, so the
// descriptor handed to Get{,Static}MethodID is kept keyed by the handle we gave back.
std::mutex g_sig_lock;
std::unordered_map<uint32_t, std::string> g_method_sig;

void RememberSignature(uint32_t mid_handle, const char* sig) {
    if (!mid_handle || !sig) return;
    std::lock_guard<std::mutex> guard(g_sig_lock);
    g_method_sig[mid_handle] = sig;
}

// Returns the argument type letters, with every reference type collapsed to 'L'. Empty and
// ok=false means the descriptor was never seen, which is not the same as a no-argument method.
std::vector<char> ArgTypes(uint32_t mid_handle, bool& ok) {
    std::string sig;
    {
        std::lock_guard<std::mutex> guard(g_sig_lock);
        auto it = g_method_sig.find(mid_handle);
        if (it == g_method_sig.end()) { ok = false; return {}; }
        sig = it->second;
    }
    ok = true;
    std::vector<char> types;
    size_t i = sig.find('(');
    if (i == std::string::npos) return types;
    for (++i; i < sig.size() && sig[i] != ')'; ++i) {
        char c = sig[i];
        if (c == '[') {
            while (i < sig.size() && sig[i] == '[') ++i;
            if (i < sig.size() && sig[i] == 'L') while (i < sig.size() && sig[i] != ';') ++i;
            types.push_back('L');
            continue;
        }
        if (c == 'L') {
            while (i < sig.size() && sig[i] != ';') ++i;
            types.push_back('L');
            continue;
        }
        types.push_back(c);
    }
    return types;
}

// --- AAPCS-32 argument walker --------------------------------------------------------------
// Models the base standard (softfp): core registers first, then the caller's stack, with
// 8-byte quantities rounded up to an even register / an 8-byte stack offset. Once anything
// lands on the stack the core registers are done, which is why r3 can end up as padding.
struct ArgWalker {
    Jit& jit;
    DynarmicHost& host;
    uint32_t ncrn;   // next core register, 4 == exhausted
    uint32_t nsaa;   // next stacked argument address

    uint32_t Word() {
        if (ncrn < 4) return jit.Regs()[ncrn++];
        const uint32_t v = host.MemoryRead32(nsaa);
        nsaa += 4;
        return v;
    }
    uint64_t DoubleWord() {
        ncrn = (ncrn + 1) & ~1u;
        if (ncrn + 2 <= 4) {
            const uint64_t lo = jit.Regs()[ncrn];
            const uint64_t hi = jit.Regs()[ncrn + 1];
            ncrn += 2;
            return lo | (hi << 32);
        }
        ncrn = 4;
        nsaa = (nsaa + 7) & ~7u;
        const uint64_t lo = host.MemoryRead32(nsaa);
        const uint64_t hi = host.MemoryRead32(nsaa + 4);
        nsaa += 8;
        return lo | (hi << 32);
    }
};

// The "..." and va_list forms go through the C default argument promotions: jboolean/jbyte/
// jchar/jshort arrive as int and a jfloat arrives as a *double*. The jvalue-array form does
// not promote anything, which is why it is unpacked separately below.
void ArgsFromRegisters(ArgWalker& w, const std::vector<char>& types, std::vector<jvalue>& out) {
    for (char t : types) {
        jvalue v{};
        switch (t) {
            case 'J': v.j = static_cast<jlong>(w.DoubleWord()); break;
            case 'D': { const uint64_t b = w.DoubleWord(); std::memcpy(&v.d, &b, 8); break; }
            case 'F': { const uint64_t b = w.DoubleWord(); double d; std::memcpy(&d, &b, 8);
                        v.f = static_cast<jfloat>(d); break; }
            case 'Z': v.z = w.Word() ? JNI_TRUE : JNI_FALSE; break;
            case 'B': v.b = static_cast<jbyte>(w.Word()); break;
            case 'C': v.c = static_cast<jchar>(w.Word()); break;
            case 'S': v.s = static_cast<jshort>(w.Word()); break;
            case 'I': v.i = static_cast<jint>(w.Word()); break;
            default:  v.l = HostRefFromGuest(w.Word()); break;   // L and [
        }
        out.push_back(v);
    }
}

void ArgsFromJvalues(DynarmicHost& host, uint32_t arr, const std::vector<char>& types,
                     std::vector<jvalue>& out) {
    for (size_t i = 0; i < types.size(); ++i) {
        const uint32_t p = arr + static_cast<uint32_t>(i * 8);
        const uint32_t lo = host.MemoryRead32(p);
        jvalue v{};
        switch (types[i]) {
            case 'J': v.j = static_cast<jlong>(lo | (static_cast<uint64_t>(host.MemoryRead32(p + 4)) << 32)); break;
            case 'D': { const uint64_t b = lo | (static_cast<uint64_t>(host.MemoryRead32(p + 4)) << 32);
                        std::memcpy(&v.d, &b, 8); break; }
            case 'F': std::memcpy(&v.f, &lo, 4); break;
            case 'Z': v.z = lo ? JNI_TRUE : JNI_FALSE; break;
            case 'B': v.b = static_cast<jbyte>(lo); break;
            case 'C': v.c = static_cast<jchar>(lo); break;
            case 'S': v.s = static_cast<jshort>(lo); break;
            case 'I': v.i = static_cast<jint>(lo); break;
            default:  v.l = HostRefFromGuest(lo); break;
        }
        out.push_back(v);
    }
}

// --- the Call<Type>Method family -----------------------------------------------------------
enum class Ret { Void, Object, Boolean, Byte, Char, Short, Int, Long, Float, Double };
enum class Form { Varargs, VaList, Array };

void DoCall(Jit& jit, DynarmicHost& host, Ret ret, bool is_static, Form form, const char* what) {
    JNIEnv* env = HostEnv();
    const uint32_t recv_h = Arg(jit, 1);
    const uint32_t mid_h = Arg(jit, 2);
    jmethodID mid = HostMethodId(mid_h);
    jobject recv = HostRefFromGuest(recv_h);

    if (!env || !mid || (!recv && !is_static)) {
        LOGE("%s: env=%p mid=%u/%p recv=%u/%p -- dropping call from LR 0x%08X",
             what, env, mid_h, mid, recv_h, recv, jit.Regs()[14]);
        SetRet64(jit, 0);
        return;
    }

    // An intercepted call never reaches Java: the host answers it (unlock-all on
    // Restore IAPs, tutorial skip on account connect). Both hooked methods return void.
    if (AbgoUnlock::RunMethodHook(host, mid_h)) {
        SetRet64(jit, 0);
        return;
    }

    bool known = false;
    const std::vector<char> types = ArgTypes(mid_h, known);
    if (!known) {
        // Once per methodID: the descriptor never went through Get{,Static}MethodID, so the
        // argument count is a guess and anything but a no-arg method will be wrong.
        static std::mutex once_lock;
        static std::unordered_map<uint32_t, bool> reported;
        std::lock_guard<std::mutex> guard(once_lock);
        if (!reported[mid_h]) {
            reported[mid_h] = true;
            LOGE("%s: no signature recorded for methodID %u (LR 0x%08X) -- assuming no arguments",
                 what, mid_h, jit.Regs()[14]);
        }
    }

    std::vector<jvalue> args;
    args.reserve(types.size());
    if (form == Form::Array) {
        ArgsFromJvalues(host, Arg(jit, 3), types, args);
    } else if (form == Form::VaList) {
        // AAPCS-32 va_list is a plain char* into one contiguous argument block, so the same
        // walk works with the core registers already spent.
        ArgWalker w{jit, host, 4, Arg(jit, 3)};
        ArgsFromRegisters(w, types, args);
    } else {
        ArgWalker w{jit, host, 3, jit.Regs()[13]};
        ArgsFromRegisters(w, types, args);
    }
    const jvalue* a = args.empty() ? nullptr : args.data();
    jclass cls = static_cast<jclass>(recv);

    switch (ret) {
        case Ret::Void:
            if (is_static) env->CallStaticVoidMethodA(cls, mid, a);
            else           env->CallVoidMethodA(recv, mid, a);
            CaptureException(env, what);
            break;
        case Ret::Object: {
            jobject r = is_static ? env->CallStaticObjectMethodA(cls, mid, a)
                                  : env->CallObjectMethodA(recv, mid, a);
            CaptureException(env, what);
            SetRet(jit, Publish(env, r));
            break;
        }
        case Ret::Boolean: {
            const jboolean r = is_static ? env->CallStaticBooleanMethodA(cls, mid, a)
                                         : env->CallBooleanMethodA(recv, mid, a);
            CaptureException(env, what);
            SetRet(jit, r ? 1u : 0u);
            break;
        }
        case Ret::Byte: {
            const jbyte r = is_static ? env->CallStaticByteMethodA(cls, mid, a)
                                      : env->CallByteMethodA(recv, mid, a);
            CaptureException(env, what);
            SetRet(jit, static_cast<uint32_t>(static_cast<int32_t>(r)));
            break;
        }
        case Ret::Char: {
            const jchar r = is_static ? env->CallStaticCharMethodA(cls, mid, a)
                                      : env->CallCharMethodA(recv, mid, a);
            CaptureException(env, what);
            SetRet(jit, static_cast<uint32_t>(r));   // jchar is unsigned
            break;
        }
        case Ret::Short: {
            const jshort r = is_static ? env->CallStaticShortMethodA(cls, mid, a)
                                       : env->CallShortMethodA(recv, mid, a);
            CaptureException(env, what);
            SetRet(jit, static_cast<uint32_t>(static_cast<int32_t>(r)));
            break;
        }
        case Ret::Int: {
            const jint r = is_static ? env->CallStaticIntMethodA(cls, mid, a)
                                     : env->CallIntMethodA(recv, mid, a);
            CaptureException(env, what);
            SetRet(jit, static_cast<uint32_t>(r));
            break;
        }
        case Ret::Long: {
            const jlong r = is_static ? env->CallStaticLongMethodA(cls, mid, a)
                                      : env->CallLongMethodA(recv, mid, a);
            CaptureException(env, what);
            SetRet64(jit, static_cast<uint64_t>(r));
            break;
        }
        case Ret::Float: {
            const jfloat r = is_static ? env->CallStaticFloatMethodA(cls, mid, a)
                                       : env->CallFloatMethodA(recv, mid, a);
            CaptureException(env, what);
            SetRet(jit, FloatBits(r));   // softfp: a float returns in r0, not s0
            break;
        }
        case Ret::Double: {
            const jdouble r = is_static ? env->CallStaticDoubleMethodA(cls, mid, a)
                                        : env->CallDoubleMethodA(recv, mid, a);
            CaptureException(env, what);
            uint64_t bits;
            std::memcpy(&bits, &r, sizeof(bits));
            SetRet64(jit, bits);         // softfp: a double returns in r0:r1
            break;
        }
    }
}

// --- FindClass ------------------------------------------------------------------------------
// FindClass on a thread the VM did not create resolves against the system class loader, which
// does not know com/rovio/* or com/exient/*. Falling back to the application loader keeps guest
// worker threads working instead of handing back a null the guest will treat as "not present".
jobject AppClassLoader(JNIEnv* env) {
    static jobject cached = nullptr;
    static bool tried = false;
    if (tried) return cached;
    tried = true;

    jclass at = env->FindClass("android/app/ActivityThread");
    if (!at) { env->ExceptionClear(); return nullptr; }
    jmethodID cur = env->GetStaticMethodID(at, "currentApplication", "()Landroid/app/Application;");
    if (!cur) { env->ExceptionClear(); return nullptr; }
    jobject app = env->CallStaticObjectMethod(at, cur);
    if (!app) { env->ExceptionClear(); return nullptr; }
    jclass ctx = env->GetObjectClass(app);
    jmethodID gcl = env->GetMethodID(ctx, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (!gcl) { env->ExceptionClear(); return nullptr; }
    jobject loader = env->CallObjectMethod(app, gcl);
    if (!loader) { env->ExceptionClear(); return nullptr; }
    cached = env->NewGlobalRef(loader);
    return cached;
}

jclass FindClassAnywhere(JNIEnv* env, const char* name) {
    jclass c = env->FindClass(name);
    if (c) return c;
    env->ExceptionClear();

    jobject loader = AppClassLoader(env);
    if (!loader) return nullptr;
    jclass loader_cls = env->GetObjectClass(loader);
    jmethodID load = env->GetMethodID(loader_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!load) { env->ExceptionClear(); return nullptr; }

    std::string dotted(name);
    for (char& ch : dotted) if (ch == '/') ch = '.';
    jstring jname = env->NewStringUTF(dotted.c_str());
    jclass found = static_cast<jclass>(env->CallObjectMethod(loader, load, jname));
    env->DeleteLocalRef(jname);
    if (!found) env->ExceptionClear();
    return found;
}

}  // namespace

uint32_t GetGuestJNIEnvPtr() { return g_env_ptr; }
uint32_t GetGuestJavaVMPtr() { return g_vm_ptr; }

void InstallGuestJNIEnv(DynarmicHost& host) {
    if (g_env_ptr) return;

    ThunkManager& tm = host.GetThunkManager();
    const uint32_t table = host.GuestAlloc(kSlotCount * 4, 8);
    g_env_ptr = host.GuestAlloc(4, 4);
    host.MemoryWrite32(g_env_ptr, table);

    bool filled[kSlotCount] = {};
    auto slot = [&](uint32_t index, const char* name, ThunkHandler h) {
        if (index >= kSlotCount || filled[index]) {
            LOGE("JNIEnv slot %u (%s) is out of range or already taken -- check the index table",
                 index, name);
            return;
        }
        filled[index] = true;
        const std::string sym = std::string("GuestJNIEnv.") + name;
        // Every handler below creates host local references (FindClass, NewStringUTF,
        // GetObjectClass, CallObjectMethod ...) and only a handful delete them. Locals made
        // while servicing a guest call are only reclaimed when the enclosing Java->native
        // frame returns, and on the bridge's own threads -- the job pump, the watchdog --
        // there is no such frame at all, so they accumulate until the 512-entry local table
        // overflows and ART aborts the process. One frame per guest JNI call scopes them
        // exactly. Anything meant to outlive the call is already a global ref
        // (GuestRefFromHost, the class-loader cache), which PopLocalFrame does not touch.
        tm.RegisterThunk(sym, [h = std::move(h)](Jit& jit, DynarmicHost& host) {
            JNIEnv* env = HostEnv();
            const bool framed = env && env->PushLocalFrame(16) == 0;
            h(jit, host);
            if (framed) env->PopLocalFrame(nullptr);
        });
        host.MemoryWrite32(table + index * 4, tm.GetThunkSymbolTable().at(sym));
    };

    // --- version -------------------------------------------------------------------------
    slot(kGetVersion, "GetVersion", [](Jit& jit, DynarmicHost&) {
        SetRet(jit, JNI_VERSION_1_6);
    });

    // --- classes and identity -------------------------------------------------------------
    slot(kFindClass, "FindClass", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        const char* name = GuestStr(host, Arg(jit, 1));
        if (!env || !name) { SetRet(jit, 0); return; }
        jclass c = FindClassAnywhere(env, name);
        // Failures always; successes only the first time per class name. The device's log
        // flow control drops the whole process's output when we get chatty, and the engine
        // re-resolves the same handful of classes on every screen.
        static std::set<std::string> announced;
        if (!c) LOGE("FindClass('%s') failed (LR 0x%08X)", name, jit.Regs()[14]);
        else if (announced.insert(name).second) LOGI("FindClass('%s')", name);
        SetRet(jit, Publish(env, c));
    });

    slot(kGetObjectClass, "GetObjectClass", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        SetRet(jit, (env && o) ? Publish(env, env->GetObjectClass(o)) : 0);
    });

    slot(kGetSuperclass, "GetSuperclass", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
        SetRet(jit, (env && c) ? Publish(env, env->GetSuperclass(c)) : 0);
    });

    slot(kIsInstanceOf, "IsInstanceOf", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 2)));
        SetRet(jit, (env && c && env->IsInstanceOf(o, c)) ? 1u : 0u);
    });

    slot(kIsSameObject, "IsSameObject", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        if (!env) { SetRet(jit, 0); return; }
        SetRet(jit, env->IsSameObject(HostRefFromGuest(Arg(jit, 1)),
                                      HostRefFromGuest(Arg(jit, 2))) ? 1u : 0u);
    });

    // --- IDs -------------------------------------------------------------------------------
    auto method_id = [](bool is_static) {
        return [is_static](Jit& jit, DynarmicHost& host) {
            JNIEnv* env = HostEnv();
            jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
            const char* name = GuestStr(host, Arg(jit, 2));
            const char* sig = GuestStr(host, Arg(jit, 3));
            if (!env || !c || !name || !sig) {
                LOGE("Get%sMethodID with class=%u name=%p sig=%p (LR 0x%08X)",
                     is_static ? "Static" : "", Arg(jit, 1), name, sig, jit.Regs()[14]);
                SetRet(jit, 0);
                return;
            }
            jmethodID m = is_static ? env->GetStaticMethodID(c, name, sig)
                                    : env->GetMethodID(c, name, sig);
            CaptureException(env, "GetMethodID");
            if (!m) {
                LOGE("Get%sMethodID('%s','%s') not found (LR 0x%08X)",
                     is_static ? "Static" : "", name, sig, jit.Regs()[14]);
                SetRet(jit, 0);
                return;
            }
            const uint32_t h = GuestMethodId(m);
            RememberSignature(h, sig);
            // Some resolved names belong to online services this build can never reach;
            // the calls themselves are answered host-side (see abgo_unlock.cpp).
            AbgoUnlock::OnMethodResolved(h, name);
            SetRet(jit, h);
        };
    };
    slot(kGetMethodID, "GetMethodID", method_id(false));
    slot(kGetStaticMethodID, "GetStaticMethodID", method_id(true));

    auto field_id = [](bool is_static) {
        return [is_static](Jit& jit, DynarmicHost& host) {
            JNIEnv* env = HostEnv();
            jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
            const char* name = GuestStr(host, Arg(jit, 2));
            const char* sig = GuestStr(host, Arg(jit, 3));
            if (!env || !c || !name || !sig) { SetRet(jit, 0); return; }
            jfieldID f = is_static ? env->GetStaticFieldID(c, name, sig)
                                   : env->GetFieldID(c, name, sig);
            CaptureException(env, "GetFieldID");
            if (!f) LOGE("Get%sFieldID('%s','%s') not found (LR 0x%08X)",
                         is_static ? "Static" : "", name, sig, jit.Regs()[14]);
            SetRet(jit, GuestFieldId(f));
        };
    };
    slot(kGetFieldID, "GetFieldID", field_id(false));
    slot(kGetStaticFieldID, "GetStaticFieldID", field_id(true));

    // --- construction -----------------------------------------------------------------------
    auto new_object = [](Form form) {
        return [form](Jit& jit, DynarmicHost& host) {
            JNIEnv* env = HostEnv();
            jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
            const uint32_t mid_h = Arg(jit, 2);
            jmethodID mid = HostMethodId(mid_h);
            if (!env || !c || !mid) {
                LOGE("NewObject with class=%u mid=%u (LR 0x%08X)", Arg(jit, 1), mid_h, jit.Regs()[14]);
                SetRet(jit, 0);
                return;
            }
            bool known = false;
            const std::vector<char> types = ArgTypes(mid_h, known);
            if (!known) LOGE("NewObject: no signature for methodID %u (LR 0x%08X)", mid_h, jit.Regs()[14]);
            std::vector<jvalue> args;
            if (form == Form::Array) {
                ArgsFromJvalues(host, Arg(jit, 3), types, args);
            } else if (form == Form::VaList) {
                ArgWalker w{jit, host, 4, Arg(jit, 3)};
                ArgsFromRegisters(w, types, args);
            } else {
                ArgWalker w{jit, host, 3, jit.Regs()[13]};
                ArgsFromRegisters(w, types, args);
            }
            jobject o = env->NewObjectA(c, mid, args.empty() ? nullptr : args.data());
            CaptureException(env, "NewObject");
            SetRet(jit, Publish(env, o));
        };
    };
    slot(kNewObject,  "NewObject",  new_object(Form::Varargs));
    slot(kNewObjectV, "NewObjectV", new_object(Form::VaList));
    slot(kNewObjectA, "NewObjectA", new_object(Form::Array));

    // --- calls -------------------------------------------------------------------------------
    auto call = [](Ret ret, bool is_static, Form form, const char* what) {
        return [ret, is_static, form, what](Jit& jit, DynarmicHost& host) {
            DoCall(jit, host, ret, is_static, form, what);
        };
    };
    struct CallSlot { uint32_t plain, v, a; Ret ret; const char* name; };
    static const CallSlot kInstanceCalls[] = {
        {kCallObjectMethod,  kCallObjectMethodV,  kCallObjectMethodA,  Ret::Object,  "CallObjectMethod"},
        {kCallBooleanMethod, kCallBooleanMethodV, kCallBooleanMethodA, Ret::Boolean, "CallBooleanMethod"},
        {kCallByteMethod,    kCallByteMethodV,    kCallByteMethodA,    Ret::Byte,    "CallByteMethod"},
        {kCallCharMethod,    kCallCharMethodV,    kCallCharMethodA,    Ret::Char,    "CallCharMethod"},
        {kCallShortMethod,   kCallShortMethodV,   kCallShortMethodA,   Ret::Short,   "CallShortMethod"},
        {kCallDoubleMethod,  kCallDoubleMethodV,  kCallDoubleMethodA,  Ret::Double,  "CallDoubleMethod"},
        {kCallIntMethod,     kCallIntMethodV,     kCallIntMethodA,     Ret::Int,     "CallIntMethod"},
        {kCallLongMethod,    kCallLongMethodV,    kCallLongMethodA,    Ret::Long,    "CallLongMethod"},
        {kCallFloatMethod,   kCallFloatMethodV,   kCallFloatMethodA,   Ret::Float,   "CallFloatMethod"},
        {kCallVoidMethod,    kCallVoidMethodV,    kCallVoidMethodA,    Ret::Void,    "CallVoidMethod"},
    };
    static const CallSlot kStaticCalls[] = {
        {kCallStaticObjectMethod,  kCallStaticObjectMethodV,  kCallStaticObjectMethodA,  Ret::Object,  "CallStaticObjectMethod"},
        {kCallStaticBooleanMethod, kCallStaticBooleanMethodV, kCallStaticBooleanMethodA, Ret::Boolean, "CallStaticBooleanMethod"},
        {kCallStaticByteMethod,    kCallStaticByteMethodV,    kCallStaticByteMethodA,    Ret::Byte,    "CallStaticByteMethod"},
        {kCallStaticCharMethod,    kCallStaticCharMethodV,    kCallStaticCharMethodA,    Ret::Char,    "CallStaticCharMethod"},
        {kCallStaticShortMethod,   kCallStaticShortMethodV,   kCallStaticShortMethodA,   Ret::Short,   "CallStaticShortMethod"},
        {kCallStaticDoubleMethod,  kCallStaticDoubleMethodV,  kCallStaticDoubleMethodA,  Ret::Double,  "CallStaticDoubleMethod"},
        {kCallStaticIntMethod,     kCallStaticIntMethodV,     kCallStaticIntMethodA,     Ret::Int,     "CallStaticIntMethod"},
        {kCallStaticLongMethod,    kCallStaticLongMethodV,    kCallStaticLongMethodA,    Ret::Long,    "CallStaticLongMethod"},
        {kCallStaticFloatMethod,   kCallStaticFloatMethodV,   kCallStaticFloatMethodA,   Ret::Float,   "CallStaticFloatMethod"},
        {kCallStaticVoidMethod,    kCallStaticVoidMethodV,    kCallStaticVoidMethodA,    Ret::Void,    "CallStaticVoidMethod"},
    };
    for (int table_index = 0; table_index < 2; ++table_index) {
        const bool is_static = table_index == 1;
        const CallSlot* set = is_static ? kStaticCalls : kInstanceCalls;
        for (int i = 0; i < 10; ++i) {
            const CallSlot& cs = set[i];
            slot(cs.plain, cs.name, call(cs.ret, is_static, Form::Varargs, cs.name));
            slot(cs.v, (std::string(cs.name) + "V").c_str(), call(cs.ret, is_static, Form::VaList, cs.name));
            slot(cs.a, (std::string(cs.name) + "A").c_str(), call(cs.ret, is_static, Form::Array, cs.name));
        }
    }

    // --- instance fields ---------------------------------------------------------------------
    slot(kGetObjectField, "GetObjectField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        jfieldID f = HostFieldId(Arg(jit, 2));
        SetRet(jit, (env && o && f) ? Publish(env, env->GetObjectField(o, f)) : 0);
    });
    slot(kGetBooleanField, "GetBooleanField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        jfieldID f = HostFieldId(Arg(jit, 2));
        SetRet(jit, (env && o && f && env->GetBooleanField(o, f)) ? 1u : 0u);
    });
    slot(kGetIntField, "GetIntField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        jfieldID f = HostFieldId(Arg(jit, 2));
        SetRet(jit, (env && o && f) ? static_cast<uint32_t>(env->GetIntField(o, f)) : 0);
    });
    slot(kGetLongField, "GetLongField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        jfieldID f = HostFieldId(Arg(jit, 2));
        SetRet64(jit, (env && o && f) ? static_cast<uint64_t>(env->GetLongField(o, f)) : 0);
    });
    slot(kGetFloatField, "GetFloatField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        jfieldID f = HostFieldId(Arg(jit, 2));
        SetRet(jit, (env && o && f) ? FloatBits(env->GetFloatField(o, f)) : 0);
    });

    slot(kSetObjectField, "SetObjectField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        jfieldID f = HostFieldId(Arg(jit, 2));
        if (env && o && f) env->SetObjectField(o, f, HostRefFromGuest(Arg(jit, 3)));
    });
    slot(kSetBooleanField, "SetBooleanField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        jfieldID f = HostFieldId(Arg(jit, 2));
        if (env && o && f) env->SetBooleanField(o, f, Arg(jit, 3) ? JNI_TRUE : JNI_FALSE);
    });
    slot(kSetIntField, "SetIntField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        jfieldID f = HostFieldId(Arg(jit, 2));
        if (env && o && f) env->SetIntField(o, f, static_cast<jint>(Arg(jit, 3)));
    });
    slot(kSetLongField, "SetLongField", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        jfieldID f = HostFieldId(Arg(jit, 2));
        // env, obj, fieldID fill r0-r2 and the jlong needs an even register pair, so r3 is
        // padding and the value lands entirely on the caller's stack. ArgWalker knows the rule.
        ArgWalker w{jit, host, 3, jit.Regs()[13]};
        const uint64_t v = w.DoubleWord();
        if (env && o && f) env->SetLongField(o, f, static_cast<jlong>(v));
    });
    slot(kSetFloatField, "SetFloatField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        jfieldID f = HostFieldId(Arg(jit, 2));
        if (env && o && f) {
            float v;
            const uint32_t bits = Arg(jit, 3);
            std::memcpy(&v, &bits, 4);
            env->SetFloatField(o, f, v);
        }
    });

    // --- static fields -----------------------------------------------------------------------
    slot(kGetStaticObjectField, "GetStaticObjectField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
        jfieldID f = HostFieldId(Arg(jit, 2));
        SetRet(jit, (env && c && f) ? Publish(env, env->GetStaticObjectField(c, f)) : 0);
    });
    slot(kGetStaticBooleanField, "GetStaticBooleanField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
        jfieldID f = HostFieldId(Arg(jit, 2));
        SetRet(jit, (env && c && f && env->GetStaticBooleanField(c, f)) ? 1u : 0u);
    });
    slot(kGetStaticIntField, "GetStaticIntField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
        jfieldID f = HostFieldId(Arg(jit, 2));
        SetRet(jit, (env && c && f) ? static_cast<uint32_t>(env->GetStaticIntField(c, f)) : 0);
    });

    // --- strings ------------------------------------------------------------------------------
    slot(kNewStringUTF, "NewStringUTF", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        const char* s = GuestStr(host, Arg(jit, 1));
        SetRet(jit, (env && s) ? Publish(env, env->NewStringUTF(s)) : 0);
    });
    slot(kGetStringLength, "GetStringLength", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jstring s = static_cast<jstring>(HostRefFromGuest(Arg(jit, 1)));
        SetRet(jit, (env && s) ? static_cast<uint32_t>(env->GetStringLength(s)) : 0);
    });
    slot(kGetStringUTFLength, "GetStringUTFLength", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jstring s = static_cast<jstring>(HostRefFromGuest(Arg(jit, 1)));
        SetRet(jit, (env && s) ? static_cast<uint32_t>(env->GetStringUTFLength(s)) : 0);
    });
    slot(kGetStringUTFChars, "GetStringUTFChars", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jstring s = static_cast<jstring>(HostRefFromGuest(Arg(jit, 1)));
        if (!env || !s) { SetRet(jit, 0); return; }
        const char* chars = env->GetStringUTFChars(s, nullptr);
        if (!chars) { CaptureException(env, "GetStringUTFChars"); SetRet(jit, 0); return; }
        const uint32_t len = static_cast<uint32_t>(std::strlen(chars)) + 1;
        const uint32_t g = BlockAlloc(host, len);
        if (g) std::memcpy(GuestToHost(host.GetGuestMemoryBase(), g), chars, len);
        env->ReleaseStringUTFChars(s, chars);
        // The guest treats the result as const char*, so it must be a guest address.
        if (const uint32_t is_copy = Arg(jit, 2)) host.MemoryWrite8(is_copy, JNI_TRUE);
        SetRet(jit, g);
    });
    slot(kReleaseStringUTFChars, "ReleaseStringUTFChars", [](Jit& jit, DynarmicHost&) {
        BlockFree(Arg(jit, 2));
    });

    // --- references ----------------------------------------------------------------------------
    // Every handle is backed by a host global ref, so local and global are the same thing here
    // and a local frame has nothing to unwind.
    slot(kNewGlobalRef, "NewGlobalRef", [](Jit& jit, DynarmicHost&) {
        SetRet(jit, GuestRefFromHost(HostRefFromGuest(Arg(jit, 1))));
    });
    slot(kNewLocalRef, "NewLocalRef", [](Jit& jit, DynarmicHost&) {
        SetRet(jit, GuestRefFromHost(HostRefFromGuest(Arg(jit, 1))));
    });
    slot(kDeleteGlobalRef, "DeleteGlobalRef", [](Jit& jit, DynarmicHost&) {
        GuestRefDelete(Arg(jit, 1));
    });
    slot(kDeleteLocalRef, "DeleteLocalRef", [](Jit& jit, DynarmicHost&) {
        GuestRefDelete(Arg(jit, 1));
    });
    slot(kPushLocalFrame, "PushLocalFrame", [](Jit& jit, DynarmicHost&) {
        SetRet(jit, 0);
    });
    slot(kPopLocalFrame, "PopLocalFrame", [](Jit& jit, DynarmicHost&) {
        SetRet(jit, Arg(jit, 1));
    });

    // --- exceptions ------------------------------------------------------------------------------
    slot(kExceptionOccurred, "ExceptionOccurred", [](Jit& jit, DynarmicHost&) {
        CaptureException(HostEnv(), "ExceptionOccurred");
        SetRet(jit, t_pending_exc);
    });
    slot(kExceptionCheck, "ExceptionCheck", [](Jit& jit, DynarmicHost&) {
        CaptureException(HostEnv(), "ExceptionCheck");
        SetRet(jit, t_pending_exc ? 1u : 0u);
    });
    slot(kExceptionClear, "ExceptionClear", [](Jit& jit, DynarmicHost&) {
        if (JNIEnv* env = HostEnv()) env->ExceptionClear();
        if (t_pending_exc) { GuestRefDelete(t_pending_exc); t_pending_exc = 0; }
    });
    slot(kExceptionDescribe, "ExceptionDescribe", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        if (!env) return;
        env->ExceptionDescribe();
        if (t_pending_exc) LOGE("guest ExceptionDescribe: exception handle %u pending", t_pending_exc);
    });
    slot(kThrow, "Throw", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jthrowable t = static_cast<jthrowable>(HostRefFromGuest(Arg(jit, 1)));
        if (!env || !t) { SetRet(jit, static_cast<uint32_t>(-1)); return; }
        // Parked rather than thrown: a live host exception would abort the next host JNI call
        // the guest makes, long before it returns to Java.
        if (t_pending_exc) GuestRefDelete(t_pending_exc);
        t_pending_exc = GuestRefFromHost(t);
        LOGE("guest Throw of handle %u (LR 0x%08X)", Arg(jit, 1), jit.Regs()[14]);
        SetRet(jit, 0);
    });
    slot(kThrowNew, "ThrowNew", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
        const char* msg = GuestStr(host, Arg(jit, 2));
        LOGE("guest ThrowNew('%s') (LR 0x%08X)", msg ? msg : "", jit.Regs()[14]);
        if (!env || !c) { SetRet(jit, static_cast<uint32_t>(-1)); return; }
        env->ThrowNew(c, msg);
        CaptureException(env, "ThrowNew");
        SetRet(jit, 0);
    });

    // --- arrays ------------------------------------------------------------------------------------
    slot(kGetArrayLength, "GetArrayLength", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jarray a = static_cast<jarray>(HostRefFromGuest(Arg(jit, 1)));
        SetRet(jit, (env && a) ? static_cast<uint32_t>(env->GetArrayLength(a)) : 0);
    });
    slot(kNewByteArray, "NewByteArray", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        SetRet(jit, env ? Publish(env, env->NewByteArray(static_cast<jsize>(Arg(jit, 1)))) : 0);
    });
    slot(kNewIntArray, "NewIntArray", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        SetRet(jit, env ? Publish(env, env->NewIntArray(static_cast<jsize>(Arg(jit, 1)))) : 0);
    });
    slot(kNewObjectArray, "NewObjectArray", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 2)));
        if (!env || !c) { SetRet(jit, 0); return; }
        jobjectArray a = env->NewObjectArray(static_cast<jsize>(Arg(jit, 1)), c,
                                             HostRefFromGuest(Arg(jit, 3)));
        CaptureException(env, "NewObjectArray");
        SetRet(jit, Publish(env, a));
    });
    slot(kGetObjectArrayElement, "GetObjectArrayElement", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobjectArray a = static_cast<jobjectArray>(HostRefFromGuest(Arg(jit, 1)));
        if (!env || !a) { SetRet(jit, 0); return; }
        jobject o = env->GetObjectArrayElement(a, static_cast<jsize>(Arg(jit, 2)));
        CaptureException(env, "GetObjectArrayElement");
        SetRet(jit, Publish(env, o));
    });
    slot(kSetObjectArrayElement, "SetObjectArrayElement", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobjectArray a = static_cast<jobjectArray>(HostRefFromGuest(Arg(jit, 1)));
        if (!env || !a) return;
        env->SetObjectArrayElement(a, static_cast<jsize>(Arg(jit, 2)), HostRefFromGuest(Arg(jit, 3)));
        CaptureException(env, "SetObjectArrayElement");
    });

    slot(kGetByteArrayElements, "GetByteArrayElements", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jbyteArray a = static_cast<jbyteArray>(HostRefFromGuest(Arg(jit, 1)));
        if (!env || !a) { SetRet(jit, 0); return; }
        const jsize len = env->GetArrayLength(a);
        const uint32_t g = BlockAlloc(host, static_cast<uint32_t>(len));
        if (!g) { SetRet(jit, 0); return; }
        env->GetByteArrayRegion(a, 0, len, static_cast<jbyte*>(GuestToHost(host.GetGuestMemoryBase(), g)));
        CaptureException(env, "GetByteArrayElements");
        {
            std::lock_guard<std::mutex> guard(g_pin_lock);
            g_pin_len[g] = len;
        }
        if (const uint32_t is_copy = Arg(jit, 2)) host.MemoryWrite8(is_copy, JNI_TRUE);
        SetRet(jit, g);
    });
    slot(kReleaseByteArrayElements, "ReleaseByteArrayElements", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jbyteArray a = static_cast<jbyteArray>(HostRefFromGuest(Arg(jit, 1)));
        const uint32_t g = Arg(jit, 2);
        const uint32_t mode = Arg(jit, 3);
        jsize len = 0;
        {
            std::lock_guard<std::mutex> guard(g_pin_lock);
            auto it = g_pin_len.find(g);
            if (it != g_pin_len.end()) { len = it->second; g_pin_len.erase(it); }
        }
        if (env && a && len && mode != JNI_ABORT) {
            env->SetByteArrayRegion(a, 0, len,
                                    static_cast<const jbyte*>(GuestToHost(host.GetGuestMemoryBase(), g)));
            CaptureException(env, "ReleaseByteArrayElements");
        }
        if (mode != JNI_COMMIT) BlockFree(g);
    });
    slot(kGetByteArrayRegion, "GetByteArrayRegion", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jbyteArray a = static_cast<jbyteArray>(HostRefFromGuest(Arg(jit, 1)));
        const uint32_t buf = StackArg(jit, host, 0);
        if (!env || !a || !buf) return;
        env->GetByteArrayRegion(a, static_cast<jsize>(Arg(jit, 2)), static_cast<jsize>(Arg(jit, 3)),
                                static_cast<jbyte*>(GuestToHost(host.GetGuestMemoryBase(), buf)));
        CaptureException(env, "GetByteArrayRegion");
    });
    slot(kSetByteArrayRegion, "SetByteArrayRegion", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jbyteArray a = static_cast<jbyteArray>(HostRefFromGuest(Arg(jit, 1)));
        const uint32_t buf = StackArg(jit, host, 0);
        if (!env || !a || !buf) return;
        env->SetByteArrayRegion(a, static_cast<jsize>(Arg(jit, 2)), static_cast<jsize>(Arg(jit, 3)),
                                static_cast<const jbyte*>(GuestToHost(host.GetGuestMemoryBase(), buf)));
        CaptureException(env, "SetByteArrayRegion");
    });

    // --- monitors and the VM ------------------------------------------------------------------------
    slot(kMonitorEnter, "MonitorEnter", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        SetRet(jit, (env && o) ? static_cast<uint32_t>(env->MonitorEnter(o)) : static_cast<uint32_t>(-1));
    });
    slot(kMonitorExit, "MonitorExit", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject o = HostRefFromGuest(Arg(jit, 1));
        SetRet(jit, (env && o) ? static_cast<uint32_t>(env->MonitorExit(o)) : static_cast<uint32_t>(-1));
    });
    slot(kGetJavaVM, "GetJavaVM", [](Jit& jit, DynarmicHost& host) {
        if (const uint32_t out = Arg(jit, 1)) host.MemoryWrite32(out, g_vm_ptr);
        SetRet(jit, 0);
    });

    // --- the rest of the field accessors ------------------------------------------------------
    // Mechanical, but not optional: an unimplemented getter answers 0, which is a plausible
    // value for every one of these types and therefore invisible until something downstream
    // stops making sense. Build.TIME arriving through GetStaticLongField (slot 151) is
    // exactly how this bit us.
    struct FieldSlot { uint32_t get, set; char kind; bool is_static; const char* name; };
    static const FieldSlot kFields[] = {
        {kGetByteField,          kSetByteField,          'B', false, "ByteField"},
        {kGetCharField,          kSetCharField,          'C', false, "CharField"},
        {kGetShortField,         kSetShortField,         'S', false, "ShortField"},
        {kGetDoubleField,        kSetDoubleField,        'D', false, "DoubleField"},
        {kGetStaticByteField,    kSetStaticByteField,    'B', true,  "StaticByteField"},
        {kGetStaticCharField,    kSetStaticCharField,    'C', true,  "StaticCharField"},
        {kGetStaticShortField,   kSetStaticShortField,   'S', true,  "StaticShortField"},
        {kGetStaticLongField,    kSetStaticLongField,    'J', true,  "StaticLongField"},
        {kGetStaticFloatField,   kSetStaticFloatField,   'F', true,  "StaticFloatField"},
        {kGetStaticDoubleField,  kSetStaticDoubleField,  'D', true,  "StaticDoubleField"},
    };
    for (const FieldSlot& fs : kFields) {
        const char kind = fs.kind;
        const bool st = fs.is_static;
        slot(fs.get, (std::string("Get") + fs.name).c_str(), [kind, st](Jit& jit, DynarmicHost&) {
            JNIEnv* env = HostEnv();
            jobject o = HostRefFromGuest(Arg(jit, 1));
            jclass c = static_cast<jclass>(o);
            jfieldID f = HostFieldId(Arg(jit, 2));
            if (!env || !o || !f) { SetRet64(jit, 0); return; }
            switch (kind) {
                case 'B': SetRet(jit, static_cast<uint32_t>(static_cast<int32_t>(
                              st ? env->GetStaticByteField(c, f) : env->GetByteField(o, f)))); break;
                case 'C': SetRet(jit, static_cast<uint32_t>(
                              st ? env->GetStaticCharField(c, f) : env->GetCharField(o, f))); break;
                case 'S': SetRet(jit, static_cast<uint32_t>(static_cast<int32_t>(
                              st ? env->GetStaticShortField(c, f) : env->GetShortField(o, f)))); break;
                case 'J': SetRet64(jit, static_cast<uint64_t>(env->GetStaticLongField(c, f))); break;
                case 'F': SetRet(jit, FloatBits(st ? env->GetStaticFloatField(c, f)
                                                   : env->GetFloatField(o, f))); break;
                case 'D': { const jdouble d = st ? env->GetStaticDoubleField(c, f)
                                                 : env->GetDoubleField(o, f);
                            uint64_t bits; std::memcpy(&bits, &d, 8); SetRet64(jit, bits); break; }
                default: SetRet64(jit, 0); break;
            }
            CaptureException(env, "GetField");
        });
        slot(fs.set, (std::string("Set") + fs.name).c_str(), [kind, st](Jit& jit, DynarmicHost& host) {
            JNIEnv* env = HostEnv();
            jobject o = HostRefFromGuest(Arg(jit, 1));
            jclass c = static_cast<jclass>(o);
            jfieldID f = HostFieldId(Arg(jit, 2));
            if (!env || !o || !f) return;
            // 8-byte values need an even register pair; env/obj/fieldID have already taken
            // r0-r2, so r3 is padding and the value sits entirely on the caller's stack.
            if (kind == 'J' || kind == 'D') {
                ArgWalker w{jit, host, 3, jit.Regs()[13]};
                const uint64_t bits = w.DoubleWord();
                if (kind == 'J') {
                    const jlong v = static_cast<jlong>(bits);
                    if (st) env->SetStaticLongField(c, f, v); else env->SetLongField(o, f, v);
                } else {
                    jdouble d; std::memcpy(&d, &bits, 8);
                    if (st) env->SetStaticDoubleField(c, f, d); else env->SetDoubleField(o, f, d);
                }
                return;
            }
            const uint32_t raw = Arg(jit, 3);
            switch (kind) {
                case 'B': { const jbyte v = static_cast<jbyte>(raw);
                            if (st) env->SetStaticByteField(c, f, v); else env->SetByteField(o, f, v); break; }
                case 'C': { const jchar v = static_cast<jchar>(raw);
                            if (st) env->SetStaticCharField(c, f, v); else env->SetCharField(o, f, v); break; }
                case 'S': { const jshort v = static_cast<jshort>(raw);
                            if (st) env->SetStaticShortField(c, f, v); else env->SetShortField(o, f, v); break; }
                case 'F': { jfloat v; std::memcpy(&v, &raw, 4);
                            if (st) env->SetStaticFloatField(c, f, v); else env->SetFloatField(o, f, v); break; }
                default: break;
            }
        });
    }
    slot(kSetStaticObjectField, "SetStaticObjectField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
        jfieldID f = HostFieldId(Arg(jit, 2));
        if (env && c && f) env->SetStaticObjectField(c, f, HostRefFromGuest(Arg(jit, 3)));
    });
    slot(kSetStaticBooleanField, "SetStaticBooleanField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
        jfieldID f = HostFieldId(Arg(jit, 2));
        if (env && c && f) env->SetStaticBooleanField(c, f, Arg(jit, 3) ? JNI_TRUE : JNI_FALSE);
    });
    slot(kSetStaticIntField, "SetStaticIntField", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
        jfieldID f = HostFieldId(Arg(jit, 2));
        if (env && c && f) env->SetStaticIntField(c, f, static_cast<jint>(Arg(jit, 3)));
    });

    // --- UTF-16 strings ---------------------------------------------------------------------
    slot(kNewString, "NewString", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        const uint32_t src = Arg(jit, 1);
        const jsize len = static_cast<jsize>(Arg(jit, 2));
        if (!env || !src) { SetRet(jit, 0); return; }
        SetRet(jit, Publish(env, env->NewString(
            static_cast<const jchar*>(GuestToHost(host.GetGuestMemoryBase(), src)), len)));
    });
    slot(kGetStringChars, "GetStringChars", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jstring s = static_cast<jstring>(HostRefFromGuest(Arg(jit, 1)));
        if (!env || !s) { SetRet(jit, 0); return; }
        const jsize len = env->GetStringLength(s);
        const uint32_t g = BlockAlloc(host, static_cast<uint32_t>(len + 1) * 2);
        if (!g) { SetRet(jit, 0); return; }
        env->GetStringRegion(s, 0, len, static_cast<jchar*>(GuestToHost(host.GetGuestMemoryBase(), g)));
        CaptureException(env, "GetStringChars");
        host.MemoryWrite16(g + static_cast<uint32_t>(len) * 2, 0);
        if (const uint32_t is_copy = Arg(jit, 2)) host.MemoryWrite8(is_copy, JNI_TRUE);
        SetRet(jit, g);
    });
    slot(kReleaseStringChars, "ReleaseStringChars", [](Jit& jit, DynarmicHost&) {
        BlockFree(Arg(jit, 2));
    });
    slot(kGetStringRegion, "GetStringRegion", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jstring s = static_cast<jstring>(HostRefFromGuest(Arg(jit, 1)));
        const uint32_t buf = StackArg(jit, host, 0);
        if (!env || !s || !buf) return;
        env->GetStringRegion(s, static_cast<jsize>(Arg(jit, 2)), static_cast<jsize>(Arg(jit, 3)),
                             static_cast<jchar*>(GuestToHost(host.GetGuestMemoryBase(), buf)));
        CaptureException(env, "GetStringRegion");
    });
    slot(kGetStringUTFRegion, "GetStringUTFRegion", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jstring s = static_cast<jstring>(HostRefFromGuest(Arg(jit, 1)));
        const uint32_t buf = StackArg(jit, host, 0);
        if (!env || !s || !buf) return;
        env->GetStringUTFRegion(s, static_cast<jsize>(Arg(jit, 2)), static_cast<jsize>(Arg(jit, 3)),
                                static_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), buf)));
        CaptureException(env, "GetStringUTFRegion");
    });

    // --- int arrays --------------------------------------------------------------------------
    slot(kGetIntArrayElements, "GetIntArrayElements", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jintArray a = static_cast<jintArray>(HostRefFromGuest(Arg(jit, 1)));
        if (!env || !a) { SetRet(jit, 0); return; }
        const jsize len = env->GetArrayLength(a);
        const uint32_t g = BlockAlloc(host, static_cast<uint32_t>(len) * 4);
        if (!g) { SetRet(jit, 0); return; }
        env->GetIntArrayRegion(a, 0, len, static_cast<jint*>(GuestToHost(host.GetGuestMemoryBase(), g)));
        CaptureException(env, "GetIntArrayElements");
        {
            std::lock_guard<std::mutex> guard(g_pin_lock);
            g_pin_len[g] = len;
        }
        if (const uint32_t is_copy = Arg(jit, 2)) host.MemoryWrite8(is_copy, JNI_TRUE);
        SetRet(jit, g);
    });
    slot(kReleaseIntArrayElements, "ReleaseIntArrayElements", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jintArray a = static_cast<jintArray>(HostRefFromGuest(Arg(jit, 1)));
        const uint32_t g = Arg(jit, 2);
        const uint32_t mode = Arg(jit, 3);
        jsize len = 0;
        {
            std::lock_guard<std::mutex> guard(g_pin_lock);
            auto it = g_pin_len.find(g);
            if (it != g_pin_len.end()) { len = it->second; g_pin_len.erase(it); }
        }
        if (env && a && len && mode != JNI_ABORT) {
            env->SetIntArrayRegion(a, 0, len,
                                   static_cast<const jint*>(GuestToHost(host.GetGuestMemoryBase(), g)));
            CaptureException(env, "ReleaseIntArrayElements");
        }
        if (mode != JNI_COMMIT) BlockFree(g);
    });
    slot(kGetIntArrayRegion, "GetIntArrayRegion", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jintArray a = static_cast<jintArray>(HostRefFromGuest(Arg(jit, 1)));
        const uint32_t buf = StackArg(jit, host, 0);
        if (!env || !a || !buf) return;
        env->GetIntArrayRegion(a, static_cast<jsize>(Arg(jit, 2)), static_cast<jsize>(Arg(jit, 3)),
                               static_cast<jint*>(GuestToHost(host.GetGuestMemoryBase(), buf)));
        CaptureException(env, "GetIntArrayRegion");
    });
    slot(kSetIntArrayRegion, "SetIntArrayRegion", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jintArray a = static_cast<jintArray>(HostRefFromGuest(Arg(jit, 1)));
        const uint32_t buf = StackArg(jit, host, 0);
        if (!env || !a || !buf) return;
        env->SetIntArrayRegion(a, static_cast<jsize>(Arg(jit, 2)), static_cast<jsize>(Arg(jit, 3)),
                               static_cast<const jint*>(GuestToHost(host.GetGuestMemoryBase(), buf)));
        CaptureException(env, "SetIntArrayRegion");
    });

    // --- references, reflection, direct buffers ------------------------------------------------
    // Every handle is already backed by a global ref, so weak and strong are the same here.
    slot(kNewWeakGlobalRef, "NewWeakGlobalRef", [](Jit& jit, DynarmicHost&) {
        SetRet(jit, GuestRefFromHost(HostRefFromGuest(Arg(jit, 1))));
    });
    slot(kDeleteWeakGlobalRef, "DeleteWeakGlobalRef", [](Jit& jit, DynarmicHost&) {
        GuestRefDelete(Arg(jit, 1));
    });
    slot(kEnsureLocalCapacity, "EnsureLocalCapacity", [](Jit& jit, DynarmicHost&) {
        SetRet(jit, 0);   // handles come from a growable table; capacity is never the problem
    });
    slot(kGetObjectRefType, "GetObjectRefType", [](Jit& jit, DynarmicHost&) {
        SetRet(jit, Arg(jit, 1) ? 2u : 0u);   // JNIGlobalRefType / JNIInvalidRefType
    });
    slot(kIsAssignableFrom, "IsAssignableFrom", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jclass a = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
        jclass b = static_cast<jclass>(HostRefFromGuest(Arg(jit, 2)));
        SetRet(jit, (env && a && b && env->IsAssignableFrom(a, b)) ? 1u : 0u);
    });
    slot(kAllocObject, "AllocObject", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jclass c = static_cast<jclass>(HostRefFromGuest(Arg(jit, 1)));
        if (!env || !c) { SetRet(jit, 0); return; }
        jobject o = env->AllocObject(c);
        CaptureException(env, "AllocObject");
        SetRet(jit, Publish(env, o));
    });
    slot(kFatalError, "FatalError", [](Jit& jit, DynarmicHost& host) {
        const char* msg = GuestStr(host, Arg(jit, 1));
        LOGE("guest FatalError('%s') from LR 0x%08X", msg ? msg : "?", jit.Regs()[14]);
        std::abort();   // the real FatalError does not return either
    });
    // A direct buffer over guest memory needs no copy: the guest address plus the arena base
    // IS a host address, and the arena is mapped for the life of the process.
    slot(kNewDirectByteBuffer, "NewDirectByteBuffer", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        const uint32_t addr = Arg(jit, 1);
        ArgWalker w{jit, host, 2, jit.Regs()[13]};
        const jlong cap = static_cast<jlong>(w.DoubleWord());
        if (!env || !addr) { SetRet(jit, 0); return; }
        jobject b = env->NewDirectByteBuffer(GuestToHost(host.GetGuestMemoryBase(), addr), cap);
        CaptureException(env, "NewDirectByteBuffer");
        SetRet(jit, Publish(env, b));
    });
    slot(kGetDirectBufferAddress, "GetDirectBufferAddress", [](Jit& jit, DynarmicHost& host) {
        JNIEnv* env = HostEnv();
        jobject b = HostRefFromGuest(Arg(jit, 1));
        if (!env || !b) { SetRet(jit, 0); return; }
        void* p = env->GetDirectBufferAddress(b);
        const uintptr_t base = reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase());
        const uintptr_t hp = reinterpret_cast<uintptr_t>(p);
        if (!p || hp < base || hp - base >= host.GetGuestMemorySize()) {
            LOGE("GetDirectBufferAddress: %p is host memory, unreachable from the guest", p);
            SetRet(jit, 0);
            return;
        }
        SetRet(jit, static_cast<uint32_t>(hp - base));
    });
    slot(kGetDirectBufferCapacity, "GetDirectBufferCapacity", [](Jit& jit, DynarmicHost&) {
        JNIEnv* env = HostEnv();
        jobject b = HostRefFromGuest(Arg(jit, 1));
        SetRet64(jit, (env && b) ? static_cast<uint64_t>(env->GetDirectBufferCapacity(b))
                                 : static_cast<uint64_t>(-1));
    });
    // The guest's own natives are guest code and ART cannot be handed a pointer into the JIT's
    // address space. Nothing in ABGo registers natives this way -- all 42 resolve by name --
    // so this exists to be loud if that ever stops being true.
    slot(kRegisterNatives, "RegisterNatives", [](Jit& jit, DynarmicHost&) {
        LOGE("guest RegisterNatives(%u methods) from LR 0x%08X -- IGNORED, guest function "
             "pointers cannot be given to ART", Arg(jit, 3), jit.Regs()[14]);
        SetRet(jit, 0);
    });
    slot(kUnregisterNatives, "UnregisterNatives", [](Jit& jit, DynarmicHost&) { SetRet(jit, 0); });

    // --- everything else --------------------------------------------------------------------------
    // A silent 0 from an unimplemented slot is indistinguishable from a legitimate null, so each
    // one gets its own trampoline and announces its index and the guest LR the first time it runs.
    for (uint32_t i = 0; i < kSlotCount; ++i) {
        if (filled[i]) continue;
        char name[32];
        std::snprintf(name, sizeof(name), "Slot%03u", i);
        tm.RegisterThunk(std::string("GuestJNIEnv.") + name, [i](Jit& jit, DynarmicHost&) {
            static std::mutex once_lock;
            static bool reported[kSlotCount] = {};
            {
                std::lock_guard<std::mutex> guard(once_lock);
                if (reported[i]) { SetRet64(jit, 0); return; }
                reported[i] = true;
            }
            LOGE("UNIMPLEMENTED JNIEnv slot %u called from LR 0x%08X (r1=0x%08X r2=0x%08X r3=0x%08X)",
                 i, jit.Regs()[14], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
            SetRet64(jit, 0);
        });
        host.MemoryWrite32(table + i * 4,
                           tm.GetThunkSymbolTable().at(std::string("GuestJNIEnv.") + name));
    }

    // --- the guest JavaVM ----------------------------------------------------------------------------
    const uint32_t invoke_table = host.GuestAlloc(kInvokeSlotCount * 4, 8);
    g_vm_ptr = host.GuestAlloc(4, 4);
    host.MemoryWrite32(g_vm_ptr, invoke_table);

    auto vm_slot = [&](uint32_t index, const char* name, ThunkHandler h) {
        const std::string sym = std::string("GuestJavaVM.") + name;
        tm.RegisterThunk(sym, std::move(h));
        host.MemoryWrite32(invoke_table + index * 4, tm.GetThunkSymbolTable().at(sym));
    };
    // Attaching is what HostEnv() already does for this thread; the guest only ever needs the
    // one JNIEnv, so all three hand back the same cell.
    auto give_env = [](Jit& jit, DynarmicHost& host) {
        HostEnv();
        if (const uint32_t out = Arg(jit, 1)) host.MemoryWrite32(out, g_env_ptr);
        SetRet(jit, HostEnv() ? JNI_OK : JNI_ERR);
    };
    vm_slot(kAttachCurrentThread, "AttachCurrentThread", give_env);
    vm_slot(kAttachCurrentThreadAsDaemon, "AttachCurrentThreadAsDaemon", give_env);
    vm_slot(kGetEnv, "GetEnv", give_env);
    vm_slot(kDetachCurrentThread, "DetachCurrentThread", [](Jit& jit, DynarmicHost&) {
        SetRet(jit, JNI_OK);   // HostEnv() leaves detaching to thread exit
    });
    vm_slot(kDestroyJavaVM, "DestroyJavaVM", [](Jit& jit, DynarmicHost&) {
        LOGE("guest called DestroyJavaVM -- ignored");
        SetRet(jit, JNI_ERR);
    });
    for (uint32_t i = 0; i < 3; ++i) host.MemoryWrite32(invoke_table + i * 4, 0);

    LOGI("guest JNIEnv at 0x%08X (table 0x%08X), JavaVM at 0x%08X", g_env_ptr, table, g_vm_ptr);
}
