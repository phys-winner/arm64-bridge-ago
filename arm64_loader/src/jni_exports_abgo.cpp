// Host-side Java native entry points for Angry Birds Go! 2.9.1.
//
// The bridge process is 64-bit, so Android resolves every Java native method against the
// symbols of THIS library, not against libABK.so -- the guest's own Java_* exports are
// invisible to the runtime. So the bridge exports all 42 of them and forwards each into
// the guest under Dynarmic.
//
// Forwarding is mechanical: args[0] is the guest-side fake JNIEnv, args[1] is a handle for
// the receiver (the jclass for a static native, the jobject otherwise), then the declared
// arguments one 32-bit word each. The guest is softfp (lesson 2.1), so a float is just its
// bit pattern in a core register and a long is an even-aligned register pair.

#include <jni.h>
#include <android/log.h>
#include <GLES2/gl2.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#include "dynarmic_host.h"
#include "elf_loader.h"
#include "guest_jni.h"
#include "guest_jobs.h"
#include "thunk_manager.h"
#include "thunks_opensles.h"
#include "abgo_unlock.h"

#define LOG_TAG "ABGO_EXPORTS"
#include "bridge_log.h"

extern std::unique_ptr<DynarmicHost> g_host;

namespace {

// Frame-stall forensics. One observed freeze leaves NO stack holding the JIT mutex: the
// mutex reads unlocked-with-waiters-flag (a lost futex wakeup), with every pump path
// asleep on it. The probe names the owner when there is one, and when it is a lost
// wakeup it wakes the sleepers (legal: spurious wakeups are allowed) and re-arms itself.
std::atomic<long long> g_last_frame_ms{0};
std::atomic<bool> g_stall_probe_started{false};
std::atomic<int> g_stall_reports{0};

void StallProbeLoop() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        const long long last = g_last_frame_ms.load(std::memory_order_relaxed);
        if (!last || g_stall_reports.load(std::memory_order_relaxed) >= 20) continue;
        const long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        if (now - last < 15000) continue;
        if (!g_host) continue;
        TraceDump("no frame for >15 s");
        if (g_host->RecoverStalledMutex("no frame for >15 s")) {            // Give the woken pump a moment; if frames resume the timestamp refreshes.
            g_stall_reports.fetch_add(1, std::memory_order_relaxed);
            g_last_frame_ms.store(now, std::memory_order_relaxed);
        } else {
            g_stall_reports.store(20, std::memory_order_relaxed);   // real owner: report once
        }
    }
}

void StartStallProbe() {
    if (g_stall_probe_started.exchange(true)) return;
    g_last_frame_ms.store(static_cast<long long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()));
    std::thread(StallProbeLoop).detach();
}

// One call's worth of guest arguments plus the handles minted for it. An ordinary native
// call hands the guest nothing it is allowed to keep, so every handle we created dies when
// the call returns.
struct GuestCall {
    std::vector<uint32_t> args;
    std::vector<uint32_t> owned;

    explicit GuestCall(jobject self) {
        args.push_back(GetGuestJNIEnvPtr());
        Ref(self);
    }

    void Int(jint v)      { args.push_back(static_cast<uint32_t>(v)); }
    void Bool(jboolean v) { args.push_back(v ? 1u : 0u); }
    void Float(jfloat v)  { args.push_back(FloatBits(v)); }
    void Long(jlong v)    { PushLong(args, v); }
    void Ref(jobject o) {
        const uint32_t h = GuestRefFromHost(o);
        if (h) owned.push_back(h);
        args.push_back(h);
    }

    uint32_t Invoke(const char* symbol) {
        const uint32_t r = CallGuestJni(symbol, args);
        for (uint32_t h : owned) GuestRefDelete(h);
        owned.clear();
        return r;
    }
};

// AAPCS only defines the low byte of a bool return; the rest of r0 is whatever was there.
jboolean AsBool(uint32_t r0) { return (r0 & 0xFFu) ? JNI_TRUE : JNI_FALSE; }

// nativeDrawFrame returning 0 is the engine saying "quit", and the chain that produces it is
// CXGSApp3D::Tick -> CApp::Update -> CXGSAppAndroid::Update -> CXGSAppBase::Update, which is
// simply `return m_iQuitFlag == 0` on the app object. GetXGSApp() is an ordinary guest symbol,
// so the host can just ask for the object and read the flag -- far cheaper than inferring it.
void ReportQuit() {
    static bool reported = false;
    if (reported || !g_host) return;
    reported = true;

    // GetXGSApp() and these globals are internal to libABK, so none of them are in .dynsym --
    // FindSymbol cannot see them. Read them at their static vaddrs plus the module base.
    ElfLoader* abk = g_host->FindModule("libABK.so");
    if (!abk) { LOGE("QUIT: libABK.so module not found"); return; }
    const uint32_t base = abk->GetBaseAddress();
    auto rd = [&](uint32_t vaddr) { return g_host->MemoryRead32(base + vaddr); };

    const uint32_t app = rd(0x00DE4930);   // s_ptXGSApp, set by CXGSAppBase::CXGSAppBase
    LOGE("QUIT: nativeDrawFrame returned 0. s_ptXGSApp=0x%08X g_pApplication=0x%08X "
         "CXGSMem::s_bInitialised=%u s_pptHeaps=0x%08X XGS_tMainThreadID=0x%08X",
         app, rd(0x00DABECC), rd(0x00DE4C74), rd(0x00DE4BB0), rd(0x00DE4950));
    LOGE("QUIT:   smokeTest enabled=%u quit=%u  ms_pLoadManager=0x%08X g_ptXGSFE=0x%08X "
         "g_ptXGSRenderDevice=0x%08X g_ptXGSDataBridge=0x%08X",
         rd(0x00DD1A68), rd(0x00DD1A58), rd(0x00DC42E4), rd(0x00DC30AC),
         rd(0x00DE59A8), rd(0x00DE4F80));
    if (app) {
        LOGE("QUIT:   app vptr=0x%08X quitFlag(+12)=0x%08X state(+40)=0x%08X (+316)=0x%08X "
             "(+328)=0x%08X",
             g_host->MemoryRead32(app), g_host->MemoryRead32(app + 12),
             g_host->MemoryRead32(app + 40), g_host->MemoryRead32(app + 316),
             g_host->MemoryRead32(app + 328));
        const uint32_t vt = g_host->MemoryRead32(app);
        for (int i = 0; i < 16; i += 4) {
            LOGE("QUIT:   vtable[%2d..%2d] = %08X %08X %08X %08X", i, i + 3,
                 g_host->MemoryRead32(vt + (i + 0) * 4), g_host->MemoryRead32(vt + (i + 1) * 4),
                 g_host->MemoryRead32(vt + (i + 2) * 4), g_host->MemoryRead32(vt + (i + 3) * 4));
        }
    }
}

void ReportMissing(const char* what) {
    LOGE("unimplemented native %s -- libABK.so does not export it either, so stock ABGo "
         "would have thrown UnsatisfiedLinkError here", what);
}

}  // namespace

// --- com.exient.ExientGLSurfaceView (all static) -------------------------------------------

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeContextCreated(JNIEnv*, jclass self) {
    GuestCall c(self);
    LOGI("nativeContextCreated");
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeContextCreated");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeContextDestroyed(JNIEnv*, jclass self) {
    GuestCall c(self);
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeContextDestroyed");
}

extern "C" JNIEXPORT jint JNICALL
Java_com_exient_ExientGLSurfaceView_nativeDrawFrame(JNIEnv*, jclass self) {
    GuestCall c(self);
    StartStallProbe();
    g_last_frame_ms.store(static_cast<long long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()),
        std::memory_order_relaxed);
    const auto t_frame = std::chrono::steady_clock::now();
    ThunkProfileFrameBegin();
    // Before the frame, so work the guest posted last frame has finished by the time this
    // frame reads the result. Nothing else runs the engine's jobs -- see guest_jobs.cpp.
    if (g_host) PumpGuestJobs(*g_host);
    // Deferred restore/connect actions are retried every frame until the guest application has
    // attached its player and FTUE objects. Tick itself polls adb properties only once in 60
    // frames, so this does not turn the frame path into a property-read loop.
    if (g_host) AbgoUnlock::Tick(*g_host);
    // The engine refills a sound's buffer queue only from the OpenSL callback, and nothing
    // was delivering those: the audio thread that used to is started from jni_bridge.cpp,
    // which is not in this build. Every sound therefore played whatever was enqueued up
    // front -- about a second -- and then stopped dead. Same rule as the job pump: outside
    // Jit::Run, from the frame loop.
    if (g_host) PumpOpenSLESCallbacks(*g_host);
    const jint r = static_cast<jint>(c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeDrawFrame"));
    TraceEvent("FRAME_DONE", static_cast<uint32_t>(r), 0);
    // Zero means "quit" to ExientGLSurfaceView$Renderer.onDrawFrame, which then calls
    // nativeTerminate and Activity.finish(). Nothing else in the log says why, so dig the
    // reason out of the app object while the guest is still standing.
    if (r == 0) ReportQuit();
    // A frame that draws nothing looks identical to a frame that drew and was discarded. Ask
    // GL which it was; bounded, because a stuck error state would repeat every frame.
    {
        static int reported = 0;
        if (reported < 12) {
            const GLenum e = glGetError();
            if (e != GL_NO_ERROR) { ++reported; LOGE("GL error 0x%04X after frame", e); }
        }
    }
    // Calls the guest made from inside a thunk could not run re-entrantly; this is the one
    // per-frame host entry point that is guaranteed to be outside Jit::Run.
    if (g_host) g_host->DrainDeferred();

    // Everything above ran on GLThread, so this one number covers the whole engine: physics,
    // GL submission, the job pump and the audio pump. A drop has to show up here first.
    const double frame_ms =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t_frame).count();
    ThunkProfileFrameEnd(frame_ms);
    {
        static double window_ms = 0.0, worst_ms = 0.0;
        static uint32_t frames = 0, janky = 0;
        window_ms += frame_ms;
        if (frame_ms > worst_ms) worst_ms = frame_ms;
        if (frame_ms > 20.0) ++janky;          // over the 60 Hz budget with slack
        if (++frames >= 120) {
            LOGI("[FRAME] %.1f fps over %u frames | avg %.2f ms | worst %.2f ms | %u janky",
                 1000.0 * frames / window_ms, frames, window_ms / frames, worst_ms, janky);
            frames = janky = 0;
            window_ms = worst_ms = 0.0;
        }
    }
    return r;
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeGamepadAddKeyEvent(JNIEnv*, jclass self,
                                                             jint device, jint key, jint action) {
    GuestCall c(self);
    c.Int(device);
    c.Int(key);
    c.Int(action);
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeGamepadAddKeyEvent");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeGamepadAddMotionEvent(JNIEnv*, jclass self,
                                                                jint device, jint axis, jfloat value) {
    GuestCall c(self);
    c.Int(device);
    c.Int(axis);
    c.Float(value);
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeGamepadAddMotionEvent");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeInitialize(JNIEnv*, jclass self,
                                                     jobject activity, jobject asset_manager) {
    // These three handles are deliberately NOT deleted. The guest stores the Activity and
    // the AssetManager and dereferences them for the life of the process (every asset open
    // goes through the stored AssetManager), so their global refs have to outlive the call.
    const std::vector<uint32_t> args = {
        GetGuestJNIEnvPtr(),
        GuestRefFromHost(self),
        GuestRefFromHost(activity),
        GuestRefFromHost(asset_manager),
    };
    LOGI("nativeInitialize(activity=%u, assets=%u) entering guest", args[2], args[3]);
    CallGuestJni("Java_com_exient_ExientGLSurfaceView_nativeInitialize", args);
    LOGI("nativeInitialize returned");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeInputAddTouchEvent(JNIEnv*, jclass self,
                                                             jint action, jfloat x, jfloat y,
                                                             jint pointer_id, jfloat pressure,
                                                             jint a, jint b) {
    GuestCall c(self);
    c.Int(action);
    c.Float(x);
    c.Float(y);
    c.Int(pointer_id);
    c.Float(pressure);
    c.Int(a);
    c.Int(b);
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeInputAddTouchEvent");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeInputCancelTouchEvents(JNIEnv*, jclass self) {
    GuestCall c(self);
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeInputCancelTouchEvents");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativePause(JNIEnv*, jclass self) {
    GuestCall c(self);
    LOGI("nativePause");
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativePause");
    // The engine's own pause path never touched the host AudioTracks, so whatever was
    // sounding kept sounding after the app lost the foreground.
    PauseAudioPlayback();
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeResume(JNIEnv*, jclass self) {
    GuestCall c(self);
    LOGI("nativeResume");
    // Audio first: the guest needs no audio during its resume work, and this way a voice
    // the guest restarts itself does not race our own restart.
    ResumeAudioPlayback();
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeResume");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeStop(JNIEnv*, jclass self) {
    GuestCall c(self);
    LOGI("nativeStop");
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeStop");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeSurfaceChanged(JNIEnv*, jclass self,
                                                         jint width, jint height) {
    GuestCall c(self);
    c.Int(width);
    c.Int(height);
    LOGI("nativeSurfaceChanged");
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeSurfaceChanged");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeSurfaceCreated(JNIEnv*, jclass self) {
    GuestCall c(self);
    LOGI("nativeSurfaceCreated");
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeSurfaceCreated");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeTerminate(JNIEnv*, jclass self) {
    GuestCall c(self);
    LOGI("nativeTerminate");
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeTerminate");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeWindowFocusChanged(JNIEnv*, jclass self, jboolean focused) {
    GuestCall c(self);
    c.Bool(focused);
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeWindowFocusChanged");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeWindowSurfaceCreated(JNIEnv*, jclass self) {
    GuestCall c(self);
    LOGI("nativeWindowSurfaceCreated");
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeWindowSurfaceCreated");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_ExientGLSurfaceView_nativeWindowSurfaceDestroyed(JNIEnv*, jclass self) {
    GuestCall c(self);
    c.Invoke("Java_com_exient_ExientGLSurfaceView_nativeWindowSurfaceDestroyed");
}

// --- com.exient.XGS.* -----------------------------------------------------------------------

extern "C" JNIEXPORT void JNICALL
Java_com_exient_XGS_XGSActivity_nativeOnConfigurationChanged(JNIEnv*, jclass self) {
    GuestCall c(self);
    c.Invoke("Java_com_exient_XGS_XGSActivity_nativeOnConfigurationChanged");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_XGS_XGSCameraInput_onPreviewFrameNative(JNIEnv*, jclass self, jbyteArray frame) {
    GuestCall c(self);
    c.Ref(frame);
    c.Invoke("Java_com_exient_XGS_XGSCameraInput_onPreviewFrameNative");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_XGS_XGSConnectivityManager_nativeOnConnectivityStateChanged__(JNIEnv*, jclass self) {
    GuestCall c(self);
    c.Invoke("Java_com_exient_XGS_XGSConnectivityManager_nativeOnConnectivityStateChanged__");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_XGS_XGSMotionSensor_NativeAccelerometerCallback(JNIEnv*, jclass self,
                                                                jfloat x, jfloat y, jfloat z) {
    GuestCall c(self);
    c.Float(x);
    c.Float(y);
    c.Float(z);
    c.Invoke("Java_com_exient_XGS_XGSMotionSensor_NativeAccelerometerCallback");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_XGS_XGSMovie_NativePlaybackCompleteCallback__(JNIEnv*, jclass self) {
    GuestCall c(self);
    c.Invoke("Java_com_exient_XGS_XGSMovie_NativePlaybackCompleteCallback__");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_XGS_XGSVirtualKeyboard_nativeBackButtonCallback__Z(JNIEnv*, jobject self,
                                                                   jboolean down) {
    GuestCall c(self);
    c.Bool(down);
    c.Invoke("Java_com_exient_XGS_XGSVirtualKeyboard_nativeBackButtonCallback__Z");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_XGS_XGSVirtualKeyboard_nativeMenuButtonCallback__Z(JNIEnv*, jobject self,
                                                                   jboolean down) {
    GuestCall c(self);
    c.Bool(down);
    c.Invoke("Java_com_exient_XGS_XGSVirtualKeyboard_nativeMenuButtonCallback__Z");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_XGS_XGSVirtualKeyboard_nativeUnicodeCharCallback__I(JNIEnv*, jobject self,
                                                                    jint code_point) {
    GuestCall c(self);
    c.Int(code_point);
    c.Invoke("Java_com_exient_XGS_XGSVirtualKeyboard_nativeUnicodeCharCallback__I");
}

extern "C" JNIEXPORT void JNICALL
Java_com_exient_XGS_XGSVirtualKeyboard_onHidden__(JNIEnv*, jobject self) {
    GuestCall c(self);
    c.Invoke("Java_com_exient_XGS_XGSVirtualKeyboard_onHidden__");
}

// --- com.rovio.angrybirdsgo.AngryBirdsGoActivity ---------------------------------------------

extern "C" JNIEXPORT jstring JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoActivity_getAppStoreString__(JNIEnv*, jobject self) {
    GuestCall c(self);
    const uint32_t handle = c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoActivity_getAppStoreString__");
    if (handle == 0) return nullptr;
    // The handle stays in the table: deleting it would drop the global ref the jstring we
    // are about to hand back to Java is made of. Called once at startup, so it does not grow.
    return static_cast<jstring>(HostRefFromGuest(handle));
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoActivity_getDistributionBoolean__(JNIEnv*, jobject self) {
    GuestCall c(self);
    return AsBool(c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoActivity_getDistributionBoolean__"));
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoActivity_isAdXTrackingOn(JNIEnv*, jobject self) {
    GuestCall c(self);
    return AsBool(c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoActivity_isAdXTrackingOn"));
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoActivity_isDeviceAmazon(JNIEnv*, jobject self) {
    GuestCall c(self);
    return AsBool(c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoActivity_isDeviceAmazon"));
}

// --- com.rovio.angrybirdsgo.AngryBirdsGoChromecast -------------------------------------------

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_addChromecastDevice(JNIEnv*, jobject self,
                                                                       jstring id, jstring name,
                                                                       jstring description,
                                                                       jstring status, jstring extra,
                                                                       jlong handle) {
    GuestCall c(self);
    c.Ref(id);
    c.Ref(name);
    c.Ref(description);
    c.Ref(status);
    c.Ref(extra);
    c.Long(handle);
    c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_addChromecastDevice");
}

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_changeChromecastDevice(JNIEnv*, jobject self,
                                                                          jstring id, jstring name,
                                                                          jstring description,
                                                                          jstring status, jstring extra,
                                                                          jlong handle) {
    GuestCall c(self);
    c.Ref(id);
    c.Ref(name);
    c.Ref(description);
    c.Ref(status);
    c.Ref(extra);
    c.Long(handle);
    c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_changeChromecastDevice");
}

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_chromecastConnectionDisconnected(JNIEnv*, jobject self) {
    GuestCall c(self);
    c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_chromecastConnectionDisconnected");
}

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_chromecastConnectionFailed(JNIEnv*, jobject self) {
    GuestCall c(self);
    c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_chromecastConnectionFailed");
}

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_removeChromecastDevice(JNIEnv*, jobject self,
                                                                          jstring id) {
    GuestCall c(self);
    c.Ref(id);
    c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_removeChromecastDevice");
}

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_tellChromeCastDeviceSelected(JNIEnv*, jobject self,
                                                                                jstring id) {
    GuestCall c(self);
    c.Ref(id);
    c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_tellChromeCastDeviceSelected");
}

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_tellChromeCastDeviceUnselected(JNIEnv*, jobject self,
                                                                                  jstring id) {
    GuestCall c(self);
    c.Ref(id);
    c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecast_tellChromeCastDeviceUnselected");
}

// libABK.so exports this, but no Java class declares it native, so nothing can ever call it
// through the runtime. Exported anyway so the bridge's export set matches the guest's, and
// so a future reflective/registerNatives caller finds it instead of an UnsatisfiedLinkError.
extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecastRenderer_sendCtheByteBuffer(JNIEnv*, jobject self,
                                                                              jobject buffer) {
    GuestCall c(self);
    c.Ref(buffer);
    c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecastRenderer_sendCtheByteBuffer");
}

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecastService_00024ABKPresentation_presentationReady(
        JNIEnv*, jobject self) {
    GuestCall c(self);
    c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoChromecastService_00024ABKPresentation_presentationReady");
}

// --- com.rovio.angrybirdsgo.AngryBirdsGoGooglePlayServices$GooglePlusNativeCallbacks ---------

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoGooglePlayServices_00024GooglePlusNativeCallbacks_GooglePlusOnConnectFailed(
        JNIEnv*, jclass self) {
    GuestCall c(self);
    c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoGooglePlayServices_00024GooglePlusNativeCallbacks_GooglePlusOnConnectFailed");
}

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoGooglePlayServices_00024GooglePlusNativeCallbacks_GooglePlusOnPlayerAuthenticated(
        JNIEnv*, jclass self) {
    GuestCall c(self);
    c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoGooglePlayServices_00024GooglePlusNativeCallbacks_GooglePlusOnPlayerAuthenticated");
}

// --- com.rovio.angrybirdsgo.AngryBirdsGoIntentService ----------------------------------------

extern "C" JNIEXPORT jboolean JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoIntentService_sendPushNotificationAlert(JNIEnv*, jobject self) {
    GuestCall c(self);
    return AsBool(c.Invoke("Java_com_rovio_angrybirdsgo_AngryBirdsGoIntentService_sendPushNotificationAlert"));
}

// --- natives with no guest implementation -----------------------------------------------------
// These three are declared native in the APK's smali but libABK.so exports nothing for them,
// so the stock game would die with UnsatisfiedLinkError if Java ever reached them. Exported
// as loud no-ops so the bridge merely logs instead.

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoActivity_00024FacebookCallbackImpl_OnPhotoUploadBegin(
        JNIEnv*, jobject) {
    static bool reported = false;
    if (!reported) { reported = true; ReportMissing("AngryBirdsGoActivity$FacebookCallbackImpl.OnPhotoUploadBegin()V"); }
}

extern "C" JNIEXPORT void JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoActivity_00024FacebookCallbackImpl_OnPhotoUploadComplete(
        JNIEnv*, jobject, jboolean) {
    static bool reported = false;
    if (!reported) { reported = true; ReportMissing("AngryBirdsGoActivity$FacebookCallbackImpl.OnPhotoUploadComplete(Z)V"); }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_rovio_angrybirdsgo_AngryBirdsGoIntentService_sendNotification(JNIEnv*, jobject, jstring) {
    static bool reported = false;
    if (!reported) { reported = true; ReportMissing("AngryBirdsGoIntentService.sendNotification(Ljava/lang/String;)Z"); }
    return JNI_FALSE;
}
