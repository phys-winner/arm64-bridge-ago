// EGL passthrough for the guest.
//
// The Galaxy on Fire 2 reference never needed this: that game let Java own EGL entirely.
// Angry Birds Go! also runs under a GLSurfaceView whose ContextFactory/WindowSurfaceFactory
// create the context and window surface on the Java side -- but libABK.so still imports 20
// EGL entry points and uses them to query state and to set the swap interval
// (CXGSRenderDeviceOGL::PresentScene). So they have to exist.
//
// The awkward part is that EGLDisplay/EGLSurface/EGLContext/EGLConfig are host pointers,
// 64-bit here, and the guest can only hold 32 bits. Every one of them therefore crosses the
// boundary as an index into a small table, exactly like the JNI object handles.

#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"

#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <android/log.h>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#define LOG_TAG "ABGO_EGL"
#include "bridge_log.h"

namespace {

std::mutex g_lock;
std::vector<void*> g_handles{nullptr};                 // index 0 == EGL_NO_* / null
std::unordered_map<void*, uint32_t> g_handle_index;

uint32_t Tok(void* p) {
    if (!p) return 0;
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_handle_index.find(p);
    if (it != g_handle_index.end()) return it->second;
    g_handles.push_back(p);
    const uint32_t h = static_cast<uint32_t>(g_handles.size() - 1);
    g_handle_index[p] = h;
    return h;
}

void* Ptr(uint32_t tok) {
    if (tok == 0) return nullptr;
    std::lock_guard<std::mutex> guard(g_lock);
    if (tok >= g_handles.size()) {
        LOGE("bad EGL handle %u", tok);
        return nullptr;
    }
    return g_handles[tok];
}

// Copies a guest EGL_NONE-terminated attribute list into a host one.
std::vector<EGLint> ReadAttribList(DynarmicHost& host, uint32_t gaddr) {
    std::vector<EGLint> out;
    if (gaddr == 0) return out;
    for (int i = 0; i < 256; ++i) {
        const EGLint v = static_cast<EGLint>(host.MemoryRead32(gaddr + i * 4));
        out.push_back(v);
        if (v == EGL_NONE) return out;
    }
    LOGE("attrib list at 0x%08X not terminated after 256 entries", gaddr);
    out.push_back(EGL_NONE);
    return out;
}

}  // namespace

void RegisterEGLThunks(ThunkManager& tm, DynarmicHost& host) {
    tm.RegisterThunk("eglGetDisplay", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        // The guest passes EGL_DEFAULT_DISPLAY (0); anything else would be a native display
        // pointer it cannot own, so ignore the value and always hand back the default.
        jit.Regs()[0] = Tok(eglGetDisplay(EGL_DEFAULT_DISPLAY));
    });

    tm.RegisterThunk("eglInitialize", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        EGLint major = 0, minor = 0;
        const EGLBoolean ok = eglInitialize(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])), &major, &minor);
        if (jit.Regs()[1]) h.MemoryWrite32(jit.Regs()[1], static_cast<uint32_t>(major));
        if (jit.Regs()[2]) h.MemoryWrite32(jit.Regs()[2], static_cast<uint32_t>(minor));
        jit.Regs()[0] = ok;
    });

    tm.RegisterThunk("eglTerminate", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        // Java's GLSurfaceView owns the display; letting the guest terminate it would take
        // the whole surface down with it.
        LOGI("ignoring guest eglTerminate -- the display belongs to GLSurfaceView");
        jit.Regs()[0] = EGL_TRUE;
    });

    tm.RegisterThunk("eglBindAPI", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglBindAPI(jit.Regs()[0]);
    });

    tm.RegisterThunk("eglQueryString", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        const char* s = eglQueryString(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])),
                                       static_cast<EGLint>(jit.Regs()[1]));
        if (!s) { jit.Regs()[0] = 0; return; }
        // The guest keeps the pointer, so the copy has to outlive the call. These strings are
        // a fixed small set, so cache one guest copy per string rather than leaking per call.
        static std::unordered_map<std::string, uint32_t> cache;
        auto it = cache.find(s);
        if (it == cache.end()) {
            const size_t n = std::strlen(s) + 1;
            const uint32_t g = h.GuestAlloc(n, 1);
            std::memcpy(GuestToHost(h.GetGuestMemoryBase(), g), s, n);
            it = cache.emplace(s, g).first;
        }
        jit.Regs()[0] = it->second;
    });

    tm.RegisterThunk("eglGetConfigs", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        const EGLint size = static_cast<EGLint>(jit.Regs()[2]);
        std::vector<EGLConfig> cfgs(size > 0 ? size : 0);
        EGLint num = 0;
        const EGLBoolean ok = eglGetConfigs(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])),
                                            cfgs.empty() ? nullptr : cfgs.data(), size, &num);
        if (jit.Regs()[1]) {
            for (EGLint i = 0; i < num && i < size; ++i) {
                h.MemoryWrite32(jit.Regs()[1] + i * 4, Tok(cfgs[i]));
            }
        }
        if (jit.Regs()[3]) h.MemoryWrite32(jit.Regs()[3], static_cast<uint32_t>(num));
        jit.Regs()[0] = ok;
    });

    tm.RegisterThunk("eglChooseConfig", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        auto attribs = ReadAttribList(h, jit.Regs()[1]);
        const uint32_t sp = jit.Regs()[13];
        const EGLint size = static_cast<EGLint>(jit.Regs()[3]);
        const uint32_t num_gaddr = h.MemoryRead32(sp);
        std::vector<EGLConfig> cfgs(size > 0 ? size : 0);
        EGLint num = 0;
        const EGLBoolean ok = eglChooseConfig(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])),
                                              attribs.empty() ? nullptr : attribs.data(),
                                              cfgs.empty() ? nullptr : cfgs.data(), size, &num);
        if (jit.Regs()[2]) {
            for (EGLint i = 0; i < num && i < size; ++i) {
                h.MemoryWrite32(jit.Regs()[2] + i * 4, Tok(cfgs[i]));
            }
        }
        if (num_gaddr) h.MemoryWrite32(num_gaddr, static_cast<uint32_t>(num));
        jit.Regs()[0] = ok;
    });

    tm.RegisterThunk("eglGetConfigAttrib", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        EGLint value = 0;
        const EGLBoolean ok = eglGetConfigAttrib(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])),
                                                 static_cast<EGLConfig>(Ptr(jit.Regs()[1])),
                                                 static_cast<EGLint>(jit.Regs()[2]), &value);
        if (jit.Regs()[3]) h.MemoryWrite32(jit.Regs()[3], static_cast<uint32_t>(value));
        jit.Regs()[0] = ok;
    });

    tm.RegisterThunk("eglCreateContext", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        // eglCreateContext takes exactly four arguments, so attrib_list is r3, not stacked.
        auto attribs = ReadAttribList(h, jit.Regs()[3]);
        EGLContext ctx = eglCreateContext(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])),
                                          static_cast<EGLConfig>(Ptr(jit.Regs()[1])),
                                          static_cast<EGLContext>(Ptr(jit.Regs()[2])),
                                          attribs.empty() ? nullptr : attribs.data());
        jit.Regs()[0] = Tok(ctx);
    });

    tm.RegisterThunk("eglDestroyContext", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglDestroyContext(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])),
                                          static_cast<EGLContext>(Ptr(jit.Regs()[1])));
    });

    tm.RegisterThunk("eglCreateWindowSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        // r2 would be an ANativeWindow the guest cannot own. It only ever gets here for its
        // own secondary surfaces, and there is nothing sane to pass, so refuse loudly rather
        // than hand back a surface pointing at the wrong window.
        LOGE("guest eglCreateWindowSurface -- unsupported, the window belongs to GLSurfaceView");
        (void)h;
        jit.Regs()[0] = 0;   // EGL_NO_SURFACE
    });

    tm.RegisterThunk("eglDestroySurface", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglDestroySurface(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])),
                                          static_cast<EGLSurface>(Ptr(jit.Regs()[1])));
    });

    tm.RegisterThunk("eglQuerySurface", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        EGLint value = 0;
        const EGLBoolean ok = eglQuerySurface(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])),
                                              static_cast<EGLSurface>(Ptr(jit.Regs()[1])),
                                              static_cast<EGLint>(jit.Regs()[2]), &value);
        if (jit.Regs()[3]) h.MemoryWrite32(jit.Regs()[3], static_cast<uint32_t>(value));
        jit.Regs()[0] = ok;
    });

    tm.RegisterThunk("eglSurfaceAttrib", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglSurfaceAttrib(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])),
                                         static_cast<EGLSurface>(Ptr(jit.Regs()[1])),
                                         static_cast<EGLint>(jit.Regs()[2]),
                                         static_cast<EGLint>(jit.Regs()[3]));
    });

    tm.RegisterThunk("eglGetCurrentContext", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = Tok(eglGetCurrentContext());
    });

    tm.RegisterThunk("eglGetCurrentSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = Tok(eglGetCurrentSurface(static_cast<EGLint>(jit.Regs()[0])));
    });

    tm.RegisterThunk("eglMakeCurrent", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        // Passed through, but this is the first thing to suspect if the screen goes black:
        // GLSurfaceView already made its context current on this thread before calling
        // nativeDrawFrame, and a guest makeCurrent with EGL_NO_SURFACE would undo that.
        const EGLBoolean ok = eglMakeCurrent(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])),
                                             static_cast<EGLSurface>(Ptr(jit.Regs()[1])),
                                             static_cast<EGLSurface>(Ptr(jit.Regs()[2])),
                                             static_cast<EGLContext>(Ptr(jit.Regs()[3])));
        LOGI("guest eglMakeCurrent(draw=%u read=%u ctx=%u) -> %d",
             jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], ok);
        jit.Regs()[0] = ok;
    });

    tm.RegisterThunk("eglSwapInterval", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglSwapInterval(static_cast<EGLDisplay>(Ptr(jit.Regs()[0])),
                                        static_cast<EGLint>(jit.Regs()[1]));
    });

    tm.RegisterThunk("eglSwapBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        // ponytail: no-op on purpose. GLSurfaceView swaps for us right after onDrawFrame
        // returns, so honouring the guest's swap as well would present twice per frame.
        // If a secondary (Chromecast) surface ever needs a real swap, key this on which
        // surface is current instead of dropping it wholesale.
        jit.Regs()[0] = EGL_TRUE;
    });

    // --- GL extension entry points the guest fetches through eglGetProcAddress ------------
    //
    // Returning 0 for all of them was wrong. XGSOGL_genVertexArray (libABK 0x559AD0) stores
    // whatever eglGetProcAddress hands back and calls it with no null check, so the first
    // CApp::DoRender jumped straight to guest address 0 -- 2312 times in one run, once per
    // 2D batch. The extension IS supported by the host driver; only the pointer was missing.
    //
    // A host pointer means nothing to the guest, so each of these gets a real thunk and
    // eglGetProcAddress answers with its trampoline. Only names on this list get one: an
    // unknown extension must still report "unavailable" so the guest takes its fallback.
    // GLuint/GLenum are 4 bytes on both sides, so guest arrays are passed straight through
    // the arena without a bounce buffer.
    {
        auto host_fn = [](const char* n) { return eglGetProcAddress(n); };

        tm.RegisterThunk("glGenVertexArraysOES", [host_fn](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
            static auto fn = reinterpret_cast<void (*)(GLsizei, GLuint*)>(host_fn("glGenVertexArraysOES"));
            auto* out = static_cast<GLuint*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[1]));
            if (fn && out) fn(static_cast<GLsizei>(jit.Regs()[0]), out);
        });
        tm.RegisterThunk("glDeleteVertexArraysOES", [host_fn](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
            static auto fn = reinterpret_cast<void (*)(GLsizei, const GLuint*)>(host_fn("glDeleteVertexArraysOES"));
            auto* in = static_cast<const GLuint*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[1]));
            if (fn && in) fn(static_cast<GLsizei>(jit.Regs()[0]), in);
        });
        tm.RegisterThunk("glBindVertexArrayOES", [host_fn](Dynarmic::A32::Jit& jit, DynarmicHost&) {
            static auto fn = reinterpret_cast<void (*)(GLuint)>(host_fn("glBindVertexArrayOES"));
            if (fn) fn(jit.Regs()[0]);
        });
        tm.RegisterThunk("glIsVertexArrayOES", [host_fn](Dynarmic::A32::Jit& jit, DynarmicHost&) {
            static auto fn = reinterpret_cast<GLboolean (*)(GLuint)>(host_fn("glIsVertexArrayOES"));
            jit.Regs()[0] = fn ? fn(jit.Regs()[0]) : 0;
        });
        tm.RegisterThunk("glDiscardFramebufferEXT", [host_fn](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
            static auto fn = reinterpret_cast<void (*)(GLenum, GLsizei, const GLenum*)>(host_fn("glDiscardFramebufferEXT"));
            auto* att = static_cast<const GLenum*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[2]));
            if (fn && att) fn(jit.Regs()[0], static_cast<GLsizei>(jit.Regs()[1]), att);
        });
        // Debug markers: no-ops on purpose, they only feed a GPU capture tool.
        tm.RegisterThunk("glInsertEventMarkerEXT", [](Dynarmic::A32::Jit&, DynarmicHost&) {});
        tm.RegisterThunk("glPushGroupMarkerEXT",   [](Dynarmic::A32::Jit&, DynarmicHost&) {});
        tm.RegisterThunk("glPopGroupMarkerEXT",    [](Dynarmic::A32::Jit&, DynarmicHost&) {});
    }

    tm.RegisterThunk("eglGetProcAddress", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        static const std::set<std::string> kProvided = {
            "glGenVertexArraysOES", "glDeleteVertexArraysOES", "glBindVertexArrayOES",
            "glIsVertexArrayOES", "glDiscardFramebufferEXT",
            "glInsertEventMarkerEXT", "glPushGroupMarkerEXT", "glPopGroupMarkerEXT",
        };
        const char* name = static_cast<const char*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[0]));
        if (name && kProvided.count(name)) {
            const uint32_t tramp = h.GetThunkManager().GetOrCreateThunkAddress(name);
            LOGI("guest eglGetProcAddress('%s') -> 0x%08X", name, tramp);
            jit.Regs()[0] = tramp;
            return;
        }
        // Anything else genuinely has no trampoline; say so, and let the guest's own
        // "extension unavailable" path run.
        static int misses = 0;
        if (misses++ < 8) {
            LOGE("guest eglGetProcAddress('%s') -> 0 (no trampoline for host extensions)",
                 name ? name : "?");
        }
        jit.Regs()[0] = 0;
    });

    (void)host;
}
