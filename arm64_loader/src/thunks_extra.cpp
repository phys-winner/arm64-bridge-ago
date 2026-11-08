// Thunks Angry Birds Go! needs that the Galaxy on Fire 2 reference never hit.
//
// All of these are straight passthroughs; they are split out only so the reference files
// stay recognisably the reference. The interesting work (EGL, libandroid assets, the libc
// tail) lives elsewhere.
//
// softfp reminder (lesson 2.1): Tag_ABI_VFP_args is absent from every guest object, so a
// float argument is just its bit pattern in a core register and a double occupies an
// even-aligned register pair. Never read jit.ExtRegs() here.

#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include "guest_jobs.h"

#include <GLES2/gl2.h>
#include <android/log.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#define LOG_TAG "ABGO_THUNK"
#include "bridge_log.h"

namespace {

using Jit = Dynarmic::A32::Jit;

// Every one of these takes a guest address and hands back a host pointer into the guest
// arena. Safe because the whole 32-bit space is mapped (DynarmicHost::Initialize).
inline char* GStr(DynarmicHost& h, uint32_t a) {
    return static_cast<char*>(GuestToHost(h.GetGuestMemoryBase(), a));
}
inline uint8_t* GPtr(DynarmicHost& h, uint32_t a) {
    return static_cast<uint8_t*>(GuestToHost(h.GetGuestMemoryBase(), a));
}
// Guest wchar_t is 32-bit on Android/ARM.
inline uint32_t* GWStr(DynarmicHost& h, uint32_t a) {
    return static_cast<uint32_t*>(GuestToHost(h.GetGuestMemoryBase(), a));
}
constexpr uint32_t kWEOF = 0xFFFFFFFFu;

float F(uint32_t bits) {
    float v;
    std::memcpy(&v, &bits, sizeof(v));
    return v;
}

uint32_t FBits(float v) {
    uint32_t bits;
    std::memcpy(&bits, &v, sizeof(bits));
    return bits;
}

double ReadD01(const Dynarmic::A32::Jit& jit) {
    const uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
    double v;
    std::memcpy(&v, &raw, sizeof(v));
    return v;
}

double ReadD23(const Dynarmic::A32::Jit& jit) {
    const uint64_t raw = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
    double v;
    std::memcpy(&v, &raw, sizeof(v));
    return v;
}

void WriteD01(Dynarmic::A32::Jit& jit, double v) {
    uint64_t raw;
    std::memcpy(&raw, &v, sizeof(raw));
    jit.Regs()[0] = static_cast<uint32_t>(raw);
    jit.Regs()[1] = static_cast<uint32_t>(raw >> 32);
}

// --- libc DATA symbols -------------------------------------------------------------------
// These are STT_OBJECT, bound with R_ARM_GLOB_DAT: the GOT slot receives the ADDRESS OF THE
// VARIABLE and the guest then loads through it. A thunk trampoline is the wrong thing
// entirely -- the guest would read `svc #id; bx lr` as data. That is not a crash, it is
// isalnum() answering from an opcode, which is exactly the kind of failure that looks like
// anything but its cause. So each one gets a real guest cell.
//
// bionic's ctype trio are POINTERS to 257-entry tables whose slot 0 is the EOF slot; every
// accessor indexes (table + 1)[c]. Layout is the historic BSD one and is what the 2019 NDK
// the game was built against used.
enum : uint8_t {
    kCU = 0x01, kCL = 0x02, kCD = 0x04, kCS = 0x08,
    kCP = 0x10, kCC = 0x20, kCX = 0x40, kCB = 0x80,
};

uint8_t CtypeFlags(int c) {
    if (c < 0 || c > 255) return 0;
    if (c >= 128) return 0;                                  // "C" locale: high bytes classify as nothing
    if (c == ' ') return kCS | kCB;
    if (c == '\t') return kCC | kCS | kCB;
    if (c == '\n' || c == '\v' || c == '\f' || c == '\r') return kCC | kCS;
    if (c < 32 || c == 127) return kCC;
    if (c >= '0' && c <= '9') return kCD | kCX;
    if (c >= 'A' && c <= 'F') return kCU | kCX;
    if (c >= 'a' && c <= 'f') return kCL | kCX;
    if (c >= 'A' && c <= 'Z') return kCU;
    if (c >= 'a' && c <= 'z') return kCL;
    return kCP;
}

// Allocates a guest cell holding `value` and publishes `name` as the cell's address.
void DataCell(ThunkManager& tm, DynarmicHost& h, const char* name, uint32_t value) {
    const uint32_t cell = h.GuestAlloc(4, 4);
    h.MemoryWrite32(cell, value);
    tm.RegisterSymbol(name, cell);
}

void RegisterLibcDataSymbols(ThunkManager& tm, DynarmicHost& h) {
    // _ctype_ -> char[257], slot 0 is the EOF entry.
    const uint32_t ctype_tab = h.GuestAlloc(257, 4);
    h.MemoryWrite8(ctype_tab, 0);
    for (int c = 0; c < 256; ++c) h.MemoryWrite8(ctype_tab + 1 + c, CtypeFlags(c));
    DataCell(tm, h, "_ctype_", ctype_tab);

    // _tolower_tab_ / _toupper_tab_ -> short[257], slot 0 is the EOF entry (-1).
    const uint32_t lower_tab = h.GuestAlloc(257 * 2, 4);
    const uint32_t upper_tab = h.GuestAlloc(257 * 2, 4);
    h.MemoryWrite16(lower_tab, 0xFFFF);
    h.MemoryWrite16(upper_tab, 0xFFFF);
    for (int c = 0; c < 256; ++c) {
        const int lo = (c >= 'A' && c <= 'Z') ? c + 32 : c;
        const int up = (c >= 'a' && c <= 'z') ? c - 32 : c;
        h.MemoryWrite16(lower_tab + 2 * (1 + c), static_cast<uint16_t>(lo));
        h.MemoryWrite16(upper_tab + 2 * (1 + c), static_cast<uint16_t>(up));
    }
    DataCell(tm, h, "_tolower_tab_", lower_tab);
    DataCell(tm, h, "_toupper_tab_", upper_tab);

    DataCell(tm, h, "__page_size", 4096);
    // Nonzero and constant: the guest reads it at function entry and compares it on exit, so
    // only stability matters, not unpredictability.
    DataCell(tm, h, "__stack_chk_guard", 0x000AFF0Au);

    // environ -> char**; give it a real empty (NULL-terminated) vector rather than a null
    // pointer, because getenv-style loops walk it without checking.
    const uint32_t envv = h.GuestAlloc(4, 4);
    h.MemoryWrite32(envv, 0);
    DataCell(tm, h, "environ", envv);

    // __sF is the array itself, not a pointer: stdin/stdout/stderr are &__sF[0..2]. Nothing
    // reads the contents here -- the stdio thunks key off integer handles -- so this exists
    // so the guest's `stderr` is a stable address instead of a trampoline.
    // ponytail: sizeof(FILE) on 32-bit bionic is 84; if a guest fprintf(stderr) ever needs to
    // land in logcat, recognise this range in the stdio thunks.
    const uint32_t sf = h.GuestAlloc(3 * 84, 8);
    std::memset(GPtr(h, sf), 0, 3 * 84);
    tm.RegisterSymbol("__sF", sf);

    LOGI("libc data symbols: _ctype_ table 0x%08X, __sF 0x%08X", ctype_tab, sf);
}

}  // namespace

void RegisterExtraThunks(ThunkManager& tm, DynarmicHost& host) {
    // ---- GLES2 -------------------------------------------------------------------------
    tm.RegisterThunk("glFinish", [](Dynarmic::A32::Jit&, DynarmicHost&) {
        glFinish();
    });
    tm.RegisterThunk("glValidateProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glValidateProgram(jit.Regs()[0]);
    });
    tm.RegisterThunk("glClearStencil", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glClearStencil(static_cast<GLint>(jit.Regs()[0]));
    });
    tm.RegisterThunk("glClearDepthf", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glClearDepthf(F(jit.Regs()[0]));
    });
    tm.RegisterThunk("glStencilMask", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glStencilMask(jit.Regs()[0]);
    });
    tm.RegisterThunk("glStencilFunc", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glStencilFunc(jit.Regs()[0], static_cast<GLint>(jit.Regs()[1]), jit.Regs()[2]);
    });
    tm.RegisterThunk("glStencilOp", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glStencilOp(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2]);
    });
    tm.RegisterThunk("glBlendEquationSeparate", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glBlendEquationSeparate(jit.Regs()[0], jit.Regs()[1]);
    });
    tm.RegisterThunk("glBlendFuncSeparate", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        glBlendFuncSeparate(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });
    tm.RegisterThunk("glBindAttribLocation", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        glBindAttribLocation(jit.Regs()[0], jit.Regs()[1],
                             static_cast<const GLchar*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[2])));
    });
    tm.RegisterThunk("glGetFloatv", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        glGetFloatv(jit.Regs()[0],
                    static_cast<GLfloat*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[1])));
    });
    tm.RegisterThunk("glUniform1fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        glUniform1fv(static_cast<GLint>(jit.Regs()[0]), static_cast<GLsizei>(jit.Regs()[1]),
                     static_cast<const GLfloat*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[2])));
    });
    tm.RegisterThunk("glUniform2fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        glUniform2fv(static_cast<GLint>(jit.Regs()[0]), static_cast<GLsizei>(jit.Regs()[1]),
                     static_cast<const GLfloat*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[2])));
    });
    tm.RegisterThunk("glBufferSubData", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        glBufferSubData(jit.Regs()[0], static_cast<GLintptr>(jit.Regs()[1]),
                        static_cast<GLsizeiptr>(jit.Regs()[2]),
                        GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[3]));
    });
    tm.RegisterThunk("glCopyTexImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        const uint32_t sp = jit.Regs()[13];
        glCopyTexImage2D(jit.Regs()[0], static_cast<GLint>(jit.Regs()[1]), jit.Regs()[2],
                         static_cast<GLint>(jit.Regs()[3]),
                         static_cast<GLint>(h.MemoryRead32(sp)),
                         static_cast<GLsizei>(h.MemoryRead32(sp + 4)),
                         static_cast<GLsizei>(h.MemoryRead32(sp + 8)),
                         static_cast<GLint>(h.MemoryRead32(sp + 12)));
    });
    tm.RegisterThunk("glTexSubImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        const uint32_t sp = jit.Regs()[13];
        glTexSubImage2D(jit.Regs()[0], static_cast<GLint>(jit.Regs()[1]),
                        static_cast<GLint>(jit.Regs()[2]), static_cast<GLint>(jit.Regs()[3]),
                        static_cast<GLsizei>(h.MemoryRead32(sp)),
                        static_cast<GLsizei>(h.MemoryRead32(sp + 4)),
                        h.MemoryRead32(sp + 8), h.MemoryRead32(sp + 12),
                        GuestToHost(h.GetGuestMemoryBase(), h.MemoryRead32(sp + 16)));
    });
    tm.RegisterThunk("glCompressedTexSubImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        const uint32_t sp = jit.Regs()[13];
        glCompressedTexSubImage2D(jit.Regs()[0], static_cast<GLint>(jit.Regs()[1]),
                                  static_cast<GLint>(jit.Regs()[2]), static_cast<GLint>(jit.Regs()[3]),
                                  static_cast<GLsizei>(h.MemoryRead32(sp)),
                                  static_cast<GLsizei>(h.MemoryRead32(sp + 4)),
                                  h.MemoryRead32(sp + 8),
                                  static_cast<GLsizei>(h.MemoryRead32(sp + 12)),
                                  GuestToHost(h.GetGuestMemoryBase(), h.MemoryRead32(sp + 16)));
    });

    // ---- libm --------------------------------------------------------------------------
    tm.RegisterThunk("asin",  [](Dynarmic::A32::Jit& jit, DynarmicHost&) { WriteD01(jit, std::asin(ReadD01(jit))); });
    tm.RegisterThunk("atan",  [](Dynarmic::A32::Jit& jit, DynarmicHost&) { WriteD01(jit, std::atan(ReadD01(jit))); });
    tm.RegisterThunk("ceil",  [](Dynarmic::A32::Jit& jit, DynarmicHost&) { WriteD01(jit, std::ceil(ReadD01(jit))); });
    tm.RegisterThunk("cosh",  [](Dynarmic::A32::Jit& jit, DynarmicHost&) { WriteD01(jit, std::cosh(ReadD01(jit))); });
    tm.RegisterThunk("sinh",  [](Dynarmic::A32::Jit& jit, DynarmicHost&) { WriteD01(jit, std::sinh(ReadD01(jit))); });
    tm.RegisterThunk("tanh",  [](Dynarmic::A32::Jit& jit, DynarmicHost&) { WriteD01(jit, std::tanh(ReadD01(jit))); });
    tm.RegisterThunk("fmod",  [](Dynarmic::A32::Jit& jit, DynarmicHost&) { WriteD01(jit, std::fmod(ReadD01(jit), ReadD23(jit))); });
    tm.RegisterThunk("modf", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        // double modf(double x, double* iptr) -- x in r0:r1, iptr (a guest pointer) in r2.
        double intpart = 0.0;
        const double frac = std::modf(ReadD01(jit), &intpart);
        if (auto* p = static_cast<double*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[2]))) {
            *p = intpart;
        }
        WriteD01(jit, frac);
    });

    // float variants: single word in, single word out
    tm.RegisterThunk("expf",  [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = FBits(std::exp(F(jit.Regs()[0]))); });
    tm.RegisterThunk("asinf", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = FBits(std::asin(F(jit.Regs()[0]))); });
    tm.RegisterThunk("ceilf", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = FBits(std::ceil(F(jit.Regs()[0]))); });
    tm.RegisterThunk("fabsf", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = FBits(std::fabs(F(jit.Regs()[0]))); });
    tm.RegisterThunk("atan2f", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = FBits(std::atan2(F(jit.Regs()[0]), F(jit.Regs()[1])));
    });
    tm.RegisterThunk("__isinf", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = std::isinf(ReadD01(jit)) ? 1 : 0;
    });

    // ---- liblog ------------------------------------------------------------------------
    // __android_log_assert(cond, tag, fmt, ...) never returns in bionic. Keep that contract:
    // swallowing it would let the guest continue past a state it declared impossible.
    tm.RegisterThunk("__android_log_assert", [](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        const char* cond = static_cast<const char*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* tag  = static_cast<const char*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[1]));
        const char* fmt  = static_cast<const char*>(GuestToHost(h.GetGuestMemoryBase(), jit.Regs()[2]));
        LOGE("guest assertion failed: cond='%s' tag='%s' fmt='%s' (guest LR 0x%08X)",
             cond ? cond : "?", tag ? tag : "?", fmt ? fmt : "?", jit.Regs()[14]);
        std::abort();
    });

    RegisterLibcDataSymbols(tm, host);

    // ---- string.h ------------------------------------------------------------------------
    // Every one of these was previously the default stub, i.e. it returned 0. strchr and
    // strstr answering "not found" for every input, and strnlen answering 0 for every string,
    // is not a subtle failure mode -- it is most of a C library quietly lying.
    tm.RegisterThunk("strchr", [](Jit& jit, DynarmicHost& h) {
        const char* s = GStr(h, jit.Regs()[0]);
        if (!s) { jit.Regs()[0] = 0; return; }
        const char* p = std::strchr(s, static_cast<int>(static_cast<int8_t>(jit.Regs()[1] & 0xFF)));
        jit.Regs()[0] = p ? jit.Regs()[0] + static_cast<uint32_t>(p - s) : 0;
    });
    tm.RegisterThunk("strstr", [](Jit& jit, DynarmicHost& h) {
        const char* hay = GStr(h, jit.Regs()[0]);
        const char* ndl = GStr(h, jit.Regs()[1]);
        if (!hay || !ndl) { jit.Regs()[0] = 0; return; }
        const char* p = std::strstr(hay, ndl);
        jit.Regs()[0] = p ? jit.Regs()[0] + static_cast<uint32_t>(p - hay) : 0;
    });
    tm.RegisterThunk("strnlen", [](Jit& jit, DynarmicHost& h) {
        const char* s = GStr(h, jit.Regs()[0]);
        jit.Regs()[0] = s ? static_cast<uint32_t>(strnlen(s, jit.Regs()[1])) : 0;
    });
    tm.RegisterThunk("strncat", [](Jit& jit, DynarmicHost& h) {
        char* d = GStr(h, jit.Regs()[0]);
        const char* s = GStr(h, jit.Regs()[1]);
        if (d && s) std::strncat(d, s, jit.Regs()[2]);
        // returns dest
    });
    tm.RegisterThunk("strpbrk", [](Jit& jit, DynarmicHost& h) {
        const char* s = GStr(h, jit.Regs()[0]);
        const char* set = GStr(h, jit.Regs()[1]);
        if (!s || !set) { jit.Regs()[0] = 0; return; }
        const char* p = std::strpbrk(s, set);
        jit.Regs()[0] = p ? jit.Regs()[0] + static_cast<uint32_t>(p - s) : 0;
    });
    tm.RegisterThunk("strcspn", [](Jit& jit, DynarmicHost& h) {
        const char* s = GStr(h, jit.Regs()[0]);
        const char* set = GStr(h, jit.Regs()[1]);
        jit.Regs()[0] = (s && set) ? static_cast<uint32_t>(std::strcspn(s, set)) : 0;
    });
    tm.RegisterThunk("memrchr", [](Jit& jit, DynarmicHost& h) {
        const uint8_t* s = GPtr(h, jit.Regs()[0]);
        const uint32_t n = jit.Regs()[2];
        const uint8_t c = static_cast<uint8_t>(jit.Regs()[1]);
        if (!s) { jit.Regs()[0] = 0; return; }
        for (uint32_t i = n; i-- > 0;) {
            if (s[i] == c) { jit.Regs()[0] += i; return; }
        }
        jit.Regs()[0] = 0;
    });
    tm.RegisterThunk("memccpy", [](Jit& jit, DynarmicHost& h) {
        uint8_t* d = GPtr(h, jit.Regs()[0]);
        const uint8_t* s = GPtr(h, jit.Regs()[1]);
        const uint8_t c = static_cast<uint8_t>(jit.Regs()[2]);
        const uint32_t n = jit.Regs()[3];
        if (!d || !s) { jit.Regs()[0] = 0; return; }
        for (uint32_t i = 0; i < n; ++i) {
            d[i] = s[i];
            if (s[i] == c) { jit.Regs()[0] += i + 1; return; }   // points past the copied byte
        }
        jit.Regs()[0] = 0;
    });
    // "C" locale collation is plain byte order, and transform is a plain copy.
    tm.RegisterThunk("strcoll", [](Jit& jit, DynarmicHost& h) {
        const char* a = GStr(h, jit.Regs()[0]);
        const char* b = GStr(h, jit.Regs()[1]);
        jit.Regs()[0] = static_cast<uint32_t>((a && b) ? std::strcmp(a, b) : 0);
    });
    tm.RegisterThunk("strxfrm", [](Jit& jit, DynarmicHost& h) {
        char* d = GStr(h, jit.Regs()[0]);
        const char* s = GStr(h, jit.Regs()[1]);
        const uint32_t n = jit.Regs()[2];
        if (!s) { jit.Regs()[0] = 0; return; }
        const size_t len = std::strlen(s);
        if (d && n) { const size_t copy = len < n ? len : n - 1; std::memcpy(d, s, copy); d[copy] = 0; }
        jit.Regs()[0] = static_cast<uint32_t>(len);
    });
    tm.RegisterThunk("strerror_r", [](Jit& jit, DynarmicHost& h) {
        char* buf = GStr(h, jit.Regs()[1]);
        const uint32_t n = jit.Regs()[2];
        if (buf && n) std::snprintf(buf, n, "errno %d", static_cast<int>(jit.Regs()[0]));
        jit.Regs()[0] = 0;
    });
    tm.RegisterThunk("basename", [](Jit& jit, DynarmicHost& h) {
        const char* s = GStr(h, jit.Regs()[0]);
        if (!s) return;   // returns its argument
        const char* slash = std::strrchr(s, '/');
        if (slash) jit.Regs()[0] += static_cast<uint32_t>(slash + 1 - s);
    });
    // strtok keeps state between calls; the guest is one logical thread of control per JIT,
    // but keep it thread_local anyway so a guest worker cannot corrupt the main sequence.
    tm.RegisterThunk("strtok_r", [](Jit& jit, DynarmicHost& h) {
        const uint32_t save_addr = jit.Regs()[2];
        uint32_t cur = jit.Regs()[0] ? jit.Regs()[0] : (save_addr ? h.MemoryRead32(save_addr) : 0);
        const char* set = GStr(h, jit.Regs()[1]);
        if (!cur || !set) { jit.Regs()[0] = 0; return; }
        char* s = GStr(h, cur);
        while (*s && std::strchr(set, *s)) { ++s; ++cur; }
        if (!*s) {
            if (save_addr) h.MemoryWrite32(save_addr, cur);
            jit.Regs()[0] = 0;
            return;
        }
        const uint32_t start = cur;
        while (*s && !std::strchr(set, *s)) { ++s; ++cur; }
        if (*s) { *s = '\0'; ++cur; }
        if (save_addr) h.MemoryWrite32(save_addr, cur);
        jit.Regs()[0] = start;
    });
    tm.RegisterThunk("strtok", [](Jit& jit, DynarmicHost& h) {
        static thread_local uint32_t t_save = 0;
        uint32_t cur = jit.Regs()[0] ? jit.Regs()[0] : t_save;
        const char* set = GStr(h, jit.Regs()[1]);
        if (!cur || !set) { jit.Regs()[0] = 0; return; }
        char* s = GStr(h, cur);
        while (*s && std::strchr(set, *s)) { ++s; ++cur; }
        if (!*s) { t_save = cur; jit.Regs()[0] = 0; return; }
        const uint32_t start = cur;
        while (*s && !std::strchr(set, *s)) { ++s; ++cur; }
        if (*s) { *s = '\0'; ++cur; }
        t_save = cur;
        jit.Regs()[0] = start;
    });
    tm.RegisterThunk("strtod", [](Jit& jit, DynarmicHost& h) {
        const char* s = GStr(h, jit.Regs()[0]);
        const uint32_t endp = jit.Regs()[1];
        if (!s) { WriteD01(jit, 0.0); return; }
        char* end = nullptr;
        const double v = std::strtod(s, &end);
        if (endp) h.MemoryWrite32(endp, jit.Regs()[0] + static_cast<uint32_t>(end - s));
        WriteD01(jit, v);
    });
    // atof and strtof had no thunks at all, so the default stub answered 0 -- and the engine
    // parses every float attribute of its UI layout that way. The result was a frontend that
    // built its widgets, processed input and drew nothing, because every position, size and
    // scale in it was zero. softfp: a double comes back in r0:r1, a float in r0.
    tm.RegisterThunk("atof", [](Jit& jit, DynarmicHost& h) {
        const char* s = GStr(h, jit.Regs()[0]);
        WriteD01(jit, s ? std::strtod(s, nullptr) : 0.0);
    });
    tm.RegisterThunk("strtof", [](Jit& jit, DynarmicHost& h) {
        const char* s = GStr(h, jit.Regs()[0]);
        const uint32_t endp = jit.Regs()[1];
        float v = 0.0f;
        if (s) {
            char* end = nullptr;
            v = std::strtof(s, &end);
            if (endp) h.MemoryWrite32(endp, jit.Regs()[0] + static_cast<uint32_t>(end - s));
        }
        uint32_t bits;
        std::memcpy(&bits, &v, sizeof(bits));
        jit.Regs()[0] = bits;
    });
    tm.RegisterThunk("atol", [](Jit& jit, DynarmicHost& h) {
        const char* s = GStr(h, jit.Regs()[0]);
        jit.Regs()[0] = s ? static_cast<uint32_t>(std::strtol(s, nullptr, 10)) : 0;
    });

    // strtoll/strtoull return 64-bit in r0:r1; base is the third argument, in r2.
    tm.RegisterThunk("strtoll", [](Jit& jit, DynarmicHost& h) {
        const char* s = GStr(h, jit.Regs()[0]);
        const uint32_t endp = jit.Regs()[1];
        const int base = static_cast<int>(jit.Regs()[2]);
        char* end = nullptr;
        const long long v = s ? std::strtoll(s, &end, base) : 0;
        if (endp && s) h.MemoryWrite32(endp, jit.Regs()[0] + static_cast<uint32_t>(end - s));
        jit.Regs()[0] = static_cast<uint32_t>(static_cast<unsigned long long>(v));
        jit.Regs()[1] = static_cast<uint32_t>(static_cast<unsigned long long>(v) >> 32);
    });
    tm.RegisterThunk("strtoull", [](Jit& jit, DynarmicHost& h) {
        const char* s = GStr(h, jit.Regs()[0]);
        const uint32_t endp = jit.Regs()[1];
        const int base = static_cast<int>(jit.Regs()[2]);
        char* end = nullptr;
        const unsigned long long v = s ? std::strtoull(s, &end, base) : 0;
        if (endp && s) h.MemoryWrite32(endp, jit.Regs()[0] + static_cast<uint32_t>(end - s));
        jit.Regs()[0] = static_cast<uint32_t>(v);
        jit.Regs()[1] = static_cast<uint32_t>(v >> 32);
    });

    // ---- ctype.h / wchar.h ------------------------------------------------------------------
    tm.RegisterThunk("isalnum", [](Jit& jit, DynarmicHost&) {
        const int c = static_cast<int>(jit.Regs()[0]);
        jit.Regs()[0] = (CtypeFlags(c) & (kCU | kCL | kCD)) ? 1 : 0;
    });
    tm.RegisterThunk("isspace", [](Jit& jit, DynarmicHost&) {
        const int c = static_cast<int>(jit.Regs()[0]);
        jit.Regs()[0] = (CtypeFlags(c) & kCS) ? 1 : 0;
    });
    tm.RegisterThunk("towlower", [](Jit& jit, DynarmicHost&) {
        const uint32_t c = jit.Regs()[0];
        jit.Regs()[0] = (c >= 'A' && c <= 'Z') ? c + 32 : c;
    });
    tm.RegisterThunk("towupper", [](Jit& jit, DynarmicHost&) {
        const uint32_t c = jit.Regs()[0];
        jit.Regs()[0] = (c >= 'a' && c <= 'z') ? c - 32 : c;
    });
    // The "C" locale is what bionic starts in and nothing here calls setlocale to leave it,
    // so a lone byte >= 0x80 is not a character and btowc must say so.
    tm.RegisterThunk("btowc", [](Jit& jit, DynarmicHost&) {
        const uint32_t c = jit.Regs()[0];
        jit.Regs()[0] = (c < 128) ? c : kWEOF;
    });
    tm.RegisterThunk("wctob", [](Jit& jit, DynarmicHost&) {
        const uint32_t wc = jit.Regs()[0];
        jit.Regs()[0] = (wc < 128) ? wc : static_cast<uint32_t>(-1);   // EOF
    });
    // wctype()'s return value is opaque; iswctype() only has to agree with it.
    tm.RegisterThunk("wctype", [](Jit& jit, DynarmicHost& h) {
        static const char* kNames[] = {"alnum", "alpha", "blank", "cntrl", "digit", "graph",
                                       "lower", "print", "punct", "space", "upper", "xdigit"};
        const char* name = GStr(h, jit.Regs()[0]);
        jit.Regs()[0] = 0;
        if (!name) return;
        for (uint32_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); ++i) {
            if (std::strcmp(name, kNames[i]) == 0) { jit.Regs()[0] = i + 1; return; }
        }
    });
    tm.RegisterThunk("iswctype", [](Jit& jit, DynarmicHost&) {
        const uint32_t wc = jit.Regs()[0];
        const uint32_t desc = jit.Regs()[1];
        const uint8_t f = (wc < 256) ? CtypeFlags(static_cast<int>(wc)) : 0;
        bool r = false;
        switch (desc) {
            case 1:  r = (f & (kCU | kCL | kCD)) != 0; break;   // alnum
            case 2:  r = (f & (kCU | kCL)) != 0; break;         // alpha
            case 3:  r = (wc == ' ' || wc == '\t'); break;      // blank
            case 4:  r = (f & kCC) != 0; break;                 // cntrl
            case 5:  r = (f & kCD) != 0; break;                 // digit
            case 6:  r = (f & (kCU | kCL | kCD | kCP)) != 0; break;   // graph
            case 7:  r = (f & kCL) != 0; break;                 // lower
            case 8:  r = (f & (kCU | kCL | kCD | kCP | kCB)) != 0; break;  // print
            case 9:  r = (f & kCP) != 0; break;                 // punct
            case 10: r = (f & kCS) != 0; break;                 // space
            case 11: r = (f & kCU) != 0; break;                 // upper
            case 12: r = (f & kCX) != 0; break;                 // xdigit
            default: r = false; break;
        }
        jit.Regs()[0] = r ? 1 : 0;
    });
    tm.RegisterThunk("wcslen", [](Jit& jit, DynarmicHost& h) {
        const uint32_t* w = GWStr(h, jit.Regs()[0]);
        if (!w) { jit.Regs()[0] = 0; return; }
        uint32_t n = 0;
        while (w[n]) ++n;
        jit.Regs()[0] = n;
    });
    tm.RegisterThunk("wmemcpy", [](Jit& jit, DynarmicHost& h) {
        if (jit.Regs()[2]) std::memcpy(GPtr(h, jit.Regs()[0]), GPtr(h, jit.Regs()[1]), jit.Regs()[2] * 4);
    });
    tm.RegisterThunk("wmemmove", [](Jit& jit, DynarmicHost& h) {
        if (jit.Regs()[2]) std::memmove(GPtr(h, jit.Regs()[0]), GPtr(h, jit.Regs()[1]), jit.Regs()[2] * 4);
    });
    tm.RegisterThunk("wmemset", [](Jit& jit, DynarmicHost& h) {
        uint32_t* d = GWStr(h, jit.Regs()[0]);
        const uint32_t v = jit.Regs()[1], n = jit.Regs()[2];
        if (d) for (uint32_t i = 0; i < n; ++i) d[i] = v;
    });
    tm.RegisterThunk("wmemcmp", [](Jit& jit, DynarmicHost& h) {
        const uint32_t* a = GWStr(h, jit.Regs()[0]);
        const uint32_t* b = GWStr(h, jit.Regs()[1]);
        const uint32_t n = jit.Regs()[2];
        int r = 0;
        if (a && b) for (uint32_t i = 0; i < n && r == 0; ++i) r = (a[i] < b[i]) ? -1 : (a[i] > b[i]) ? 1 : 0;
        jit.Regs()[0] = static_cast<uint32_t>(r);
    });
    tm.RegisterThunk("wmemchr", [](Jit& jit, DynarmicHost& h) {
        const uint32_t* s = GWStr(h, jit.Regs()[0]);
        const uint32_t c = jit.Regs()[1], n = jit.Regs()[2];
        if (!s) { jit.Regs()[0] = 0; return; }
        for (uint32_t i = 0; i < n; ++i) if (s[i] == c) { jit.Regs()[0] += i * 4; return; }
        jit.Regs()[0] = 0;
    });
    tm.RegisterThunk("wcscoll", [](Jit& jit, DynarmicHost& h) {
        const uint32_t* a = GWStr(h, jit.Regs()[0]);
        const uint32_t* b = GWStr(h, jit.Regs()[1]);
        int r = 0;
        if (a && b) { uint32_t i = 0; while (a[i] && a[i] == b[i]) ++i; r = (a[i] < b[i]) ? -1 : (a[i] > b[i]) ? 1 : 0; }
        jit.Regs()[0] = static_cast<uint32_t>(r);
    });
    tm.RegisterThunk("wcsxfrm", [](Jit& jit, DynarmicHost& h) {
        uint32_t* d = GWStr(h, jit.Regs()[0]);
        const uint32_t* s = GWStr(h, jit.Regs()[1]);
        const uint32_t n = jit.Regs()[2];
        if (!s) { jit.Regs()[0] = 0; return; }
        uint32_t len = 0;
        while (s[len]) ++len;
        if (d && n) { const uint32_t copy = len < n ? len : n - 1; for (uint32_t i = 0; i < copy; ++i) d[i] = s[i]; d[copy] = 0; }
        jit.Regs()[0] = len;
    });
    // UTF-8, which is what bionic's default locale is.
    tm.RegisterThunk("wcrtomb", [](Jit& jit, DynarmicHost& h) {
        const uint32_t out = jit.Regs()[0];
        const uint32_t wc = jit.Regs()[1];
        char buf[4];
        int n;
        if (wc < 0x80)          { buf[0] = static_cast<char>(wc); n = 1; }
        else if (wc < 0x800)    { buf[0] = static_cast<char>(0xC0 | (wc >> 6));  buf[1] = static_cast<char>(0x80 | (wc & 0x3F)); n = 2; }
        else if (wc < 0x10000)  { buf[0] = static_cast<char>(0xE0 | (wc >> 12)); buf[1] = static_cast<char>(0x80 | ((wc >> 6) & 0x3F)); buf[2] = static_cast<char>(0x80 | (wc & 0x3F)); n = 3; }
        else if (wc < 0x110000) { buf[0] = static_cast<char>(0xF0 | (wc >> 18)); buf[1] = static_cast<char>(0x80 | ((wc >> 12) & 0x3F)); buf[2] = static_cast<char>(0x80 | ((wc >> 6) & 0x3F)); buf[3] = static_cast<char>(0x80 | (wc & 0x3F)); n = 4; }
        else { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        if (out) std::memcpy(GPtr(h, out), buf, static_cast<size_t>(n));
        jit.Regs()[0] = static_cast<uint32_t>(n);
    });
    tm.RegisterThunk("mbrtowc", [](Jit& jit, DynarmicHost& h) {
        const uint32_t pwc = jit.Regs()[0];
        const uint32_t src = jit.Regs()[1];
        const uint32_t n = jit.Regs()[2];
        if (!src || n == 0) { jit.Regs()[0] = static_cast<uint32_t>(-2); return; }
        const uint8_t* s = GPtr(h, src);
        uint32_t wc = 0, len = 0;
        if (s[0] < 0x80)        { wc = s[0]; len = 1; }
        else if ((s[0] & 0xE0) == 0xC0) { wc = s[0] & 0x1Fu; len = 2; }
        else if ((s[0] & 0xF0) == 0xE0) { wc = s[0] & 0x0Fu; len = 3; }
        else if ((s[0] & 0xF8) == 0xF0) { wc = s[0] & 0x07u; len = 4; }
        else { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        if (len > n) { jit.Regs()[0] = static_cast<uint32_t>(-2); return; }
        for (uint32_t i = 1; i < len; ++i) {
            if ((s[i] & 0xC0) != 0x80) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
            wc = (wc << 6) | (s[i] & 0x3Fu);
        }
        if (pwc) h.MemoryWrite32(pwc, wc);
        jit.Regs()[0] = (wc == 0) ? 0 : len;
    });
    tm.RegisterThunk("setlocale", [](Jit& jit, DynarmicHost& h) {
        // One cached guest copy: the guest keeps the pointer.
        static uint32_t s_c_locale = 0;
        if (!s_c_locale) {
            s_c_locale = h.GuestAlloc(2, 1);
            std::memcpy(GPtr(h, s_c_locale), "C", 2);
        }
        jit.Regs()[0] = s_c_locale;
    });

    // ---- time ---------------------------------------------------------------------------------
    // The reason the guest spun: with clock_gettime stubbed to 0 its frame timer never moved,
    // so every "has enough time passed" loop was an infinite one.
    tm.RegisterThunk("clock_gettime", [](Jit& jit, DynarmicHost& h) {
        const uint32_t clk = jit.Regs()[0];
        const uint32_t out = jit.Regs()[1];
        struct timespec ts {};
        clockid_t id = CLOCK_MONOTONIC;
        if (clk == CLOCK_REALTIME || clk == CLOCK_REALTIME_COARSE) id = CLOCK_REALTIME;
        else if (clk == CLOCK_PROCESS_CPUTIME_ID) id = CLOCK_PROCESS_CPUTIME_ID;
        else if (clk == CLOCK_THREAD_CPUTIME_ID) id = CLOCK_THREAD_CPUTIME_ID;
        if (clock_gettime(id, &ts) != 0) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        // Guest timespec is two 32-bit longs.
        if (out) {
            h.MemoryWrite32(out + 0, static_cast<uint32_t>(ts.tv_sec));
            h.MemoryWrite32(out + 4, static_cast<uint32_t>(ts.tv_nsec));
        }
        jit.Regs()[0] = 0;
    });
    tm.RegisterThunk("nanosleep", [](Jit& jit, DynarmicHost& host) {
        // Sleeping here would stall the whole guest, which runs on the caller's thread; treat
        // it as the yield point it really is (see OnGuestYield).
        OnGuestYield(host, jit.Regs()[14]);
        jit.Regs()[0] = 0;
    });
    tm.RegisterThunk("sched_yield", [](Jit& jit, DynarmicHost& host) {
        OnGuestYield(host, jit.Regs()[14]);
        jit.Regs()[0] = 0;
    });
    tm.RegisterThunk("clock", [](Jit& jit, DynarmicHost&) {
        struct timespec ts {};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        // CLOCKS_PER_SEC is 1000000 on both sides.
        jit.Regs()[0] = static_cast<uint32_t>(ts.tv_sec * 1000000ull + ts.tv_nsec / 1000ull);
    });
    tm.RegisterThunk("difftime", [](Jit& jit, DynarmicHost&) {
        WriteD01(jit, static_cast<double>(static_cast<int32_t>(jit.Regs()[0])) -
                      static_cast<double>(static_cast<int32_t>(jit.Regs()[1])));
    });
    // The guest struct tm is 9 ints then a 32-bit tm_gmtoff and a 32-bit tm_zone pointer; the
    // host's is LP64 and diverges after tm_isdst, so copy field by field rather than memcpy.
    auto write_guest_tm = [](DynarmicHost& h, uint32_t dst, const struct tm& t) {
        const int32_t f[9] = {t.tm_sec, t.tm_min, t.tm_hour, t.tm_mday, t.tm_mon,
                              t.tm_year, t.tm_wday, t.tm_yday, t.tm_isdst};
        for (int i = 0; i < 9; ++i) h.MemoryWrite32(dst + i * 4, static_cast<uint32_t>(f[i]));
        h.MemoryWrite32(dst + 36, static_cast<uint32_t>(t.tm_gmtoff));
        h.MemoryWrite32(dst + 40, 0);   // tm_zone: no guest copy of the name
    };
    tm.RegisterThunk("gmtime_r", [write_guest_tm](Jit& jit, DynarmicHost& h) {
        const time_t t = static_cast<time_t>(static_cast<int32_t>(h.MemoryRead32(jit.Regs()[0])));
        struct tm out {};
        if (!gmtime_r(&t, &out) || !jit.Regs()[1]) { jit.Regs()[0] = 0; return; }
        write_guest_tm(h, jit.Regs()[1], out);
        jit.Regs()[0] = jit.Regs()[1];
    });
    tm.RegisterThunk("localtime_r", [write_guest_tm](Jit& jit, DynarmicHost& h) {
        const time_t t = static_cast<time_t>(static_cast<int32_t>(h.MemoryRead32(jit.Regs()[0])));
        struct tm out {};
        if (!localtime_r(&t, &out) || !jit.Regs()[1]) { jit.Regs()[0] = 0; return; }
        write_guest_tm(h, jit.Regs()[1], out);
        jit.Regs()[0] = jit.Regs()[1];
    });
    tm.RegisterThunk("gmtime", [write_guest_tm](Jit& jit, DynarmicHost& h) {
        static uint32_t s_tm = 0;
        if (!s_tm) s_tm = h.GuestAlloc(44, 4);
        const time_t t = static_cast<time_t>(static_cast<int32_t>(h.MemoryRead32(jit.Regs()[0])));
        struct tm out {};
        if (!gmtime_r(&t, &out)) { jit.Regs()[0] = 0; return; }
        write_guest_tm(h, s_tm, out);
        jit.Regs()[0] = s_tm;
    });

    // ---- more libm ------------------------------------------------------------------------------
    tm.RegisterThunk("floorf", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = FBits(std::floor(F(jit.Regs()[0]))); });
    tm.RegisterThunk("logf",   [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = FBits(std::log(F(jit.Regs()[0]))); });
    tm.RegisterThunk("tanf",   [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = FBits(std::tan(F(jit.Regs()[0]))); });
    tm.RegisterThunk("fmodf",  [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = FBits(std::fmod(F(jit.Regs()[0]), F(jit.Regs()[1])));
    });
    tm.RegisterThunk("lrint",  [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = static_cast<uint32_t>(static_cast<int32_t>(std::lrint(ReadD01(jit))));
    });

    // ---- pthread tail ----------------------------------------------------------------------------
    // The bridge runs the guest on one thread of control, so its locks and condition variables
    // are already fictions (see thunks_libc.cpp). These complete the set rather than change the
    // model -- a stub that returns 0 for "did I get the lock" is only safe because nothing else
    // is running.
    auto pthread_ok = [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0; };
    for (const char* n : {"pthread_cond_init", "pthread_cond_destroy", "pthread_cond_signal",
                          "pthread_cond_timedwait", "pthread_cond_timedwait_monotonic",
                          "pthread_condattr_init", "pthread_condattr_destroy",
                          "pthread_mutex_trylock", "pthread_mutexattr_destroy",
                          "pthread_rwlock_init", "pthread_rwlock_destroy",
                          "pthread_rwlock_rdlock", "pthread_rwlock_wrlock",
                          "pthread_rwlock_unlock", "pthread_detach", "pthread_join",
                          "pthread_key_delete", "pthread_setname_np", "pthread_kill",
                          "pthread_getschedparam", "pthread_setschedparam"}) {
        tm.RegisterThunk(n, pthread_ok);
    }
    tm.RegisterThunk("pthread_equal", [](Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = (jit.Regs()[0] == jit.Regs()[1]) ? 1 : 0;
    });
    tm.RegisterThunk("pthread_exit", [](Jit& jit, DynarmicHost&) {
        LOGE("guest pthread_exit from LR 0x%08X -- returning instead", jit.Regs()[14]);
        jit.Regs()[0] = 0;
    });

    // ---- process / system ------------------------------------------------------------------------
    tm.RegisterThunk("getuid",  [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = static_cast<uint32_t>(getuid()); });
    tm.RegisterThunk("geteuid", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = static_cast<uint32_t>(geteuid()); });
    tm.RegisterThunk("getgid",  [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = static_cast<uint32_t>(getgid()); });
    tm.RegisterThunk("getegid", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = static_cast<uint32_t>(getegid()); });
    tm.RegisterThunk("sysconf", [](Jit& jit, DynarmicHost&) {
        // The guest's _SC_* numbers are bionic's and match the host's.
        const long v = sysconf(static_cast<int>(jit.Regs()[0]));
        jit.Regs()[0] = static_cast<uint32_t>(v < 0 ? 0 : v);
    });
    tm.RegisterThunk("getauxval", [](Jit& jit, DynarmicHost&) {
        // AT_PAGESZ only. Reporting no HWCAP is the conservative answer: it makes a guest that
        // dispatches on features take its scalar path, which is always correct.
        jit.Regs()[0] = (jit.Regs()[0] == 6 /*AT_PAGESZ*/) ? 4096u : 0u;
    });
    tm.RegisterThunk("__get_h_errno", [](Jit& jit, DynarmicHost&) { jit.Regs()[0] = 0x304; });
    auto guest_exit = [](Jit& jit, DynarmicHost& h) {
        LOGE("guest exit(%d) ignored (LR 0x%08X)", static_cast<int>(jit.Regs()[0]), jit.Regs()[14]);
        h.DumpGuestBacktrace("exit()", jit.Regs()[13], jit.Regs()[14]);
    };
    tm.RegisterThunk("_exit", guest_exit);
    tm.RegisterThunk("exit", guest_exit);

    (void)host;
}
