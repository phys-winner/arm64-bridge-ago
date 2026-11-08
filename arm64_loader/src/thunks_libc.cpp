#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include "thunks_opensles.h"
#include "elf_loader.h"
#include "guest_jobs.h"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <ctime>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <android/log.h>
#include <algorithm>
#include <unordered_map>
#include <string>
#include <sstream>
#include <vector>

#define LOG_TAG "GOF2_LibcThunks"
#include "bridge_log.h"

extern "C" FILE *funopen(const void *cookie,
                         int (*readfn)(void *, char *, int),
                         int (*writefn)(void *, const char *, int),
                         fpos_t (*seekfn)(void *, fpos_t, int),
                         int (*closefn)(void *));

struct ApkEntry {
    char name[128];
    off_t data_offset;
    off_t file_size;
};

static ApkEntry g_apk_entries[128];
static int g_num_apk_entries = 0;
static char g_apk_indexed_path[1024] = {0};
static int g_apk_indexed_fd = -1;

static std::vector<GuestThreadWorker> g_thread_workers;

const std::vector<GuestThreadWorker>& GetGuestThreadWorkers() {
    return g_thread_workers;
}

void AddGuestThreadWorker(uint32_t start_func, uint32_t arg) {
    g_thread_workers.push_back({start_func, arg});
}

struct ApkCookie {
    off_t base_offset;
    off_t file_size;
    off_t current_offset;
};

static int ApkRead(void* cookie, char* buf, int size) {
    ApkCookie* c = static_cast<ApkCookie*>(cookie);
    if (size <= 0 || !c || g_apk_indexed_fd < 0) return 0;

    if (c->current_offset + size > c->file_size) {
        size = static_cast<int>(c->file_size - c->current_offset);
    }
    if (size <= 0) return 0;

    ssize_t n = pread(g_apk_indexed_fd, buf, size, c->base_offset + c->current_offset);
    if (n > 0) {
        c->current_offset += n;
        return static_cast<int>(n);
    }
    LOGI("ApkRead: size=%d, offset=%lld, n=%zd", size, static_cast<long long>(c->current_offset), n);
    return 0;
}

static fpos_t ApkSeek(void* cookie, fpos_t offset, int whence) {
    ApkCookie* c = static_cast<ApkCookie*>(cookie);
    if (!c) return -1;
    off_t target = 0;

    if (whence == SEEK_SET) target = offset;
    else if (whence == SEEK_CUR) target = c->current_offset + offset;
    else if (whence == SEEK_END) target = c->file_size + offset;
    else return -1;

    if (target < 0) return -1;
    if (target > c->file_size) target = c->file_size;
    c->current_offset = target;
    return target;
}

static int ApkClose(void* cookie) {
    ApkCookie* c = static_cast<ApkCookie*>(cookie);
    if (c) {
        free(c);
    }
    return 0;
}

extern "C" int IndexApk(const char* apk_path) {
    if (!apk_path) return -1;
    strncpy(g_apk_indexed_path, apk_path, sizeof(g_apk_indexed_path) - 1);
    if (g_apk_indexed_fd >= 0) close(g_apk_indexed_fd);
    g_apk_indexed_fd = open(g_apk_indexed_path, O_RDONLY);
    if (g_apk_indexed_fd < 0) {
        LOGE("IndexApk: Failed to open APK: %s (errno %d)", g_apk_indexed_path, errno);
        return -1;
    }

    off_t file_len = lseek(g_apk_indexed_fd, 0, SEEK_END);
    if (file_len < 22) return -1;

    off_t search_len = file_len < 65536 + 22 ? file_len : 65536 + 22;
    off_t search_start = file_len - search_len;
    unsigned char* buf = static_cast<unsigned char*>(malloc(search_len));
    if (!buf) return -1;

    pread(g_apk_indexed_fd, buf, search_len, search_start);
    off_t eocd_offset = -1;
    for (ssize_t i = search_len - 22; i >= 0; --i) {
        if (buf[i] == 0x50 && buf[i+1] == 0x4b && buf[i+2] == 0x05 && buf[i+3] == 0x06) {
            eocd_offset = search_start + i;
            break;
        }
    }
    free(buf);

    if (eocd_offset < 0) {
        LOGE("IndexApk: EOCD not found in APK!");
        return -1;
    }

    unsigned char eocd[22];
    pread(g_apk_indexed_fd, eocd, 22, eocd_offset);
    uint16_t num_entries = *reinterpret_cast<uint16_t*>(eocd + 10);
    uint32_t cd_size = *reinterpret_cast<uint32_t*>(eocd + 12);
    uint32_t cd_offset = *reinterpret_cast<uint32_t*>(eocd + 16);

    unsigned char* cd = static_cast<unsigned char*>(malloc(cd_size));
    if (!cd) return -1;
    pread(g_apk_indexed_fd, cd, cd_size, cd_offset);

    g_num_apk_entries = 0;
    uint32_t pos = 0;
    for (int i = 0; i < num_entries && pos + 46 <= cd_size; ++i) {
        if (*reinterpret_cast<uint32_t*>(cd + pos) != 0x02014b50) break;
        uint16_t method = *reinterpret_cast<uint16_t*>(cd + pos + 10);
        uint32_t usize = *reinterpret_cast<uint32_t*>(cd + pos + 24);
        uint16_t fn_len = *reinterpret_cast<uint16_t*>(cd + pos + 28);
        uint16_t extra_len = *reinterpret_cast<uint16_t*>(cd + pos + 30);
        uint16_t comm_len = *reinterpret_cast<uint16_t*>(cd + pos + 32);
        uint32_t local_hdr_offset = *reinterpret_cast<uint32_t*>(cd + pos + 42);

        char fn[256] = {0};
        int cpy = fn_len < 255 ? fn_len : 255;
        memcpy(fn, cd + pos + 46, cpy);

        // ".obb": the 345 MB expansion file ships inside the APK now (assets/main.*.obb,
        // STORED) instead of being copied to /sdcard/Android/obb. The engine still builds the
        // external path and fopen()s it; that fails, and the APK fallback below serves the
        // same bytes straight out of the zip. Nothing is extracted.
        if (strstr(fn, "FMOD") != nullptr || strstr(fn, ".fsb") != nullptr || strstr(fn, ".fev") != nullptr
            || strstr(fn, "assets/data/audio") != nullptr || strstr(fn, ".obb") != nullptr) {
            unsigned char local_hdr[30];
            pread(g_apk_indexed_fd, local_hdr, 30, local_hdr_offset);
            uint16_t l_fn_len = *reinterpret_cast<uint16_t*>(local_hdr + 26);
            uint16_t l_extra_len = *reinterpret_cast<uint16_t*>(local_hdr + 28);
            off_t raw_data_offset = local_hdr_offset + 30 + l_fn_len + l_extra_len;

            if (g_num_apk_entries < 128) {
                strncpy(g_apk_entries[g_num_apk_entries].name, fn, 127);
                g_apk_entries[g_num_apk_entries].data_offset = raw_data_offset;
                g_apk_entries[g_num_apk_entries].file_size = usize;
                LOGI("IndexApk entry [%d]: %s (method=%d, size=%u, offset=%lld)",
                     g_num_apk_entries, fn, method, usize, static_cast<long long>(raw_data_offset));
                g_num_apk_entries++;
            }
        }
        pos += 46 + fn_len + extra_len + comm_len;
    }
    free(cd);
    LOGI("IndexApk: Indexed %d audio entries from APK: %s", g_num_apk_entries, apk_path);
    return 0;
}

static ApkEntry* FindApkEntry(const char* path) {
    if (!path || g_num_apk_entries == 0) return nullptr;
    const char* slash = strrchr(path, '/');
    const char* base = slash ? slash + 1 : path;

    char preferred[256];
    snprintf(preferred, sizeof(preferred), "assets/data/audio/%s", base);
    char in_assets[256];
    snprintf(in_assets, sizeof(in_assets), "assets/%s", base);
    for (int i = 0; i < g_num_apk_entries; ++i) {
        if (strcmp(g_apk_entries[i].name, preferred) == 0 || strcmp(g_apk_entries[i].name, path) == 0
            || strcmp(g_apk_entries[i].name, in_assets) == 0) {
            return &g_apk_entries[i];
        }
    }

    // 3. Language suffix fallback (e.g. FMOD_GOF2_VOICE.fsb -> FMOD_GOF2_VOICE_eng.fsb)
    std::string base_str(base);
    if (base_str.size() > 4 && base_str.substr(base_str.size() - 4) == ".fsb") {
        std::string stem = base_str.substr(0, base_str.size() - 4);
        std::string eng_variant = "assets/data/audio/" + stem + "_eng.fsb";
        for (int i = 0; i < g_num_apk_entries; ++i) {
            if (g_apk_entries[i].name == eng_variant || strstr(g_apk_entries[i].name, (stem + "_eng").c_str()) != nullptr) {
                return &g_apk_entries[i];
            }
        }
        for (int i = 0; i < g_num_apk_entries; ++i) {
            if (strstr(g_apk_entries[i].name, stem.c_str()) != nullptr) {
                return &g_apk_entries[i];
            }
        }
    }
    return nullptr;
}

struct VirtualFd {
    int real_apk_fd;
    size_t file_size;
    off_t file_offset; // offset within APK
    off_t current_pos; // 0 .. file_size
};
static std::unordered_map<int, VirtualFd> g_vfd_map;
static int g_next_vfd = 1000;

// File regions already mapped into the guest arena, so a second mmap of the same region reuses
// the first. See the mmap thunk for why this matters.
struct GuestFileMapping {
    dev_t dev;
    ino_t ino;
    off_t off;
    size_t span;
    uint32_t va;
};
static std::vector<GuestFileMapping> g_guest_file_maps;
static std::mutex g_file_map_mutex;

// Open directories. The guest treats the DIR* as opaque, so it gets a small handle; the
// dirent it walks has to be real guest memory in bionic's layout (see the opendir thunk).
struct GuestDir {
    DIR* dir;
    uint32_t entry;      // guest struct dirent, rewritten on every readdir
};
static constexpr uint32_t kGuestDirentSize = 280;   // 19 + 256, rounded to 8
static std::unordered_map<uint32_t, GuestDir> g_dir_map;
static uint32_t g_next_dir_handle = 0x00D10000;
static std::mutex g_vfd_mutex;

static std::unordered_map<uint32_t, FILE*> g_file_map;
// Handle of the main expansion .obb, for the fread trace below.
static uint32_t g_obb_handle = 0;

// fread/fwrite get size*count straight from the guest's own arithmetic, so a corrupt caller
// can point a wild length into host memory past the arena.
static bool GuestSpanOK(DynarmicHost& host, const void* p, uint64_t total) {
    if (!p || total == 0) return false;
    const uintptr_t off = reinterpret_cast<uintptr_t>(p) -
                          reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase());
    return off < host.GetGuestMemorySize() &&
           total <= host.GetGuestMemorySize() - off;
}

// A guest FILE* cannot be an opaque counter.
//
// The engine never calls fileno(): CXGSFileSystemPOSIX::Open_Common (libABK 0x51FCC8) has it
// inlined as *(short*)(FILE* + 14) -- bionic's `short _file` -- and feeds the result straight
// into fstat() (for the file size) and, on the ROM path, mmap(). While the handle was a bare
// counter that halfword read never-written guest memory, so every POSIX-opened file came back
// as fstat(0) == stdin == size 0. Visible damage: the 345 MB main OBB mounted as an empty pak
// via CXGSFileSystemAndroidAPK::InitialiseExpansionFiles, every asset that lives in it went
// missing, and CTextureAtlasManager::GetHeight tripped its own bounds check (UDF at
// libABK+0x2AF7D0) on the first sprite CApp::Init built.
//
// So the handle has to BE a guest block with a descriptor fstat() can answer for at +14.
// ponytail: blocks are not recycled -- 64 bytes per open against a ~736 MB guest heap. Add a
// free list only if a long session actually runs the bump allocator out.
static uint32_t PublishGuestFile(DynarmicHost& host, FILE* f, int guest_fd) {
    const uint32_t handle = host.GuestAlloc(64, 8);
    if (!handle) return 0;
    memset(GuestToHost(host.GetGuestMemoryBase(), handle), 0, 64);
    host.MemoryWrite16(handle + 14, static_cast<uint16_t>(guest_fd));
    g_file_map[handle] = f;
    return handle;
}

static std::unordered_map<uint32_t, void*> g_tls_map;
static uint32_t g_next_tls_key = 1;

#undef st_atime
#undef st_mtime
#undef st_ctime
#undef st_atime_nsec
#undef st_mtime_nsec
#undef st_ctime_nsec

// 32-bit ARM Linux/Android struct stat layout
// bionic's 32-bit ARM `struct stat`, field for field. This is NOT the old Linux layout with
// 16-bit mode/uid and st_size at +20: bionic on arm uses the stat64 shape unconditionally, so
// st_size sits at +48 and every other field moves with it.
//
// The old layout looked harmless because nothing checked it -- until CXGSFileSystemPOSIX::Open
// mapped an expansion file. It reads the size straight out of the buffer (`LDR R1,[R7,#len]`,
// i.e. buf+0x30) and hands it to mmap, so it was mmap'ing st_ctime bytes: the log showed a
// request for 1787691008 bytes, which is simply "now" in seconds since the epoch. Anything
// that read a size or an S_ISDIR out of a guest stat was wrong the same way.
struct Arm32Stat {
    uint64_t st_dev;          //  0
    uint32_t __pad0;          //  8
    uint32_t __st_ino;        // 12
    uint32_t st_mode;         // 16
    uint32_t st_nlink;        // 20
    uint32_t st_uid;          // 24
    uint32_t st_gid;          // 28
    uint64_t st_rdev;         // 32
    uint32_t __pad3;          // 40
    uint32_t __pad4;          // 44 (st_size is 8-byte aligned)
    int64_t  st_size;         // 48
    uint32_t st_blksize;      // 56
    uint32_t __pad5;          // 60
    uint64_t st_blocks;       // 64
    uint32_t st_atime_;       // 72
    uint32_t st_atime_nsec;   // 76
    uint32_t st_mtime_;       // 80
    uint32_t st_mtime_nsec;   // 84
    uint32_t st_ctime_;       // 88
    uint32_t st_ctime_nsec;   // 92
    uint64_t st_ino;          // 96
};                            // 104
static_assert(sizeof(Arm32Stat) == 104, "guest struct stat must match bionic arm32");
static_assert(offsetof(Arm32Stat, st_size) == 48, "guest st_size offset");

// bsearch telemetry: a lookup table that always misses looks exactly like an empty one.
uint64_t g_bsearch_calls = 0;
uint64_t g_bsearch_hits = 0;

// A length that came out of a guest register is not trustworthy. The arena is one flat 4 GiB
// mapping, so a block that runs off its end lands in the host's own address space -- and a
// single wild memcpy there corrupts the host heap, which then crashes somewhere else entirely,
// seconds later, inside malloc. Clamp instead, and say so.
static size_t ClampToArena(DynarmicHost& host, uint32_t addr, size_t n) {
    const uint64_t end = static_cast<uint64_t>(addr) + n;
    if (end <= host.GetGuestMemorySize()) return n;
    static int reported = 0;
    if (reported++ < 8)
        LOGE("guest block 0x%08X + %zu runs past the %zu-byte arena -- clamped",
             addr, n, host.GetGuestMemorySize());
    return addr < host.GetGuestMemorySize() ? host.GetGuestMemorySize() - addr : 0;
}

static void WriteArm32Stat(uint8_t* guest_base, uint32_t gaddr, const struct stat& st) {
    if (!gaddr) return;
    Arm32Stat* arm_st = reinterpret_cast<Arm32Stat*>(GuestToHost(guest_base, gaddr));
    if (!arm_st) return;
    memset(arm_st, 0, sizeof(Arm32Stat));
    arm_st->st_dev = st.st_dev;
    arm_st->__st_ino = static_cast<uint32_t>(st.st_ino);
    arm_st->st_ino = st.st_ino;
    arm_st->st_mode = st.st_mode;
    arm_st->st_nlink = static_cast<uint32_t>(st.st_nlink);
    arm_st->st_uid = st.st_uid;
    arm_st->st_gid = st.st_gid;
    arm_st->st_rdev = st.st_rdev;
    arm_st->st_size = st.st_size;
    arm_st->st_blksize = static_cast<uint32_t>(st.st_blksize);
    arm_st->st_blocks = static_cast<uint64_t>(st.st_blocks);
    arm_st->st_atime_ = static_cast<uint32_t>(st.st_atim.tv_sec);
    arm_st->st_mtime_ = static_cast<uint32_t>(st.st_mtim.tv_sec);
    arm_st->st_ctime_ = static_cast<uint32_t>(st.st_ctim.tv_sec);
}

// Guest printf formatter
// printf for the guest.
//
// The previous version threw the conversion spec away ("skip width/modifiers") and printed
// with defaults, so `%03d` produced "1" instead of "001". That is not cosmetic:
// CEventDefinitionManager::LoadEvent builds "CHARSPEC:Boss_%03d.xml", opens it with
// CXGSFileSystem::fopen and calls straight through the result -- "Boss_1.xml" does not exist
// in data/characters/charxml.pak, fopen returns 0 and the guest jumps through a null vptr.
//
// It also read one word for `%f`. The guest is softfp and these are varargs, so a float is
// promoted to double: eight bytes, 8-byte aligned, which under AAPCS means it must start on an
// even core register and r3 alone cannot hold one. Reading a single word there desynchronises
// every later argument as well.
//
// So: parse the whole spec, fetch the argument at its real width, and let the host's snprintf
// do the formatting with that exact spec.
namespace {

// The variadic argument sequence of an AAPCS call, continuing into the stack after r3.
struct GuestVaArgs {
    Dynarmic::A32::Jit& jit;
    DynarmicHost& host;
    int reg;                 // next core register, 4 == "the rest is on the stack"
    uint32_t sp;
    uint32_t stack_off = 0;

    uint32_t Next32() {
        if (reg <= 3) return jit.Regs()[reg++];
        const uint32_t v = host.MemoryRead32(sp + stack_off);
        stack_off += 4;
        return v;
    }
    uint64_t Next64() {
        if (reg <= 3) {
            if (reg & 1) ++reg;              // 8-byte alignment: start on an even register
            if (reg <= 2) {                  // r0:r1 or r2:r3
                const uint32_t lo = jit.Regs()[reg++];
                const uint32_t hi = jit.Regs()[reg++];
                return lo | (static_cast<uint64_t>(hi) << 32);
            }
            reg = 4;                         // r3 on its own cannot hold it; skip to the stack
        }
        stack_off = (stack_off + 7) & ~7u;
        const uint32_t lo = host.MemoryRead32(sp + stack_off);
        const uint32_t hi = host.MemoryRead32(sp + stack_off + 4);
        stack_off += 8;
        return lo | (static_cast<uint64_t>(hi) << 32);
    }
};

}  // namespace

static std::string FormatGuestString(Dynarmic::A32::Jit& jit, DynarmicHost& host, const char* fmt, int first_arg_reg) {
    if (!fmt) return "";
    std::string result;
    GuestVaArgs args{jit, host, first_arg_reg, jit.Regs()[13]};

    for (const char* p = fmt; *p; ) {
        if (*p != '%') { result += *p++; continue; }
        ++p;
        if (*p == '%') { result += '%'; ++p; continue; }
        if (!*p) { result += '%'; break; }

        std::string spec = "%";
        while (*p && std::strchr("-+ #0'", *p)) spec += *p++;               // flags
        // A '*' takes its value from the argument list; substitute it so the host spec needs
        // only the one value argument.
        if (*p == '*') { spec += std::to_string(static_cast<int32_t>(args.Next32())); ++p; }
        else while (isdigit(static_cast<unsigned char>(*p))) spec += *p++;  // width
        if (*p == '.') {
            spec += *p++;
            if (*p == '*') { spec += std::to_string(static_cast<int32_t>(args.Next32())); ++p; }
            else while (isdigit(static_cast<unsigned char>(*p))) spec += *p++;
        }

        bool is64 = false;                                                 // length modifier
        if (*p == 'h') { ++p; if (*p == 'h') ++p; }
        else if (*p == 'l') { ++p; if (*p == 'l') { ++p; is64 = true; } }   // guest long is 32-bit
        else if (*p == 'j' || *p == 'q' || *p == 'L') { ++p; is64 = true; }
        else if (*p == 'z' || *p == 't') { ++p; }

        const char conv = *p ? *p++ : 'd';
        char buf[512];
        switch (conv) {
            case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': {
                if (is64) {
                    spec += "ll"; spec += conv;
                    snprintf(buf, sizeof(buf), spec.c_str(), static_cast<long long>(args.Next64()));
                } else {
                    spec += conv;
                    snprintf(buf, sizeof(buf), spec.c_str(), static_cast<int32_t>(args.Next32()));
                }
                result += buf;
                break;
            }
            case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A': {
                // Always a double here: varargs promote float, and softfp puts it in the core
                // registers as an 8-byte value.
                const uint64_t bits = args.Next64();
                double d;
                std::memcpy(&d, &bits, sizeof(d));
                spec += conv;
                snprintf(buf, sizeof(buf), spec.c_str(), d);
                result += buf;
                break;
            }
            case 'c': {
                spec += 'c';
                snprintf(buf, sizeof(buf), spec.c_str(), static_cast<int>(args.Next32()));
                result += buf;
                break;
            }
            case 's': {
                const uint32_t gstr = args.Next32();
                const char* str = gstr ? reinterpret_cast<const char*>(
                                             GuestToHost(host.GetGuestMemoryBase(), gstr))
                                       : nullptr;
                if (!str) str = "(null)";
                spec += 's';
                if (spec == "%s") { result += str; break; }   // no width: never truncate
                snprintf(buf, sizeof(buf), spec.c_str(), str);
                result += buf;
                break;
            }
            case 'p': {
                snprintf(buf, sizeof(buf), "0x%08x", args.Next32());
                result += buf;
                break;
            }
            case 'n':                       // writes through a pointer; never wanted here
                args.Next32();
                break;
            default:
                result += conv;             // unknown conversion: pass it through untouched
                break;
        }
    }
    return result;
}

// scanf is the mirror of the printf fix above and the same class of silent lie: the stub
// returned 0 and wrote nothing, so every conversion left its destination at whatever the caller
// had initialised it to. Nothing crashes -- the frontend just draws a tree of zero-sized
// widgets. UI sizes arrive as strings ("50%", "100px", "20mm") and
// CXGSUIDimensionSerialiser::StringToValueParser turns each into a float with
// sscanf(buf, "%f", &out); CXGSColourU32::FromString, XGSFromStringXGSVector32*,
// CXGSHeapString::FromString, CSaveManager::LoadFromSaveBlock and
// CDeviceConfig::CAndroidOSVersion::GetOSVersion all go the same way -- 60+ call sites.
//
// The directives are decoded here rather than handed to the host's sscanf, because the results
// have to land in *guest* memory at guest widths and there is no portable way to build a host
// va_list. The numbers themselves still go through strtol/strtod on a width-bounded copy of the
// input, which is what scanf does internally anyway.
namespace {

// One scanned integer, stored at the width the length modifier asked for.
void StoreGuestInt(DynarmicHost& host, uint32_t addr, int bytes, uint64_t v) {
    switch (bytes) {
        case 1: host.MemoryWrite8(addr, static_cast<uint8_t>(v)); break;
        case 2: host.MemoryWrite16(addr, static_cast<uint16_t>(v)); break;
        case 8: host.MemoryWrite64(addr, v); break;
        default: host.MemoryWrite32(addr, static_cast<uint32_t>(v)); break;
    }
}

}  // namespace

static int ScanGuestString(Dynarmic::A32::Jit& jit, DynarmicHost& host, const char* in,
                           const char* fmt, int first_arg_reg) {
    if (!in || !fmt) return -1;
    GuestVaArgs args{jit, host, first_arg_reg, jit.Regs()[13]};

    const char* s = in;
    int assigned = 0;
    bool matched_anything = false;

    for (const char* p = fmt; *p; ) {
        if (isspace(static_cast<unsigned char>(*p))) {           // whitespace: any run, or none
            while (isspace(static_cast<unsigned char>(*s))) ++s;
            ++p;
            continue;
        }
        if (*p != '%') {                                        // literal: must match exactly
            if (*s != *p) return assigned ? assigned : (matched_anything ? 0 : (*s ? 0 : -1));
            ++s; ++p;
            matched_anything = true;
            continue;
        }
        ++p;
        if (*p == '%') {
            while (isspace(static_cast<unsigned char>(*s))) ++s;
            if (*s != '%') return assigned;
            ++s; ++p;
            continue;
        }

        const bool suppress = (*p == '*');
        if (suppress) ++p;

        size_t width = 0;                                       // 0 == unlimited
        while (isdigit(static_cast<unsigned char>(*p))) width = width * 10 + static_cast<size_t>(*p++ - '0');

        int bytes = 4;                                          // guest int/long/pointer
        bool is_double = false;
        if (*p == 'h') { ++p; bytes = 2; if (*p == 'h') { ++p; bytes = 1; } }
        else if (*p == 'l') { ++p; is_double = true; if (*p == 'l') { ++p; bytes = 8; is_double = false; } }
        else if (*p == 'j' || *p == 'q') { ++p; bytes = 8; }
        else if (*p == 'L') { ++p; is_double = true; }
        else if (*p == 'z' || *p == 't') { ++p; }

        const char conv = *p ? *p++ : '\0';
        if (!conv) break;

        // %c and %[ take the input as-is; everything else skips leading whitespace first.
        if (conv != 'c' && conv != '[' && conv != 'n') {
            while (isspace(static_cast<unsigned char>(*s))) ++s;
        }

        switch (conv) {
            case 'n': {                                         // consumed so far; not a conversion
                if (!suppress) StoreGuestInt(host, args.Next32(), bytes,
                                             static_cast<uint64_t>(s - in));
                break;
            }
            case 'c': {
                const size_t n = width ? width : 1;
                if (std::strlen(s) < n) return assigned ? assigned : -1;
                const uint32_t dst = suppress ? 0 : args.Next32();
                for (size_t i = 0; i < n; ++i)
                    if (dst) host.MemoryWrite8(dst + static_cast<uint32_t>(i),
                                               static_cast<uint8_t>(s[i]));
                s += n;
                matched_anything = true;
                if (!suppress) ++assigned;
                break;
            }
            case 's': {
                if (!*s) return assigned ? assigned : -1;
                const char* start = s;
                while (*s && !isspace(static_cast<unsigned char>(*s)) &&
                       (!width || static_cast<size_t>(s - start) < width)) ++s;
                if (s == start) return assigned;
                const uint32_t dst = suppress ? 0 : args.Next32();
                if (dst) {
                    for (const char* q = start; q < s; ++q)
                        host.MemoryWrite8(dst + static_cast<uint32_t>(q - start),
                                          static_cast<uint8_t>(*q));
                    host.MemoryWrite8(dst + static_cast<uint32_t>(s - start), 0);
                }
                matched_anything = true;
                if (!suppress) ++assigned;
                break;
            }
            case '[': {                                         // scanset
                const bool negate = (*p == '^');
                if (negate) ++p;
                bool set[256] = {};
                if (*p == ']') { set[static_cast<unsigned char>(']')] = true; ++p; }
                while (*p && *p != ']') {
                    if (p[1] == '-' && p[2] && p[2] != ']') {    // a-z range
                        for (unsigned char c = static_cast<unsigned char>(p[0]);
                             c <= static_cast<unsigned char>(p[2]); ++c) set[c] = true;
                        p += 3;
                    } else {
                        set[static_cast<unsigned char>(*p++)] = true;
                    }
                }
                if (*p == ']') ++p;
                const char* start = s;
                while (*s && set[static_cast<unsigned char>(*s)] != negate &&
                       (!width || static_cast<size_t>(s - start) < width)) ++s;
                if (s == start) return assigned;
                const uint32_t dst = suppress ? 0 : args.Next32();
                if (dst) {
                    for (const char* q = start; q < s; ++q)
                        host.MemoryWrite8(dst + static_cast<uint32_t>(q - start),
                                          static_cast<uint8_t>(*q));
                    host.MemoryWrite8(dst + static_cast<uint32_t>(s - start), 0);
                }
                matched_anything = true;
                if (!suppress) ++assigned;
                break;
            }
            case 'a': case 'A': case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': {
                char tmp[128];
                const size_t n = std::min(width ? width : sizeof(tmp) - 1, sizeof(tmp) - 1);
                std::strncpy(tmp, s, n); tmp[n] = '\0';
                char* end = nullptr;
                const double d = std::strtod(tmp, &end);
                if (!end || end == tmp) return assigned ? assigned : (*s ? assigned : -1);
                s += (end - tmp);
                if (!suppress) {
                    const uint32_t dst = args.Next32();
                    if (is_double || bytes == 8) {
                        uint64_t bits; std::memcpy(&bits, &d, sizeof(bits));
                        host.MemoryWrite64(dst, bits);
                    } else {
                        const float f = static_cast<float>(d);
                        uint32_t bits; std::memcpy(&bits, &f, sizeof(bits));
                        host.MemoryWrite32(dst, bits);
                    }
                    ++assigned;
                }
                matched_anything = true;
                break;
            }
            case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': case 'p': {
                char tmp[128];
                const size_t n = std::min(width ? width : sizeof(tmp) - 1, sizeof(tmp) - 1);
                std::strncpy(tmp, s, n); tmp[n] = '\0';
                const int base = (conv == 'i') ? 0
                               : (conv == 'o') ? 8
                               : (conv == 'x' || conv == 'X' || conv == 'p') ? 16 : 10;
                char* end = nullptr;
                const bool is_signed = (conv == 'd' || conv == 'i');
                const uint64_t v = is_signed
                        ? static_cast<uint64_t>(std::strtoll(tmp, &end, base))
                        : std::strtoull(tmp, &end, base);
                if (!end || end == tmp) return assigned ? assigned : (*s ? assigned : -1);
                s += (end - tmp);
                if (!suppress) StoreGuestInt(host, args.Next32(),
                                             conv == 'p' ? 4 : bytes, v);
                matched_anything = true;
                if (!suppress) ++assigned;
                break;
            }
            default:
                return assigned;                                // unknown conversion: stop here
        }
    }
    return assigned;
}

// Runs the four format strings the engine actually depends on, on the first sscanf call (the
// first one available with a live Jit). A parser that silently stops assigning looks exactly
// like the stub it replaced, so it has to say so out loud.
static void ScanGuestSelfTest(Dynarmic::A32::Jit& jit, DynarmicHost& host) {
    const uint32_t scratch = host.GuestAlloc(256, 8);
    if (!scratch) { LOGE("[SCANTEST] FAIL: no scratch memory"); return; }
    uint8_t* mem = host.GetGuestMemoryBase();
    const uint32_t out = scratch;           // 5 output slots
    const uint32_t sp  = scratch + 64;      // synthetic argument block, all past r3
    const uint32_t text = scratch + 128;

    const uint32_t saved_sp = jit.Regs()[13];
    jit.Regs()[13] = sp;
    int fails = 0;

    auto put = [&](const char* s) { std::strcpy(reinterpret_cast<char*>(mem + text), s); };
    auto arg = [&](int i, uint32_t v) { host.MemoryWrite32(sp + 4u * static_cast<uint32_t>(i), v); };
    auto f32 = [&](int i) { float f; std::memcpy(&f, mem + out + 4u * i, 4); return f; };
    auto i32 = [&](int i) { return static_cast<int32_t>(host.MemoryRead32(out + 4u * static_cast<uint32_t>(i))); };
    auto check = [&](const char* what, bool ok) { if (!ok) { ++fails; LOGE("[SCANTEST] FAIL: %s", what); } };

    // The one that blacks out the frontend: CXGSUIDimensionSerialiser::StringToValueParser.
    std::memset(mem + out, 0, 32);
    arg(0, out);
    put("50");
    check("%f on \"50\"", ScanGuestString(jit, host, reinterpret_cast<const char*>(mem + text), "%f", 4) == 1
                          && f32(0) == 50.0f);

    // XGSFromStringXGSVector32, including a negative and an exponent.
    std::memset(mem + out, 0, 32);
    arg(0, out); arg(1, out + 4); arg(2, out + 8);
    put("1.5 -2 3e2");
    check("%g %g %g", ScanGuestString(jit, host, reinterpret_cast<const char*>(mem + text), "%g %g %g", 4) == 3
                      && f32(0) == 1.5f && f32(1) == -2.0f && f32(2) == 300.0f);

    // CXGSColourU32::FromString: literals, optional whitespace and %n.
    std::memset(mem + out, 0, 32);
    arg(0, out); arg(1, out + 4); arg(2, out + 8); arg(3, out + 12); arg(4, out + 16);
    put("r:12 g:34 b:56 a:78");
    check("colour + %n",
          ScanGuestString(jit, host, reinterpret_cast<const char*>(mem + text),
                          " r : %d g : %d b : %d a : %d%n", 4) == 4
          && i32(0) == 12 && i32(1) == 34 && i32(2) == 56 && i32(3) == 78 && i32(4) == 19);

    // TVersionInfo::ParseVersionInfo shape: literals between conversions.
    std::memset(mem + out, 0, 32);
    arg(0, out); arg(1, out + 4); arg(2, out + 8);
    put("2.9.1");
    check("%d.%d.%d", ScanGuestString(jit, host, reinterpret_cast<const char*>(mem + text), "%d.%d.%d", 4) == 3
                      && i32(0) == 2 && i32(1) == 9 && i32(2) == 1);

    jit.Regs()[13] = saved_sp;
    host.GuestFree(scratch);
    if (!fails) LOGI("[SCANTEST] ok: 4 engine formats parsed");
}

void ThunkManager::RegisterLibcThunks() {
    uint8_t* mem = m_host.GetGuestMemoryBase();

    *reinterpret_cast<uint32_t*>(mem + 0x100) = 0xDEADBEEF;
    *reinterpret_cast<uint32_t*>(mem + 0x300) = 0;

    m_symbol_to_address["__stack_chk_guard"] = 0x100;
    m_symbol_to_address["__sF"] = 0x200;

    RegisterThunk("__errno", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0x300;
    });

    // -------------------------------------------------------------
    // Additional POSIX & Math Thunks for FMOD
    // -------------------------------------------------------------

    auto read_double_01 = [](const Dynarmic::A32::Jit& jit) -> double {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        return val;
    };
    auto write_double_01 = [](Dynarmic::A32::Jit& jit, double val) {
        uint64_t raw;
        memcpy(&raw, &val, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((raw >> 32) & 0xFFFFFFFF);
    };

    RegisterThunk("sin", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, sin(read_double_01(jit)));
    });
    RegisterThunk("cos", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, cos(read_double_01(jit)));
    });
    RegisterThunk("tan", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, tan(read_double_01(jit)));
    });
    RegisterThunk("acos", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, acos(read_double_01(jit)));
    });
    RegisterThunk("atan2", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double y = read_double_01(jit);
        uint64_t raw_x = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
        double x;
        memcpy(&x, &raw_x, sizeof(double));
        write_double_01(jit, atan2(y, x));
    });
    RegisterThunk("exp", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, exp(read_double_01(jit)));
    });
    RegisterThunk("log", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, log(read_double_01(jit)));
    });
    RegisterThunk("log10", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, log10(read_double_01(jit)));
    });
    RegisterThunk("log10f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = log10f(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });
    RegisterThunk("pow", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        double x = read_double_01(jit);
        uint64_t raw_y = (static_cast<uint64_t>(jit.Regs()[3]) << 32) | jit.Regs()[2];
        double y;
        memcpy(&y, &raw_y, sizeof(double));
        write_double_01(jit, pow(x, y));
    });
    RegisterThunk("sqrt", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, sqrt(read_double_01(jit)));
    });
    RegisterThunk("floor", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, floor(read_double_01(jit)));
    });
    RegisterThunk("rint", [=](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        write_double_01(jit, rint(read_double_01(jit)));
    });
    RegisterThunk("lrintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        jit.Regs()[0] = static_cast<uint32_t>(lrintf(val));
    });
    RegisterThunk("frexp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        uint32_t exp_ptr = jit.Regs()[2];
        int exp_val = 0;
        double res = frexp(val, &exp_val);
        if (exp_ptr) host.MemoryWrite32(exp_ptr, static_cast<uint32_t>(exp_val));
        uint64_t res_raw;
        memcpy(&res_raw, &res, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(res_raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((res_raw >> 32) & 0xFFFFFFFF);
    });
    RegisterThunk("ldexp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t raw = (static_cast<uint64_t>(jit.Regs()[1]) << 32) | jit.Regs()[0];
        double val;
        memcpy(&val, &raw, sizeof(double));
        int exp_val = static_cast<int>(jit.Regs()[2]);
        double res = ldexp(val, exp_val);
        uint64_t res_raw;
        memcpy(&res_raw, &res, sizeof(double));
        jit.Regs()[0] = static_cast<uint32_t>(res_raw & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>((res_raw >> 32) & 0xFFFFFFFF);
    });

    // Memory & Strings
    RegisterThunk("memmove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        size_t n = ClampToArena(host, src, ClampToArena(host, dst, jit.Regs()[2]));
        void* h_dst = GuestToHost(host.GetGuestMemoryBase(), dst);
        const void* h_src = GuestToHost(host.GetGuestMemoryBase(), src);
        if (h_dst && h_src && n > 0) memmove(h_dst, h_src, n);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("memmem", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t haystack = jit.Regs()[0];
        uint32_t hlen = jit.Regs()[1];
        uint32_t needle = jit.Regs()[2];
        uint32_t nlen = jit.Regs()[3];
        const void* h_hay = GuestToHost(host.GetGuestMemoryBase(), haystack);
        const void* h_nee = GuestToHost(host.GetGuestMemoryBase(), needle);
        if (h_hay && h_nee && hlen >= nlen) {
            const void* found = memmem(h_hay, hlen, h_nee, nlen);
            if (found) {
                uint32_t offset = static_cast<uint32_t>(reinterpret_cast<const uint8_t*>(found) - reinterpret_cast<const uint8_t*>(h_hay));
                jit.Regs()[0] = haystack + offset;
                return;
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("strcat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        char* h_dst = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), dst));
        const char* h_src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), src));
        if (h_dst && h_src) strcat(h_dst, h_src);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("strncpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dst = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        char* h_dst = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), dst));
        const char* h_src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), src));
        if (h_dst && h_src && n > 0) strncpy(h_dst, h_src, n);
        jit.Regs()[0] = dst;
    });
    RegisterThunk("strncasecmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t s1 = jit.Regs()[0];
        uint32_t s2 = jit.Regs()[1];
        uint32_t n = jit.Regs()[2];
        const char* h_s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s1));
        const char* h_s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s2));
        jit.Regs()[0] = (h_s1 && h_s2) ? static_cast<uint32_t>(strncasecmp(h_s1, h_s2, n)) : 0;
    });
    RegisterThunk("strtol", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t nptr = jit.Regs()[0];
        uint32_t endptr = jit.Regs()[1];
        int base = static_cast<int>(jit.Regs()[2]);
        const char* h_nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), nptr));
        if (!h_nptr) { jit.Regs()[0] = 0; return; }
        char* h_end = nullptr;
        long val = strtol(h_nptr, &h_end, base);
        if (endptr && h_end) {
            uint32_t offset = static_cast<uint32_t>(h_end - h_nptr);
            host.MemoryWrite32(endptr, nptr + offset);
        }
        jit.Regs()[0] = static_cast<uint32_t>(val);
    });
    RegisterThunk("puts", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t s = jit.Regs()[0];
        const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), s));
        if (str) LOGI("[puts] %s", str);
        jit.Regs()[0] = 1;
    });
    RegisterThunk("vsnprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t buf = jit.Regs()[0];
        uint32_t size = jit.Regs()[1];
        uint32_t fmt = jit.Regs()[2];
        char* h_buf = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), buf));
        const char* h_fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), fmt));
        if (!h_buf || size == 0) { jit.Regs()[0] = 0; return; }
        if (!h_fmt) { h_buf[0] = 0; jit.Regs()[0] = 0; return; }
        strncpy(h_buf, h_fmt, size - 1);
        h_buf[size - 1] = 0;
        jit.Regs()[0] = static_cast<uint32_t>(strlen(h_buf));
    });

    // Time & Threading
    RegisterThunk("gettimeofday", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t tv_ptr = jit.Regs()[0];
        if (tv_ptr) {
            struct timeval tv;
            gettimeofday(&tv, nullptr);
            host.MemoryWrite32(tv_ptr + 0, static_cast<uint32_t>(tv.tv_sec));
            host.MemoryWrite32(tv_ptr + 4, static_cast<uint32_t>(tv.tv_usec));
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("usleep", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        // Not a sleep -- the guest's way of saying "let something else run". See OnGuestYield.
        OnGuestYield(host, jit.Regs()[14]);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("lrand48", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(lrand48());
    });
    RegisterThunk("srand48", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        srand48(static_cast<long>(jit.Regs()[0]));
        jit.Regs()[0] = 0;
    });
    RegisterThunk("utime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("unlink", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("chown", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("fcntl", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });

    // Semaphores & Pthread
    RegisterThunk("sem_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        uint32_t val = jit.Regs()[2];
        if (sem_ptr) host.MemoryWrite32(sem_ptr, val);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_wait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        if (sem_ptr) {
            uint32_t val = host.MemoryRead32(sem_ptr);
            if (val > 0) {
                host.MemoryWrite32(sem_ptr, val - 1);
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_trywait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        if (sem_ptr) {
            uint32_t val = host.MemoryRead32(sem_ptr);
            if (val > 0) {
                host.MemoryWrite32(sem_ptr, val - 1);
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_post", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        if (sem_ptr) {
            uint32_t val = host.MemoryRead32(sem_ptr);
            host.MemoryWrite32(sem_ptr, val + 1);
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("sem_post", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sem_ptr = jit.Regs()[0];
        if (sem_ptr) {
            uint32_t val = host.MemoryRead32(sem_ptr);
            host.MemoryWrite32(sem_ptr, val + 1);
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_self", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0x1001;
    });
    RegisterThunk("pthread_attr_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_attr_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_attr_setdetachstate", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_attr_setstacksize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t mtx = jit.Regs()[0];
        if (mtx) host.MemoryWrite32(mtx, 0);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutex_destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutexattr_init", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_mutexattr_settype", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });
    RegisterThunk("pthread_create", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t thread_out = jit.Regs()[0];
        uint32_t start_func = jit.Regs()[2];
        uint32_t arg = jit.Regs()[3];
        // Rate-limited: the engine creates dozens of XGSThreads during CApp::Init and the
        // device's log flow control drops the rest of the process's output when it does.
        static int logged = 0;
        if (logged < 5)
            LOGI("pthread_create: thread_out=0x%08X, func=0x%08X, arg=0x%08X", thread_out, start_func, arg);
        else if (logged == 5)
            LOGI("pthread_create: further calls silenced");
        ++logged;
        AddGuestThreadWorker(start_func, arg);
        // Nobody runs these bodies, but the job-scheduler ones tell the host which scheduler
        // objects exist so their queues can be drained per frame instead (guest_jobs.cpp).
        RegisterGuestThread(host, start_func, arg);
        // The Galaxy on Fire 2 build poked arg+0x10C and arg+0x134 here to force FMOD's
        // Thread/AsyncThread m_running flags true. Those offsets belong to FMOD's objects;
        // in Angry Birds Go! `arg` is an XGSThread and the writes land on unrelated fields.
        // Removed rather than ported: guessing at a struct layout is how you get corruption
        // that surfaces somewhere else entirely.
        if (thread_out) host.MemoryWrite32(thread_out, 0x1000 + GetGuestThreadWorkers().size());
        jit.Regs()[0] = 0; // Return OK
    });

    // Sockets & Net (Stubs)
    RegisterThunk("socket", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("bind", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("listen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("accept", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("connect", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("send", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("recv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("select", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("setsockopt", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0xFFFFFFFF; });
    RegisterThunk("inet_addr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("gethostbyname", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Android & Runtime
    RegisterThunk("__android_log_write", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int prio = static_cast<int>(jit.Regs()[0]);
        uint32_t tag_ptr = jit.Regs()[1];
        uint32_t msg_ptr = jit.Regs()[2];
        const char* tag = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), tag_ptr));
        const char* msg = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), msg_ptr));
#ifdef BRIDGE_ENABLE_LOGGING
        if (tag && msg) __android_log_write(prio, tag, msg);
#endif
        jit.Regs()[0] = 1;
    });
    RegisterThunk("__aeabi_atexit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_pure_virtual", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGE("__cxa_pure_virtual called!");
        jit.Regs()[0] = 0;
    });
    RegisterThunk("__cxa_type_match", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_begin_cleanup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_call_unexpected", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__gnu_Unwind_Find_exidx", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("dlopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t name_ptr = jit.Regs()[0];
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), name_ptr));
        LOGI("dlopen('%s', %d)", name ? name : "NULL", jit.Regs()[1]);
        jit.Regs()[0] = 0x50005000; // Non-null handle
    });
    RegisterThunk("dlclose", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("dlsym", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sym_ptr = jit.Regs()[1];
        const char* sym = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), sym_ptr));
        LOGI("dlsym(handle, '%s')", sym ? sym : "NULL");
        if (sym) {
            if (strncmp(sym, "SL_IID_", 7) == 0) {
                uint32_t iid_ptr = GetOpenSLESInterfacePointer(sym);
                if (iid_ptr != 0) {
                    jit.Regs()[0] = iid_ptr;
                    return;
                }
            }
            if (strcmp(sym, "slCreateEngine") == 0) {
                jit.Regs()[0] = host.GetThunkManager().GetOrCreateThunkAddress("slCreateEngine");
                return;
            }
            auto it = host.GetThunkManager().GetThunkSymbolTable().find(sym);
            if (it != host.GetThunkManager().GetThunkSymbolTable().end()) {
                jit.Regs()[0] = it->second;
                return;
            }
            if (host.GetFmodEventLoader()) {
                uint32_t addr = host.GetFmodEventLoader()->GetSymbolAddress(sym);
                if (addr != 0) { jit.Regs()[0] = addr; return; }
            }
            if (host.GetFmodExLoader()) {
                uint32_t addr = host.GetFmodExLoader()->GetSymbolAddress(sym);
                if (addr != 0) { jit.Regs()[0] = addr; return; }
            }
            uint32_t addr = host.GetThunkManager().GetOrCreateThunkAddress(sym);
            jit.Regs()[0] = addr;
            return;
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("__system_property_get", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t val_ptr = jit.Regs()[1];
        // Answer from the device the bridge is running on. Returning "" for everything left
        // XGSGetDeviceConfigName building "android---", so CDeviceConfig could never find
        // data/deviceconfigs/<device>.json and every device fell back to the generic tier.
        if (!name || !val_ptr) { jit.Regs()[0] = 0; return; }
        char value[PROP_VALUE_MAX] = {0};
        const int len = __system_property_get(name, value);
        char* out = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), val_ptr));
        if (out) memcpy(out, value, static_cast<size_t>(len) + 1);
        static int logged = 0;
        if (logged++ < 12) LOGI("__system_property_get('%s') -> '%s'", name, value);
        jit.Regs()[0] = len;
    });

    // C++ Memory Allocation operators
    RegisterThunk("_Znaj", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_Znwj", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZnajRKSt9nothrow_t", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZnwjRKSt9nothrow_t", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("_ZdaPv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("_ZdlPv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("_ZNSt8ios_base4InitC1Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_ZNSt8ios_base4InitD1Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});

    // Memory Allocation inside guest space
    RegisterThunk("malloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t size = jit.Regs()[0];
        jit.Regs()[0] = host.GuestAlloc(size, 8);
    });

    RegisterThunk("calloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t num = jit.Regs()[0];
        size_t size = jit.Regs()[1];
        uint32_t addr = host.GuestAlloc(num * size, 8);
        if (addr) {
            memset(GuestToHost(host.GetGuestMemoryBase(), addr), 0, num * size);
        }
        jit.Regs()[0] = addr;
    });

    RegisterThunk("realloc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t old_addr = jit.Regs()[0];
        size_t new_size = jit.Regs()[1];
        uint32_t new_addr = host.GuestAlloc(new_size, 8);
        if (old_addr && new_addr) {
            // Only what the old block actually held: it is usually smaller than the new size,
            // and copying new_size bytes reads past its end into whatever follows.
            const uint32_t old_size = host.GuestAllocSize(old_addr);
            const size_t copy = old_size && old_size < new_size ? old_size : new_size;
            memcpy(GuestToHost(host.GetGuestMemoryBase(), new_addr),
                   GuestToHost(host.GetGuestMemoryBase(), old_addr), copy);
            host.GuestFree(old_addr);
        }
        jit.Regs()[0] = new_addr;
    });

    RegisterThunk("free", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        host.GuestFree(jit.Regs()[0]);
    });

    RegisterThunk("memalign", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        size_t alignment = jit.Regs()[0];
        size_t size = jit.Regs()[1];
        jit.Regs()[0] = host.GuestAlloc(size, alignment);
    });

    // Logging & Formatted output
    RegisterThunk("__android_log_print", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
#ifdef BRIDGE_ENABLE_LOGGING
        int prio = static_cast<int>(jit.Regs()[0]);
        const char* tag = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        std::string formatted = FormatGuestString(jit, host, fmt, 3);
        __android_log_print(prio, tag ? tag : "GOF2_Guest", "[GUEST] %s", formatted.c_str());
#endif
        // No-log release: the guest ignores the return value; skip the va_list walk and
        // the string build entirely (lessons doc: no-op BEFORE argument evaluation).
        jit.Regs()[0] = 0;
    });

    RegisterThunk("printf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        std::string formatted = FormatGuestString(jit, host, fmt, 1);
        LOGI("[printf] %s", formatted.c_str());
        jit.Regs()[0] = formatted.length();
    });

    RegisterThunk("fprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        std::string formatted = FormatGuestString(jit, host, fmt, 2);
        LOGI("[fprintf] %s", formatted.c_str());
        jit.Regs()[0] = formatted.length();
    });

    RegisterThunk("sprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* str = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        std::string formatted = FormatGuestString(jit, host, fmt, 2);
        if (str) {
            strcpy(str, formatted.c_str());
            jit.Regs()[0] = formatted.length();
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("snprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* str = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        size_t size = jit.Regs()[1];
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        std::string formatted = FormatGuestString(jit, host, fmt, 3);
        if (str && size > 0) {
            strncpy(str, formatted.c_str(), size - 1);
            str[size - 1] = '\0';
            jit.Regs()[0] = formatted.length();
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("sscanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static bool tested = false;
        if (!tested) { tested = true; ScanGuestSelfTest(jit, host); }
        const char* in  = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* fmt = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = static_cast<uint32_t>(ScanGuestString(jit, host, in, fmt, 2));
    });
    RegisterThunk("vfprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("vasprintf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("putc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = jit.Regs()[0]; });
    RegisterThunk("fputc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = jit.Regs()[0]; });

    // Math functions
    RegisterThunk("sinf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = sinf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("cosf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = cosf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("sqrtf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = sqrtf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("atanf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = atanf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("acosf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float val = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float res = acosf(val);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    RegisterThunk("powf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float base = *reinterpret_cast<float*>(&jit.Regs()[0]);
        float exp = *reinterpret_cast<float*>(&jit.Regs()[1]);
        float res = powf(base, exp);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&res);
    });

    // String & Memory functions
    RegisterThunk("strcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? strcmp(s1, s2) : 0;
    });

    RegisterThunk("strncmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = (s1 && s2) ? strncmp(s1, s2, n) : 0;
    });

    RegisterThunk("strcasecmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s1 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* s2 = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = (s1 && s2) ? strcasecmp(s1, s2) : 0;
    });

    RegisterThunk("strlen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = s ? static_cast<uint32_t>(strlen(s)) : 0;
    });

    RegisterThunk("strcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* dest = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (dest && src) strcpy(dest, src);
    });

    RegisterThunk("strdup", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!src) { jit.Regs()[0] = 0; return; }
        size_t len = strlen(src) + 1;
        uint32_t dest_addr = host.GuestAlloc(len);
        memcpy(GuestToHost(host.GetGuestMemoryBase(), dest_addr), src, len);
        jit.Regs()[0] = dest_addr;
    });

    RegisterThunk("strrchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int c = static_cast<int>(jit.Regs()[1]);
        if (!s) { jit.Regs()[0] = 0; return; }
        const char* res = strrchr(s, c);
        jit.Regs()[0] = res ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(res) - reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase())) : 0;
    });

    RegisterThunk("strerror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* err = strerror(static_cast<int>(jit.Regs()[0]));
        size_t len = strlen(err) + 1;
        uint32_t dest = host.GuestAlloc(len);
        memcpy(GuestToHost(host.GetGuestMemoryBase(), dest), err, len);
        jit.Regs()[0] = dest;
    });

    RegisterThunk("strtoul", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* nptr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int base = static_cast<int>(jit.Regs()[2]);
        jit.Regs()[0] = nptr ? static_cast<uint32_t>(strtoul(nptr, nullptr, base)) : 0;
    });

    RegisterThunk("atoi", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = str ? atoi(str) : 0;
    });

    RegisterThunk("islower", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = islower(static_cast<int>(jit.Regs()[0]));
    });

    RegisterThunk("isxdigit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = isxdigit(static_cast<int>(jit.Regs()[0]));
    });

    RegisterThunk("memset", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        int c = static_cast<int>(jit.Regs()[1]);
        size_t n = ClampToArena(host, jit.Regs()[0], jit.Regs()[2]);
        if (s) memset(s, c, n);
    });

    RegisterThunk("memcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* dest = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* src = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = ClampToArena(host, jit.Regs()[0], jit.Regs()[2]);
        n = ClampToArena(host, jit.Regs()[1], n);
        if (dest && src) memcpy(dest, src, n);
    });

    RegisterThunk("memcmp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* s1 = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s2 = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        jit.Regs()[0] = (s1 && s2) ? memcmp(s1, s2, n) : 0;
    });

    RegisterThunk("memchr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        int c = static_cast<int>(jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        void* res = s ? const_cast<void*>(memchr(s, c, n)) : nullptr;
        jit.Regs()[0] = res ? HostToGuest(host.GetGuestMemoryBase(), res) : 0;
    });

    // Real qsort, with the guest's own comparator called through DynarmicHost::RunFunctionNested.
    //
    // The array is sorted by permuting an index vector first, so the comparator always sees the
    // two elements at their ORIGINAL guest addresses and nothing moves under it; the permutation
    // is applied afterwards out of a host-side copy. std::stable_sort also keeps a comparator
    // that answers 0 for equal keys from reordering equal elements, which the engine's
    // hash-ordered tile tables quietly rely on.
    RegisterThunk("qsort", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t base = jit.Regs()[0];
        const uint32_t count = jit.Regs()[1];
        const uint32_t size = jit.Regs()[2];
        const uint32_t cmp = jit.Regs()[3];
        if (!base || !cmp || !size || count < 2) return;
        const uint64_t bytes = static_cast<uint64_t>(count) * size;
        if (bytes > (64ull << 20) || base + bytes > host.GetGuestMemorySize()) {
            LOGE("qsort: refusing %u elements of %u bytes at 0x%08X", count, size, base);
            return;
        }

        uint8_t* const elems = static_cast<uint8_t*>(GuestToHost(host.GetGuestMemoryBase(), base));
        std::vector<uint32_t> order(count);
        for (uint32_t i = 0; i < count; ++i) order[i] = i;
        std::stable_sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
            const uint32_t r = host.RunFunctionNested(cmp, {base + a * size, base + b * size});
            return static_cast<int32_t>(r) < 0;
        });

        const std::vector<uint8_t> copy(elems, elems + static_cast<size_t>(bytes));
        for (uint32_t i = 0; i < count; ++i) {
            memcpy(elems + static_cast<size_t>(i) * size,
                   copy.data() + static_cast<size_t>(order[i]) * size, size);
        }
    });

    // Same class of bug as the qsort no-op above: a default stub returns 0, the guest reads
    // that as "not found", and a lookup table silently behaves as if it were empty. The
    // comparator is guest code, so it runs on the nested Jit exactly like qsort's.
    RegisterThunk("bsearch", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t key = jit.Regs()[0];
        const uint32_t base = jit.Regs()[1];
        const uint32_t count = jit.Regs()[2];
        const uint32_t size = jit.Regs()[3];
        const uint32_t cmp = host.MemoryRead32(jit.Regs()[13]);   // 5th arg, on the stack
        jit.Regs()[0] = 0;
        if (!key || !base || !cmp || !size || !count) return;
        const uint64_t bytes = static_cast<uint64_t>(count) * size;
        if (base + bytes > host.GetGuestMemorySize()) {
            LOGE("bsearch: refusing %u elements of %u bytes at 0x%08X", count, size, base);
            return;
        }
        ++g_bsearch_calls;
        uint32_t lo = 0, hi = count;
        while (lo < hi) {
            const uint32_t mid = lo + (hi - lo) / 2;
            const uint32_t elem = base + mid * size;
            const int32_t r = static_cast<int32_t>(host.RunFunctionNested(cmp, {key, elem}));
            if (r == 0) { ++g_bsearch_hits; jit.Regs()[0] = elem; return; }
            if (r < 0) hi = mid; else lo = mid + 1;
        }
    });

    // ARM AEABI Helpers
    RegisterThunk("__aeabi_idiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int32_t num = static_cast<int32_t>(jit.Regs()[0]);
        int32_t den = static_cast<int32_t>(jit.Regs()[1]);
        jit.Regs()[0] = den ? (num / den) : 0;
    });

    RegisterThunk("__aeabi_uidiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t num = jit.Regs()[0];
        uint32_t den = jit.Regs()[1];
        jit.Regs()[0] = den ? (num / den) : 0;
    });

    RegisterThunk("__aeabi_idivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int32_t num = static_cast<int32_t>(jit.Regs()[0]);
        int32_t den = static_cast<int32_t>(jit.Regs()[1]);
        if (den != 0) {
            jit.Regs()[0] = num / den;
            jit.Regs()[1] = num % den;
        } else {
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
        }
    });

    RegisterThunk("__aeabi_uidivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t num = jit.Regs()[0];
        uint32_t den = jit.Regs()[1];
        if (den != 0) {
            jit.Regs()[0] = num / den;
            jit.Regs()[1] = num % den;
        } else {
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
        }
    });

    RegisterThunk("__aeabi_uldivmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t num = static_cast<uint64_t>(jit.Regs()[0]) | (static_cast<uint64_t>(jit.Regs()[1]) << 32);
        uint64_t den = static_cast<uint64_t>(jit.Regs()[2]) | (static_cast<uint64_t>(jit.Regs()[3]) << 32);
        if (den != 0) {
            uint64_t q = num / den;
            uint64_t r = num % den;
            jit.Regs()[0] = static_cast<uint32_t>(q & 0xFFFFFFFF);
            jit.Regs()[1] = static_cast<uint32_t>(q >> 32);
            jit.Regs()[2] = static_cast<uint32_t>(r & 0xFFFFFFFF);
            jit.Regs()[3] = static_cast<uint32_t>(r >> 32);
        }
    });

    RegisterThunk("__gnu_ldivmod_helper", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t num = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        int64_t den = static_cast<int64_t>(jit.Regs()[2]) | (static_cast<int64_t>(jit.Regs()[3]) << 32);
        if (den != 0) {
            int64_t q = num / den;
            int64_t r = num % den;
            jit.Regs()[0] = static_cast<uint32_t>(q & 0xFFFFFFFF);
            jit.Regs()[1] = static_cast<uint32_t>(q >> 32);
            jit.Regs()[2] = static_cast<uint32_t>(r & 0xFFFFFFFF);
            jit.Regs()[3] = static_cast<uint32_t>(r >> 32);
        }
    });

    RegisterThunk("__aeabi_memcpy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memcpy(d, s, n);
    });
    RegisterThunk("__aeabi_memcpy4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memcpy(d, s, n);
    });
    RegisterThunk("__aeabi_memcpy8", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memcpy(d, s, n);
    });

    RegisterThunk("__aeabi_memmove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memmove(d, s, n);
    });
    RegisterThunk("__aeabi_memmove4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        const void* s = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t n = jit.Regs()[2];
        if (d && s) memmove(d, s, n);
    });

    RegisterThunk("__aeabi_memclr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        if (d) memset(d, 0, n);
    });
    RegisterThunk("__aeabi_memclr4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        if (d) memset(d, 0, n);
    });
    RegisterThunk("__aeabi_memclr8", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        if (d) memset(d, 0, n);
    });
    RegisterThunk("__aeabi_memset4", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* d = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t n = jit.Regs()[1];
        int c = static_cast<int>(jit.Regs()[2]);
        if (d) memset(d, c, n);
    });

    RegisterThunk("__aeabi_f2lz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float f = *reinterpret_cast<float*>(&jit.Regs()[0]);
        int64_t i = static_cast<int64_t>(f);
        jit.Regs()[0] = static_cast<uint32_t>(i & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(i >> 32);
    });

    RegisterThunk("__aeabi_f2ulz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float f = *reinterpret_cast<float*>(&jit.Regs()[0]);
        uint64_t u = static_cast<uint64_t>(f);
        jit.Regs()[0] = static_cast<uint32_t>(u & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(u >> 32);
    });

    RegisterThunk("__aeabi_l2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t i = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        float f = static_cast<float>(i);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&f);
    });

    RegisterThunk("__aeabi_ul2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint64_t u = static_cast<uint64_t>(jit.Regs()[0]) | (static_cast<uint64_t>(jit.Regs()[1]) << 32);
        float f = static_cast<float>(u);
        jit.Regs()[0] = *reinterpret_cast<uint32_t*>(&f);
    });

    RegisterThunk("__aeabi_l2d", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int64_t i = static_cast<int64_t>(jit.Regs()[0]) | (static_cast<int64_t>(jit.Regs()[1]) << 32);
        double d = static_cast<double>(i);
        uint64_t u = *reinterpret_cast<uint64_t*>(&d);
        jit.Regs()[0] = static_cast<uint32_t>(u & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(u >> 32);
    });

    // AEABI memory functions
    auto aeabi_memclr_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t n = jit.Regs()[1];
        if (dest && n) {
            memset(GuestToHost(host.GetGuestMemoryBase(), dest), 0, n);
        }
    };
    RegisterThunk("__aeabi_memclr", aeabi_memclr_handler);
    RegisterThunk("__aeabi_memclr4", aeabi_memclr_handler);
    RegisterThunk("__aeabi_memclr8", aeabi_memclr_handler);

    auto aeabi_memset_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t n = jit.Regs()[1];
        int c = static_cast<int>(jit.Regs()[2]);
        if (dest && n) {
            memset(GuestToHost(host.GetGuestMemoryBase(), dest), c, n);
        }
    };
    RegisterThunk("__aeabi_memset", aeabi_memset_handler);
    RegisterThunk("__aeabi_memset4", aeabi_memset_handler);
    RegisterThunk("__aeabi_memset8", aeabi_memset_handler);

    auto aeabi_memcpy_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        size_t n = ClampToArena(host, src, ClampToArena(host, dest, jit.Regs()[2]));
        if (dest && src && n) {
            memcpy(GuestToHost(host.GetGuestMemoryBase(), dest),
                   GuestToHost(host.GetGuestMemoryBase(), src), n);
        }
    };
    RegisterThunk("__aeabi_memcpy", aeabi_memcpy_handler);
    RegisterThunk("__aeabi_memcpy4", aeabi_memcpy_handler);
    RegisterThunk("__aeabi_memcpy8", aeabi_memcpy_handler);

    auto aeabi_memmove_handler = [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t dest = jit.Regs()[0];
        uint32_t src = jit.Regs()[1];
        size_t n = ClampToArena(host, src, ClampToArena(host, dest, jit.Regs()[2]));
        if (dest && src && n) {
            memmove(GuestToHost(host.GetGuestMemoryBase(), dest),
                    GuestToHost(host.GetGuestMemoryBase(), src), n);
        }
    };
    RegisterThunk("__aeabi_memmove", aeabi_memmove_handler);
    RegisterThunk("__aeabi_memmove4", aeabi_memmove_handler);
    RegisterThunk("__aeabi_memmove8", aeabi_memmove_handler);

    // Pthreads
    RegisterThunk("pthread_mutex_lock", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_mutex_unlock", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_cond_wait", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("pthread_cond_broadcast", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    RegisterThunk("pthread_once", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t control_addr = jit.Regs()[0];
        uint32_t init_routine = jit.Regs()[1];
        uint32_t control_val = control_addr ? host.MemoryRead32(control_addr) : 1;
        if (control_addr) host.MemoryWrite32(control_addr, 1);
        if (control_val == 0 && init_routine) {
            jit.Regs()[15] = init_routine & ~1u;
            if (init_routine & 1) {
                jit.SetCpsr(jit.Cpsr() | 0x20);
            } else {
                jit.SetCpsr(jit.Cpsr() & ~0x20);
            }
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_key_create", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key_ptr = jit.Regs()[0];
        if (key_ptr) host.MemoryWrite32(key_ptr, g_next_tls_key++);
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_setspecific", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key = jit.Regs()[0];
        uint32_t val = jit.Regs()[1];
        g_tls_map[key] = reinterpret_cast<void*>(static_cast<uintptr_t>(val));
        jit.Regs()[0] = 0;
    });

    RegisterThunk("pthread_getspecific", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t key = jit.Regs()[0];
        auto it = g_tls_map.find(key);
        jit.Regs()[0] = (it != g_tls_map.end()) ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(it->second)) : 0;
    });

    RegisterThunk("fopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* mode = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (!path) { jit.Regs()[0] = 0; return; }

        FILE* f = fopen(path, mode ? mode : "r");
        int guest_fd = f ? fileno(f) : -1;
        if (!f) {
            ApkEntry* entry = FindApkEntry(path);
            if (entry && g_apk_indexed_fd >= 0) {
                ApkCookie* cookie = static_cast<ApkCookie*>(malloc(sizeof(ApkCookie)));
                cookie->base_offset = entry->data_offset;
                cookie->file_size = entry->file_size;
                cookie->current_offset = 0;

                f = funopen(cookie, ApkRead, nullptr, ApkSeek, ApkClose);
                if (f) {
                    // A funopen stream has no descriptor, but the inlined fileno() described
                    // at PublishGuestFile still needs one fstat() can size. Hand out a virtual
                    // fd from the same table the open()/fstat() thunks already use.
                    //
                    // The vfd carries a real dup of the APK descriptor, not -1: the engine
                    // mmap()s the file it just fopen()ed, and the mmap thunk resolves a vfd to
                    // (real fd, offset-inside-the-APK). With -1 there it returned MAP_FAILED,
                    // which is how the main OBB used to mount as a pak with no entries.
                    std::lock_guard<std::mutex> lock(g_vfd_mutex);
                    guest_fd = g_next_vfd++;
                    g_vfd_map[guest_fd] = { dup(g_apk_indexed_fd),
                                            static_cast<size_t>(entry->file_size),
                                            entry->data_offset, 0 };
                    LOGI("fopen: APK direct stream opened '%s' -> '%s' (size %lld, offset %lld, vfd %d)",
                         path, entry->name, static_cast<long long>(entry->file_size),
                         static_cast<long long>(entry->data_offset), guest_fd);
                }
            }
        }

        if (f) {
            uint32_t handle = PublishGuestFile(host, f, guest_fd);
            if (!handle) LOGE("fopen('%s'): no guest heap left for the FILE block", path);
            // The pak/OBB opens are the ones whose size the engine takes from the inlined
            // fileno()+fstat(); report what the guest will actually see for them.
            if (strstr(path, ".obb") || strstr(path, ".pak")) {
                struct stat st{};
                const int rc = fstat(guest_fd, &st);
                LOGI("fopen('%s') -> handle 0x%08X, guest fd %d, fstat rc=%d size=%lld",
                     path, handle, guest_fd, rc, static_cast<long long>(st.st_size));
                if (strstr(path, "main.") && strstr(path, ".obb")) g_obb_handle = handle;
            }
            jit.Regs()[0] = handle;
        } else {
            // Bounded, because the engine probes for optional files constantly. Worth having:
            // without it a failing open is completely silent on this side.
            static int reported = 0;
            if (reported < 64) {
                ++reported;
                LOGI("fopen('%s', '%s') failed, errno=%d", path, mode ? mode : "r", errno);
            }
            jit.Regs()[0] = 0;
        }
    });

    // Real fgets/mkdir: both were default stubs, and both fail silently. CDeviceConfig reads
    // its JSON with fgets, and the engine creates its cache directories with mkdir.
    RegisterThunk("fgets", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* buf = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const int size = static_cast<int>(jit.Regs()[1]);
        auto it = g_file_map.find(jit.Regs()[2]);
        if (!buf || size <= 0 || it == g_file_map.end()) { jit.Regs()[0] = 0; return; }
        jit.Regs()[0] = fgets(buf, size, it->second) ? jit.Regs()[0] : 0;
    });

    RegisterThunk("mkdir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = path ? mkdir(path, static_cast<mode_t>(jit.Regs()[1])) : -1;
    });

    // fputs(const char *s, FILE *stream). Was the last default stub still firing on a cold
    // start (one line, from libgnustl_shared+0x50764). Lesson 2.16: on Android fd 1 and 2 go
    // nowhere, and that is exactly where a C++ runtime writes the reason it is giving up --
    // so an unknown stream goes to the log rather than being swallowed. A stream the guest
    // really opened is written for real.
    RegisterThunk("fputs", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* s = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!s) { jit.Regs()[0] = -1; return; }
        auto it = g_file_map.find(jit.Regs()[1]);
        if (it != g_file_map.end()) {
            jit.Regs()[0] = static_cast<uint32_t>(fputs(s, it->second));
            return;
        }
        LOGI("[guest fputs] %s", s);
        jit.Regs()[0] = static_cast<uint32_t>(strlen(s));
    });

    RegisterThunk("fdopen", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const char* mode = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        FILE* f = fdopen(fd, mode);
        jit.Regs()[0] = f ? PublishGuestFile(host, f, fd) : 0;
    });

    RegisterThunk("fclose", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        if (it != g_file_map.end()) {
            // Drop the virtual fd this handle published at +14, if it had one.
            const int guest_fd = static_cast<int16_t>(host.MemoryRead16(handle + 14));
            if (guest_fd >= 1000) {
                std::lock_guard<std::mutex> lock(g_vfd_mutex);
                auto vit = g_vfd_map.find(guest_fd);
                if (vit != g_vfd_map.end()) {
                    // The vfd owns a dup of the APK descriptor (fopen's APK fallback needs a
                    // real fd so mmap can map the entry). Any mapping already made off it
                    // stays valid -- mmap does not keep the descriptor.
                    if (vit->second.real_apk_fd >= 0) close(vit->second.real_apk_fd);
                    g_vfd_map.erase(vit);
                }
            }
            // The guest checks this result: an fclose that quietly claims success makes a
            // failing save look written.
            const int rc = fclose(it->second);
            g_file_map.erase(it);
            jit.Regs()[0] = static_cast<uint32_t>(rc);
        } else {
            jit.Regs()[0] = -1;
        }
    });

    RegisterThunk("fread", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        void* ptr = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t size = jit.Regs()[1];
        size_t count = jit.Regs()[2];
        uint32_t handle = jit.Regs()[3];
        if (ptr && size && count &&
            !GuestSpanOK(host, ptr, static_cast<uint64_t>(size) * count)) {
            LOGE("fread: guest span %p x %zu*%zu leaves the arena", ptr, size, count);
            jit.Regs()[0] = 0;
            return;
        }
        auto it = g_file_map.find(handle);
        size_t res = (it != g_file_map.end() && ptr) ? fread(ptr, size, count, it->second) : 0;
        // Trace the first reads off the main OBB: whether CXGSFileSystemPAK::Initialise gets
        // past the header is the difference between "345 MB of assets mounted" and "every
        // texture atlas silently empty".
        if (handle && handle == g_obb_handle) {
            static int traced = 0;
            if (traced < 12) {
                LOGI("fread(obb): %zu x %zu -> %zu at pos %lld",
                     size, count, res, static_cast<long long>(ftello(it->second)));
                ++traced;
            }
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("fwrite", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* ptr = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]);
        size_t size = jit.Regs()[1];
        size_t count = jit.Regs()[2];
        uint32_t handle = jit.Regs()[3];
        if (ptr && size && count &&
            !GuestSpanOK(host, ptr, static_cast<uint64_t>(size) * count)) {
            LOGE("fwrite: guest span %p x %zu*%zu leaves the arena", ptr, size, count);
            jit.Regs()[0] = 0;
            return;
        }
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end() && ptr) ? fwrite(ptr, size, count, it->second) : 0;
    });

    RegisterThunk("fseek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        long offset = static_cast<long>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);
        auto it = g_file_map.find(handle);
        int res = (it != g_file_map.end()) ? fseek(it->second, offset, whence) : -1;
        jit.Regs()[0] = res;
    });

    RegisterThunk("fseeko", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);
        auto it = g_file_map.find(handle);
        int res = (it != g_file_map.end()) ? fseeko(it->second, offset, whence) : -1;
        jit.Regs()[0] = res;
    });

    RegisterThunk("ftell", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? static_cast<uint32_t>(ftell(it->second)) : 0;
    });

    RegisterThunk("ftello", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        off_t res = (it != g_file_map.end()) ? ftello(it->second) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("fileno", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? fileno(it->second) : -1;
    });

    RegisterThunk("clearerr", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        if (it != g_file_map.end()) clearerr(it->second);
    });

    RegisterThunk("ferror", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? ferror(it->second) : 0;
    });

    RegisterThunk("open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int flags = static_cast<int>(jit.Regs()[1]);
        int mode = static_cast<int>(jit.Regs()[2]);

        int fd = -1;
        if (path && (flags & O_CREAT) == 0 && (flags & O_WRONLY) == 0 && (flags & O_RDWR) == 0) {
            ApkEntry* entry = FindApkEntry(path);
            if (entry && g_apk_indexed_fd >= 0) {
                int dup_fd = dup(g_apk_indexed_fd);
                if (dup_fd >= 0) {
                    std::lock_guard<std::mutex> lock(g_vfd_mutex);
                    int vfd = g_next_vfd++;
                    g_vfd_map[vfd] = { dup_fd, static_cast<size_t>(entry->file_size), entry->data_offset, 0 };
                    LOGI("open: APK direct stream opened '%s' -> '%s' (vfd %d, size %zu, offset %lld)",
                         path, entry->name, vfd, entry->file_size, static_cast<long long>(entry->data_offset));
                    jit.Regs()[0] = static_cast<uint32_t>(vfd);
                    return;
                }
            }
        }

        fd = open(path ? path : "", flags, mode);
        jit.Regs()[0] = (fd >= 0) ? static_cast<uint32_t>(fd) : static_cast<uint32_t>(-1);
    });

    RegisterThunk("close", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                close(it->second.real_apk_fd);
                g_vfd_map.erase(it);
                jit.Regs()[0] = 0;
                return;
            }
        }
        jit.Regs()[0] = (fd >= 0) ? static_cast<uint32_t>(close(fd)) : static_cast<uint32_t>(-1);
    });

    RegisterThunk("read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
        if (!buf) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                VirtualFd& vfd = it->second;
                if (vfd.current_pos >= static_cast<off_t>(vfd.file_size)) {
                    jit.Regs()[0] = 0; // EOF
                    return;
                }
                size_t avail = vfd.file_size - vfd.current_pos;
                size_t to_read = (count < avail) ? count : avail;
                ssize_t nread = pread(vfd.real_apk_fd, buf, to_read, vfd.file_offset + vfd.current_pos);
                if (nread > 0) {
                    vfd.current_pos += nread;
                }
                jit.Regs()[0] = (nread >= 0) ? static_cast<uint32_t>(nread) : static_cast<uint32_t>(-1);
                return;
            }
        }

        ssize_t res = (fd >= 0) ? read(fd, buf, count) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("write", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        const void* buf = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        size_t count = jit.Regs()[2];
        ssize_t res = (buf && fd >= 0) ? write(fd, buf, count) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("lseek", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        off_t offset = static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1]));
        int whence = static_cast<int>(jit.Regs()[2]);

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                VirtualFd& vfd = it->second;
                off_t new_pos = vfd.current_pos;
                if (whence == SEEK_SET) new_pos = offset;
                else if (whence == SEEK_CUR) new_pos += offset;
                else if (whence == SEEK_END) new_pos = static_cast<off_t>(vfd.file_size) + offset;
                else { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }

                if (new_pos < 0) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
                vfd.current_pos = new_pos;
                jit.Regs()[0] = static_cast<uint32_t>(new_pos);
                return;
            }
        }

        off_t res = (fd >= 0) ? lseek(fd, offset, whence) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("lseek64", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        int64_t offset = static_cast<int64_t>(jit.Regs()[2]) | (static_cast<int64_t>(jit.Regs()[3]) << 32);
        int whence = static_cast<int>(host.MemoryRead32(jit.Regs()[13]));

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                VirtualFd& vfd = it->second;
                off_t new_pos = vfd.current_pos;
                if (whence == SEEK_SET) new_pos = offset;
                else if (whence == SEEK_CUR) new_pos += offset;
                else if (whence == SEEK_END) new_pos = static_cast<off_t>(vfd.file_size) + offset;
                else { jit.Regs()[0] = static_cast<uint32_t>(-1); jit.Regs()[1] = static_cast<uint32_t>(-1); return; }

                if (new_pos < 0) { jit.Regs()[0] = static_cast<uint32_t>(-1); jit.Regs()[1] = static_cast<uint32_t>(-1); return; }
                vfd.current_pos = new_pos;
                jit.Regs()[0] = static_cast<uint32_t>(new_pos & 0xFFFFFFFF);
                jit.Regs()[1] = static_cast<uint32_t>(new_pos >> 32);
                return;
            }
        }

        off64_t res = (fd >= 0) ? lseek64(fd, offset, whence) : -1;
        jit.Regs()[0] = static_cast<uint32_t>(res & 0xFFFFFFFF);
        jit.Regs()[1] = static_cast<uint32_t>(res >> 32);
    });

    RegisterThunk("access", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int mode = static_cast<int>(jit.Regs()[1]);
        int res = access(path ? path : "", mode);
        if (res != 0 && FindApkEntry(path)) {
            res = 0;
        }
        jit.Regs()[0] = res;
    });

    // Directory iteration. There were no thunks for these at all, so opendir() answered 0 via
    // the default stub -- and CSaveManager::LoadSaveGame enumerates DOCS: before touching a
    // save file. CXGSFileSystemPOSIX::OpenDir sets its out-parameter to 0 and returns an error
    // when opendir fails, but LoadSaveGame calls IsValid() on it without checking, so the guest
    // read guest address 0, took the word at +8 (the Thumb exit trap, 0xDF00DF00) for a
    // function pointer and jumped there.
    //
    // The DIR* the guest gets is an opaque handle -- it only ever passes it back -- but the
    // dirent* is dereferenced, so it has to be a real guest block in bionic's layout:
    //   +0 d_ino(8)  +8 d_off(8)  +16 d_reclen(2)  +18 d_type(1)  +19 d_name[256]
    // `d_name` at +19 is confirmed by CXGSFileIterator_POSIX::GetName, which returns
    // `this->m_pEntry + 19`. One block per open directory, rewritten on each readdir, which is
    // what libc does too.
    RegisterThunk("opendir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        DIR* d = path ? opendir(path) : nullptr;
        if (!d) {
            static int reported = 0;
            if (reported++ < 16) LOGI("opendir('%s') failed, errno=%d", path ? path : "(null)", errno);
            jit.Regs()[0] = 0;
            return;
        }
        const uint32_t block = host.GuestAlloc(kGuestDirentSize, 8);
        if (!block) { closedir(d); jit.Regs()[0] = 0; return; }
        const uint32_t handle = g_next_dir_handle++;
        g_dir_map[handle] = {d, block};
        jit.Regs()[0] = handle;
    });

    RegisterThunk("readdir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto it = g_dir_map.find(jit.Regs()[0]);
        if (it == g_dir_map.end()) { jit.Regs()[0] = 0; return; }
        struct dirent* e = readdir(it->second.dir);
        if (!e) { jit.Regs()[0] = 0; return; }

        uint8_t* b = host.GetGuestMemoryBase() + it->second.entry;
        memset(b, 0, kGuestDirentSize);
        const uint64_t ino = e->d_ino;
        memcpy(b + 0, &ino, 8);
        const uint16_t reclen = kGuestDirentSize;
        memcpy(b + 16, &reclen, 2);
        b[18] = e->d_type;
        strncpy(reinterpret_cast<char*>(b + 19), e->d_name, 255);
        jit.Regs()[0] = it->second.entry;
    });

    RegisterThunk("closedir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto it = g_dir_map.find(jit.Regs()[0]);
        if (it == g_dir_map.end()) { jit.Regs()[0] = -1; return; }
        closedir(it->second.dir);
        host.GuestFree(it->second.entry);
        g_dir_map.erase(it);
        jit.Regs()[0] = 0;
    });

    RegisterThunk("rewinddir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto it = g_dir_map.find(jit.Regs()[0]);
        if (it != g_dir_map.end()) rewinddir(it->second.dir);
        jit.Regs()[0] = 0;
    });

    RegisterThunk("stat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        uint32_t buf_gaddr = jit.Regs()[1];
        struct stat st;
        int res = stat(path ? path : "", &st);
        if (res != 0) {
            ApkEntry* entry = FindApkEntry(path);
            if (entry) {
                memset(&st, 0, sizeof(st));
                st.st_size = entry->file_size;
                st.st_mode = S_IFREG | 0644;
                st.st_nlink = 1;
                res = 0;
            }
        }
        if (res == 0) {
            WriteArm32Stat(host.GetGuestMemoryBase(), buf_gaddr, st);
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("feof", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t handle = jit.Regs()[0];
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? feof(it->second) : 1;
    });

    RegisterThunk("fflush", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t handle = jit.Regs()[0];
        // fflush(NULL) means "every open output stream". The save dance is
        // write-temp, fflush, fsync, rename; answering success while flushing nothing
        // silently skipped the flush step of it.
        if (handle == 0) {
            int rc = 0;
            for (const auto& entry : g_file_map)
                if (fflush(entry.second) != 0) rc = EOF;
            jit.Regs()[0] = static_cast<uint32_t>(rc);
            return;
        }
        auto it = g_file_map.find(handle);
        jit.Regs()[0] = (it != g_file_map.end()) ? static_cast<uint32_t>(fflush(it->second)) : 0;
    });

    RegisterThunk("setvbuf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 0;
    });

    // mmap/munmap, for real. CXGSFileSystemPOSIX::Open maps a whole expansion file and hands
    // the pointer to CXGSROMStream::SetData:
    //     MOV R2,#1 (PROT_READ); MOV R3,R2 (MAP_SHARED); LDRSH R12,[R12,#0xE] (the inlined
    //     fileno()); STR R6,[SP,#offset]; STR R12,[SP,#fd]; BL mmap; CMN R0,#1
    // The guest only rejects -1, so the old stub's 0 counted as success and CXGSROMStream got
    // 345 MB of zeroes: the main OBB mounted as a pak with no entries, every one of the 59
    // files inside it looked missing, and the boot parked on the download screen trying to
    // fetch them. AAssetManager assets were unaffected, which is why the APK-side paks worked
    // and only OBB-side ones did not.
    //
    // The guest arena is one anonymous MAP_PRIVATE reservation, so a file mapping can be laid
    // straight into it with MAP_FIXED and the guest reads it at base + vaddr like any other
    // memory -- no copy, no 345 MB of RSS. MAP_PRIVATE, never MAP_SHARED, so a stray guest
    // write cannot reach the OBB on disk.
    RegisterThunk("mmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t len   = jit.Regs()[1];
        const uint32_t flags = jit.Regs()[3];
        const uint32_t sp    = jit.Regs()[13];         // AAPCS: args 5 and 6 are on the stack
        int            fd    = static_cast<int>(host.MemoryRead32(sp));
        off_t          off   = static_cast<off_t>(host.MemoryRead32(sp + 4));

        constexpr uint32_t kMapAnonymous = 0x20;       // Linux MAP_ANONYMOUS on arm
        constexpr uint32_t kMapFailed    = 0xFFFFFFFF;
        const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));

        if (len == 0) { jit.Regs()[0] = kMapFailed; return; }

        if (fd < 0 || (flags & kMapAnonymous)) {
            // Anonymous: fresh mapping space, which the arena zero-fills for us.
            const uint32_t va = host.GuestAllocMapping((len + page - 1) & ~(page - 1), page);
            jit.Regs()[0] = va ? va : kMapFailed;
            return;
        }

        // A virtual fd is an entry inside the APK: map the real APK descriptor at the entry's
        // offset instead.
        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                off += it->second.file_offset;
                fd = it->second.real_apk_fd;
            }
        }
        if (fd < 0) { jit.Regs()[0] = kMapFailed; return; }

        // mmap needs a page-aligned file offset; keep the remainder as a bias on the result.
        const off_t  aligned = off & ~static_cast<off_t>(page - 1);
        const size_t bias    = static_cast<size_t>(off - aligned);
        const size_t span    = (len + bias + page - 1) & ~(page - 1);

        // Hand back the mapping this file region already has. The guest arena is a bump
        // allocator, so a second mapping of the same file is a second permanent 345 MB hole:
        // CBasicDownloadScreen's install path calls UtilCloseAllOpenPaks and reopens
        // everything, which re-maps the main OBB, and two of those exhaust the 736 MB heap
        // ("GuestAlloc out of guest heap" right after MainLoadingFunc starts). The pages are
        // MAP_PRIVATE and the consumers are read-only ROM streams, so sharing is safe.
        struct stat fst{};
        if (fstat(fd, &fst) == 0) {
            std::lock_guard<std::mutex> lock(g_file_map_mutex);
            for (const auto& m : g_guest_file_maps) {
                if (m.dev == fst.st_dev && m.ino == fst.st_ino && m.off == aligned && m.span == span) {
                    jit.Regs()[0] = m.va + static_cast<uint32_t>(bias);
                    return;
                }
            }
        }

        const uint32_t va = host.GuestAllocMapping(span, page);
        if (!va) { LOGE("mmap: no guest arena for %zu bytes", span); jit.Regs()[0] = kMapFailed; return; }

        if (static_cast<uint64_t>(va) + span > host.GetGuestMemorySize()) {
            LOGE("mmap: 0x%08X + %zu would run past the guest arena", va, span);
            jit.Regs()[0] = kMapFailed;
            return;
        }
        void* want = host.GetGuestMemoryBase() + va;
        void* got = ::mmap(want, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, aligned);
        if (got == MAP_FAILED) {
            LOGE("mmap(fd=%d, len=%u, off=%lld) failed: %s", fd, len,
                 static_cast<long long>(off), strerror(errno));
            jit.Regs()[0] = kMapFailed;
            return;
        }
        {
            std::lock_guard<std::mutex> lock(g_file_map_mutex);
            g_guest_file_maps.push_back({fst.st_dev, fst.st_ino, aligned, span, va});
        }
        LOGI("mmap: fd=%d len=%u off=%lld -> guest 0x%08X", fd, len,
             static_cast<long long>(off), va + static_cast<uint32_t>(bias));
        jit.Regs()[0] = va + static_cast<uint32_t>(bias);
    });

    RegisterThunk("munmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t addr = jit.Regs()[0];
        const uint32_t len  = jit.Regs()[1];
        const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        if (!addr || !len) { jit.Regs()[0] = 0; return; }
        static int logged = 0;
        if (logged++ < 8) LOGI("munmap(0x%08X, %u)", addr, len);

        // Put anonymous pages back rather than leaving a hole: the arena has to stay one
        // continuous mapping or the next access through base + vaddr faults.
        const uint32_t base_va = addr & ~static_cast<uint32_t>(page - 1);
        size_t span = (static_cast<uint64_t>(len) + (addr - base_va) + page - 1) & ~(page - 1);

        // A cached file mapping stays: another filesystem may still be reading through it, and
        // the arena address is never reused anyway.
        {
            std::lock_guard<std::mutex> lock(g_file_map_mutex);
            for (const auto& m : g_guest_file_maps) {
                if (base_va >= m.va && base_va < m.va + m.span) { jit.Regs()[0] = 0; return; }
            }
        }
        // MAP_FIXED writes to *host* address space. Both the address and the length come
        // straight from the guest, so a bogus pair would unmap whatever the host has after the
        // arena -- which is how a wild munmap turned into a SIGSEGV inside jemalloc, half a
        // second later, on an unrelated free.
        const uint64_t end = static_cast<uint64_t>(base_va) + span;
        if (end > host.GetGuestMemorySize()) {
            LOGE("munmap: refusing 0x%08X + %zu, past the %zu-byte guest arena",
                 base_va, span, host.GetGuestMemorySize());
            jit.Regs()[0] = 0;
            return;
        }
        void* p = ::mmap(host.GetGuestMemoryBase() + base_va, span, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (p == MAP_FAILED) LOGE("munmap: could not restore arena at 0x%08X: %s", base_va, strerror(errno));
        jit.Regs()[0] = 0;
    });

    RegisterThunk("fstat", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fd = static_cast<int>(jit.Regs()[0]);
        uint32_t buf_gaddr = jit.Regs()[1];
        struct stat st;
        int res = -1;

        {
            std::lock_guard<std::mutex> lock(g_vfd_mutex);
            auto it = g_vfd_map.find(fd);
            if (it != g_vfd_map.end()) {
                memset(&st, 0, sizeof(st));
                st.st_size = it->second.file_size;
                st.st_mode = S_IFREG | 0644;
                st.st_nlink = 1;
                res = 0;
            }
        }

        if (res != 0) {
            res = fstat(fd, &st);
        }

        if (res == 0) {
            WriteArm32Stat(host.GetGuestMemoryBase(), buf_gaddr, st);
        }
        jit.Regs()[0] = res;
    });

    RegisterThunk("remove", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = remove(path ? path : "");
    });

    RegisterThunk("rename", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* oldp = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        const char* newp = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[0] = rename(oldp ? oldp : "", newp ? newp : "");
    });

    RegisterThunk("chmod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("umask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    // mkstemp(char *template). The engine's save path is mkstemp, write, fsync, rename;
    // the stub's -1 failed that at the very first step, which is why saves never landed
    // at all. The template lives in guest memory and gets the generated name written
    // back into it, exactly like the real thing.
    RegisterThunk("mkstemp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char* tmpl = reinterpret_cast<char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!tmpl) { jit.Regs()[0] = static_cast<uint32_t>(-1); return; }
        const int fd = mkstemp(tmpl);
        if (fd < 0)
            LOGE("mkstemp('%s') failed: %s", tmpl, strerror(errno));
        jit.Regs()[0] = static_cast<uint32_t>(fd);
    });
    RegisterThunk("getpid", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = getpid(); });

    RegisterThunk("time", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(time(nullptr));
    });

    RegisterThunk("localtime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        time_t t = static_cast<time_t>(host.MemoryRead32(jit.Regs()[0]));
        struct tm* tm_res = localtime(&t);
        if (tm_res) {
            uint32_t gtm = host.GuestAlloc(sizeof(struct tm));
            memcpy(GuestToHost(host.GetGuestMemoryBase(), gtm), tm_res, sizeof(struct tm));
            jit.Regs()[0] = gtm;
        } else {
            jit.Regs()[0] = 0;
        }
    });

    RegisterThunk("mktime", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        struct tm* tm_ptr = reinterpret_cast<struct tm*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        jit.Regs()[0] = tm_ptr ? static_cast<uint32_t>(mktime(tm_ptr)) : 0;
    });

    RegisterThunk("raise", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // Runtime guards & hooks
    // Fatal guest paths. abort()/terminate must not RETURN into a caller that cannot
    // cope (a real abort never returns): the calling job/call is stopped here, the frame
    // carries on. Without this a failed canary or a throw under the stub unwind spins
    // here flooding the log forever.
    RegisterThunk("__stack_chk_fail", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static int hits = 0;
        if (hits++ < 4)
            LOGE("__stack_chk_fail #%d: guest LR 0x%08X (%s) -- stopping the call", hits,
                 jit.Regs()[14], host.DescribeAddress(jit.Regs()[14]).c_str());
        host.HaltCurrentCall();
    });

    RegisterThunk("abort", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static int hits = 0;
        if (hits++ < 4)
            LOGE("Guest abort() #%d from LR 0x%08X (%s) -- stopping the call", hits,
                 jit.Regs()[14], host.DescribeAddress(jit.Regs()[14]).c_str());
        host.HaltCurrentCall();
    });

    // A C++ throw cannot work here: EHABI unwinding is stubbed, so instead of unwinding,
    // the throw degrades into terminate/abort UB. Stop the call at the throw point (and
    // name the exception type while logging is compiled in).
    RegisterThunk("__cxa_throw", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static int hits = 0;
        if (hits++ < 8) {
            const uint32_t ti = jit.Regs()[1];
            const uint32_t name = ti ? host.MemoryRead32(ti + 4) : 0;
            const char* nm = name ? reinterpret_cast<const char*>(
                host.GetGuestMemoryBase() + name) : "?";
            LOGE("__cxa_throw #%d: type=%s, from LR 0x%08X (%s) -- stopping the call",
                 hits, nm, jit.Regs()[14], host.DescribeAddress(jit.Regs()[14]).c_str());
        }
        host.HaltCurrentCall();
    });

    RegisterThunk("__assert2", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* file = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        int line = static_cast<int>(jit.Regs()[1]);
        const char* func = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        const char* expr = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        LOGE("Assertion failed: %s at %s:%d (%s)", expr ? expr : "", file ? file : "", line, func ? func : "");
    });

    RegisterThunk("__cxa_atexit", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__cxa_finalize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__aeabi_unwind_cpp_pr0", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("__aeabi_unwind_cpp_pr1", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_Resume", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_RaiseException", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_DeleteException", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("_Unwind_GetLanguageSpecificData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_GetRegionStart", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_VRS_Get", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_Unwind_VRS_Set", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("__gnu_unwind_frame", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // ---------------------------------------------------------------------------
    // The last symbols that were still answering through the default stub. None of them sits
    // on the game's path -- the callers are NSPR/NSS (RNG_SystemInfoForRNG, PR_GetEnv,
    // _PR_UnixInit), google_breakpad's ExceptionHandler and Skynest's own NSPR copy -- but
    // "return 0" is a lie for most of them, and three of those lies are the dangerous kind
    // where 0 means "success" and the out-parameter is left holding stack garbage.

    // pipe(): 0 meant "success" while the two fds were never written, so NSPR went on to
    // read/write/close whatever integers happened to be on the guest stack. A stray close()
    // of, say, guest fd 153 (the main OBB) would have been a silent corruption with no visible
    // cause. Host fds are guest fds here -- only APK entries get virtual ones -- so a real
    // pipe() needs nothing but the two stores.
    RegisterThunk("pipe", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        int fds[2] = {-1, -1};
        int res = pipe(fds);
        if (res == 0) {
            host.MemoryWrite32(jit.Regs()[0] + 0, static_cast<uint32_t>(fds[0]));
            host.MemoryWrite32(jit.Regs()[0] + 4, static_cast<uint32_t>(fds[1]));
        }
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    // readdir_r(): returns 0 on success and stores NULL through `result` at end-of-stream.
    // The stub returned 0 without touching `result`, i.e. "here is an entry" pointing at
    // garbage. Reuses the same guest dirent block as readdir when the caller passes one of
    // our DIR handles.
    RegisterThunk("readdir_r", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t entry_gaddr = jit.Regs()[1];
        const uint32_t result_gaddr = jit.Regs()[2];
        auto it = g_dir_map.find(jit.Regs()[0]);
        if (it == g_dir_map.end()) {
            if (result_gaddr) host.MemoryWrite32(result_gaddr, 0);
            jit.Regs()[0] = EBADF;
            return;
        }
        errno = 0;
        struct dirent* e = readdir(it->second.dir);
        if (!e) {
            if (result_gaddr) host.MemoryWrite32(result_gaddr, 0);
            jit.Regs()[0] = static_cast<uint32_t>(errno);   // 0 = clean end of stream
            return;
        }
        uint8_t* b = host.GetGuestMemoryBase() + entry_gaddr;
        memset(b, 0, kGuestDirentSize);
        const uint64_t ino = e->d_ino;
        memcpy(b + 0, &ino, 8);
        const uint16_t reclen = kGuestDirentSize;
        memcpy(b + 16, &reclen, 2);
        b[18] = e->d_type;
        strncpy(reinterpret_cast<char*>(b + 19), e->d_name, 255);
        if (result_gaddr) host.MemoryWrite32(result_gaddr, entry_gaddr);
        jit.Regs()[0] = 0;
    });

    // pathconf(path, _PC_NAME_MAX) is how the readdir_r caller above sizes its dirent buffer;
    // the stub's 0 said "names are zero bytes long".
    RegisterThunk("pathconf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* path = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        long res = pathconf(path ? path : "/", static_cast<int>(jit.Regs()[1]));
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });
    RegisterThunk("fpathconf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = static_cast<uint32_t>(fpathconf(static_cast<int>(jit.Regs()[0]),
                                                        static_cast<int>(jit.Regs()[1])));
    });

    // ioctl(): every observed call comes from Skynest with r0 = -1, i.e. it is already asking
    // about a socket that was never created. Answering "success" told it the opposite. The
    // request codes are guest-side structs we would have to translate one by one, and none of
    // them is on a path that works offline, so this fails honestly instead.
    RegisterThunk("ioctl", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int fd = static_cast<int>(jit.Regs()[0]);
        static int reported = 0;
        if (reported++ < 8) LOGI("ioctl(fd=%d, req=0x%08x) -> -1 (not translated)", fd, jit.Regs()[1]);
        errno = (fd < 0) ? EBADF : ENOTTY;
        jit.Regs()[0] = static_cast<uint32_t>(-1);
    });

    RegisterThunk("fsync", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int fd = static_cast<int>(jit.Regs()[0]);
        std::lock_guard<std::mutex> lock(g_vfd_mutex);
        // Virtual fds are read-only views into the APK; there is nothing to flush.
        jit.Regs()[0] = g_vfd_map.count(fd) ? 0 : static_cast<uint32_t>(fsync(fd));
    });
    RegisterThunk("fdatasync", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int fd = static_cast<int>(jit.Regs()[0]);
        std::lock_guard<std::mutex> lock(g_vfd_mutex);
        jit.Regs()[0] = g_vfd_map.count(fd) ? 0 : static_cast<uint32_t>(fdatasync(fd));
    });

    // gethostname()/sysinfo() are NSS's entropy gathering (RNG_SystemInfoForRNG). Returning
    // "success" with the buffer untouched fed it uninitialised guest stack -- harmless for an
    // offline build, but indistinguishable in the log from a thunk that works.
    RegisterThunk("gethostname", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        char name[256] = {0};
        int res = gethostname(name, sizeof(name) - 1);
        const uint32_t len = static_cast<uint32_t>(jit.Regs()[1]);
        if (res == 0 && len) {
            uint8_t* b = host.GetGuestMemoryBase() + jit.Regs()[0];
            const size_t n = std::min<size_t>(strlen(name), len - 1);
            memcpy(b, name, n);
            b[n] = 0;
        }
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    // struct sysinfo is all `long`, so the guest's is 64 bytes against the host's 112 -- the
    // same class of mismatch as struct stat (5.3c). Fields are copied one by one, and mem_unit
    // is doubled until every byte count fits in 32 bits, which is exactly what the kernel does
    // for 32-bit callers on a large-memory machine.
    RegisterThunk("sysinfo", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        struct sysinfo si;
        int res = sysinfo(&si);
        if (res != 0) { jit.Regs()[0] = static_cast<uint32_t>(res); return; }

        uint64_t unit = si.mem_unit ? si.mem_unit : 1;
        uint64_t mem[7] = {si.totalram, si.freeram, si.sharedram, si.bufferram,
                           si.totalswap, si.freeswap, si.totalhigh};
        uint64_t high_free = si.freehigh;
        auto too_big = [&] {
            for (uint64_t v : mem) if (v > 0xFFFFFFFFull) return true;
            return high_free > 0xFFFFFFFFull;
        };
        while (too_big()) {
            for (uint64_t& v : mem) v >>= 1;
            high_free >>= 1;
            unit <<= 1;
        }

        const uint32_t g = jit.Regs()[0];
        uint8_t* b = host.GetGuestMemoryBase() + g;
        memset(b, 0, 64);
        auto put = [&](int off, uint32_t v) { memcpy(b + off, &v, 4); };
        put(0, static_cast<uint32_t>(si.uptime));
        for (int i = 0; i < 3; ++i) put(4 + 4 * i, static_cast<uint32_t>(si.loads[i]));
        for (int i = 0; i < 6; ++i) put(16 + 4 * i, static_cast<uint32_t>(mem[i]));
        const uint16_t procs = si.procs;
        memcpy(b + 40, &procs, 2);
        put(44, static_cast<uint32_t>(mem[6]));            // totalhigh
        put(48, static_cast<uint32_t>(high_free));         // freehigh
        put(52, static_cast<uint32_t>(unit));              // mem_unit
        jit.Regs()[0] = 0;
    });

    // Profiler hooks around a blocking call; a no-op is what they are, not what we settled for.
    RegisterThunk("__google_potentially_blocking_region_begin", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    RegisterThunk("__google_potentially_blocking_region_end", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});

    RegisterThunk("inet_pton", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int af = static_cast<int>(jit.Regs()[0]);
        const char* src = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        uint8_t tmp[16] = {0};
        int res = src ? inet_pton(af, src, tmp) : 0;
        if (res == 1 && jit.Regs()[2]) {
            memcpy(host.GetGuestMemoryBase() + jit.Regs()[2], tmp, af == AF_INET6 ? 16 : 4);
        }
        jit.Regs()[0] = static_cast<uint32_t>(res);
    });

    RegisterThunk("inet_ntop", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const int af = static_cast<int>(jit.Regs()[0]);
        const void* src = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]);
        const uint32_t dst = jit.Regs()[2];
        const uint32_t size = jit.Regs()[3];
        char buf[INET6_ADDRSTRLEN] = {0};
        const char* res = (src && inet_ntop(af, src, buf, sizeof(buf))) ? buf : nullptr;
        if (res && size > strlen(buf)) {
            memcpy(host.GetGuestMemoryBase() + dst, buf, strlen(buf) + 1);
            jit.Regs()[0] = dst;
        } else {
            errno = ENOSPC;
            jit.Regs()[0] = 0;
        }
    });

    // sigaction(): the handlers belong to google_breakpad (SIGSEGV/SIGABRT) and NSPR
    // (SIGPIPE), and a guest handler cannot run on a host signal anyway -- installing one for
    // real would only take crash reporting away from the host. So nothing is installed, but
    // the old-action out-parameter is zeroed instead of left as garbage: the guest saves it
    // and restores it later, and restoring garbage is how a stub turns into a jump to nowhere.
    // Guest struct sigaction (bionic arm32): +0 sa_flags, +4 handler, +8 sa_mask, +12 restorer.
    RegisterThunk("sigaction", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t oldact = jit.Regs()[2];
        if (oldact) memset(host.GetGuestMemoryBase() + oldact, 0, 16);
        static int reported = 0;
        if (reported++ < 8) LOGI("sigaction(sig=%d) ignored (guest handlers cannot run on host signals)",
                                 jit.Regs()[0]);
        jit.Regs()[0] = 0;
    });

    // getenv(): NULL is the honest answer for every name NSPR asks about on Android, but the
    // default stub gave the same answer for reasons it could not know. The guest keeps the
    // pointer, so the value needs a guest-side copy with the lifetime of the process.
    RegisterThunk("getenv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static std::unordered_map<std::string, uint32_t> cache;
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        if (!name) { jit.Regs()[0] = 0; return; }
        auto it = cache.find(name);
        if (it != cache.end()) { jit.Regs()[0] = it->second; return; }
        const char* val = getenv(name);
        uint32_t g = 0;
        if (val) {
            const size_t n = strlen(val) + 1;
            g = host.GuestAlloc(static_cast<uint32_t>(n), 8);   // never freed, like the rest of environ
            if (g) memcpy(host.GetGuestMemoryBase() + g, val, n);
        }
        cache[name] = g;
        jit.Regs()[0] = g;
    });

    // Asset override: see InstallAssetOverrideHook below. R1 is the archive-relative entry
    // name; returning ip=0 makes the trampoline return NULL so FileInterfaceAndroid::OpenRead
    // falls through to its plain fopen(rootDir + path) branch.
    RegisterThunk("gof2_zip_fopen_hook", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static uint32_t s_real = 0;
        if (!s_real) s_real = host.GetElfLoader().GetSymbolAddress("zip_fopen");
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        jit.Regs()[12] = HasAssetOverride(name) ? 0u : s_real;
    });
}

// ---------------------------------------------------------------------------
// Loading modified assets from <externalFilesDir>/...
//
// FileInterfaceAndroid::OpenRead() tries zip_fopen() on the APK and on the optional expansion
// zip first, and only falls back to fopen(appRootDir + path) when both miss. Making zip_fopen
// report "not found" for any file the user dropped into the external files dir therefore turns
// that fallback into a full override mechanism without touching the engine's file logic.
// ---------------------------------------------------------------------------

static std::string g_override_root;   // e.g. /sdcard/Android/data/<pkg>/files/
static bool g_override_enabled = false;

void SetAssetOverrideRoot(const std::string& root) {
    g_override_root = root;
    if (!g_override_root.empty() && g_override_root.back() != '/') g_override_root += '/';
    struct stat st;
    g_override_enabled = !g_override_root.empty() &&
                         stat(g_override_root.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
    LOGI("Asset override root: '%s' (%s)", g_override_root.c_str(), g_override_enabled ? "active" : "inactive");
}

bool HasAssetOverride(const char* entry_name) {
    if (!g_override_enabled || !entry_name) return false;
    // Entry names look like "assets/data/textures/x.aei" or
    // "47947_GOF2CONTENT_ETC/assets/data/textures/x.aei".
    const char* rel = strstr(entry_name, "assets/");
    if (!rel) return false;
    rel += 7;
    if (!*rel) return false;
    std::string path = g_override_root + rel;
    if (access(path.c_str(), R_OK) != 0) return false;
    LOGI("Asset override: '%s' -> '%s'", entry_name, path.c_str());
    return true;
}

void InstallAssetOverrideHook(DynarmicHost& host) {
    if (!g_override_enabled) return;

    const uint32_t kZipFopenPlt = 0x4005ef80;  // PLT slot for zip_fopen inside libgof2hdaa.so
    static bool s_installed = false;
    if (s_installed) return;

    uint32_t hook = host.GetThunkManager().GetOrCreateThunkAddress("gof2_zip_fopen_hook");
    uint32_t svc = host.MemoryRead32(hook);
    if ((svc & 0xFF000000) != 0xEF000000) {
        LOGE("InstallAssetOverrideHook: unexpected trampoline at 0x%08X", hook);
        return;
    }

    // ARM veneer: run the hook, then either tail-call the real zip_fopen (ip != 0)
    // or return NULL.
    uint32_t veneer = host.GuestAlloc(32, 4);
    host.MemoryWrite32(veneer + 0,  svc);         // svc  #id
    host.MemoryWrite32(veneer + 4,  0xE35C0000);  // cmp  ip, #0
    host.MemoryWrite32(veneer + 8,  0x112FFF1C);  // bxne ip
    host.MemoryWrite32(veneer + 12, 0xE3A00000);  // mov  r0, #0
    host.MemoryWrite32(veneer + 16, 0xE12FFF1E);  // bx   lr
    host.InvalidateGuestCode(veneer, 32);

    host.MemoryWrite32(kZipFopenPlt + 0, 0xE51FF004);  // ldr pc, [pc, #-4]
    host.MemoryWrite32(kZipFopenPlt + 4, veneer);
    host.InvalidateGuestCode(kZipFopenPlt, 12);

    s_installed = true;
    LOGI("Installed zip_fopen asset-override hook (veneer 0x%08X)", veneer);
}
