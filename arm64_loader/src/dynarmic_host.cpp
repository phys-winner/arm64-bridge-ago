#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"
#include "extra_settings.h"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <android/log.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <unistd.h>
#endif

#define LOG_TAG "GOF2_ARM64_Loader"
#include "bridge_log.h"

#define EXIT_TRAP_ARM   0x00000004
#define EXIT_TRAP_THUMB 0x00000008

DynarmicHost::DynarmicHost() = default;

DynarmicHost::~DynarmicHost() {
    if (m_memory) {
#if defined(_WIN32)
        VirtualFree(m_memory, 0, MEM_RELEASE);
#else
        munmap(m_memory, m_memory_size);
#endif
        m_memory = nullptr;
    }
}

// Reserve guest memory. MAP_NORESERVE keeps the 4 GiB reservation virtual: untouched pages
// cost nothing and only written pages are ever committed.
static uint8_t* MapGuestMemory(size_t size) {
#if defined(_WIN32)
    return reinterpret_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
#else
    void* p = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    return p == MAP_FAILED ? nullptr : reinterpret_cast<uint8_t*>(p);
#endif
}

// The kernel's kuser helper page. On a real ARM32 Linux the kernel maps one page at
// 0xFFFF0000 holding a handful of routines the C library branches to by absolute address;
// libSkynestSDK's static initialisers use __kuser_memory_barrier, which is why one of its 48
// initialisers used to break off with "[RUNAWAY] code fetch outside any mapped module:
// 0xFFFF0FA0". The whole 32-bit space is already reserved here, so the page is ordinary guest
// memory and the fix is to put the kernel's own code in it.
//
// Only what can be implemented honestly goes in. __kuser_get_tls stays a loud undefined
// instruction: there is no per-thread storage in this bridge, and a made-up pointer would turn
// a visible stop into silent corruption -- the same reason __kuser_cmpxchg mattered, since a
// compare-and-swap that answers wrong corrupts data with nothing in the log.
void DynarmicHost::InstallKuserHelperPage() {
    const auto put = [&](uint32_t addr, std::initializer_list<uint32_t> words) {
        uint32_t i = 0;
        for (uint32_t wrd : words)
            *reinterpret_cast<uint32_t*>(m_memory + addr + 4 * i++) = wrd;
    };
    // Every slot first: an unreachable-by-design gap must fault loudly, not run whatever the
    // page happened to hold.
    for (uint32_t a = kKuserPageStart; a < kKuserPageEnd; a += 4)
        *reinterpret_cast<uint32_t*>(m_memory + a) = 0xE7FEDEFFu;   // permanently undefined

    put(0xFFFF0FA0, {0xE12FFF1E});                  // __kuser_memory_barrier: BX LR
                                                    // one guest thread runs at a time, and the
                                                    // JIT already orders its own accesses
    put(0xFFFF0FC0, {0xE5923000,                    // __kuser_cmpxchg: LDR   R3, [R2]
                     0xE0533000,                    //                  SUBS  R3, R3, R0
                     0x05821000,                    //                  STREQ R1, [R2]
                     0xE2730000,                    //                  RSBS  R0, R3, #0
                     0xE12FFF1E});                  //                  BX    LR
                                                    // RSBS leaves r0 = 0 and C set exactly when
                                                    // the compare matched, which is the ABI.
    // __kuser_get_tls at 0xFFFF0FE0 deliberately left as the undefined word.
    *reinterpret_cast<uint32_t*>(m_memory + 0xFFFF0FFC) = 2;   // helper version: barrier + cmpxchg,
                                                              // no cmpxchg64 (that is version 5)
}

bool DynarmicHost::Initialize() {
    // Mapping the whole 32-bit space lets the JIT emit a single `ldr Wt, [Xfastmem, Waddr, uxtw]`
    // per guest access instead of a call into MemoryRead*/MemoryWrite*.
    m_memory_size = GUEST_ADDRESS_SPACE;
    m_memory = MapGuestMemory(m_memory_size);

    bool fastmem = m_memory != nullptr && GetExtraSettings().fastmem != 0;
    if (m_memory == nullptr) {
        LOGE("Could not reserve %zu bytes for the guest address space; "
             "falling back to %zu bytes without fastmem.", GUEST_ADDRESS_SPACE, GUEST_FALLBACK_SIZE);
        m_memory_size = GUEST_FALLBACK_SIZE;
        m_memory = MapGuestMemory(m_memory_size);
        if (!m_memory) {
            LOGE("Failed to allocate guest memory (%zu bytes)", m_memory_size);
            m_memory_size = 0;
            return false;
        }
    }

    // ARM exit trap at 0x00000004: SVC 0 (0xEF000000)
    *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_ARM) = 0xEF000000;

    // Thumb exit trap at 0x00000008: SVC 0 (0xDF00, 0xDF00)
    *reinterpret_cast<uint32_t*>(m_memory + EXIT_TRAP_THUMB) = 0xDF00DF00;

    InstallKuserHelperPage();

    m_thunk_manager = std::make_unique<ThunkManager>(*this);
    m_thunk_manager->RegisterAllThunks();

    // The JIT dereferences global_monitor unconditionally for LDREX/STREX, so it must exist.
    // Two slots, not one: m_jit_nested is a second processor as far as the monitor is
    // concerned, even though the two never run at the same time.
    m_monitor = std::make_unique<Dynarmic::ExclusiveMonitor>(2);

    Dynarmic::A32::UserConfig config;
    config.callbacks = this;
    config.global_monitor = m_monitor.get();
    config.arch_version = Dynarmic::A32::ArchVersion::v7;  // guest libs are ARMv7-A + NEON
    config.enable_cycle_counting = false;                  // no timing model; skips AddTicks emission
    config.always_little_endian = true;                    // guest never uses SETEND; drops CPSR.E handling
    config.define_unpredictable_behaviour = true;          // define rather than halt on odd encodings
    if (fastmem) {
        config.fastmem_pointer = reinterpret_cast<uintptr_t>(m_memory);
    }

    m_jit = std::make_unique<Dynarmic::A32::Jit>(config);
    config.processor_id = 1;
    m_jit_nested = std::make_unique<Dynarmic::A32::Jit>(config);
    m_active_jit = m_jit.get();
    StartWatchdog();
    GuestHeapSelfTest();
    LOGI("Dynarmic Host initialized: %zu bytes guest space, fastmem %s",
         m_memory_size, fastmem ? "ON" : "OFF");
    return true;
}

// A guest that spins forever is otherwise invisible: the calling thread never returns, so
// there is no crash, no ANR trace worth reading, and nothing at all in logcat. HaltExecution
// is the one Jit call that is safe from another thread, so the watchdog trips it and lets
// RunFunction print where the guest actually was.
void DynarmicHost::StartWatchdog() {
    if (m_watchdog_started.exchange(true)) return;
    std::thread([this] {
        uint64_t last = 0;
        int stalled = 0;
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            const uint64_t now = m_run_seq.load(std::memory_order_relaxed);
            if (m_is_running_jit && now == last) {
                if (++stalled >= 3) {   // ~6 s with no new RunFunction and still inside one
                    stalled = 0;
                    m_watchdog_tripped.store(true, std::memory_order_relaxed);
                    // HaltExecution is the only Jit call safe from another thread; hit both,
                    // because the wedge may be inside a nested run.
                    if (m_jit) m_jit->HaltExecution(Dynarmic::HaltReason::UserDefined2);
                    if (m_jit_nested) m_jit_nested->HaltExecution(Dynarmic::HaltReason::UserDefined2);
                }
            } else {
                stalled = 0;
            }
            last = now;
        }
    }).detach();
}

// A poor man's guest backtrace. ARM32 release builds have no frame pointer, so this scans the
// stack for words that both land inside a mapped module and are preceded by a BL/BLX -- i.e.
// they look like return addresses. It over-reports (stale slots survive in dead frames) but
// the true chain is in there in order, which is all that is needed to answer "who called
// this". Without it, a guest that reaches exit() or wedges names no code at all.
void DynarmicHost::DumpGuestBacktrace(const char* why, uint32_t sp, uint32_t lr) {
    LOGE("[BT] %s -- LR 0x%08X (%s) SP 0x%08X", why, lr, DescribeAddress(lr).c_str(), sp);
    int printed = 0;
    for (uint32_t a = sp; a + 4 <= sp + 0x600 && printed < 20; a += 4) {
        const uint32_t v = MemoryRead32(a);
        const uint32_t target = v & ~1u;
        if (target < 0x40000000 || !IsExecutableGuestAddress(target)) continue;
        const uint32_t prev = MemoryRead32(target - 4);
        const bool is_bl  = (prev & 0x0F000000u) == 0x0B000000u;   // BL <imm>
        const bool is_blx = (prev & 0x0FFFFFF0u) == 0x012FFF30u;   // BLX <reg>
        if (!is_bl && !is_blx) continue;
        LOGE("[BT]   #%-2d 0x%08X  %s", printed++, v, DescribeAddress(v).c_str());
    }
    if (printed == 0) LOGE("[BT]   (no return addresses recognised on the stack)");
}

// Which module a guest address belongs to, for the watchdog report.
std::string DynarmicHost::DescribeAddress(uint32_t addr) const {
    char buf[128];
    for (const auto& m : m_modules) {
        const uint32_t base = m.second->GetBaseAddress();
        if (addr >= base && addr < base + m.second->GetImageSize()) {
            std::snprintf(buf, sizeof(buf), "%s+0x%X", m.first.c_str(), addr - base);
            return buf;
        }
    }
    if (addr < kTrampolineEnd) {
        const uint32_t id = (addr - 0x00010000u) / 8u;
        const char* name = m_thunk_manager ? m_thunk_manager->GetThunkName(id) : "";
        std::snprintf(buf, sizeof(buf), "thunk %s (#%u)", name, id);
        return buf;
    }
    std::snprintf(buf, sizeof(buf), "unmapped 0x%08X", addr);
    return buf;
}

// Search order: guest modules as they were loaded, then the legacy FMOD slots (null for
// ABGo), then a host thunk trampoline.
uint32_t DynarmicHost::ResolveGuestSymbol(const std::string& name) {
    for (auto& m : m_modules) {
        uint32_t addr = m.second->GetSymbolAddress(name);
        if (addr != 0) return addr;
    }
    if (m_fmodevent_loader) {
        uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
        if (addr != 0) return addr;
    }
    if (m_fmodex_loader) {
        uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
        if (addr != 0) return addr;
    }
    if (m_elf_loader && m_modules.empty()) {
        uint32_t addr = m_elf_loader->GetSymbolAddress(name);
        if (addr != 0) return addr;
    }
    return m_thunk_manager->GetOrCreateThunkAddress(name);
}

ElfLoader* DynarmicHost::FindModule(const std::string& name) {
    for (auto& m : m_modules) {
        if (m.first == name) return m.second.get();
    }
    return nullptr;
}

bool DynarmicHost::LoadModulesFromMemory(const std::vector<GuestModuleImage>& images) {
    if (images.empty()) {
        LOGE("LoadModulesFromMemory called with no images");
        return false;
    }

    // Pass 1: map every object first, so relocation can see every other object's exports.
    for (const auto& img : images) {
        auto loader = std::make_unique<ElfLoader>(m_memory, m_next_module_base);
        LOGI("Mapping guest module '%s' (%zu bytes) at 0x%08X",
             img.name.c_str(), img.size, m_next_module_base);
        if (!loader->LoadFromMemory(img.data, img.size)) {
            LOGE("Failed to map guest module '%s'", img.name.c_str());
            return false;
        }
        const uint32_t image_size = loader->GetImageSize();
        // round up to 1 MB and leave a 1 MB guard so a bad reloc lands in nothing
        const uint32_t step = ((image_size + 0xFFFFFu) & ~0xFFFFFu) + 0x100000u;
        LOGI("  '%s' image=%u bytes, next base 0x%08X", img.name.c_str(), image_size,
             m_next_module_base + step);
        m_next_module_base += step;
        m_modules.emplace_back(img.name, std::move(loader));
    }

    // The last module is the game; keep the legacy accessors pointing at it.
    m_elf_loader.reset();
    ElfLoader* main_module = m_modules.back().second.get();

    // Pass 2: relocate in load order.
    auto resolver = [this](const std::string& name) -> uint32_t {
        return ResolveGuestSymbol(name);
    };
    for (auto& m : m_modules) {
        LOGI("Relocating '%s'...", m.first.c_str());
        if (!m.second->Relocate(resolver)) {
            LOGE("Failed to relocate guest module '%s'", m.first.c_str());
            return false;
        }
    }

    // Pass 3: static initialisers, again in load order.
    for (auto& m : m_modules) {
        const auto& init = m.second->GetInitArray();
        LOGI("Running %zu initialisers for '%s'...", init.size(), m.first.c_str());
        for (uint32_t fn : init) {
            RunFunction(fn);
        }
        LOGI("  '%s' initialised", m.first.c_str());
    }

    LOGI("All %zu guest modules loaded; main module base 0x%08X",
         m_modules.size(), main_module->GetBaseAddress());
    return true;
}

bool DynarmicHost::LoadGame(const std::string& elf_path) {
    LOGI("Loading main game ELF from file: %s", elf_path.c_str());
    m_elf_loader = std::make_unique<ElfLoader>(m_memory, 0x40000000);
    if (!m_elf_loader->Load(elf_path)) {
        LOGE("Failed to load ELF: %s", elf_path.c_str());
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate ELF.");
        return false;
    }

    LOGI("Running %zu static initializers in .init_array...", m_elf_loader->GetInitArray().size());
    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Game ELF loaded and initialized successfully!");
    return true;
}

bool DynarmicHost::LoadGameFromMemory(const uint8_t* data, size_t size) {
    LOGI("Loading main game ELF from memory (%zu bytes)...", size);
    m_elf_loader = std::make_unique<ElfLoader>(m_memory, 0x40000000);
    if (!m_elf_loader->LoadFromMemory(data, size)) {
        LOGE("Failed to load ELF from memory buffer");
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate ELF.");
        return false;
    }

    LOGI("Running %zu static initializers in .init_array...", m_elf_loader->GetInitArray().size());
    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Game ELF loaded from memory and initialized successfully!");
    return true;
}

bool DynarmicHost::LoadLibraries(const std::string& fmodex_path, const std::string& fmodevent_path, const std::string& game_path) {
    LOGI("Loading libraries: fmodex='%s', fmodevent='%s', game='%s'", fmodex_path.c_str(), fmodevent_path.c_str(), game_path.c_str());

    m_fmodex_loader = std::make_unique<ElfLoader>(m_memory, 0x40400000);
    if (!m_fmodex_loader->Load(fmodex_path)) {
        LOGE("Failed to load libfmodex.so from %s", fmodex_path.c_str());
        return false;
    }

    m_fmodevent_loader = std::make_unique<ElfLoader>(m_memory, 0x40600000);
    if (!m_fmodevent_loader->Load(fmodevent_path)) {
        LOGE("Failed to load libfmodevent.so from %s", fmodevent_path.c_str());
        return false;
    }

    m_elf_loader = std::make_unique<ElfLoader>(m_memory, 0x40000000);
    if (!m_elf_loader->Load(game_path)) {
        LOGE("Failed to load libgof2hdaa.so from %s", game_path.c_str());
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_fmodex_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodex.so");
        return false;
    }

    if (!m_fmodevent_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodevent.so");
        return false;
    }

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libgof2hdaa.so");
        return false;
    }

    LOGI("Running initializers for libfmodex.so (%zu funcs)...", m_fmodex_loader->GetInitArray().size());
    for (uint32_t init_func : m_fmodex_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Running initializers for libfmodevent.so (%zu funcs)...", m_fmodevent_loader->GetInitArray().size());
    for (uint32_t init_func : m_fmodevent_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Running initializers for libgof2hdaa.so (%zu funcs)...", m_elf_loader->GetInitArray().size());
    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("All libraries loaded, relocated, and initialized successfully with sound!");
    return true;
}

bool DynarmicHost::LoadLibrariesFromMemory(const uint8_t* fmodex_data, size_t fmodex_size,
                                           const uint8_t* fmodevent_data, size_t fmodevent_size,
                                           const uint8_t* game_data, size_t game_size) {
    LOGI("Loading libraries from memory: fmodex=%zu bytes, fmodevent=%zu bytes, game=%zu bytes",
         fmodex_size, fmodevent_size, game_size);

    m_fmodex_loader = std::make_unique<ElfLoader>(m_memory, 0x40400000);
    if (!m_fmodex_loader->LoadFromMemory(fmodex_data, fmodex_size)) {
        LOGE("Failed to load libfmodex.so from memory");
        return false;
    }

    m_fmodevent_loader = std::make_unique<ElfLoader>(m_memory, 0x40600000);
    if (!m_fmodevent_loader->LoadFromMemory(fmodevent_data, fmodevent_size)) {
        LOGE("Failed to load libfmodevent.so from memory");
        return false;
    }

    m_elf_loader = std::make_unique<ElfLoader>(m_memory, 0x40000000);
    if (!m_elf_loader->LoadFromMemory(game_data, game_size)) {
        LOGE("Failed to load libgof2hdaa.so from memory");
        return false;
    }

    auto resolver = [this](const std::string& name) -> uint32_t {
        if (m_fmodevent_loader) {
            uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_fmodex_loader) {
            uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        if (m_elf_loader) {
            uint32_t addr = m_elf_loader->GetSymbolAddress(name);
            if (addr != 0) return addr;
        }
        return m_thunk_manager->GetOrCreateThunkAddress(name);
    };

    if (!m_fmodex_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodex.so");
        return false;
    }

    if (!m_fmodevent_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libfmodevent.so");
        return false;
    }

    if (!m_elf_loader->Relocate(resolver)) {
        LOGE("Failed to relocate libgof2hdaa.so");
        return false;
    }

    LOGI("Running initializers for libfmodex.so (%zu funcs)...", m_fmodex_loader->GetInitArray().size());
    for (uint32_t init_func : m_fmodex_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Running initializers for libfmodevent.so (%zu funcs)...", m_fmodevent_loader->GetInitArray().size());
    for (uint32_t init_func : m_fmodevent_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("Running initializers for libgof2hdaa.so (%zu funcs)...", m_elf_loader->GetInitArray().size());
    for (uint32_t init_func : m_elf_loader->GetInitArray()) {
        RunFunction(init_func);
    }

    LOGI("All libraries loaded from memory and initialized successfully with sound!");
    return true;
}

// bionic packs a held mutex as counter bits [13:0], a "locked with waiters" flag in bit 14,
// and the owner TID in bits [30:16]. Reading the first word of the native handle names the
// owner of a stuck lock, which is otherwise invisible: no stack shows a thread that exited,
// and no stack shows a thread waiting politely. A state of unlocked-with-waiters-flag set
// (0x4000, owner 0) is a lost wakeup: sleepers will never wake on their own, but a futex
// wake on the same word is always safe (spurious wakeups are legal) and unsticks them.
void DynarmicHost::LogMutexOwner(const char* why) {
    const pthread_mutex_t* m = m_mutex.native_handle();
    const int state = *reinterpret_cast<const int*>(m);
    const int owner = (state >> 16) & 0x3FFF;
    const int counter = state & 0x3FFF;
    LOGE("[MUTEX] %s: state=0x%08X owner_tid=%d counter=%d waiters_flag=%d", why, state,
         owner, counter, (state & 0x4000) ? 1 : 0);
    if (owner > 0) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/task/%d", owner);
        FILE* f = fopen(path, "rb");
        if (f) {
            fclose(f);
            LOGE("[MUTEX] owner %d still exists -- see its stack in a debuggerd dump", owner);
        } else {
            LOGE("[MUTEX] owner %d is GONE -- the lock leaked with a dead thread", owner);
        }
    }
}

bool DynarmicHost::RecoverStalledMutex(const char* why) {
    pthread_mutex_t* m = m_mutex.native_handle();
    const int state = *reinterpret_cast<volatile int*>(m);
    const int owner = (state >> 16) & 0x3FFF;
    const int counter = state & 0x3FFF;
    if (owner != 0 || counter != 0 || !(state & 0x4000)) {
        LogMutexOwner(why);
        return false;
    }
    LOGE("[MUTEX] %s: unlocked with sleeping waiters (state=0x%08X) -- issuing futex wake",
         why, state);
    // The first word of the bionic mutex object IS the futex word. Waking sleepers on an
    // unlocked mutex is legal: they re-check the state and one of them takes the lock.
    auto* futex_word = reinterpret_cast<int32_t*>(const_cast<pthread_mutex_t*>(m));
    syscall(SYS_futex, futex_word, FUTEX_WAKE, 0x7FFFFFFF, nullptr, nullptr, 0);
    return true;
}

void DynarmicHost::HaltCurrentCall() {
    if (m_jit) m_jit->HaltExecution(Dynarmic::HaltReason::UserDefined2);
    if (m_jit_nested) m_jit_nested->HaltExecution(Dynarmic::HaltReason::UserDefined2);
}

uint32_t DynarmicHost::FindSymbol(const std::string& name) {
    for (auto& m : m_modules) {
        uint32_t addr = m.second->GetSymbolAddress(name);
        if (addr) return addr;
    }
    if (m_elf_loader) {
        uint32_t addr = m_elf_loader->GetSymbolAddress(name);
        if (addr) return addr;
    }
    if (m_fmodevent_loader) {
        uint32_t addr = m_fmodevent_loader->GetSymbolAddress(name);
        if (addr) return addr;
    }
    if (m_fmodex_loader) {
        uint32_t addr = m_fmodex_loader->GetSymbolAddress(name);
        if (addr) return addr;
    }
    return 0;
}

uint32_t DynarmicHost::RunFunction(uint32_t target_pc, const std::vector<uint32_t>& args) {
    if (!m_jit) return 0;
    TraceEvent("RUN", target_pc, m_is_running_jit ? 1u : 0u);
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    TraceEvent("RUN_LOCKED", target_pc, 0);

    if (m_is_running_jit) {
        // Jit::Run is not re-entrant (a32_interface.cpp asserts on it), so a call made from
        // inside a thunk cannot run now. Queue it for the next DrainDeferred instead of
        // dropping it -- this is what used to make IAP credit grants do nothing.
        m_deferred.emplace_back(target_pc, args);
        TraceEvent("RUN_DEFERRED", target_pc, 0);
        return 0;
    }

    m_is_running_jit = true;
    m_run_seq.fetch_add(1, std::memory_order_relaxed);
    struct JitRunningGuard {
        bool& flag;
        ~JitRunningGuard() { flag = false; }
    } running_guard{m_is_running_jit};

    // Reset CPU registers for call
    for (size_t i = 0; i < args.size() && i < 4; ++i) {
        m_jit->Regs()[i] = args[i];
    }

    // Stack pointer
    m_jit->Regs()[13] = m_stack_top;

    // If more than 4 arguments, push onto guest stack
    if (args.size() > 4) {
        size_t extra_args = args.size() - 4;
        // AAPCS requires SP to be 8-byte aligned at a public interface. An odd number of
        // stacked words would leave it 4-aligned, and then a jlong the caller placed on an
        // even argument slot would land 4-aligned too -- LDRD/VLDR territory.
        uint32_t sp = (m_stack_top - static_cast<uint32_t>(extra_args * 4)) & ~7u;
        m_jit->Regs()[13] = sp;
        for (size_t i = 0; i < extra_args; ++i) {
            *reinterpret_cast<uint32_t*>(m_memory + sp + i * 4) = args[4 + i];
        }
    }

    // Return address -> exit trap (with Thumb bit if target is Thumb)
    bool is_thumb = (target_pc & 1) != 0;
    m_jit->Regs()[14] = is_thumb ? (EXIT_TRAP_THUMB | 1) : EXIT_TRAP_ARM;

    // Set PC
    m_jit->Regs()[15] = target_pc & ~1u;
    m_jit->SetCpsr((m_jit->Cpsr() & ~0x20u) | (is_thumb ? 0x20u : 0u));

    m_jit->ClearHalt();
    Dynarmic::HaltReason hr = m_jit->Run();

    // Woken by the watchdog rather than by the exit trap: report and give up on this call
    // instead of resuming, so the boot sequence keeps going and the log names the offender.
    if (m_watchdog_tripped.exchange(false)) {
        const uint32_t pc = m_jit->Regs()[15];
        LOGE("[WATCHDOG] guest wedged: entry 0x%08X (%s)", target_pc, DescribeAddress(target_pc).c_str());
        LOGE("[WATCHDOG]   PC=0x%08X (%s) LR=0x%08X SP=0x%08X",
             pc, DescribeAddress(pc).c_str(), m_jit->Regs()[14], m_jit->Regs()[13]);
        LOGE("[WATCHDOG]   r0=%08X r1=%08X r2=%08X r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X",
             m_jit->Regs()[0], m_jit->Regs()[1], m_jit->Regs()[2], m_jit->Regs()[3],
             m_jit->Regs()[4], m_jit->Regs()[5], m_jit->Regs()[6], m_jit->Regs()[7]);
        DumpGuestBacktrace("watchdog", m_jit->Regs()[13], m_jit->Regs()[14]);
        m_jit->ClearHalt();
        TraceEvent("RUN_WDG_BAIL", target_pc, 0);
        return 0;
    }

    uint32_t final_pc = m_jit->Regs()[15];
    if (final_pc != EXIT_TRAP_ARM && final_pc != (EXIT_TRAP_ARM + 4) &&
        final_pc != (EXIT_TRAP_THUMB & ~1u) && final_pc != ((EXIT_TRAP_THUMB & ~1u) + 2)) {
        LOGI("RunFunction(0x%08X) unexpected halt with reason=0x%X, PC=0x%08X, LR=0x%08X, R0=0x%08X, SP=0x%08X",
             target_pc, static_cast<unsigned>(hr), final_pc, m_jit->Regs()[14], m_jit->Regs()[0], m_jit->Regs()[13]);
    }

    TraceEvent("RUN_DONE", target_pc, m_jit->Regs()[0]);
    return m_jit->Regs()[0];
}

// Guest code called from *inside* a thunk, with its result available before the thunk returns.
//
// Dynarmic::A32::Jit::Run is not re-entrant on one instance, which is why RunFunction queues
// such calls for DrainDeferred instead. Deferring is right for fire-and-forget callbacks and
// useless when the thunk needs the answer now: qsort() cannot sort without asking the guest
// comparator, and the silent no-op it had instead left CXGSTextureAtlas's tile array in file
// order. CXGSTextureAtlas::GetTilePosition binary-searches that array, so every sprite name
// missed, every texture descriptor got tile 0xFFFF, and CTextureAtlasManager::GetHeight
// eventually tripped its own bounds check (UDF at libABK+0x2AF7D0) during CApp::Init.
//
// A second Jit over the same callbacks, the same memory and its own stack fixes it. The
// nesting is strictly single-threaded -- the outer Run is stopped in a thunk while this one
// executes -- so there is no race to guard against, only re-entrancy, and a separate instance
// is exactly that.
uint32_t DynarmicHost::RunFunctionNested(uint32_t target_pc, const std::vector<uint32_t>& args) {
    if (!m_jit_nested || !target_pc) return 0;
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (m_nested_depth >= 1) {
        // One level is all the guest needs. Going deeper would need a Jit per level, and a
        // comparator that calls back into a thunk that sorts is not a real case.
        static int reported = 0;
        if (reported++ < 4) LOGE("RunFunctionNested: refusing to nest twice (pc 0x%08X)", target_pc);
        return 0;
    }

    Dynarmic::A32::Jit* const outer = m_active_jit;
    m_active_jit = m_jit_nested.get();
    ++m_nested_depth;
    // Counts as progress, or a long sort looks to the watchdog like a wedged guest.
    m_run_seq.fetch_add(1, std::memory_order_relaxed);

    Dynarmic::A32::Jit& jit = *m_jit_nested;
    for (size_t i = 0; i < args.size() && i < 4; ++i) jit.Regs()[i] = args[i];

    uint32_t sp = m_nested_stack_top;
    if (args.size() > 4) {
        const size_t extra = args.size() - 4;
        sp = (sp - static_cast<uint32_t>(extra * 4)) & ~7u;   // AAPCS: 8-byte aligned
        for (size_t i = 0; i < extra; ++i) {
            *reinterpret_cast<uint32_t*>(m_memory + sp + i * 4) = args[4 + i];
        }
    }
    jit.Regs()[13] = sp;

    const bool is_thumb = (target_pc & 1) != 0;
    jit.Regs()[14] = is_thumb ? (EXIT_TRAP_THUMB | 1) : EXIT_TRAP_ARM;
    jit.Regs()[15] = target_pc & ~1u;
    jit.SetCpsr((jit.Cpsr() & ~0x20u) | (is_thumb ? 0x20u : 0u));
    jit.ClearHalt();
    jit.Run();

    const uint32_t final_pc = jit.Regs()[15];
    if (final_pc != EXIT_TRAP_ARM && final_pc != (EXIT_TRAP_ARM + 4) &&
        final_pc != (EXIT_TRAP_THUMB & ~1u) && final_pc != ((EXIT_TRAP_THUMB & ~1u) + 2)) {
        static int reported = 0;
        if (reported++ < 8) {
            LOGE("RunFunctionNested(0x%08X %s) halted at 0x%08X (%s)", target_pc,
                 DescribeAddress(target_pc).c_str(), final_pc, DescribeAddress(final_pc).c_str());
        }
    }

    const uint32_t result = jit.Regs()[0];
    --m_nested_depth;
    m_active_jit = outer;
    return result;
}

void DynarmicHost::InvalidateGuestCode(uint32_t addr, size_t size) {
    if (m_jit) m_jit->InvalidateCacheRange(addr, size);
}

void DynarmicHost::DrainDeferred() {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (m_is_running_jit || m_deferred.empty()) return;
    auto batch = std::move(m_deferred);
    m_deferred.clear();
    for (auto& call : batch) {
        LOGI("Running deferred call to 0x%08X", call.first);
        RunFunction(call.first, call.second);
    }
}

// The guest heap.
//
// malloc/calloc/realloc/memalign all land here and free() used to be a no-op, which was fine
// while the boot died early: the arena is 736 MB and nothing reached the point of churning it.
// Once the boot got as far as CApp::MainLoadingFunc it exhausted the whole thing in about four
// seconds of asset loading -- "GuestAlloc out of guest heap" repeating until every allocation
// returned 0.
//
// Best-fit free list with coalescing, and the metadata kept on the host side rather than in
// headers inside the arena: the guest cannot corrupt it by overrunning a block, and blocks
// handed to the guest are exactly the bytes it asked for. Two maps, because both directions
// are needed -- by size to find a fit in O(log n), by address to merge with neighbours.
//
// Alignment above 8 bypasses the free list and takes fresh arena. The only caller that asks
// for more is the mmap thunk mapping a whole expansion file, which happens twice per run.
static constexpr uint32_t kGuestHeapBase  = 0x50000000;
static constexpr uint32_t kGuestHeapLimit = 0x7E000000;
static constexpr uint32_t kGuestHeapSplitMin = 32;   // do not leave slivers behind

void DynarmicHost::HeapInsertFree(uint32_t addr, uint32_t size) {
    if (!size) return;
    // Merge with the block that ends where this one starts, and the one that starts where it
    // ends. Without this the free list degrades into unusable dust.
    auto next = m_heap_free_by_addr.lower_bound(addr);
    if (next != m_heap_free_by_addr.end() && next->first == addr + size) {
        const uint32_t na = next->first, ns = next->second;   // copies: erase invalidates next
        HeapEraseFree(na, ns);
        size += ns;
    }
    auto prev = m_heap_free_by_addr.lower_bound(addr);
    if (prev != m_heap_free_by_addr.begin()) {
        --prev;
        const uint32_t pa = prev->first, ps = prev->second;
        if (pa + ps == addr) {
            HeapEraseFree(pa, ps);
            addr = pa;
            size += ps;
        }
    }
    m_heap_free_by_addr[addr] = size;
    m_heap_free_by_size[size].insert(addr);
}

void DynarmicHost::HeapEraseFree(uint32_t addr, uint32_t size) {
    m_heap_free_by_addr.erase(addr);
    auto it = m_heap_free_by_size.find(size);
    if (it == m_heap_free_by_size.end()) return;
    it->second.erase(addr);
    if (it->second.empty()) m_heap_free_by_size.erase(it);
}

uint32_t DynarmicHost::GuestAlloc(size_t size, size_t alignment) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    ++m_alloc_calls;
    if (size == 0) size = 1;
    // Every block start stays 8-aligned, so an alignment of 8 or less is free and anything
    // larger only needs the block to be (align - 8) bytes longer than the request.
    uint32_t align = static_cast<uint32_t>(alignment);
    if (align < 8 || (align & (align - 1))) align = 8;      // memalign wants a power of two
    const uint32_t need = static_cast<uint32_t>((size + 7) & ~size_t{7});
    if (align > 8) ++m_alloc_bigalign;

    // The free list, for aligned requests as well. Sending those straight to the frontier is
    // what ate the arena: 82% of the engine's allocations come through memalign, so 440 MB of
    // freed space sat unused while the bump pointer ran to the end and every later allocation
    // failed -- which surfaced as garbage globals and a wedge in CXGSFontBuffer2D, nowhere
    // near the allocator. Ask for the worst case so the search stays a plain best-fit lookup.
    const uint32_t want = need + (align - 8);
    auto bucket = m_heap_free_by_size.lower_bound(want);
    // Skip past any bucket that has been emptied: one of those sitting at the smallest key
    // >= want would otherwise abandon the whole free list.
    while (bucket != m_heap_free_by_size.end() && bucket->second.empty())
        bucket = m_heap_free_by_size.erase(bucket);
    if (bucket != m_heap_free_by_size.end()) {
        const uint32_t bsize = bucket->first;
        const uint32_t base = *bucket->second.begin();
        HeapEraseFree(base, bsize);
        const uint32_t addr = (base + align - 1) & ~(align - 1);
        if (addr > base) HeapInsertFree(base, addr - base);   // head padding back to the pool
        const uint32_t rest = bsize - (addr - base);          // >= need, by choice of `want`
        uint32_t taken = need;
        if (rest - need >= kGuestHeapSplitMin) {
            HeapInsertFree(addr + need, rest - need);
        } else {
            taken = rest;                // remainder too small to be useful; keep it
        }
        m_heap_used[addr] = taken;
        ++m_alloc_reuse;
        return addr;
    }
    ++m_alloc_nofit;
    ++m_alloc_bump;

    const uint32_t aligned = (m_heap_current + align - 1) & ~(align - 1);
    if (static_cast<uint64_t>(aligned) + need > kGuestHeapLimit) {
        ++m_alloc_fails;
        ReportHeapExhaustion(need);
        return 0;
    }
    if (aligned > m_heap_current) HeapInsertFree(m_heap_current, aligned - m_heap_current);
    m_heap_current = aligned + need;
    m_heap_used[aligned] = need;
    return aligned;
}

void DynarmicHost::GuestFree(uint32_t addr) {
    if (!addr) return;
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    ++m_free_calls;
    auto it = m_heap_used.find(addr);
    if (it == m_heap_used.end()) { ++m_free_misses; return; }   // not ours: ignore
    const uint32_t size = it->second;
    m_heap_used.erase(it);
    HeapInsertFree(addr, size);
}

// Whole-file mappings: their own bump region above both guest stacks, so a 345 MB OBB does
// not permanently occupy half the malloc heap. Never reclaimed -- see the mmap thunk, which
// reuses an existing mapping of the same file region instead of making a second one.
uint32_t DynarmicHost::GuestAllocMapping(size_t size, size_t alignment) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    constexpr uint32_t kMapLimit = 0xF0000000;
    const uint32_t aligned = (m_map_current + static_cast<uint32_t>(alignment - 1)) &
                             ~static_cast<uint32_t>(alignment - 1);
    if (static_cast<uint64_t>(aligned) + size > kMapLimit) {
        LOGE("GuestAllocMapping out of mapping space: at 0x%08X, want %zu", aligned, size);
        return 0;
    }
    m_map_current = aligned + static_cast<uint32_t>(size);
    return aligned;
}

// Says whether the heap is leaking, fragmented, or simply too small -- three very different
// problems that all look like "allocation returned 0".
void DynarmicHost::ReportHeapExhaustion(uint32_t want) {
    static int reported = 0;
    if (reported++ >= 3) return;
    uint64_t free_bytes = 0;
    uint32_t largest = 0;
    for (const auto& b : m_heap_free_by_addr) {
        free_bytes += b.second;
        if (b.second > largest) largest = b.second;
    }
    uint64_t used_bytes = 0;
    for (const auto& b : m_heap_used) used_bytes += b.second;
    LOGE("GuestAlloc out of guest heap: want %u, frontier 0x%08X, limit 0x%08X", want,
         m_heap_current, kGuestHeapLimit);
    LOGE("  live %zu blocks / %llu MB, free %zu blocks / %llu MB, largest free %u KB",
         m_heap_used.size(), static_cast<unsigned long long>(used_bytes >> 20),
         m_heap_free_by_addr.size(), static_cast<unsigned long long>(free_bytes >> 20),
         largest >> 10);
}

uint32_t DynarmicHost::GuestAllocSize(uint32_t addr) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    auto it = m_heap_used.find(addr);
    return it == m_heap_used.end() ? 0 : it->second;
}

// The arena filled up while the frontend just sat there, and "GuestAlloc out of guest heap"
// alone cannot say why: a leak, fragmentation, and the two free maps disagreeing all look the
// same from the call site. The exhaustion report said 440 MB free with a 69 MB block in it and
// a 2592-byte request still failed, which is only possible if m_heap_free_by_size has lost
// entries that m_heap_free_by_addr still holds -- so count that directly.
void DynarmicHost::LogHeapStats(const char* why) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    uint64_t used_bytes = 0, free_bytes = 0;
    for (const auto& b : m_heap_used) used_bytes += b.second;
    uint32_t largest = 0;
    size_t desync = 0;
    for (const auto& b : m_heap_free_by_addr) {
        free_bytes += b.second;
        if (b.second > largest) largest = b.second;
        auto it = m_heap_free_by_size.find(b.second);
        if (it == m_heap_free_by_size.end() || !it->second.count(b.first)) ++desync;
    }
    size_t by_size_count = 0, empty_buckets = 0;
    for (const auto& b : m_heap_free_by_size) {
        by_size_count += b.second.size();
        if (b.second.empty()) ++empty_buckets;
    }
    LOGI("heap %s: frontier=0x%08X live=%zu/%lluMB free=%zu(bySize %zu)/%lluMB largest=%uKB "
         "desync=%zu buckets=%zu(empty %zu)  allocs=%llu frees=%llu freeMisses=%llu "
         "allocFails=%llu | reuse=%llu bump=%llu nofit=%llu bigalign=%llu",
         why, m_heap_current, m_heap_used.size(),
         static_cast<unsigned long long>(used_bytes >> 20),
         m_heap_free_by_addr.size(), by_size_count,
         static_cast<unsigned long long>(free_bytes >> 20), largest >> 10, desync,
         m_heap_free_by_size.size(), empty_buckets,
         static_cast<unsigned long long>(m_alloc_calls),
         static_cast<unsigned long long>(m_free_calls),
         static_cast<unsigned long long>(m_free_misses),
         static_cast<unsigned long long>(m_alloc_fails),
         static_cast<unsigned long long>(m_alloc_reuse),
         static_cast<unsigned long long>(m_alloc_bump),
         static_cast<unsigned long long>(m_alloc_nofit),
         static_cast<unsigned long long>(m_alloc_bigalign));
}

// The smallest thing that fails if the allocator above is wrong: allocate a mixed batch, free
// half of it, allocate again and check that nothing overlaps and that the freed space actually
// comes back. Runs once at startup, costs microseconds, and turns a silent heap corruption
// into a line in logcat.
void DynarmicHost::GuestHeapSelfTest() {
    const uint32_t before = m_heap_current;
    std::vector<std::pair<uint32_t, uint32_t>> live;
    uint32_t seed = 12345;
    auto rnd = [&seed] { seed = seed * 1103515245u + 12345u; return (seed >> 16) & 0x3FF; };

    // Mixed alignments on purpose: memalign is 82% of the engine's traffic and an aligned
    // request that quietly bypasses the free list looks exactly like a working allocator
    // until the arena runs out a minute later.
    static const uint32_t kAligns[] = {8, 8, 16, 32, 64};
    for (int i = 0; i < 200; ++i) {
        const uint32_t n = rnd() + 1;
        const uint32_t al = kAligns[i % 5];
        const uint32_t a = GuestAlloc(n, al);
        if (!a) { LOGE("[HEAPTEST] FAIL: allocation %d of %u bytes returned 0", i, n); return; }
        if (a & (al - 1)) { LOGE("[HEAPTEST] FAIL: 0x%08X not %u-aligned", a, al); return; }
        live.emplace_back(a, n);
    }
    for (size_t i = 0; i < live.size(); i += 2) GuestFree(live[i].first);
    const uint32_t frontier = m_heap_current;

    std::vector<std::pair<uint32_t, uint32_t>> second;
    for (int i = 0; i < 100; ++i) {
        const uint32_t n = rnd() + 1;
        const uint32_t al = kAligns[i % 5];
        const uint32_t a = GuestAlloc(n, al);
        if (!a) { LOGE("[HEAPTEST] FAIL: reallocation %d returned 0", i); return; }
        if (a & (al - 1)) { LOGE("[HEAPTEST] FAIL: 0x%08X not %u-aligned", a, al); return; }
        second.emplace_back(a, n);
    }
    for (const auto& x : second) {
        for (size_t i = 1; i < live.size(); i += 2) {   // the still-live odd blocks
            const uint32_t lo = live[i].first, hi = lo + live[i].second;
            if (x.first < hi && lo < x.first + x.second) {
                LOGE("[HEAPTEST] FAIL: 0x%08X+%u overlaps live 0x%08X+%u",
                     x.first, x.second, lo, live[i].second);
                return;
            }
        }
    }
    const bool reused = m_heap_current - frontier < 100u * 1024u;
    LOGI("[HEAPTEST] ok: 300 allocations, no overlap, %s (frontier grew %u bytes)",
         reused ? "freed space reused" : "NOT reusing freed space", m_heap_current - frontier);

    for (const auto& x : second) GuestFree(x.first);
    for (size_t i = 1; i < live.size(); i += 2) GuestFree(live[i].first);
    // Give the arena back to a clean state so the test leaves no trace.
    m_heap_used.clear();
    m_heap_free_by_addr.clear();
    m_heap_free_by_size.clear();
    m_heap_current = before;
}

// Lesson 2.4: the guest arena is zero-filled and 0x00000000 decodes as the perfectly legal
// `andeq r0, r0, r0`, so a jump through a junk pointer makes the JIT translate a fresh block
// every 0x8000 bytes forever -- RSS climbs until the low-memory killer takes the process and
// it reads like a memory leak. Fence code fetch to the trampoline page plus the mapped guest
// modules; anything else returns a permanently-undefined instruction so ExceptionRaised fires
// with the registers still intact and the bad jump is obvious.
bool DynarmicHost::IsExecutableGuestAddress(std::uint32_t vaddr) const {
    // The exit traps, and nothing else below the trampolines. Letting the whole first 64 KB
    // through was worse than useless: a call through a null vtable slot lands on the zero page,
    // executes 0x00000000 (`andeq r0, r0, r0`) up to the SVC at 0x4, and halts -- which
    // RunFunction cannot tell apart from a real return, so it reports r0 = 0. A frame that
    // jumped through a null pointer came back looking like "the game asked to quit".
    if (vaddr >= EXIT_TRAP_ARM && vaddr < EXIT_TRAP_THUMB + 4) return true;
    if (vaddr >= 0x00010000 && vaddr < kTrampolineEnd) return true;   // SVC trampolines
    if (vaddr >= kKuserPageStart && vaddr < kKuserPageEnd) return true;   // kuser helpers
    for (const auto& m : m_modules) {
        const uint32_t base = m.second->GetBaseAddress();
        if (vaddr >= base && vaddr < base + m.second->GetImageSize()) return true;
    }
    for (const ElfLoader* l : {m_elf_loader.get(), m_fmodex_loader.get(), m_fmodevent_loader.get()}) {
        if (!l) continue;
        const uint32_t base = l->GetBaseAddress();
        if (vaddr >= base && vaddr < base + l->GetImageSize()) return true;
    }
    return false;
}

std::optional<std::uint32_t> DynarmicHost::MemoryReadCode(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 4 > m_memory_size) {
        return std::nullopt;
    }
    if (!IsExecutableGuestAddress(vaddr)) {
        if (m_runaway_reports < 16) {
            ++m_runaway_reports;
            LOGE("[RUNAWAY] code fetch outside any mapped module: 0x%08X", vaddr);
            if (m_jit) DumpGuestBacktrace("runaway", Active()->Regs()[13], Active()->Regs()[14]);
        }
        return 0xE7FEDEFFu;  // permanently undefined -> ExceptionRaised
    }
    return *reinterpret_cast<uint32_t*>(m_memory + vaddr);
}

std::uint8_t DynarmicHost::MemoryRead8(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) < m_memory_size) return m_memory[vaddr];
    return 0;
}

std::uint16_t DynarmicHost::MemoryRead16(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 2 <= m_memory_size) return *reinterpret_cast<uint16_t*>(m_memory + vaddr);
    return 0;
}

std::uint32_t DynarmicHost::MemoryRead32(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) return *reinterpret_cast<uint32_t*>(m_memory + vaddr);
    return 0;
}

std::uint64_t DynarmicHost::MemoryRead64(std::uint32_t vaddr) {
    if (static_cast<uint64_t>(vaddr) + 8 <= m_memory_size) return *reinterpret_cast<uint64_t*>(m_memory + vaddr);
    return 0;
}

void DynarmicHost::MemoryWrite8(std::uint32_t vaddr, std::uint8_t value) {
    if (static_cast<uint64_t>(vaddr) < m_memory_size) m_memory[vaddr] = value;
}

void DynarmicHost::MemoryWrite16(std::uint32_t vaddr, std::uint16_t value) {
    if (static_cast<uint64_t>(vaddr) + 2 <= m_memory_size) *reinterpret_cast<uint16_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::MemoryWrite32(std::uint32_t vaddr, std::uint32_t value) {
    if (static_cast<uint64_t>(vaddr) + 4 <= m_memory_size) *reinterpret_cast<uint32_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::MemoryWrite64(std::uint32_t vaddr, std::uint64_t value) {
    if (static_cast<uint64_t>(vaddr) + 8 <= m_memory_size) *reinterpret_cast<uint64_t*>(m_memory + vaddr) = value;
}

void DynarmicHost::InterpreterFallback(std::uint32_t pc, std::size_t num_instructions) {
    LOGE("Interpreter Fallback at 0x%08X", pc);
    Active()->HaltExecution(Dynarmic::HaltReason::UserDefined1);
}

// A raw `SVC 0` from the guest is an inline Linux syscall: number in r7, args in r0-r5.
// google_breakpad is compiled with its own syscall stubs -- it has to be async-signal-safe --
// and it is the only thing that does this: all 135 `SVC 0` sites in libABK.so sit inside the
// breakpad object files, and libSkynestSDK/libgnustl have none. Halting the JIT here killed
// CXGSCrashReporter::CreateImpl, and with it the whole ExientGLSurfaceView.nativeInitialize
// call, on the first sigaltstack.
//
// Nothing here needs to succeed. Breakpad only writes a minidump after a crash, and a guest
// crash reporter is worthless in this bridge anyway. -ENOSYS is what an unsupported kernel
// answers and every breakpad call site already has an error path -- the sigaltstack one sets
// errno, falls through to calloc and carries on. Implement a real syscall only when this log
// shows something actually depends on one.
void DynarmicHost::EmulateGuestSyscall() {
    const uint32_t nr = Active()->Regs()[7];
    if (m_syscalls_seen.insert(nr).second) {
        LOGE("[SYSCALL] guest issued raw syscall %u from 0x%08X (%s) -- answering -ENOSYS",
             nr, Active()->Regs()[15], DescribeAddress(Active()->Regs()[15]).c_str());
    }
    Active()->Regs()[0] = static_cast<uint32_t>(-38);   // -ENOSYS
}

void DynarmicHost::CallSVC(std::uint32_t swi) {
    // The RunFunction exit traps at 0x4 (ARM) and 0x8 (Thumb) are themselves `SVC 0`, so the
    // address test has to come first or every returning guest call looks like a syscall.
    if (Active()->Regs()[15] <= 0x40) {
        Active()->HaltExecution(Dynarmic::HaltReason::UserDefined1);
        return;
    }
    if (swi == 0) {
        EmulateGuestSyscall();
        return;
    }
    // *Active(), never *m_jit: a thunk reached from RunFunctionNested runs on the second Jit,
    // and handing it the main Jit's register file makes every argument garbage. qsort never
    // exposed this because its comparators barely call thunks; the first nested call that ran
    // real engine code (CSaveManager::Update from the yield hook) hit memcpy with a length
    // taken from the wrong register and wrote clean off the end of the guest arena, which
    // showed up as a SIGSEGV inside the host's own malloc some seconds later.
    m_thunk_manager->DispatchThunk(swi, *Active());
}

void DynarmicHost::ExceptionRaised(std::uint32_t pc, Dynarmic::A32::Exception exception) {
    LOGE("Exception at PC: 0x%08X (%s) type %d", pc, DescribeAddress(pc).c_str(),
         static_cast<int>(exception));
    // The registers are the whole story for a UDF: libABK is built with bounds checks that
    // compile down to `cmp; bls; udf #0`, so the operands that failed the check are still
    // live in r0-r3 and name the object that is wrong. Printing only the PC left every one of
    // these looking identical.
    LOGE("  r0=%08X r1=%08X r2=%08X r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X",
         Active()->Regs()[0], Active()->Regs()[1], Active()->Regs()[2], Active()->Regs()[3],
         Active()->Regs()[4], Active()->Regs()[5], Active()->Regs()[6], Active()->Regs()[7]);
    LOGE("  r8=%08X r9=%08X r10=%08X r11=%08X r12=%08X sp=%08X lr=%08X",
         Active()->Regs()[8], Active()->Regs()[9], Active()->Regs()[10], Active()->Regs()[11],
         Active()->Regs()[12], Active()->Regs()[13], Active()->Regs()[14]);
    // A jump through a null vptr says nothing about *what* was being loaded, and the answer is
    // usually still sitting in a callee-saved register: the filename the caller just built.
    // Print every register that points at printable text.
    for (int r = 0; r < 13; ++r) {
        const uint32_t p = Active()->Regs()[r];
        if (p < 0x1000 || static_cast<uint64_t>(p) + 64 > m_memory_size) continue;
        const char* s = reinterpret_cast<const char*>(m_memory + p);
        size_t n = 0;
        while (n < 63 && s[n] >= 0x20 && s[n] < 0x7F) ++n;
        if (n >= 6 && s[n] == '\0') LOGE("  r%d -> \"%.*s\"", r, static_cast<int>(n), s);
    }
    DumpGuestBacktrace("exception", Active()->Regs()[13], Active()->Regs()[14]);
    Active()->HaltExecution(Dynarmic::HaltReason::UserDefined1);
}

void DynarmicHost::AddTicks(std::uint64_t ticks) {
    if (m_ticks_remaining > ticks) m_ticks_remaining -= ticks;
    else m_ticks_remaining = 0;
}

std::uint64_t DynarmicHost::GetTicksRemaining() {
    return m_ticks_remaining;
}

// STREX: compare-and-set against guest memory. The ExclusiveMonitor already holds its lock
// around this and has verified the reservation, so a plain compare/store is sufficient.
template<typename T>
static bool GuestCompareAndSwap(uint8_t* mem, size_t mem_size, uint32_t vaddr, T value, T expected) {
    if (static_cast<uint64_t>(vaddr) + sizeof(T) > mem_size) return false;
    T* p = reinterpret_cast<T*>(mem + vaddr);
    if (*p != expected) return false;
    *p = value;
    return true;
}

bool DynarmicHost::MemoryWriteExclusive8(std::uint32_t vaddr, std::uint8_t value, std::uint8_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive16(std::uint32_t vaddr, std::uint16_t value, std::uint16_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive32(std::uint32_t vaddr, std::uint32_t value, std::uint32_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}

bool DynarmicHost::MemoryWriteExclusive64(std::uint32_t vaddr, std::uint64_t value, std::uint64_t expected) {
    return GuestCompareAndSwap(m_memory, m_memory_size, vaddr, value, expected);
}
