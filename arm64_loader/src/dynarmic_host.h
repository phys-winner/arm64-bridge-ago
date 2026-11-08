#pragma once

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <string>
#include <optional>
#include <map>
#include <set>
#include <unordered_map>
#include <mutex>
#include <dynarmic/interface/A32/a32.h>
#include <dynarmic/interface/A32/config.h>
#include <dynarmic/interface/exclusive_monitor.h>

class ElfLoader;
class ThunkManager;

class DynarmicHost : public Dynarmic::A32::UserCallbacks {
public:
    // The full 32-bit guest address space. Mapping all of it means fastmem can resolve any
    // guest address as base + zext32(vaddr) without ever faulting.
    static constexpr size_t GUEST_ADDRESS_SPACE = 0x100000000ULL; // 4 GiB
    // Fallback if the 4 GiB reservation is refused: no fastmem, bounds-checked callbacks.
    static constexpr size_t GUEST_FALLBACK_SIZE = 0x80000000ULL;  // 2 GiB

    DynarmicHost();
    ~DynarmicHost() override;

    bool Initialize();
    bool LoadGame(const std::string& elf_path);
    bool LoadGameFromMemory(const uint8_t* data, size_t size);

    bool LoadLibraries(const std::string& fmodex_path, const std::string& fmodevent_path, const std::string& game_path);
    bool LoadLibrariesFromMemory(const uint8_t* fmodex_data, size_t fmodex_size,
                                 const uint8_t* fmodevent_data, size_t fmodevent_size,
                                 const uint8_t* game_data, size_t game_size);

    // --- N guest objects -------------------------------------------------------------
    // Angry Birds Go! needs three of them (libgnustl_shared, libSkynestSDK, libABK) and
    // libABK alone is ~14.7 MB, so the reference's three fixed slots spaced 4 MB apart
    // both overflow and cannot express the set. Bases are bump-allocated instead.
    //
    // ORDER MATTERS. libABK.so and libgnustl_shared.so both export _Znwj/_ZdlPv/_Znaj/
    // _ZdaPv; bionic resolves first-loaded-wins and Java loads gnustl -> Skynest -> ABK,
    // so pass them in that order or allocations land in one heap and frees in another.
    struct GuestModuleImage {
        std::string name;      // for logging only
        const uint8_t* data;
        size_t size;
    };
    bool LoadModulesFromMemory(const std::vector<GuestModuleImage>& images);
    ElfLoader* FindModule(const std::string& name);
    size_t GetModuleCount() const { return m_modules.size(); }

    uint32_t RunFunction(uint32_t target_pc, const std::vector<uint32_t>& args = {});
    // Runs guest code from *inside* a thunk and returns its result now, on a second Jit.
    // Use only when the answer is needed before the thunk returns (qsort's comparator);
    // fire-and-forget callbacks belong in the deferred queue. See the implementation.
    uint32_t RunFunctionNested(uint32_t target_pc, const std::vector<uint32_t>& args = {});
    // Runs calls that were made from inside a thunk (i.e. from inside Jit::Run, where the JIT
    // is not re-entrant). Call once per frame from a point known to be outside the JIT.
    void DrainDeferred();

    uint8_t* GetGuestMemoryBase() const { return m_memory; }
    size_t GetGuestMemorySize() const { return m_memory_size; }
    // The main game object: the last entry of m_modules when the N-module path was used,
    // otherwise the single loader from LoadGame*/LoadLibraries*.
    ElfLoader& GetElfLoader() {
        return m_modules.empty() ? *m_elf_loader : *m_modules.back().second;
    }
    ElfLoader* GetFmodExLoader() { return m_fmodex_loader.get(); }
    ElfLoader* GetFmodEventLoader() { return m_fmodevent_loader.get(); }
    ThunkManager& GetThunkManager() { return *m_thunk_manager; }
    std::recursive_mutex& GetMutex() { return m_mutex; }
    // Forensics for a stuck JIT mutex: logs the bionic mutex state word, from which the
    // owner TID of a held recursive mutex can be read, plus whether that TID still exists.
    void LogMutexOwner(const char* why);
    // From inside a thunk: stop the guest call this thunk serves (fatal-guest-path
    // semantics -- abort/terminate -- must not return into a caller that cannot cope).
    // HaltExecution is the one JIT call that is safe from thunk context.
    void HaltCurrentCall();
    // When the stall is a lost futex wakeup (unlocked mutex with the waiters flag set and
    // sleepers stuck), wake them and return true. Otherwise log the real owner.
    bool RecoverStalledMutex(const char* why);
    uint32_t FindSymbol(const std::string& name);
    // Drop any cached translation of a guest range that was just rewritten.
    void InvalidateGuestCode(uint32_t addr, size_t size);
    uint32_t GuestAlloc(size_t size, size_t alignment = 8);
    void GuestFree(uint32_t addr);
    // Address space for whole-file mappings, kept out of the malloc heap: the main OBB alone
    // is 345 MB and would otherwise eat half of it permanently. Bump-only; mappings live for
    // the process.
    uint32_t GuestAllocMapping(size_t size, size_t alignment);
    // Usable bytes of a live GuestAlloc block, 0 if it is not one. realloc needs it: copying
    // the *new* size out of the old block reads past its end.
    uint32_t GuestAllocSize(uint32_t addr);
    // One line of heap truth: is it leaking, fragmented, or are the two free maps disagreeing?
    // "free() on an address we never handed out" is counted separately -- that one is a leak
    // with no other symptom until the arena runs out an hour later.
    void LogHeapStats(const char* why);

    // Dynarmic UserCallbacks interface
    std::optional<std::uint32_t> MemoryReadCode(std::uint32_t vaddr) override;

    std::uint8_t MemoryRead8(std::uint32_t vaddr) override;
    std::uint16_t MemoryRead16(std::uint32_t vaddr) override;
    std::uint32_t MemoryRead32(std::uint32_t vaddr) override;
    std::uint64_t MemoryRead64(std::uint32_t vaddr) override;

    void MemoryWrite8(std::uint32_t vaddr, std::uint8_t value) override;
    void MemoryWrite16(std::uint32_t vaddr, std::uint16_t value) override;
    void MemoryWrite32(std::uint32_t vaddr, std::uint32_t value) override;
    void MemoryWrite64(std::uint32_t vaddr, std::uint64_t value) override;

    // Needed now that global_monitor is set: the base-class defaults return false, which makes
    // every guest STREX report failure and spin its retry loop forever.
    bool MemoryWriteExclusive8(std::uint32_t vaddr, std::uint8_t value, std::uint8_t expected) override;
    bool MemoryWriteExclusive16(std::uint32_t vaddr, std::uint16_t value, std::uint16_t expected) override;
    bool MemoryWriteExclusive32(std::uint32_t vaddr, std::uint32_t value, std::uint32_t expected) override;
    bool MemoryWriteExclusive64(std::uint32_t vaddr, std::uint64_t value, std::uint64_t expected) override;

    void InterpreterFallback(std::uint32_t pc, std::size_t num_instructions) override;
    void CallSVC(std::uint32_t swi) override;
    void ExceptionRaised(std::uint32_t pc, Dynarmic::A32::Exception exception) override;

    void AddTicks(std::uint64_t ticks) override;
    std::uint64_t GetTicksRemaining() override;

    bool IsJitRunning() const { return m_is_running_jit; }
    // Heuristic guest call stack; see the implementation for why it is heuristic.
    void DumpGuestBacktrace(const char* why, uint32_t sp, uint32_t lr);
    // "libABK+0x1234" / "thunk gettimeofday (#122)" for a guest address; thunks use it to
    // name their caller.
    std::string DescribeAddress(uint32_t addr) const;

private:
    // Raw `SVC 0` (inline Linux syscall) from the guest; see the implementation.
    void EmulateGuestSyscall();
    std::set<uint32_t> m_syscalls_seen;

    // Watchdog: names the guest PC when a call never comes back (see StartWatchdog).
    void StartWatchdog();
    std::atomic<bool> m_watchdog_started{false};
    std::atomic<bool> m_watchdog_tripped{false};
    std::atomic<uint64_t> m_run_seq{0};

    uint8_t* m_memory = nullptr;
    size_t m_memory_size = 0;
    std::unique_ptr<Dynarmic::ExclusiveMonitor> m_monitor;
    std::unique_ptr<Dynarmic::A32::Jit> m_jit;
    // Second instance for RunFunctionNested. Same callbacks, same memory, its own stack.
    std::unique_ptr<Dynarmic::A32::Jit> m_jit_nested;
    // Whichever of the two is executing right now; the UserCallbacks must act on that one.
    Dynarmic::A32::Jit* m_active_jit = nullptr;
    Dynarmic::A32::Jit* Active() { return m_active_jit ? m_active_jit : m_jit.get(); }
    int m_nested_depth = 0;
    // Above the main stack (0x7F000000, growing down) and below the top of the arena, so the
    // two can never meet however deep a guest frame gets.
    uint32_t m_nested_stack_top = 0x7FF00000;
    std::unique_ptr<ElfLoader> m_fmodex_loader;
    std::unique_ptr<ElfLoader> m_fmodevent_loader;
    std::unique_ptr<ElfLoader> m_elf_loader;

    // Guest objects in load order; the last one is the main game and is also pointed at
    // by m_elf_loader so GetElfLoader()/FindSymbol keep working unchanged.
    std::vector<std::pair<std::string, std::unique_ptr<ElfLoader>>> m_modules;
    uint32_t m_next_module_base = 0x40000000;
    uint32_t ResolveGuestSymbol(const std::string& name);

    // Thunk trampolines live at 0x00010000 + 8*id; 1 MB is room for 131072 of them.
    static constexpr uint32_t kTrampolineEnd = 0x00110000;
    // The kernel's kuser helper routines, at the fixed addresses the C library branches to.
    static constexpr uint32_t kKuserPageStart = 0xFFFF0F00;
    static constexpr uint32_t kKuserPageEnd   = 0xFFFF1000;
    void InstallKuserHelperPage();
    bool IsExecutableGuestAddress(std::uint32_t vaddr) const;
    int m_runaway_reports = 0;
    std::unique_ptr<ThunkManager> m_thunk_manager;
    std::recursive_mutex m_mutex;
    bool m_is_running_jit = false;

    std::vector<std::pair<uint32_t, std::vector<uint32_t>>> m_deferred;

    // Guest heap. Metadata lives here, on the host side, not in guest memory: a guest
    // overrun then cannot corrupt the allocator, and the allocator needs no headers inside
    // blocks the guest believes it owns. See GuestAlloc.
    uint32_t m_heap_current = 0x50000000;
    std::map<uint32_t, uint32_t> m_heap_free_by_addr;              // addr -> size, for merging
    std::map<uint32_t, std::set<uint32_t>> m_heap_free_by_size;    // size -> addrs, for best fit
    std::unordered_map<uint32_t, uint32_t> m_heap_used;            // addr -> size
    void HeapInsertFree(uint32_t addr, uint32_t size);
    void HeapEraseFree(uint32_t addr, uint32_t size);
    uint64_t m_alloc_calls = 0, m_free_calls = 0, m_free_misses = 0, m_alloc_fails = 0;
    // Which path each allocation took. 440 MB sat free and unused while the frontier ran to
    // the end of the arena, so "did the free list get consulted at all" is the whole question.
    uint64_t m_alloc_reuse = 0, m_alloc_bump = 0, m_alloc_bigalign = 0, m_alloc_nofit = 0;
    void GuestHeapSelfTest();
    void ReportHeapExhaustion(uint32_t want);
    // File mappings live above both guest stacks, in their own bump region.
    uint32_t m_map_current = 0xA0000000;

    uint32_t m_stack_top    = 0x7F000000;
    std::uint64_t m_ticks_remaining = 0;
};
