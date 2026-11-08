#pragma once
//
// Host-side hooks onto the guest's own developer functionality (Angry Birds Go! 2.9.1).
//
// The release build still ships the full cheat layer in libABK.so -- CPlayerInfo::
// UnlockAllEpisodes, the unlock loops CSmokeTest::HandleCommandLineArgs runs, CGiftManager::
// CheatAddActiveGift, CFTUEManager::DebugCompleteAll -- but the CheatScreen UI that used to
// trigger it was cut from the shipped data. Dead online entry points are the remaining way
// in: the Restore IAPs button lands in a Java/native payment path Google Play can no longer
// answer, and the landing screen's account-connect button lands in a login this offline build
// can never finish. The arm64 bridge intercepts those paths and answers them here instead.

#include <cstdint>

class DynarmicHost;

namespace AbgoUnlock {

// Build variant. The default build is the full mod. -DABGO_VANILLA_ECONOMY=ON (CMake) builds the
// "vanilla economy" bridge for the stock earn rates and progression: the Restore IAPs and
// account-connect calls are still answered host-side, so no dead payment or login path runs,
// but they do nothing; there is no startup unlock, no tutorial skip and no adb trigger, and
// jni_bridge_abgo.cpp leaves the energy meter, the Restore IAPs dialogs and the tutorial
// popups to the stock code. The matching guest library is `_patch_guest.py vanilla`.
#if defined(ABGO_VANILLA_ECONOMY) && ABGO_VANILLA_ECONOMY
inline constexpr bool kVanillaEconomy = true;
#else
inline constexpr bool kVanillaEconomy = false;
#endif

// Resolve guest symbols and stage guest strings. Call once after the modules are mapped.
void Init(DynarmicHost& host);

// guest_jnienv records which jmethodID handles resolve to intercepted names.
void OnMethodResolved(uint32_t guest_method_handle, const char* name);

// True (with the action already performed) when this call belongs to an intercepted method.
bool RunMethodHook(DynarmicHost& host, uint32_t guest_method_handle);

// adb trigger, one frame in N: `setprop debug.abgo.unlock 1` runs the full unlock,
// `setprop debug.abgo.skipftue 1` completes the tutorial. Cheap property read.
void Tick(DynarmicHost& host);


}  // namespace AbgoUnlock
