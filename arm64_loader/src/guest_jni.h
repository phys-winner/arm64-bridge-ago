#pragma once
//
// Bridging JNI between the 64-bit host and the 32-bit guest.
//
// The guest cannot touch a real JNIEnv: its pointers are 32-bit and it runs under the JIT.
// So it gets a *fake* JNIEnv living in guest memory whose 256 function slots are SVC
// trampolines back into the host, and every jobject/jclass/jstring it ever sees is an
// opaque 32-bit handle into a host-side table of JNI global refs.
//
// This replaces the reference bridge's stub table, where FindClass always returned 0x3000
// and GetMethodID always returned 0x2000. Galaxy on Fire 2 never used the results; Angry
// Birds Go! really does call Environment.getExternalStorageDirectory, Runtime.exec,
// Locale.getDefault, TimeZone and Surface, and a fake handle there produces a
// plausible-looking wrong answer rather than a crash -- much worse to debug.

#include <jni.h>
#include <cstdint>
#include <vector>

class DynarmicHost;

// --- handles ---------------------------------------------------------------------------
// 0 is null in both directions.
uint32_t   GuestRefFromHost(jobject obj);      // takes a global ref; 0 for null
jobject    HostRefFromGuest(uint32_t handle);
void       GuestRefDelete(uint32_t handle);    // drops the global ref, frees the slot

// jmethodID / jfieldID are not collectable objects, so they get their own index space.
uint32_t   GuestMethodId(jmethodID id);
jmethodID  HostMethodId(uint32_t handle);
uint32_t   GuestFieldId(jfieldID id);
jfieldID   HostFieldId(uint32_t handle);

// --- host JNI access from anywhere in the bridge ----------------------------------------
// Attaches the calling thread to the VM if needed. Never returns null once JNI_OnLoad ran.
JNIEnv* HostEnv();

// --- guest-facing JNIEnv ----------------------------------------------------------------
// Builds the 256-slot table in guest memory. Call once, after ThunkManager exists.
void InstallGuestJNIEnv(DynarmicHost& host);
// The value passed as the first argument of every guest Java_* function.
uint32_t GetGuestJNIEnvPtr();
// The guest JavaVM*, i.e. what a guest JNI_OnLoad has to be handed.
uint32_t GetGuestJavaVMPtr();

// --- calling into the guest --------------------------------------------------------------
// Looks the symbol up in the loaded guest modules and runs it. args[0]/args[1] must already
// be the JNIEnv handle and the jclass/jobject handle, per the JNI calling convention.
// Returns R0. Logs once and returns 0 if the symbol is missing.
uint32_t CallGuestJni(const char* symbol, const std::vector<uint32_t>& args);

// softfp: floats and doubles travel in the core registers, never in S/D regs (lesson 2.1).
uint32_t FloatBits(float f);
void     PushDouble(std::vector<uint32_t>& args, double d);   // 8-byte aligns as it goes
void     PushLong(std::vector<uint32_t>& args, int64_t v);

// Live host global refs behind the guest handle table; see guest_jni_handles.cpp.
void LogJniStats();
