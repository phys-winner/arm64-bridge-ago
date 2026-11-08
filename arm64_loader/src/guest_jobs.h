#pragma once
//
// Running the engine's CXGSJob work without guest threads.
//
// See guest_jobs.cpp for why this exists and what it deliberately does not do.

#include <cstdint>

class DynarmicHost;

// Called for every guest pthread_create. Recognises the engine's job-worker threads and
// records the scheduler object each of them would have serviced, and queues the thread
// bodies that are known to run to completion.
void RegisterGuestThread(DynarmicHost& host, uint32_t start_func, uint32_t arg);

// Runs every queued job of every registered scheduler, plus any queued thread body, to
// completion. Must be called from outside Jit::Run -- i.e. from nativeDrawFrame, next to
// DrainDeferred.
void PumpGuestJobs(DynarmicHost& host);

// The guest asked to be descheduled (XGSThread::SleepThread -> usleep, YieldThread ->
// sched_yield). With no other guest threads this is the bridge's only chance to advance what
// those threads would have advanced. Safe to call from inside a thunk.
void OnGuestYield(DynarmicHost& host, uint32_t guest_lr = 0);
