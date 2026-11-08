#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>

// Helper to convert 32-bit guest pointer to 64-bit host pointer
inline void* GuestToHost(uint8_t* base, uint32_t gaddr) {
    if (gaddr == 0) return nullptr;
    return reinterpret_cast<void*>(base + gaddr);
}

// Helper to convert 64-bit host pointer into 32-bit guest address (if within guest arena)
inline uint32_t HostToGuest(uint8_t* base, void* hptr) {
    if (!hptr) return 0;
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(hptr) - reinterpret_cast<uintptr_t>(base));
}
