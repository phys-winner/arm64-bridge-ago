#include "extra_settings.h"
#include "thunk_manager.h"

ExtraSettings& GetExtraSettings() {
    static ExtraSettings s;
    return s;
}

// forced_dpi is 0 for ABGo, so the scale is 1 and the virtual size is the real one.
// The multiply is kept so the knob still works if anyone sets it.
static float DpiScale() {
    const int dpi = GetExtraSettings().forced_dpi;
    if (dpi <= 0) return 1.0f;
    const float s = static_cast<float>(dpi) / 320.0f;
    return (s < 0.2f || s > 4.0f) ? 1.0f : s;
}

uint32_t GetVirtualWidth() {
    return static_cast<uint32_t>(static_cast<float>(ThunkManager::s_screenWidth) * DpiScale());
}

uint32_t GetVirtualHeight() {
    return static_cast<uint32_t>(static_cast<float>(ThunkManager::s_screenHeight) * DpiScale());
}
