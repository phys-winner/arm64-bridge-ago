#pragma once
#include <cstdint>
#include <string>

// ponytail: the GOF2 bridge shipped a persisted mod-menu (iPad/retina/DPI/VIP/font-spacing
// toggles) in extra_settings.cpp + extra_ui.cpp, plus a virtual-resolution UI scaler.
// Angry Birds Go! needs none of that -- its front end has its own virtual resolution and
// the lessons doc (11.3) is explicit that changing it late produces mixed-state bugs.
// The knobs are read from eight places across thunk_manager/thunks_gl/jni_bridge, so
// rather than editing all of them this keeps the same shape with neutral defaults and
// makes the virtual resolution equal the real framebuffer.
// If ABGo ever grows a settings overlay, give this a real implementation again.

struct ExtraSettings {
    int ipad_mode = -1;       // -1 = let the game decide
    int retina_mode = -1;     // -1 = let the game decide
    int forced_dpi = 0;       // 0 = use the real display metrics (=> virtual == real)
    int max_texture_lod = 0;  // 0 = no LOD clamp
    int target_fps = 0;       // 0 = uncapped; vsync paces us
    int kaamo_vip = 0;        // GOF2-only concept
    int fastmem = 1;          // map the whole 32-bit guest space (guide 2.2)
    int ui_inset = 0;
    int font_spacing = 999;   // 999 = leave the engine's own value alone
};

ExtraSettings& GetExtraSettings();

// Kept as no-ops so the existing call sites compile unchanged.
inline void LoadExtraSettings() {}
inline void SaveExtraSettings(const ExtraSettings&) {}
inline void ApplyExtraSettings() {}
inline void ApplyPreInitExtraSettings() {}
inline void EnforceFontSpacing() {}
inline std::string GetExtraSettingsFilePath() { return {}; }

// Virtual resolution the guest engine is told about. With forced_dpi == 0 this is just
// the real framebuffer, so the ortho stretch in thunks_gl becomes identity.
uint32_t GetVirtualWidth();
uint32_t GetVirtualHeight();
