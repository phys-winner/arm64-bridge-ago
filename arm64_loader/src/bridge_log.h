#pragma once
//
// Shared log macros. Each translation unit defines LOG_TAG first, then includes this
// header instead of declaring its own __android_log_print wrappers.
//
// Info/warning chatter is compiled out unless BRIDGE_ENABLE_LOGGING is defined (CMake
// -DENABLE_LOGGING=ON). At the rate this guest logs, the device's logd flow control
// silently drops real diagnostics and every formatted line charges the frame. Errors
// stay enabled in every build: they are the diagnostics.
//
#include <android/log.h>

#ifdef BRIDGE_ENABLE_LOGGING
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) ((void)0)
#define LOGW(...) ((void)0)
#endif
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
