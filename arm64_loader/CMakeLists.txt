cmake_minimum_required(VERSION 3.22)
project(abk_arm64_bridge LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Boost Headers
set(BOOST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost")
set(BOOST_INCLUDEDIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost")
set(Boost_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost")
set(Boost_NO_SYSTEM_PATHS ON)
set(Boost_FOUND TRUE)
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost")

# Configure Dynarmic.
# NOTE: the real option is DYNARMIC_FRONTENDS (a list), not DYNARMIC_ENABLE_A32/A64 --
# the old names were silently ignored, so A64 was being built too.
set(DYNARMIC_FRONTENDS "A32" CACHE STRING "" FORCE)
set(DYNARMIC_TESTS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_USE_BUNDLED_EXTERNALS ON CACHE BOOL "" FORCE)  # cross-compiling: never pick up host libs

message(STATUS "Fetching Dynarmic from GitHub...")
FetchContent_Declare(
    dynarmic
    GIT_REPOSITORY https://github.com/azahar-emu/dynarmic.git
    GIT_TAG        e77b1ba0b7da7cbe93021b01a663acfe7c4dd516
)
FetchContent_MakeAvailable(dynarmic)

# The bridge needs patches/dynarmic-e77b1ba0-abgo.patch on top of that commit (ASIMD VADDHN and
# an Interpret terminal that skips instead of aborting). Without it the bridge still links and
# boots, then dies on the first such instruction -- so refuse to configure against a tree that
# lacks it. prepare_dynarmic.py builds the patched tree build_arm64.bat points at.
foreach(_marker
        "src/dynarmic/frontend/A32/decoder/asimd.inc|111100101Dzznnnndddd0100N0M0mmmm"
        "src/dynarmic/backend/arm64/emit_arm64_a32.cpp|MC4 arm32-to-arm64 bridge patch")
    string(REPLACE "|" ";" _marker "${_marker}")
    list(GET _marker 0 _file)
    list(GET _marker 1 _text)
    file(READ "${dynarmic_SOURCE_DIR}/${_file}" _content)
    string(FIND "${_content}" "${_text}" _pos)
    if(_pos EQUAL -1)
        message(FATAL_ERROR "Dynarmic at ${dynarmic_SOURCE_DIR} lacks "
                            "patches/dynarmic-e77b1ba0-abgo.patch (${_file}); run prepare_dynarmic.py")
    endif()
endforeach()

set(BRIDGE_SOURCES
    src/extra_settings.cpp
    src/elf_loader.cpp
    src/dynarmic_host.cpp
    src/thunk_manager.cpp
    src/thunks_opensles.cpp
    src/thunks_gl.cpp
    src/thunks_libc.cpp
    src/thunks_egl.cpp
    src/thunks_extra.cpp
    src/thunks_android.cpp
    src/abgo_unlock.cpp
    src/jni_bridge_abgo.cpp
    src/guest_jni_handles.cpp
    src/guest_jobs.cpp
    src/guest_jnienv.cpp
    src/jni_exports_abgo.cpp
)

add_library(abk_arm64_bridge SHARED ${BRIDGE_SOURCES})

target_include_directories(abk_arm64_bridge PRIVATE
    src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost
)

target_link_libraries(abk_arm64_bridge PRIVATE
    dynarmic
    GLESv2
    EGL
    OpenSLES
    log
    android
    m
    z
)

target_compile_definitions(abk_arm64_bridge PRIVATE
    ANDROID
    __ANDROID__
)

# Release default: info/warn logging is compiled out (see src/bridge_log.h), errors stay.
# A debugging build flips this on: cmake -DENABLE_LOGGING=ON ..
option(ENABLE_LOGGING "Compile info/warn logging in" OFF)
if(ENABLE_LOGGING)
    target_compile_definitions(abk_arm64_bridge PRIVATE BRIDGE_ENABLE_LOGGING)
endif()

# Vanilla economy variant (see src/abgo_unlock.h): stock earn rates and progression, every
# offline/compatibility fix kept. Pair it with `_patch_guest.py vanilla`; build_arm64.bat vanilla
# builds it into build_arm64_vanilla/.
option(ABGO_VANILLA_ECONOMY "Build the bridge without currency/progression changes" OFF)
if(ABGO_VANILLA_ECONOMY)
    target_compile_definitions(abk_arm64_bridge PRIVATE ABGO_VANILLA_ECONOMY=1)
endif()

# Android devices with 16 KB pages need suitably aligned PT_LOAD segments. Request this
# explicitly instead of relying on a particular NDK version's default.
# Checked after the build with: readelf -lW -> PT_LOAD align must be 0x4000.
target_link_options(abk_arm64_bridge PRIVATE "-Wl,-z,max-page-size=16384")

# The NDK toolchain compiles with -g whatever CMAKE_BUILD_TYPE says, so the linked library
# carries ~60 MB of DWARF plus 3 MB of .symtab/.strtab on top of ~5 MB of actual code --
# and packaging it uncompressed puts every byte of that into the APK.
#
# Strip a copy for packaging instead of stripping in place: --build-id=sha1 is already on the
# link line, so llvm-symbolizer resolves a device backtrace against the unstripped file by
# BuildId, which is how the SIGSEGV in the OpenSL ES rework was tracked to a source line.
# --strip-all is safe here because .dynsym and .dynstr are SHF_ALLOC and survive it; the
# Java_* natives Android resolves at runtime live there, not in .symtab.
add_custom_command(TARGET abk_arm64_bridge POST_BUILD
    COMMAND "${CMAKE_STRIP}" --strip-all
            -o "$<TARGET_FILE_DIR:abk_arm64_bridge>/libabk_arm64_bridge.stripped.so"
            "$<TARGET_FILE:abk_arm64_bridge>"
    COMMENT "Stripping libabk_arm64_bridge.so for packaging"
    VERBATIM)
