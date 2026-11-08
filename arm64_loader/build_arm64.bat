@echo off
setlocal
cd /d "%~dp0"

rem   build_arm64.bat           -> build_arm64\           full mod (default)
rem   build_arm64.bat vanilla   -> build_arm64_vanilla\   -DABGO_VANILLA_ECONOMY=ON
rem Dynarmic: build_deps\dynarmic-src (made by prepare_dynarmic.py: pinned commit + the ABGo
rem patch) is used when present; DYNARMIC_SOURCE_DIR overrides it with another patched tree.
rem CMakeLists.txt refuses an unpatched tree.

if not defined ANDROID_SDK set "ANDROID_SDK=%ANDROID_HOME%"
if not defined ANDROID_SDK set "ANDROID_SDK=%ANDROID_SDK_ROOT%"
if not defined ANDROID_SDK (
    echo Set ANDROID_SDK or ANDROID_HOME to your Android SDK directory.
    exit /b 1
)
if not defined NDK_VERSION set "NDK_VERSION=27.2.12479018"
if not defined CMAKE_VERSION set "CMAKE_VERSION=3.22.1"

set "CMAKE_EXE=%ANDROID_SDK%\cmake\%CMAKE_VERSION%\bin\cmake.exe"
set "TOOLCHAIN=%ANDROID_SDK%\ndk\%NDK_VERSION%\build\cmake\android.toolchain.cmake"
if not exist "%CMAKE_EXE%" (
    echo Android SDK CMake %CMAKE_VERSION% is missing.
    exit /b 1
)
if not exist "%TOOLCHAIN%" (
    echo Android NDK %NDK_VERSION% is missing.
    exit /b 1
)

set "BUILD_DIR=build_arm64"
set "VARIANT_ARGS=-DABGO_VANILLA_ECONOMY=OFF"
if /i "%~1"=="vanilla" (
    set BUILD_DIR=build_arm64_vanilla
    set VARIANT_ARGS=-DABGO_VANILLA_ECONOMY=ON
)
if not defined DYNARMIC_SOURCE_DIR if exist "%~dp0build_deps\dynarmic-src" set "DYNARMIC_SOURCE_DIR=%~dp0build_deps\dynarmic-src"
set DYNARMIC_ARGS=
if defined DYNARMIC_SOURCE_DIR set DYNARMIC_ARGS=-DFETCHCONTENT_SOURCE_DIR_DYNARMIC="%DYNARMIC_SOURCE_DIR%"

echo ==============================================
echo Building ABGo ARM64 Bridge with Dynarmic (%BUILD_DIR%)
echo NDK: %NDK_VERSION%
echo ==============================================

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
cd "%BUILD_DIR%"

"%CMAKE_EXE%" .. ^
    -G "Ninja" ^
    -DCMAKE_MAKE_PROGRAM="%ANDROID_SDK%\cmake\%CMAKE_VERSION%\bin\ninja.exe" ^
    -DCMAKE_TOOLCHAIN_FILE="%TOOLCHAIN%" ^
    -DANDROID_ABI="arm64-v8a" ^
    -DANDROID_PLATFORM=android-26 ^
    -DCMAKE_BUILD_TYPE=Release ^
    %VARIANT_ARGS% %DYNARMIC_ARGS%
if errorlevel 1 exit /b 1

"%CMAKE_EXE%" --build . --config Release
if errorlevel 1 exit /b 1

echo Build finished!
