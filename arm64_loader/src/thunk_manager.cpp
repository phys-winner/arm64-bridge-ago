#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "extra_settings.h"
#include "thunk_types.h"
#include <cerrno>
#include <algorithm>
#include <android/log.h>
#include <sys/system_properties.h>
#include <unistd.h>

#define LOG_TAG "GOF2_ThunkManager"
#include "bridge_log.h"

uint32_t ThunkManager::s_screenWidth = 1213;
uint32_t ThunkManager::s_screenHeight = 540;
uint32_t ThunkManager::s_forced_dpi = 0;
uint32_t ThunkManager::s_ui_inset = 0;

ThunkManager::ThunkManager(DynarmicHost& host) : m_host(host) {}

ThunkManager::~ThunkManager() = default;

#include "thunks_opensles.h"

// thunks_egl.cpp / thunks_extra.cpp -- the EGL, GLESv2 tail, libm and liblog imports that
// Angry Birds Go! has and the Galaxy on Fire 2 reference never did.
void RegisterEGLThunks(ThunkManager&, DynarmicHost&);
void RegisterExtraThunks(ThunkManager&, DynarmicHost&);
void RegisterAndroidThunks(ThunkManager&, DynarmicHost&);

void ThunkManager::RegisterAllThunks() {
    RegisterGLThunks();
    RegisterOpenSLESThunks(*this, m_host);
    RegisterLibcThunks();
    RegisterNFCThunks();
    // After the GL registrations so a name defined in both wins here; before any relocation,
    // which is what actually binds a guest import to a trampoline address.
    RegisterEGLThunks(*this, m_host);
    RegisterExtraThunks(*this, m_host);
    RegisterAndroidThunks(*this, m_host);
    SetupGuestJNIEnv();
}

#include <jni.h>
#include <sys/system_properties.h>
#include <cmath>
#include <cctype>
#include <cstring>

JavaVM* GetHostJavaVM();

static std::string QueryDeviceLanguage() {
    std::string lang = "en";
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass locCls = env->FindClass("java/util/Locale");
            if (locCls) {
                jmethodID getDefault = env->GetStaticMethodID(locCls, "getDefault", "()Ljava/util/Locale;");
                if (getDefault) {
                    jobject locObj = env->CallStaticObjectMethod(locCls, getDefault);
                    if (locObj) {
                        jmethodID getLang = env->GetMethodID(locCls, "getLanguage", "()Ljava/lang/String;");
                        if (getLang) {
                            jstring jStr = (jstring)env->CallObjectMethod(locObj, getLang);
                            if (jStr) {
                                const char* utf = env->GetStringUTFChars(jStr, nullptr);
                                if (utf && strlen(utf) > 0) {
                                    lang = utf;
                                }
                                if (utf) env->ReleaseStringUTFChars(jStr, utf);
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (lang.empty() || lang == "en") {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("persist.sys.locale", prop) > 0 ||
            __system_property_get("ro.product.locale", prop) > 0 ||
            __system_property_get("persist.sys.language", prop) > 0) {
            char* dash = strchr(prop, '-');
            if (dash) *dash = '\0';
            char* under = strchr(prop, '_');
            if (under) *under = '\0';
            if (strlen(prop) > 0) lang = prop;
        }
    }
    for (char& c : lang) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return lang;
}

static std::string QueryDeviceCountryCode() {
    std::string country = "US";
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass locCls = env->FindClass("java/util/Locale");
            if (locCls) {
                jmethodID getDefault = env->GetStaticMethodID(locCls, "getDefault", "()Ljava/util/Locale;");
                if (getDefault) {
                    jobject locObj = env->CallStaticObjectMethod(locCls, getDefault);
                    if (locObj) {
                        jmethodID getCountry = env->GetMethodID(locCls, "getCountry", "()Ljava/lang/String;");
                        if (getCountry) {
                            jstring jStr = (jstring)env->CallObjectMethod(locObj, getCountry);
                            if (jStr) {
                                const char* utf = env->GetStringUTFChars(jStr, nullptr);
                                if (utf && strlen(utf) > 0) {
                                    country = utf;
                                }
                                if (utf) env->ReleaseStringUTFChars(jStr, utf);
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (country.empty() || country == "US") {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("persist.sys.country", prop) > 0 ||
            __system_property_get("ro.product.locale.region", prop) > 0) {
            if (strlen(prop) > 0) country = prop;
        } else if (__system_property_get("persist.sys.locale", prop) > 0 ||
                   __system_property_get("ro.product.locale", prop) > 0) {
            char* dash = strchr(prop, '-');
            if (dash && strlen(dash + 1) >= 2) {
                country = std::string(dash + 1, 2);
            } else {
                char* under = strchr(prop, '_');
                if (under && strlen(under + 1) >= 2) {
                    country = std::string(under + 1, 2);
                }
            }
        }
    }
    for (char& c : country) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    return country;
}

static uint32_t QueryDeviceDensity() {
    if (ThunkManager::s_forced_dpi > 0) {
        return ThunkManager::s_forced_dpi;
    }
    ExtraSettings& ext = GetExtraSettings();
    if (ext.forced_dpi > 0) {
        return ext.forced_dpi;
    }
    uint32_t density = 0;
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass resCls = env->FindClass("android/content/res/Resources");
            if (resCls) {
                jmethodID getSys = env->GetStaticMethodID(resCls, "getSystem", "()Landroid/content/res/Resources;");
                if (getSys) {
                    jobject resObj = env->CallStaticObjectMethod(resCls, getSys);
                    if (resObj) {
                        jmethodID getDM = env->GetMethodID(resCls, "getDisplayMetrics", "()Landroid/util/DisplayMetrics;");
                        if (getDM) {
                            jobject dmObj = env->CallObjectMethod(resObj, getDM);
                            if (dmObj) {
                                jclass dmCls = env->FindClass("android/util/DisplayMetrics");
                                jfieldID fid = env->GetFieldID(dmCls, "densityDpi", "I");
                                if (fid) {
                                    density = static_cast<uint32_t>(env->GetIntField(dmObj, fid));
                                }
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }
    if (density == 0) {
        char prop[PROP_VALUE_MAX] = {0};
        if (__system_property_get("ro.sf.lcd_density", prop) > 0 ||
            __system_property_get("qemu.sf.lcd_density", prop) > 0) {
            density = static_cast<uint32_t>(atoi(prop));
        }
    }
    if (density == 0) {
        density = 320;
    }
    return density;
}

static uint32_t QueryDeviceIsPad() {
    ExtraSettings& ext = GetExtraSettings();
    if (ext.ipad_mode >= 0) {
        return ext.ipad_mode ? 1 : 0;
    }
    JavaVM* jvm = GetHostJavaVM();
    if (jvm) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
                attached = true;
            }
        }
        if (env) {
            jclass devInfoCls = env->FindClass("net/fishlabs/ow_utils/DeviceInfo");
            if (devInfoCls) {
                jmethodID isPadMethod = env->GetStaticMethodID(devInfoCls, "isPad", "()Z");
                if (isPadMethod) {
                    jboolean res = env->CallStaticBooleanMethod(devInfoCls, isPadMethod);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (attached) jvm->DetachCurrentThread();
                    return res ? 1 : 0;
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();

            jclass resCls = env->FindClass("android/content/res/Resources");
            if (resCls) {
                jmethodID getSys = env->GetStaticMethodID(resCls, "getSystem", "()Landroid/content/res/Resources;");
                if (getSys) {
                    jobject resObj = env->CallStaticObjectMethod(resCls, getSys);
                    if (resObj) {
                        jmethodID getCfg = env->GetMethodID(resCls, "getConfiguration", "()Landroid/content/res/Configuration;");
                        if (getCfg) {
                            jobject cfgObj = env->CallObjectMethod(resObj, getCfg);
                            if (cfgObj) {
                                jclass cfgCls = env->FindClass("android/content/res/Configuration");
                                jfieldID slFid = env->GetFieldID(cfgCls, "screenLayout", "I");
                                if (slFid) {
                                    jint screenLayout = env->GetIntField(cfgObj, slFid);
                                    if ((screenLayout & 0x0F) >= 3) { // SCREENLAYOUT_SIZE_LARGE or XLARGE
                                        if (env->ExceptionCheck()) env->ExceptionClear();
                                        if (attached) jvm->DetachCurrentThread();
                                        return 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (attached) jvm->DetachCurrentThread();
        }
    }

    uint32_t w = ThunkManager::s_screenWidth;
    uint32_t h = ThunkManager::s_screenHeight;
    uint32_t dpi = QueryDeviceDensity();
    if (w > 0 && h > 0 && dpi > 0) {
        double w_in = static_cast<double>(w) / static_cast<double>(dpi);
        double h_in = static_cast<double>(h) / static_cast<double>(dpi);
        double diag = sqrt(w_in * w_in + h_in * h_in);
        if (diag >= 6.5) return 1;
    }
    return 0;
}


void ThunkManager::RegisterNFCThunks() {
    RegisterThunk("_ZN3NFC5isPadEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t is_pad = QueryDeviceIsPad();
        LOGI("NFC::isPad called -> %u (%s)", is_pad, is_pad ? "tablet/pad" : "phone");
        jit.Regs()[0] = is_pad;
    });

    RegisterThunk("_ZN3NFC8getWidthEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        ExtraSettings& ext = GetExtraSettings();
        float scale = (ext.forced_dpi > 0) ? ((float)ext.forced_dpi / 320.0f) : 1.0f;
        if (scale < 0.2f || scale > 4.0f) scale = 1.0f;
        uint32_t virt_w = (uint32_t)((float)s_screenWidth * scale);
        LOGI("NFC::getWidth called -> %u (raw=%u, scale=%.2f)", virt_w, s_screenWidth, scale);
        jit.Regs()[0] = virt_w;
    });

    RegisterThunk("_ZN3NFC9getHeightEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        ExtraSettings& ext = GetExtraSettings();
        float scale = (ext.forced_dpi > 0) ? ((float)ext.forced_dpi / 320.0f) : 1.0f;
        if (scale < 0.2f || scale > 4.0f) scale = 1.0f;
        uint32_t virt_h = (uint32_t)((float)s_screenHeight * scale);
        LOGI("NFC::getHeight called -> %u (raw=%u, scale=%.2f)", virt_h, s_screenHeight, scale);
        jit.Regs()[0] = virt_h;
    });

    RegisterThunk("_ZN3NFC10isLanguageEPKc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* lang = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[0]));
        std::string curLang = QueryDeviceLanguage();
        LOGI("NFC::isLanguage(%s) called (device current='%s')", lang ? lang : "null", curLang.c_str());
        jit.Regs()[0] = (lang && (curLang == lang || curLang.rfind(lang, 0) == 0)) ? 1 : 0;
    });

    RegisterThunk("_ZN3NFC11getLanguageEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static uint32_t s_lang_gaddr = 0;
        std::string lang = QueryDeviceLanguage();
        if (!s_lang_gaddr) {
            s_lang_gaddr = host.GuestAlloc(32);
        }
        strncpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + s_lang_gaddr), lang.c_str(), 31);
        LOGI("NFC::getLanguage called -> '%s'", lang.c_str());
        jit.Regs()[0] = s_lang_gaddr;
    });

    RegisterThunk("_ZN3NFC14getCountryCodeEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static uint32_t s_country_gaddr = 0;
        std::string country = QueryDeviceCountryCode();
        if (!s_country_gaddr) {
            s_country_gaddr = host.GuestAlloc(32);
        }
        strncpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + s_country_gaddr), country.c_str(), 31);
        LOGI("NFC::getCountryCode called -> '%s'", country.c_str());
        jit.Regs()[0] = s_country_gaddr;
    });

    RegisterThunk("_ZN3NFC10getDensityEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t density = QueryDeviceDensity();
        LOGI("NFC::getDensity called -> %u", density);
        jit.Regs()[0] = density;
    });

    RegisterThunk("_ZN3NFC14getOrientationEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::getOrientation called -> 2 (landscape)");
        jit.Regs()[0] = 2;
    });

    RegisterThunk("_ZN3NFC12getAvailableEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::getAvailable called -> 1");
        jit.Regs()[0] = 1;
    });

    RegisterThunk("_ZN3NFC10isLoggedInEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::isLoggedIn called -> 0");
        jit.Regs()[0] = 0;
    });

    RegisterThunk("_ZN3NFC10loginAsyncEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::loginAsync called");
        jit.Regs()[0] = 0;
    });

    RegisterThunk("_ZN3NFC11logoutAsyncEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::logoutAsync called");
        jit.Regs()[0] = 0;
    });

    RegisterThunk("_ZN3NFC13showMoreGamesEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_ZN3NFC17openPrivacyPolicyEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::openPrivacyPolicy called -> triggering ExtraSettingsDialog");
        JavaVM* jvm = GetHostJavaVM();
        if (jvm) {
            JNIEnv* env = nullptr;
            bool attached = false;
            if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
                if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) attached = true;
            }
            if (env) {
                jclass nfcCls = env->FindClass("net/fishlabs/gof2hdallandroid2012/NativeFunctionCalls");
                if (nfcCls) {
                    jfieldID fid = env->GetStaticFieldID(nfcCls, "Gof2Activity", "Lnet/fishlabs/gof2hdallandroid2012/GOF2HD2012;");
                    if (fid) {
                        jobject act = env->GetStaticObjectField(nfcCls, fid);
                        if (act) {
                            jclass dlgCls = env->FindClass("net/fishlabs/gof2hdallandroid2012/ExtraSettingsDialog");
                            if (dlgCls) {
                                jmethodID showMethod = env->GetStaticMethodID(dlgCls, "show", "(Landroid/app/Activity;)V");
                                if (showMethod) {
                                    env->CallStaticVoidMethod(dlgCls, showMethod, act);
                                }
                            }
                        }
                    }
                }
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (attached) jvm->DetachCurrentThread();
            }
        }
        jit.Regs()[0] = 0;
    });

    RegisterThunk("_ZN3NFC18openTermsOfServiceEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::openTermsOfService called -> triggering ExtraSettingsDialog");
        JavaVM* jvm = GetHostJavaVM();
        if (jvm) {
            JNIEnv* env = nullptr;
            bool attached = false;
            if (jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
                if (jvm->AttachCurrentThread(&env, nullptr) == JNI_OK) attached = true;
            }
            if (env) {
                jclass nfcCls = env->FindClass("net/fishlabs/gof2hdallandroid2012/NativeFunctionCalls");
                if (nfcCls) {
                    jfieldID fid = env->GetStaticFieldID(nfcCls, "Gof2Activity", "Lnet/fishlabs/gof2hdallandroid2012/GOF2HD2012;");
                    if (fid) {
                        jobject act = env->GetStaticObjectField(nfcCls, fid);
                        if (act) {
                            jclass dlgCls = env->FindClass("net/fishlabs/gof2hdallandroid2012/ExtraSettingsDialog");
                            if (dlgCls) {
                                jmethodID showMethod = env->GetStaticMethodID(dlgCls, "show", "(Landroid/app/Activity;)V");
                                if (showMethod) {
                                    env->CallStaticVoidMethod(dlgCls, showMethod, act);
                                }
                            }
                        }
                    }
                }
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (attached) jvm->DetachCurrentThread();
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC8rateGameEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    RegisterThunk("_ZN3NFC21free_credits_rateGameEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::free_credits_rateGame called -> granting 100,000 credits");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtConsumable");
        if (sym) host.RunFunction(sym, {0});
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC28free_credits_followOnTwitterEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::free_credits_followOnTwitter called -> granting 100,000 credits");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtConsumable");
        if (sym) host.RunFunction(sym, {0});
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC31free_credits_likeGOF2OnFacebookEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::free_credits_likeGOF2OnFacebook called -> granting 100,000 credits");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtConsumable");
        if (sym) host.RunFunction(sym, {0});
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC35free_credits_likeFishlabsOnFacebookEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::free_credits_likeFishlabsOnFacebook called -> granting 100,000 credits");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtConsumable");
        if (sym) host.RunFunction(sym, {0});
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC38free_credits_subscribeToYoutubeChannelEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::free_credits_subscribeToYoutubeChannel called -> granting 100,000 credits");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtConsumable");
        if (sym) host.RunFunction(sym, {0});
        jit.Regs()[0] = 0;
    });

    RegisterThunk("_ZN3NFC23iap_buy_credits_100_000Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::iap_buy_credits_100_000 called -> executing ndk_iapBoughtConsumable(0)");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtConsumable");
        if (sym) host.RunFunction(sym, {0});
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC23iap_buy_credits_300_000Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::iap_buy_credits_300_000 called -> executing ndk_iapBoughtConsumable(1)");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtConsumable");
        if (sym) host.RunFunction(sym, {1});
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC25iap_buy_credits_1_000_000Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::iap_buy_credits_1_000_000 called -> executing ndk_iapBoughtConsumable(2)");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtConsumable");
        if (sym) host.RunFunction(sym, {2});
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC25iap_buy_credits_3_000_000Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::iap_buy_credits_3_000_000 called -> executing ndk_iapBoughtConsumable(3)");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtConsumable");
        if (sym) host.RunFunction(sym, {3});
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC26iap_buy_credits_10_000_000Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::iap_buy_credits_10_000_000 called -> executing ndk_iapBoughtConsumable(4)");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtConsumable");
        if (sym) host.RunFunction(sym, {4});
        jit.Regs()[0] = 0;
    });

    RegisterThunk("_ZN3NFC20iap_buy_dlc_valkyrieEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::iap_buy_dlc_valkyrie called -> unlocking DLC 0");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtPremium");
        if (sym) host.RunFunction(sym, {0, 1});
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC22iap_buy_dlc_kaamo_clubEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::iap_buy_dlc_kaamo_club called -> unlocking DLC 1");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtPremium");
        if (sym) host.RunFunction(sym, {1, 1});
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC21iap_buy_dlc_supernovaEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::iap_buy_dlc_supernova called -> unlocking DLC 2");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtPremium");
        if (sym) host.RunFunction(sym, {2, 1});
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC15iap_buy_dlc_vipEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::iap_buy_dlc_vip called -> activating VIP Addon");
        SetVipAddonEnabled(true);
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC24iap_buy_dlc_full_packageEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::iap_buy_dlc_full_package called -> unlocking all DLCs");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtPremium");
        if (sym) {
            host.RunFunction(sym, {0, 1});
            host.RunFunction(sym, {1, 1});
            host.RunFunction(sym, {2, 1});
            host.RunFunction(sym, {4, 1});
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFC21iap_restore_purchasesEv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("NFC::iap_restore_purchases called");
        uint32_t sym = host.GetElfLoader().GetSymbolAddress("ndk_iapBoughtPremium");
        if (sym) {
            host.RunFunction(sym, {0, 1});
            host.RunFunction(sym, {1, 1});
            host.RunFunction(sym, {2, 1});
            host.RunFunction(sym, {4, 1});
            if (IsVipAddonEnabled()) {
                host.RunFunction(sym, {3, 1});
            }
        }
        jit.Regs()[0] = 0;
    });
    RegisterThunk("_ZN3NFCC1Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_ZN3NFCC2Ev", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });

    // JNIEnv stubs
    RegisterThunk("_ZN7_JNIEnv23CallStaticBooleanMethodEP7_jclassP10_jmethodIDz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_ZN7_JNIEnv19CallStaticIntMethodEP7_jclassP10_jmethodIDz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_ZN7_JNIEnv20CallStaticVoidMethodEP7_jclassP10_jmethodIDz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_ZN7_JNIEnv13CallIntMethodEP8_jobjectP10_jmethodIDz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
    RegisterThunk("_ZN7_JNIEnv14CallVoidMethodEP8_jobjectP10_jmethodIDz", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { jit.Regs()[0] = 0; });
}


void ThunkManager::RegisterThunk(const std::string& name, ThunkHandler handler) {
    uint32_t thunk_id = static_cast<uint32_t>(m_id_to_handler.size() + 1);
    uint32_t thunk_addr = m_next_thunk_addr;
    m_next_thunk_addr += 8; // 2 instructions per trampoline

    // Write ARM32 trampoline instructions into guest memory:
    // 0: SVC #thunk_id (0xEF000000 | thunk_id)
    // 4: BX LR (0xE12FFF1E)
    uint32_t svc_instr = 0xEF000000 | (thunk_id & 0x00FFFFFF);
    uint32_t bx_lr_instr = 0xE12FFF1E;

    m_host.MemoryWrite32(thunk_addr, svc_instr);
    m_host.MemoryWrite32(thunk_addr + 4, bx_lr_instr);
    // Trampolines are also created at runtime (dlsym, OpenSL ES vtables), so the JIT may
    // already hold a translation of this address range.
    m_host.InvalidateGuestCode(thunk_addr, 8);

    m_symbol_to_address[name] = thunk_addr;
    if (thunk_id < kDispatchTableSize) m_dispatch[thunk_id] = handler;   // copy BEFORE the move below
    m_id_to_handler[thunk_id] = std::move(handler);
    m_id_to_name[thunk_id] = name;
}

void ThunkManager::RegisterSymbol(const std::string& name, uint32_t address) {
    m_symbol_to_address[name] = address;
}

uint32_t ThunkManager::GetOrCreateThunkAddress(const std::string& name) {
    auto it = m_symbol_to_address.find(name);
    if (it != m_symbol_to_address.end()) {
        return it->second;
    }
    // Default dummy stub if not explicitly registered
    // Log only the first few hits per symbol. This device's Oplus LOG_FLOWCTRL drops a
    // process's logcat output above ~300 rows/s, and a chatty stub (getenv,
    // __google_potentially_blocking_region_*) was silently pushing real diagnostics out of
    // the buffer -- including the ReportQuit dump we need to read.
    RegisterThunk(name, [name, hits = 0](Dynarmic::A32::Jit& jit, DynarmicHost& host) mutable {
        // The caller matters more than the name: "0 is a lie" only for some of these, and
        // which one it is depends on who asks (sysinfo from a memory-tier probe is fatal,
        // getenv("TMPDIR") is not). Print LR + the first four argument registers once.
        if (hits < 3) {
            const auto& r = jit.Regs();
            LOGI("[THUNK] Default stub executed for: %s  from %s  r0=%08x r1=%08x r2=%08x r3=%08x",
                 name.c_str(), host.DescribeAddress(r[14]).c_str(), r[0], r[1], r[2], r[3]);
        } else if (hits == 3) {
            LOGI("[THUNK] Default stub for %s: further hits silenced", name.c_str());
        }
        ++hits;
        jit.Regs()[0] = 0;
    });
    return m_symbol_to_address[name];
}

// Guest errno lives at this fixed address; the __errno thunk hands it out (thunks_libc.cpp).
static constexpr uint32_t kGuestErrnoAddr = 0x300;

const char* ThunkManager::GetThunkName(uint32_t thunk_id) const {
    auto it = m_id_to_name.find(thunk_id);
    return it == m_id_to_name.end() ? "" : it->second.c_str();
}

// --- frame profiler ------------------------------------------------------------------------
// See thunk_manager.h. Only the render thread is sampled and only the outermost thunk is
// timed: a thunk that re-enters the guest (qsort's comparator, a JNI callback) would
// otherwise be charged for its children twice, and the numbers stop adding up to a frame.
namespace {

struct ThunkCost { uint64_t ns = 0; uint32_t calls = 0; };
std::unordered_map<uint32_t, ThunkCost> g_frame_cost;
thread_local int g_thunk_depth = 0;
pid_t g_profile_tid = 0;          // 0 = profiling off
ThunkManager* g_profile_owner = nullptr;

inline uint64_t NowNs() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + ts.tv_nsec;
}

bool ProfileRequested() {
    char v[PROP_VALUE_MAX] = {};
    __system_property_get("debug.abgo.profile", v);
    return v[0] == '1';
}

}  // namespace

void ThunkProfileFrameBegin() {
    static const bool enabled = ProfileRequested();
    if (!enabled) return;
    g_profile_tid = gettid();
    g_frame_cost.clear();
}

void ThunkProfileFrameEnd(double frame_ms) {
    const pid_t tid = g_profile_tid;
    g_profile_tid = 0;                       // stop sampling until the next frame begins
    if (!tid) return;

    // 60 Hz budget with a little slack. Anything under this is not what drops the counter.
    if (frame_ms < 20.0) return;

    std::vector<std::pair<uint32_t, ThunkCost>> top(g_frame_cost.begin(), g_frame_cost.end());
    std::partial_sort(top.begin(), top.begin() + std::min<size_t>(8, top.size()), top.end(),
                      [](const auto& a, const auto& b) { return a.second.ns > b.second.ns; });
    if (top.size() > 8) top.resize(8);

    uint64_t total_ns = 0;
    uint64_t total_calls = 0;
    for (const auto& e : g_frame_cost) { total_ns += e.second.ns; total_calls += e.second.calls; }

    LOGI("[PROF] frame %.2f ms -- %llu thunk calls, %.2f ms in thunks",
         frame_ms, static_cast<unsigned long long>(total_calls), total_ns / 1e6);
    for (const auto& e : top) {
        const char* name = g_profile_owner ? g_profile_owner->GetThunkName(e.first) : "";
        LOGI("[PROF]   %-28s %6u calls  %7.3f ms", (name && *name) ? name : "?",
             e.second.calls, e.second.ns / 1e6);
    }
}

void ThunkManager::DispatchThunk(uint32_t thunk_id, Dynarmic::A32::Jit& jit) {
    // Hot path: dense-id table index. The cold fallback (unknown id) still goes through
    // the map, which only ever matters for ids past the table or genuine garbage.
    ThunkHandler* handler = nullptr;
    if (thunk_id > 0 && thunk_id < kDispatchTableSize) {
        handler = &m_dispatch[thunk_id];
        if (!*handler) handler = nullptr;
    }

    if (handler) {
        errno = 0;
        const bool timed = g_profile_tid != 0 && g_thunk_depth == 0 && gettid() == g_profile_tid;
        const uint64_t t0 = timed ? NowNs() : 0;
        ++g_thunk_depth;
        (*handler)(jit, m_host);
        --g_thunk_depth;
        if (timed) {
            g_profile_owner = this;
            auto& c = g_frame_cost[thunk_id];
            c.ns += NowNs() - t0;
            c.calls++;
        }
        // Publish errno to the guest. Nothing did this before, so *__errno() was permanently
        // zero -- and the engine's file opener treats "failed but errno == 0" as "retry", so a
        // missing file was an infinite fopen loop rather than an error
        // (CXGSFileSystemPOSIX::Open). Every thunk here calls real libc, so the host errno is
        // the right value to forward.
        //
        // Only when it is nonzero, which is also what C guarantees: a successful call never
        // clears errno. Clearing unconditionally is worse than not doing this at all, because
        // the very next thunk the guest runs is __errno itself -- it would hand back a pointer
        // to a cell it had just zeroed.
        if (errno != 0) m_host.MemoryWrite32(kGuestErrnoAddr, static_cast<uint32_t>(errno));
    } else {
        auto name_it = m_id_to_name.find(thunk_id);
        const char* name = (name_it != m_id_to_name.end()) ? name_it->second.c_str() : "unknown";
        LOGE("[THUNK] Unknown thunk ID: %u (%s) at PC: 0x%08X", thunk_id, name, jit.Regs()[15]);
        jit.Regs()[0] = 0;
    }
}

void ThunkManager::SetupGuestJNIEnv() {
    // Allocate table for 256 JNINativeInterface function pointers (1024 bytes)
    uint32_t table_addr = m_host.GuestAlloc(256 * 4, 8);
    // Allocate JNIEnv* (4 bytes pointing to table_addr)
    m_guest_jni_env = m_host.GuestAlloc(4, 4);
    m_host.MemoryWrite32(m_guest_jni_env, table_addr);

    // Default thunk for generic JNI methods
    uint32_t default_jni_thunk = GetOrCreateThunkAddress("JNI_GenericStub");

    for (int i = 0; i < 256; ++i) {
        m_host.MemoryWrite32(table_addr + i * 4, default_jni_thunk);
    }

    // Register specific handlers for common JNI functions:
    // Offset 0x18 (index 6): FindClass
    RegisterThunk("JNI_FindClass", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        LOGI("JNI FindClass('%s') called -> 0x3000", name ? name : "null");
        jit.Regs()[0] = 0x3000;
    });
    m_host.MemoryWrite32(table_addr + 6 * 4, m_symbol_to_address["JNI_FindClass"]);

    // Offset 0x84 (index 33): GetMethodID
    RegisterThunk("JNI_GetMethodID", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        const char* sig = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        LOGI("JNI GetMethodID('%s', '%s') called -> 0x2000", name ? name : "null", sig ? sig : "null");
        jit.Regs()[0] = 0x2000;
    });
    m_host.MemoryWrite32(table_addr + 33 * 4, m_symbol_to_address["JNI_GetMethodID"]);

    // Offset 0x1C4 (index 113): GetStaticMethodID
    RegisterThunk("JNI_GetStaticMethodID", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        const char* sig = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        uint32_t methodID = 0x2000;
        if (name) {
            if (strcmp(name, "getDisplayWidth") == 0) methodID = 0x2001;
            else if (strcmp(name, "getDisplayHeight") == 0) methodID = 0x2002;
            else if (strcmp(name, "getDensity") == 0) methodID = 0x2003;
            else if (strcmp(name, "isPad") == 0) methodID = 0x2004;
        }
        LOGI("JNI GetStaticMethodID('%s', '%s') called -> 0x%X", name ? name : "null", sig ? sig : "null", methodID);
        jit.Regs()[0] = methodID;
    });
    m_host.MemoryWrite32(table_addr + 113 * 4, m_symbol_to_address["JNI_GetStaticMethodID"]);

    // Offset 0x234 (index 141): CallStaticVoidMethod
    RegisterThunk("JNI_CallStaticVoidMethod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("JNI CallStaticVoidMethod called");
    });
    m_host.MemoryWrite32(table_addr + 141 * 4, m_symbol_to_address["JNI_CallStaticVoidMethod"]);

    // Offset 0x204 (index 129): CallStaticIntMethod
    RegisterThunk("JNI_CallStaticIntMethod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t methodID = jit.Regs()[2];
        if (methodID == 0x2001) {
            ExtraSettings& ext = GetExtraSettings();
            float scale = (ext.forced_dpi > 0) ? ((float)ext.forced_dpi / 320.0f) : 1.0f;
            if (scale < 0.2f || scale > 4.0f) scale = 1.0f;
            uint32_t virt_w = (uint32_t)((float)ThunkManager::s_screenWidth * scale);
            LOGI("JNI CallStaticIntMethod(getDisplayWidth) -> %u (raw=%u, scale=%.2f)", virt_w, ThunkManager::s_screenWidth, scale);
            jit.Regs()[0] = virt_w;
        } else if (methodID == 0x2002) {
            ExtraSettings& ext = GetExtraSettings();
            float scale = (ext.forced_dpi > 0) ? ((float)ext.forced_dpi / 320.0f) : 1.0f;
            if (scale < 0.2f || scale > 4.0f) scale = 1.0f;
            uint32_t virt_h = (uint32_t)((float)ThunkManager::s_screenHeight * scale);
            LOGI("JNI CallStaticIntMethod(getDisplayHeight) -> %u (raw=%u, scale=%.2f)", virt_h, ThunkManager::s_screenHeight, scale);
            jit.Regs()[0] = virt_h;
        } else if (methodID == 0x2003) {
            uint32_t density = QueryDeviceDensity();
            LOGI("JNI CallStaticIntMethod(getDensity) -> %u", density);
            jit.Regs()[0] = density;
        } else {
            LOGI("JNI CallStaticIntMethod (method=0x%X) -> 0", methodID);
            jit.Regs()[0] = 0;
        }
    });
    m_host.MemoryWrite32(table_addr + 129 * 4, m_symbol_to_address["JNI_CallStaticIntMethod"]);

    // Offset 0x1D4 (index 117): CallStaticBooleanMethod
    RegisterThunk("JNI_CallStaticBooleanMethod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t methodID = jit.Regs()[2];
        if (methodID == 0x2004) {
            bool is_pad = QueryDeviceIsPad();
            LOGI("JNI CallStaticBooleanMethod(isPad) -> %d", is_pad ? 1 : 0);
            jit.Regs()[0] = is_pad ? 1 : 0;
        } else {
            LOGI("JNI CallStaticBooleanMethod (method=0x%X) -> 0 (false)", methodID);
            jit.Regs()[0] = 0;
        }
    });
    m_host.MemoryWrite32(table_addr + 117 * 4, m_symbol_to_address["JNI_CallStaticBooleanMethod"]);

    // Offset 0x1C8 (index 114): CallStaticObjectMethod
    RegisterThunk("JNI_CallStaticObjectMethod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("JNI CallStaticObjectMethod called -> 0x4000");
        jit.Regs()[0] = 0x4000;
    });
    m_host.MemoryWrite32(table_addr + 114 * 4, m_symbol_to_address["JNI_CallStaticObjectMethod"]);

    // Offset 0xF4 (index 61): CallVoidMethod
    RegisterThunk("JNI_CallVoidMethod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("JNI CallVoidMethod called");
    });
    m_host.MemoryWrite32(table_addr + 61 * 4, m_symbol_to_address["JNI_CallVoidMethod"]);

    // Offset 0xC4 (index 49): CallIntMethod
    RegisterThunk("JNI_CallIntMethod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("JNI CallIntMethod called -> 0");
        jit.Regs()[0] = 0;
    });
    m_host.MemoryWrite32(table_addr + 49 * 4, m_symbol_to_address["JNI_CallIntMethod"]);

    // Offset 0x94 (index 37): CallBooleanMethod
    RegisterThunk("JNI_CallBooleanMethod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("JNI CallBooleanMethod called -> 0 (false)");
        jit.Regs()[0] = 0;
    });
    m_host.MemoryWrite32(table_addr + 37 * 4, m_symbol_to_address["JNI_CallBooleanMethod"]);

    // Offset 0x88 (index 34): CallObjectMethod
    RegisterThunk("JNI_CallObjectMethod", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        LOGI("JNI CallObjectMethod called -> 0x4000");
        jit.Regs()[0] = 0x4000;
    });
    m_host.MemoryWrite32(table_addr + 34 * 4, m_symbol_to_address["JNI_CallObjectMethod"]);

    // Offset 0x29C (index 167): NewStringUTF
    RegisterThunk("JNI_NewStringUTF", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* str = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        if (str) {
            uint32_t gstr = host.GuestAlloc(strlen(str) + 1);
            strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + gstr), str);
            jit.Regs()[0] = gstr;
        } else {
            jit.Regs()[0] = 0;
        }
    });
    m_host.MemoryWrite32(table_addr + 167 * 4, m_symbol_to_address["JNI_NewStringUTF"]);

    // Offset 0x2A4 (index 169): GetStringUTFChars
    RegisterThunk("JNI_GetStringUTFChars", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t jstr = jit.Regs()[1];
        jit.Regs()[0] = jstr;
    });
    m_host.MemoryWrite32(table_addr + 169 * 4, m_symbol_to_address["JNI_GetStringUTFChars"]);

    // Offset 0x2A8 (index 170): ReleaseStringUTFChars
    RegisterThunk("JNI_ReleaseStringUTFChars", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {});
    m_host.MemoryWrite32(table_addr + 170 * 4, m_symbol_to_address["JNI_ReleaseStringUTFChars"]);

    // Offset 0x2B0 (index 172): GetArrayLength
    RegisterThunk("JNI_GetArrayLength", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = 5;
    });
    m_host.MemoryWrite32(table_addr + 172 * 4, m_symbol_to_address["JNI_GetArrayLength"]);

    // Offset 0x2B4 (index 173): GetObjectArrayElement
    RegisterThunk("JNI_GetObjectArrayElement", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t array_ptr = jit.Regs()[1];
        uint32_t index = jit.Regs()[2];
        if (array_ptr) {
            uint32_t elem = host.MemoryRead32(array_ptr + index * 4);
            jit.Regs()[0] = elem;
        } else {
            jit.Regs()[0] = 0;
        }
    });
    m_host.MemoryWrite32(table_addr + 173 * 4, m_symbol_to_address["JNI_GetObjectArrayElement"]);

    LOGI("Guest JNIEnv configured at 0x%08X (table at 0x%08X)", m_guest_jni_env, table_addr);
}


// --- stall trace ring ----------------------------------------------------------------------
// Enter/exit breadcrumbs from the guest entry points (RunFunction, the frame loop, the
// audio pump, the job pump). Written lock-free on the hot path; the dump walks the ring
// under a mutex only when a stall is being reported. This is what answers "blocked WHERE"
// for a process no debugger can dump without root: the event with an enter and no exit IS
// the blocking call.
namespace {
struct TraceSlot {
    std::atomic<uint64_t> seq{0};
    const char* what = nullptr;
    uint32_t a = 0, b = 0;
    std::atomic<uint64_t> tid{0};
};
constexpr size_t kTraceSlots = 512;
TraceSlot g_trace[kTraceSlots];
std::atomic<uint64_t> g_trace_seq{1};

}  // namespace

void TraceEvent(const char* what, uint32_t a, uint32_t b) {
    const uint64_t s = g_trace_seq.fetch_add(1, std::memory_order_relaxed);
    TraceSlot& t = g_trace[s % kTraceSlots];
    t.a = a; t.b = b;
    t.what = what;
    t.tid.store(static_cast<uint64_t>(gettid()), std::memory_order_relaxed);
    t.seq.store(s, std::memory_order_release);
}

void TraceDump(const char* why) {
    LOGE("[TRACE] %s -- last events (enter without exit = the blocker):", why);
    const uint64_t newest = g_trace_seq.load(std::memory_order_acquire) - 1;
    for (uint64_t i = 0; i < kTraceSlots; ++i) {
        const uint64_t s = newest - i;
        if (s == 0) break;
        TraceSlot& t = g_trace[s % kTraceSlots];
        const uint64_t seen = t.seq.load(std::memory_order_acquire);
        if (seen != s) continue;   // overwritten while dumping
        LOGE("[TRACE]   seq=%llu tid=%llu %s a=%08X b=%u",
             static_cast<unsigned long long>(s),
             static_cast<unsigned long long>(t.tid.load(std::memory_order_relaxed)),
             t.what ? t.what : "?", t.a, t.b);
    }
}
