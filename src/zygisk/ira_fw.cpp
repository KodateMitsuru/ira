// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Loader for the framework half.
 *
 * The payload is a dex (src/zygisk/java/ira/fw/IraFw.java) embedded in this library and loaded into
 * system_server with InMemoryDexClassLoader - the ZygoteLoader pattern. It is embedded rather than
 * read from the module directory because system_server cannot read /data/adb, and nothing is written
 * to disk to make it work.
 */
#define LOG_TAG "ira-fw"

#include <android/log.h>
#include <jni.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "api/zygisk.hpp"
#include "ira_dex.h"   /* generated at build time: defines ira_dex[], ira_dex_len */

namespace {

JavaVM *g_vm = nullptr;
jobject g_payload = nullptr;
jmethodID g_main = nullptr;

/* Written in place by the installer: this installation's "auth" endpoint, exactly as the daemon
 * reads it from "names". The array has room for the longest name the installer writes, so the
 * replacement never moves anything; the installer verifies the token before and after the write. */
char kSocketName[33] = "IRA-SOCKET-NAME-0000000000000000";
char kControlName[33] = "IRA-CONTROL-NAME-00000000000000";

void log_jni(JNIEnv *env, const char *where) {
    if (env->ExceptionCheck()) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "jni exception at %s", where);
        env->ExceptionDescribe();
        env->ExceptionClear();
        return;
    }
    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "%s failed", where);
}

jclass load_payload(JNIEnv *env) {
    jclass buffer_cls = env->FindClass("java/nio/ByteBuffer");
    jclass loader_cls = env->FindClass("java/lang/ClassLoader");
    jclass dcl_cls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    jmethodID wrap, get_system, ctor;

    if (buffer_cls == nullptr || loader_cls == nullptr || dcl_cls == nullptr) {
        log_jni(env, "payload classes");
        return nullptr;
    }
    wrap = env->GetStaticMethodID(buffer_cls, "wrap", "([B)Ljava/nio/ByteBuffer;");
    get_system = env->GetStaticMethodID(loader_cls, "getSystemClassLoader",
                                        "()Ljava/lang/ClassLoader;");
    ctor = env->GetMethodID(dcl_cls, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (wrap == nullptr || get_system == nullptr || ctor == nullptr) {
        log_jni(env, "payload methods");
        return nullptr;
    }

    jbyteArray bytes = env->NewByteArray((jsize)ira_dex_len);

    if (bytes == nullptr) {
        log_jni(env, "dex array");
        return nullptr;
    }
    env->SetByteArrayRegion(bytes, 0, (jsize)ira_dex_len,
                            reinterpret_cast<const jbyte *>(ira_dex));

    jobject buffer = env->CallStaticObjectMethod(buffer_cls, wrap, bytes);
    jobject parent = env->CallStaticObjectMethod(loader_cls, get_system);
    jobject loader = env->NewObject(dcl_cls, ctor, buffer, parent);

    if (loader == nullptr) {
        log_jni(env, "InMemoryDexClassLoader");
        return nullptr;
    }

    jmethodID load = env->GetMethodID(loader_cls, "loadClass",
                                      "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring name = env->NewStringUTF("ira.fw.IraFw");
    auto cls = load != nullptr ? static_cast<jclass>(env->CallObjectMethod(loader, load, name))
                               : nullptr;

    if (cls == nullptr)
        log_jni(env, "loadClass ira.fw.IraFw");
    return cls;
}

void *payload_main(void *) {
    JNIEnv *env = nullptr;

    if (g_vm == nullptr || g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK)
        return nullptr;
    env->CallStaticVoidMethod(static_cast<jclass>(g_payload), g_main);
    if (env->ExceptionCheck())
        env->ExceptionDescribe();
    g_vm->DetachCurrentThread();
    return nullptr;
}

class FrameworkHalf : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *) override {
        // The framework payload belongs only to system_server, never to an app process.
        api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void postServerSpecialize(const zygisk::ServerSpecializeArgs *) override {
        if (g_payload != nullptr)
            return;
        if (env_->GetJavaVM(&g_vm) != JNI_OK)
            return;

        jclass cls = load_payload(env_);

        if (cls == nullptr) {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "payload did not load");
            return;
        }
        g_main = env_->GetStaticMethodID(cls, "main", "()V");
        jfieldID name_field = env_->GetStaticFieldID(cls, "sockName", "Ljava/lang/String;");

        jfieldID control_field = env_->GetStaticFieldID(cls, "controlName", "Ljava/lang/String;");

        if (g_main == nullptr || name_field == nullptr || control_field == nullptr) {
            log_jni(env_, "payload entry");
            return;
        }
        env_->SetStaticObjectField(cls, name_field, env_->NewStringUTF(kSocketName));
        env_->SetStaticObjectField(cls, control_field, env_->NewStringUTF(kControlName));
        g_payload = env_->NewGlobalRef(cls);

        pthread_t t;

        if (pthread_create(&t, nullptr, payload_main, nullptr) == 0)
            pthread_detach(t);
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
};

}  // namespace

REGISTER_ZYGISK_MODULE(FrameworkHalf)
