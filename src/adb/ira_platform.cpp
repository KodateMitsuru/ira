// SPDX-License-Identifier: AGPL-3.0-or-later
// Platform policy is owned by Android. Do not duplicate fs_config tables, SELinux policy or
// minijail's capability/uid transition implementation in this daemon.
#include "ira_platform.h"
#include "ira_platform.h"
#include <dlfcn.h>
#include <errno.h>
#include <linux/capability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

namespace {
struct minijail;
struct Api {
    void* utils = nullptr;
    void* se = nullptr;
    void* fs = nullptr;
    void* jail = nullptr;
    void* cap = nullptr;
    int (*server)(const char*, int, int) = nullptr;
    int (*client)(const char*, int, int) = nullptr;
    int (*inaddr_server)(int, int) = nullptr;
    int (*local_port)(int) = nullptr;
    int (*network_client)(const char*, int, int, int, int*) = nullptr;
    int (*setcon)(const char*) = nullptr;
    int (*restorecon)(const char*, unsigned) = nullptr;
    bool (*config)(const char*, bool, const char*, uid_t*, gid_t*, mode_t*, uint64_t*) = nullptr;
    void (*legacy_config)(const char*, int, const char*, unsigned*, unsigned*, unsigned*, uint64_t*) = nullptr;
    minijail* (*create)() = nullptr;
    void (*destroy)(minijail*) = nullptr;
    void (*groups)(minijail*, size_t, const gid_t*) = nullptr;
    void (*uid)(minijail*, uid_t) = nullptr;
    void (*gid)(minijail*, gid_t) = nullptr;
    void (*caps)(minijail*, uint64_t) = nullptr;
    void (*enter)(const minijail*) = nullptr;
    void* (*cap_get)() = nullptr;
    int (*cap_clear)(void*, int) = nullptr;
    int (*cap_set)(void*) = nullptr;
    int (*cap_free)(void*) = nullptr;
    bool ready = false;
} api;
template<class T> bool symbol(void* library, const char* name, T* result) {
    *result = library ? reinterpret_cast<T>(dlsym(library, name)) : nullptr;
    if (*result) return true;
    const char* reason = dlerror();
    fprintf(stderr, "ira-platform: unavailable API %s: %s\n", name, reason ? reason : "symbol not exported");
    errno = ENOSYS;
    return false;
}
}

int ira_platform_init() {
    if (api.ready) return 0;
    api.utils = dlopen("libcutils.so", RTLD_NOW | RTLD_LOCAL);
    api.se = dlopen("libselinux.so", RTLD_NOW | RTLD_LOCAL);
    api.fs = dlopen("libadbd_fs.so", RTLD_NOW | RTLD_LOCAL);
    api.jail = dlopen("libminijail.so", RTLD_NOW | RTLD_LOCAL);
    api.cap = dlopen("libcap.so", RTLD_NOW | RTLD_LOCAL);
    if (!symbol(api.utils, "socket_local_server", &api.server) ||
        !symbol(api.utils, "socket_local_client", &api.client) ||
        !symbol(api.utils, "socket_inaddr_any_server", &api.inaddr_server) ||
        !symbol(api.utils, "socket_get_local_port", &api.local_port) ||
        !symbol(api.utils, "socket_network_client_timeout", &api.network_client) ||
        !symbol(api.se, "selinux_android_setcon", &api.setcon) ||
        !symbol(api.se, "selinux_android_restorecon", &api.restorecon) ||
        !symbol(api.jail, "minijail_new", &api.create) ||
        !symbol(api.jail, "minijail_destroy", &api.destroy) ||
        !symbol(api.jail, "minijail_set_supplementary_gids", &api.groups) ||
        !symbol(api.jail, "minijail_change_uid", &api.uid) ||
        !symbol(api.jail, "minijail_change_gid", &api.gid) ||
        !symbol(api.jail, "minijail_use_caps", &api.caps) ||
        !symbol(api.jail, "minijail_enter", &api.enter) ||
        !symbol(api.cap, "cap_get_proc", &api.cap_get) ||
        !symbol(api.cap, "cap_clear_flag", &api.cap_clear) ||
        !symbol(api.cap, "cap_set_proc", &api.cap_set) ||
        !symbol(api.cap, "cap_free", &api.cap_free)) return -1;
    api.config = api.fs ? reinterpret_cast<decltype(api.config)>(dlsym(api.fs, "adbd_fs_config")) : nullptr;
    // Android releases before libadbd_fs use libcutils directly, as their adbd did.
    if (!api.config && !symbol(api.utils, "fs_config", &api.legacy_config)) return -1;
    api.ready = true;
    return 0;
}

extern "C" int socket_local_server(const char* name, int space, int type) {
    if (!api.ready) { errno = ENOSYS; return -1; }
    return api.server(name, space, type);
}
extern "C" int socket_local_client(const char* name, int space, int type) {
    if (!api.ready) { errno = ENOSYS; return -1; }
    return api.client(name, space, type);
}
extern "C" int socket_get_local_port(int fd) {
    if (!api.ready) { errno = ENOSYS; return -1; }
    return api.local_port(fd);
}
extern "C" int socket_inaddr_any_server(int port, int type) {
    if (!api.ready) { errno = ENOSYS; return -1; }
    return api.inaddr_server(port, type);
}
extern "C" int socket_network_client_timeout(const char* host, int port, int type, int timeout, int* error) {
    if (!api.ready) { errno = ENOSYS; return -1; }
    return api.network_client(host, port, type, timeout, error);
}
extern "C" int selinux_android_setcon(const char* label) {
    if (!api.ready) { errno = ENOSYS; return -1; }
    return api.setcon(label);
}
extern "C" int selinux_android_restorecon(const char* path, unsigned flags) {
    if (!api.ready) { errno = ENOSYS; return -1; }
    return api.restorecon(path, flags);
}
bool adbd_fs_config(const char* path, bool directory, const char* target, uid_t* uid, gid_t* gid,
                    mode_t* mode, uint64_t* capabilities) {
    if (!api.ready) { errno = ENOSYS; return false; }
    if (api.config) return api.config(path, directory, target, uid, gid, mode, capabilities);
    api.legacy_config(path, directory, target, uid, gid, mode, capabilities);
    return true;
}

int ira_platform_enter_service_identity(bool root) {
    if (!api.ready) { errno = ENOSYS; return -1; }
    // The group list and two-stage capability clearing follow AOSP daemon/main.cpp.
    static const gid_t groups[] = {1011, 1007, 1004, 3003, 3002, 3001, 1028, 1015,
                                   3006, 3009, 3011, 1078, 1079, 3012};
    minijail* jail = api.create();
    if (!jail) { errno = ENOMEM; return -1; }
    api.groups(jail, sizeof(groups) / sizeof(gid_t), groups);
    if (!root) {
        if (api.setcon("u:r:adbd:s0") < 0) { api.destroy(jail); return -1; }
        api.caps(jail, CAP_TO_MASK(CAP_SETUID) | CAP_TO_MASK(CAP_SETGID) | CAP_TO_MASK(CAP_SYS_NICE));
        api.gid(jail, 2000);
        api.uid(jail, 2000);
    }
    // minijail_enter aborts on a failed transition. It cannot silently continue as root.
    api.enter(jail);
    api.destroy(jail);
    if (!root) {
        void* caps = api.cap_get();
        if (!caps) return -1;
        // libcap ABI: effective=0, permitted=1, inheritable=2.
        bool ok = api.cap_clear(caps, 2) == 0 && api.cap_clear(caps, 0) == 0 &&
                  api.cap_clear(caps, 1) == 0 && api.cap_set(caps) == 0;
        int error = errno;
        api.cap_free(caps);
        if (!ok) { errno = error; return -1; }
    }
    if (geteuid() != (root ? 0 : 2000) || getegid() != (root ? 0 : 2000)) {
        errno = EPERM; return -1;
    }
    return 0;
}
