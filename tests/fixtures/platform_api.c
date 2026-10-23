// SPDX-License-Identifier: AGPL-3.0-or-later
// Test-only shared library: distinctive results prove adapters forward ABI arguments without
// fabricating policy. This is not a replacement SELinux/minijail implementation.
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>

int socket_local_server(const char* name, int space, int type) { return 1000 + space * 10 + type + (int)strlen(name); }
int socket_local_client(const char* name, int space, int type) { return 2000 + space * 10 + type + (int)strlen(name); }
int socket_inaddr_any_server(int port, int type) {
    int fd = socket(AF_INET, type | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (bind(fd, (struct sockaddr*)&address, sizeof(address)) || listen(fd, 4)) {
        int error = errno; close(fd); errno = error; return -1;
    }
    return fd;
}
int socket_network_client_timeout(const char* host, int port, int type, int timeout, int* error) {
    (void)host; (void)port; (void)type; (void)timeout; (void)error; errno = ENOTSUP; return -1;
}
int socket_get_local_port(int fd) {
    struct sockaddr_in address = {0};
    socklen_t size = sizeof(address);
    return getsockname(fd, (struct sockaddr*)&address, &size) == 0 ? ntohs(address.sin_port) : -1;
}
int selinux_android_setcon(const char* label) {
    return strcmp(label, "fixture-label") == 0 || (getenv("IRA_TEST_REAL_DROP") && strcmp(label, "u:r:adbd:s0") == 0) ? 0 : -1;
}
int selinux_android_restorecon(const char* path, unsigned flags) { return (int)strlen(path) + flags; }
#ifndef IRA_LEGACY_POLICY
bool adbd_fs_config(const char* path, bool directory, const char* target, uid_t* uid, gid_t* gid,
                    mode_t* mode, uint64_t* capabilities) {
    if (getenv("IRA_TEST_REAL_DROP") || strcmp(path, "/preserve") == 0) return false;
    *uid = 123 + directory; *gid = 456; *mode = 0754; *capabilities = 0x12345678;
    return target && strcmp(target, "target") == 0;
}
#endif
void fs_config(const char* path, int directory, const char* target, unsigned* uid, unsigned* gid,
               unsigned* mode, uint64_t* capabilities) {
    (void)path; (void)target;
    *uid = 789 + directory; *gid = 987; *mode = 0712; *capabilities = 0x87654321;
}
struct test_jail { uid_t uid; gid_t gid; };
void* minijail_new(void) { struct test_jail* jail = calloc(1, sizeof(*jail)); jail->uid = getuid(); jail->gid = getgid(); return jail; }
void minijail_destroy(void* jail) { free(jail); }
void minijail_set_supplementary_gids(void* jail, size_t size, const gid_t* list) { (void)jail; (void)size; (void)list; }
void minijail_change_uid(void* jail, uid_t uid) { ((struct test_jail*)jail)->uid = uid; }
void minijail_change_gid(void* jail, gid_t gid) { ((struct test_jail*)jail)->gid = gid; }
void minijail_use_caps(void* jail, uint64_t caps) { (void)jail; (void)caps; }
void minijail_enter(const void* opaque) {
    const struct test_jail* jail = opaque;
    if (getenv("IRA_TEST_REAL_DROP") && (setgroups(0, NULL) || setgid(jail->gid) || setuid(jail->uid))) abort();
}
void* cap_get_proc(void) { return malloc(1); }
int cap_clear_flag(void* caps, int flag) { (void)caps; return flag >= 0 && flag <= 2 ? 0 : -1; }
int cap_set_proc(void* caps) { (void)caps; return 0; }
#ifndef IRA_MISSING_API
int cap_free(void* caps) { free(caps); return 0; }
#endif
