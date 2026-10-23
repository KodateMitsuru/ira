// SPDX-License-Identifier: AGPL-3.0-or-later
#include <initializer_list>
#include "../src/adb/ira_platform.h"
#include <cutils/sockets.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
static unsigned checks;
static void expect(bool yes) { if (!yes) { fprintf(stderr, "FAIL: platform adapter check %u\n", checks + 1); abort(); } ++checks; }
int main(int argc, char** argv) {
    expect(argc == 2);
    expect(socket_local_server("x", 0, 1) == -1 && errno == ENOSYS);
    if (strcmp(argv[1], "missing") == 0) {
        expect(ira_platform_init() == -1 && errno == ENOSYS);
        expect(socket_local_client("x", 0, 1) == -1 && errno == ENOSYS);
    } else {
        expect(ira_platform_init() == 0);
        expect(ira_platform_init() == 0);
        for (int space : {0, 1, 2}) {
            expect(socket_local_server("path", space, 1) == 1005 + space * 10);
            expect(socket_local_client("path", space, 1) == 2005 + space * 10);
        }
        expect(selinux_android_setcon("fixture-label") == 0);
        expect(selinux_android_restorecon("/file", 17) == 22);
        uid_t uid = -1; gid_t gid = -1; mode_t mode = 0640; uint64_t caps = 0;
        expect(adbd_fs_config("/path", true, "target", &uid, &gid, &mode, &caps));
        if (strcmp(argv[1], "legacy") == 0) {
            expect(uid == 790 && gid == 987 && mode == 0712 && caps == 0x87654321);
        } else {
            expect(uid == 124 && gid == 456 && mode == 0754 && caps == 0x12345678);
            uid = 321; gid = 654; mode = 0600; caps = 42;
            expect(!adbd_fs_config("/preserve", false, nullptr, &uid, &gid, &mode, &caps));
            expect(uid == 321 && gid == 654 && mode == 0600 && caps == 42);
        }
    }
    printf("PASS: %u platform API forwarding checks (%s)\n", checks, argv[1]);
}
