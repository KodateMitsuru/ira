// SPDX-License-Identifier: AGPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/wait.h>
#include "../src/adb/ira_ffs.cpp"

static unsigned checks;
static void expect(bool yes, const char* what) {
    if (!yes) { fprintf(stderr, "FAIL: %s (%s)\n", what, strerror(errno)); exit(1); }
    ++checks;
}
static ino_t namespace_id() {
    struct stat status{};
    if (stat("/proc/thread-self/ns/mnt", &status) != 0) std::abort();
    return status.st_ino;
}
static void create_at(int directory, const char* name) {
    int fd = openat(directory, name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    expect(fd >= 0, "fixture file created through directory fd");
    close(fd);
}

int main(int argc, char** argv) {
    alarm(20);
    expect(argc == 2, "fixture root supplied");
    const std::string root = argv[1];
    const std::string target = root + "/private-ffs";
    const std::string late = root + "/late-storage";
    expect(mkdir(target.c_str(), 0700) == 0 && mkdir(late.c_str(), 0700) == 0,
           "mount targets created in repo build directory");
    const ino_t inherited = namespace_id();
    g_ffs_dir = mount_private("namespace-fixture", target.c_str(), "tmpfs");
    expect(g_ffs_dir >= 0, "private mount directory survives bootstrap thread exit");
    expect(namespace_id() == inherited, "daemon main thread never leaves inherited namespace");
    expect(fcntl(g_ffs_dir, F_GETFD) & FD_CLOEXEC, "private directory not leaked across exec");
    create_at(g_ffs_dir, "ep0");
    create_at(g_ffs_dir, "ep1");
    create_at(g_ffs_dir, "ep2");
    expect(access((target + "/ep0").c_str(), F_OK) != 0 && errno == ENOENT,
           "private endpoint path absent from inherited view");
    int ep0 = open_ep0();
    expect(ep0 >= 0, "production ep0 open uses pinned directory from inherited view");
    close(ep0);
    expect(arm_instance("namespace fixture idle", false) == 0, "initial descriptor arm works via dirfd");
    for (unsigned i = 0; i < 4; ++i) {
        expect(arm_instance("namespace fixture adb", true) == 0 && g_ep[0] >= 0 && g_ep[1] >= 0,
               "bulk endpoint reopen works without a private namespace");
        expect(arm_instance("namespace fixture idle", false) == 0, "idle rearm keeps directory alive");
    }
    close_all();
    expect(fcntl(g_ffs_dir, F_GETFD) >= 0, "endpoint teardown never closes private mount directory");

    expect(mount("storage-fixture", late.c_str(), "tmpfs", 0, nullptr) == 0,
           "simulate storage mounted after FunctionFS initialization");
    const std::string pushed = late + "/pushed-file";
    ino_t sync_namespace = 0;
    bool sync_written = false;
    std::thread sync([&] {
        sync_namespace = namespace_id();
        int fd = open(pushed.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (fd >= 0) {
            sync_written = write(fd, "push", 4) == 4;
            close(fd);
        }
    });
    sync.join();
    expect(sync_namespace == inherited && sync_written, "sync worker inherits live storage view");
    pid_t shell = fork();
    expect(shell >= 0, "shell child created");
    if (shell == 0) {
        int fd = open(pushed.c_str(), O_RDONLY | O_CLOEXEC);
        char data[4]{};
        bool ok = namespace_id() == inherited && fd >= 0 && read(fd, data, 4) == 4 &&
                  memcmp(data, "push", 4) == 0;
        _exit(ok ? 0 : 1);
    }
    int status;
    expect(waitpid(shell, &status, 0) == shell && WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "forked shell sees sync writes without setns");
    expect(mount_private("bad-fixture", (root + "/missing").c_str(), "tmpfs") < 0,
           "mount bootstrap failure returned to caller");
    expect(namespace_id() == inherited, "failed bootstrap cannot change daemon namespace");
    close(g_ffs_dir);
    g_ffs_dir = -1;
    expect(umount(late.c_str()) == 0, "late storage fixture unmounted");
    expect(rmdir(target.c_str()) == 0 && rmdir(late.c_str()) == 0, "mount fixture directories removed");
    printf("PASS: %u real mount-namespace checks (service inheritance, late storage, endpoint rearm)\n", checks);
}
