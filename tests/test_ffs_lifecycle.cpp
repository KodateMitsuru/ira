// SPDX-License-Identifier: AGPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../src/adb/ira_ffs.cpp"

extern bool test_defer_looper;
extern std::vector<std::function<void()>> test_looper_queue;
static int old_session[4];
static unsigned relinked;
static bool fail_rearm;

static void expect(bool condition, const char* what) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        std::exit(1);
    }
}

static void session_lost(const char*) {
    ++relinked;
    expect(!g_armed.load() && g_ep0_fde == nullptr, "old instance and ep0 watcher released before relink");
    for (int fd : old_session)
        expect(fcntl(fd, F_GETFD) == -1 && errno == EBADF, "old session fd closed before transport relink");
    char state[4]{};
    int udc = open(IRA_UDC_FILE, O_RDONLY | O_CLOEXEC);
    expect(udc >= 0 && read(udc, state, sizeof(state)) == sizeof(state) &&
           memcmp(state, "none", 4) == 0, "UDC pulled down before transport relink");
    close(udc);
    // A configfs store replaces the attribute value; emulate that in the regular-file fixture.
    udc = open(IRA_UDC_FILE, O_WRONLY | O_TRUNC | O_CLOEXEC);
    expect(udc >= 0 && write(udc, "none", 4) == 4, "fixture configfs pull-down value normalized");
    close(udc);
    if (fail_rearm) {
        expect(unlinkat(g_ffs_dir, "ep0", 0) == 0 &&
               symlinkat("/dev/full", g_ffs_dir, "ep0") == 0, "inject descriptor-write failure");
    }
}

static void reset_fixture(bool restart = false) {
    relinked = 0;
    fail_rearm = restart;
    expect(mkdir(IRA_GADGET_DIR, 0700) == 0 || errno == EEXIST, "reset fixture directory created");
    g_ffs_dir = open(IRA_GADGET_DIR, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    expect(g_ffs_dir >= 0, "fixture endpoint directory pinned");
    for (const char* name : {"ep0", "ep1", "ep2"}) {
        int fd = openat(g_ffs_dir, name, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
        expect(fd >= 0, "reset endpoint fixture created");
        close(fd);
    }
    const char controller[] = "fixture-controller\n";
    int udc = open(IRA_UDC_FILE, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    expect(udc >= 0 && write(udc, controller, sizeof(controller) - 1) == sizeof(controller) - 1,
           "fixture controller bound");
    close(udc);
    expect(arm_instance("reset fixture", true) == 0, "initial endpoint set armed");
    ep0_watch();
    old_session[0] = g_ep0; old_session[1] = g_ep[0]; old_session[2] = g_ep[1];
    old_session[3] = g_ep0_fde->fd.get();
    g_desire_adb.store(true);
    g_enabled.store(true);
    g_bound.store(true);
    g_lost = session_lost;
    test_defer_looper = true;
    ira_ffs_reset_usb_session();
    ira_ffs_reset_usb_session();
    expect(test_looper_queue.size() == 1 && g_enabled.load(), "reset deferred and duplicate pending requests coalesced");
    auto task = std::move(test_looper_queue.front());
    test_looper_queue.clear();
    if (restart) {
        pid_t child = fork();
        expect(child >= 0, "reset failure process forked");
        if (child == 0) { task(); _exit(88); } // Failure must request replacement, not return.
        int status;
        expect(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "failed descriptor rearm exits cleanly for supervisor");
        expect(access(IRA_STATE_DIR "/setchange", F_OK) == 0 && access(IRA_REVOKE_RESUME, F_OK) == 0,
               "supervisor restart and recovery intent both survive process exit");
        close_all();
        unlinkat(g_ffs_dir, "ep0", 0);
        int ep0 = openat(g_ffs_dir, "ep0", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
        expect(ep0 >= 0, "replacement process gets a fresh ep0");
        close(ep0);
        g_desire_adb.store(false); g_role_requested.store(false); g_revoke_resume = {};
        expect(load_revoke_resume() && g_desire_adb.load() && g_role_requested.load(),
               "new process restores ADB role instead of default idle");
        char before[8]{};
        int fd = open(IRA_UDC_FILE, O_RDONLY | O_CLOEXEC);
        expect(fd >= 0 && read(fd, before, sizeof(before)) == 4 && strcmp(before, "none") == 0,
               "USB stays down until new descriptors are ready");
        close(fd);
        expect(arm_instance("replacement recovery fixture", g_desire_adb.load()) == 0,
               "replacement arms recorded ADB descriptors");
        ep0_watch();
        finish_revoke_resume();
        unlink(IRA_STATE_DIR "/setchange");
    } else {
        task();
        expect(relinked == 1, "transport relinked once");
    }
    expect(g_armed.load() && g_endpoints.load() && !g_rearming && g_ep0_fde != nullptr,
           "descriptors, bulk endpoints and ep0 watch rebuilt");
    char restored[sizeof(controller)]{};
    udc = open(IRA_UDC_FILE, O_RDONLY | O_CLOEXEC);
    expect(udc >= 0 && read(udc, restored, sizeof(restored)) == sizeof(controller) - 2 &&
           strcmp(restored, "fixture-controller") == 0, "original UDC binding restored");
    expect(access(IRA_REVOKE_RESUME, F_OK) < 0 && errno == ENOENT, "completed recovery consumes its handoff");
    close(udc);
    close_all();
    for (const char* name : {"ep0", "ep1", "ep2"}) unlinkat(g_ffs_dir, name, 0);
    close(g_ffs_dir); g_ffs_dir = -1;
    unlink(IRA_UDC_FILE);
    rmdir(IRA_GADGET_DIR);
    g_lost = nullptr;
    test_defer_looper = false;
}

int main(int argc, char** argv) {
    if (argc == 3 && strcmp(argv[1], "--watch-must-close") == 0) {
        const int fd = atoi(argv[2]);
        return fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 91;
    }
    for (unsigned iteration = 0; iteration < 20; ++iteration) {
        g_ep0 = open("/dev/null", O_RDWR | O_CLOEXEC);
        g_ep[kOut] = open("/dev/null", O_RDONLY | O_CLOEXEC);
        g_ep[kIn] = open("/dev/null", O_WRONLY | O_CLOEXEC);
        expect(g_ep0 >= 0 && g_ep[kOut] >= 0 && g_ep[kIn] >= 0, "fixture fds open");
        const int ep0 = g_ep0, out = g_ep[kOut], in = g_ep[kIn];
        g_armed.store(true);
        g_endpoints.store(true);
        ep0_watch();
        expect(g_ep0_fde != nullptr, "ep0 event watch installed");
        const int watch_fd = g_ep0_fde->fd.get();
        expect(watch_fd != ep0 && fcntl(watch_fd, F_GETFD) >= 0, "watch owns a duplicate fd");
        expect(fcntl(watch_fd, F_GETFD) & FD_CLOEXEC, "ep0 watcher cannot survive backend or shell exec");
        if (iteration == 0) {
            pid_t child = fork();
            expect(child >= 0, "backend exec regression child forked");
            if (child == 0) {
                char fd[24];
                snprintf(fd, sizeof(fd), "%d", watch_fd);
                execl("/proc/self/exe", "ffs-child", "--watch-must-close", fd, nullptr);
                _exit(92);
            }
            int status;
            expect(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                   "fork/exec releases inherited ep0 watcher instead of pinning old FunctionFS session");
        }

        close_all();
        expect(g_ep0_fde == nullptr, "old event watch removed before descriptor replacement");
        for (int fd : {ep0, out, in, watch_fd})
            expect(fcntl(fd, F_GETFD) == -1 && errno == EBADF, "every old instance reference closed");
        expect(!g_armed.load() && !g_endpoints.load(), "old descriptors are no longer armed");
        close_all();
        expect(g_ep0_fde == nullptr, "repeated teardown is safe");
    }
    reset_fixture();
    reset_fixture(true);
    std::puts("PASS: ep0 ownership across 20 cycles, revoke UDC restore and failed-rearm process replacement recovery");
}
