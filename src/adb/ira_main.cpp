// SPDX-License-Identifier: AGPL-3.0-or-later
/* The ADB daemon. AOSP's implementation (libadb + adbd's services), with the transport coming
 * from a FunctionFS instance the daemon mounts itself instead of the kernel module's channel:
 * init links functions/ffs.ira into the framework's configfs gadget, the daemon writes the
 * descriptors on ep0 and pumps the two bulk endpoints, and the only thing that changes here is
 * where the bytes come from. */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <sched.h>
#include <unistd.h>

#include <cstdio>
#include <memory>

#include "adb.h"
#include "adb_auth.h"
#include "adb_trace.h"
#include "fdevent/fdevent.h"
#include "sysdeps.h"
#include "transport.h"

#include "ira_bridge.h"
#include "ira_ffs.h"
#include "ira_privileges.h"
#include "ira_platform.h"
#include "ira_service_backend.h"
#include "ira_su_server.h"

static atransport* g_transport;

/* post-fs-data.sh has to know that the descriptors are on ep0 before it lets
 * init get on with writing the UDC (a functionfs function whose descriptors
 * are missing makes the composite bind fail with -ENODEV, f_fs.c:3107, and
 * takes the whole UDC write with it).  The daemon cannot prove that through
 * configfs - its functionfs mount is pinned by a private directory fd, so the
 * ep# files are absent from the inherited namespace - so it leaves a marker in the module's
 * state directory, which is next to the binary it was started from. */
static void write_arm_marker(void) {
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

    if (n <= 0) {
        fprintf(stderr, "ira: cannot resolve /proc/self/exe: %s\n", strerror(errno));
        return;
    }
    exe[n] = 0;
    char *slash = strrchr(exe, '/');

    if (!slash) {
        fprintf(stderr, "ira: %s has no directory part\n", exe);
        return;
    }
    *slash = 0;

    char marker[PATH_MAX];
    if (snprintf(marker, sizeof(marker), "%s/state/ffs.armed", exe) >= (int)sizeof(marker)) {
        fprintf(stderr, "ira: marker path too long\n");
        return;
    }
    /* adb's sysdeps.h poisons open()/write()/close(); these are its wrappers. */
    int fd = adb_open_mode(marker, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);

    if (fd < 0) {
        fprintf(stderr, "ira: cannot write %s: %s\n", marker, strerror(errno));
        return;
    }
    if (adb_write(fd, "1\n", 2) != 2)
        fprintf(stderr, "ira: short write to %s: %s\n", marker, strerror(errno));
    adb_close(fd);
}

/* Last words before a fatal signal: which one it was, so the module's log names the failure
 * instead of ending mid-line. Written with write(2) directly because the handler may run with the
 * C library in any state. */
static void fatal_signal(int sig) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "ira: fatal signal %d (%s)\n", sig, strsignal(sig));

    if (n > 0)
        (void)adb_write(STDERR_FILENO, buf, (size_t)n);
}

atransport* ira_bridge_transport(void) {
    return g_transport;
}

/* AOSP's USB path destroys the transport when a read fails and creates a new one when the host
 * comes back (daemon/usb.cpp:519,567 -> transport.cpp:1184 -> handle_offline + destroy). This
 * daemon keeps one long-lived transport, so the same thing is done here: the old one is taken
 * offline, which closes every socket that belonged to it and drops its packet state, and a fresh
 * one is registered over a new socketpair. */
int ira_bridge_relink(void) {
    int sv[2];

    if (g_transport) {
        atransport* old = g_transport;

        g_transport = nullptr;
        /* kick_transport() is the public teardown: it stops the connection, whose thread then
         * calls HandleError exactly once (transport_fd.cpp:148). Calling HandleError here as well
         * posts a second handle_offline + transport_destroy and adbd aborts. */
        kick_transport(old, false);
    }
    if (adb_socketpair(sv) != 0)
        return -1;
    auto connection = Connection::FromFd(unique_fd(sv[0]));
    atransport* t = new atransport(kTransportUsb, kCsOffline);

    t->SetConnection(std::move(connection));
    register_transport(t);
    g_transport = t;
    /* sv[1] stays blocking.  The OUT pump writes host bytes to it and a full
     * socket is backpressure, not a lost wire; the event thread relinks (and
     * kick_transport() closes adbd's end) if the session really ends.  The IN
     * pump polls before reading, so one reader and one blocking writer on the
     * same open file description cannot steal each other's data. */
    return sv[1];
}

int main(int argc, char** argv) {
    int sv[2];

    if (argc == 3 && strcmp(argv[1], "--ira-services") == 0) {
        if (strcmp(argv[2], "root") != 0 && strcmp(argv[2], "shell") != 0) return 126;
        return ira_service_backend_main(strcmp(argv[2], "root") == 0);
    }
#if defined(__ANDROID__) && !defined(IRA_VM)
    /* init owns the mount tree with vold/FUSE storage. Module launchers can run
     * in a private namespace, so match adbd before creating threads. */
    int init_mnt = adb_open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (init_mnt < 0 || setns(init_mnt, CLONE_NEWNS) < 0) {
        int error = errno;
        if (init_mnt >= 0) adb_close(init_mnt);
        fprintf(stderr, "ira: cannot join init mount namespace: %s\n", strerror(error));
        return 1;
    }
    adb_close(init_mnt);
#endif

    if (ira_platform_init() < 0 || ira_service_backend_init() < 0) {
        fprintf(stderr, "ira: required platform APIs unavailable: %s\n", strerror(errno));
        return 1;
    }

    /* A transport can be torn down under the bridge at any moment, and the next write to that
     * socket then turns into SIGPIPE. AOSP's daemon sets this in the main() that is not compiled
     * here; without it the daemon - and with it every future session - dies on the spot. */
    signal(SIGPIPE, SIG_IGN);

    /* Nothing may end this process by accident. Its FunctionFS instance is what the configuration's
     * "ira" link points at, so a daemon that dies leaves a link to an instance that no longer
     * exists: the next UDC write then fails with -ENODEV (f_fs.c:3107) and the whole gadget stays
     * down - no adb, no USB, until a reboot. A stray kill, a closed terminal, a SIGHUP from the
     * script that started it: all of them end a device session, so all of them are ignored, and the
     * only way out is an explicit SIGKILL (or a crash, which is why the fatal signals below say
     * what happened before the process goes). */
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* A crash still takes the instance with it, so at least leave the reason in the log the module
     * redirects: the shell prints "Killed" and nothing else otherwise. */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = fatal_signal;
        sa.sa_flags = SA_RESETHAND;
        sigemptyset(&sa.sa_mask);
        for (int sig : {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE})
            sigaction(sig, &sa, nullptr);
    }

    /* Mount functionfs and write the descriptors before the framework can
     * bind the UDC: the composite refuses to bind a functionfs function whose
     * descriptors have not been written yet (f_fs.c:3107, desc_ready).  Which
     * set those descriptors are is not decided here: it follows the configfs
     * link set and is re-evaluated on every bind, because the framework links
     * its own ffs.adb into the same configuration later (ira_ffs.cpp). */
    if (ira_bridge_ffs_init() < 0) {
        fprintf(stderr, "ira: cannot bring up functions/ffs.ira\n");
        return 1;
    }
    if (ira_ffs_armed())
        write_arm_marker();
    else
        fprintf(stderr, "ira: the descriptors are not armed yet; "
                        "post-fs-data.sh will not see the marker\n");
    if (adb_socketpair(sv) != 0) {
        perror("ira: socketpair");
        return 1;
    }

    /* The daemon keeps the root it was started with: every shell session drops to the shell user
     * inside its own child, and su is the session that keeps it instead. Nothing is dropped here,
     * which is also what makes su possible without a privileged channel of any kind. */

    adbd_auth_init();

    /* What usb_init() would have registered on the phone, registered by hand on an fd. */
    auto connection = Connection::FromFd(unique_fd(sv[0]));
    atransport* t = new atransport(kTransportUsb, kCsOffline);

    t->SetConnection(std::move(connection));
    register_transport(t);
    g_transport = t;

    /* Nothing here starts the connection by hand: the device path does that inside
     * fdevent_register_transport, queued on the looper and run as soon as fdevent_loop() is up.
     * Starting it a second time is an error AOSP guards against ("Connection started multiple
     * times?"), which is how this was found. */
#ifdef IRA_VM
    /* In the harness the daemon's own trace is the point: it says what it did with each packet.
     * On a device this stays off. The trace reads its flags at init, so this has to come before. */
    if (getenv("IRA_VM_TRACE"))
        adb_trace_init(nullptr);
#endif

    fprintf(stderr, "ira: daemon pid %d, transport registered, bridge starting (%s)\n",
            (int)getpid(), ira_ffs_armed() ? "descriptors armed" : "descriptors pending");
    ira_bridge_start(sv[1]);

    /* su's privileged side: a private endpoint that turns each connection into one root shell.
     * It has its own thread, so a session that stays up as long as its caller wants does not hold
     * anything else back, and the daemon's looper starts after it exists. */
    if (ira_su_server_start() < 0)
        fprintf(stderr, "ira: the private su endpoint did not start\n");

    fdevent_loop();
    return 0;
}
