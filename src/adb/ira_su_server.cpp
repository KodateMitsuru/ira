// SPDX-License-Identifier: GPL-3.0-only AND AGPL-3.0-or-later
// IRA contributions are AGPL-3.0-or-later; Magisk-derived portions retain GPL-3.0-only.
/* The privileged side of su: the daemon's su server.
 *
 *   Modelled on Magisk's exec_root_shell: the caller sends a command string,
 *   then its own stdin/stdout/stderr as SCM_RIGHTS, and gets a root shell wired to them. What the
 *   caller sends is a NUL-terminated command line (empty for a plain "su") followed by exactly
 *   three fds.
 *
 *   There is no pty anywhere in this path on purpose. Magisk allocates one when a caller sends no
 *   fds, so that an interactive su has a terminal to talk to; here the terminal (or the pipe) is
 *   always the caller's own, and the shell inherits it as it is. That also keeps this side free of
 *   termios, of a pump between two descriptors, and of the second exit-status channel such a pump
 *   needs.
 *
 *   The exit status goes back on the same connection as one big-endian 32-bit word, after the
 *   shell has been waited for: the caller sees the shell's own status, not this server's. */
#include <errno.h>
#include <paths.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <thread>

#include "ira_names.h"
#include "ira_privileges.h"
#include "ira_session_shell.h"
#include "ira_su_server.h"

/* The abstract namespace, like adbd's own socket: nothing is created on disk, so there is no node
 * to chmod, no stale node after a crash, and no path for anything to walk into.
 *
 * The name itself is this installation's "su" endpoint from "names". Session shells get it in
 * IRA_SU_SOCKET below, so the packaged mksh carries no constant and is not patched. */
static char g_su_name[108];

/* How the caller reaches us: an abstract address is sun_path[0] == '\0' followed by the name, and
 * the length has to be exact - a length that leaves the rest of sun_path in the address would make
 * the name depend on whatever was on the stack. */
static socklen_t abstract_length(const char* name) {
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name));
}

/* ------------------------------------------------------------------ *
 * receiving the request
 * ------------------------------------------------------------------ */

/* The fds that came with the command. A caller may send all three in one message or one at a time
 * (Magisk's send_fd does the latter), so they are collected from every message read here and the
 * count is what decides when the request is complete. */
struct received {
    int fds[3];
    int nfds;
};

static void received_close(struct received* r) {
    for (int i = 0; i < r->nfds; i++)
        close(r->fds[i]);
    r->nfds = 0;
}

/* One read, keeping the fds. The command string and the fds may arrive in one message - the
 * control data then comes with the first byte - so every read here is a recvmsg. */
static ssize_t recv_some(int conn, char* buf, size_t len, struct received* r) {
    char control[CMSG_SPACE(8 * sizeof(int))];
    struct iovec iov;
    struct msghdr msg;
    ssize_t n;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buf;
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    do {
        n = recvmsg(conn, &msg, MSG_CMSG_CLOEXEC);
    } while (n < 0 && errno == EINTR);
    if (n < 0)
        return -1;

    for (struct cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
            continue;
        size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        const int* fds = (const int*)CMSG_DATA(c);

        for (size_t i = 0; i < count; i++) {
            /* More than three is not a request this server knows: the extras are closed here so
             * that they do not hang off a session that will never use them. */
            if (r->nfds < 3)
                r->fds[r->nfds++] = fds[i];
            else
                close(fds[i]);
        }
    }
    return n;
}

/* The command line, up to and including its NUL. Byte at a time, so nothing past the terminator is
 * consumed: the fds come after it and are read for themselves. */
static bool read_command(int conn, char* cmd, size_t cap, struct received* r) {
    size_t n = 0;

    for (;;) {
        char c;
        ssize_t got = recv_some(conn, &c, 1, r);

        /* A zero read is the end of the stream: the command has to be terminated before that. */
        if (got <= 0)
            return false;
        if (c == '\0') {
            cmd[n] = '\0';
            return true;
        }
        if (n + 1 >= cap)
            return false;
        cmd[n++] = c;
    }
}

/* The three fds, when they are not already here. What arrives as filler (a sender with a
 * one-byte message per fd) is discarded. */
static bool read_fds(int conn, struct received* r) {
    while (r->nfds < 3) {
        char c;
        ssize_t got = recv_some(conn, &c, 1, r);

        /* The fds are the answer, not the filler byte: a sender is free to put all three in one
         * message (with or without a payload) or to send one at a time. */
        if (r->nfds >= 3)
            break;
        if (got <= 0)
            return false;
    }
    return true;
}

/* ------------------------------------------------------------------ *
 * the shell
 * ------------------------------------------------------------------ */

/* The status the caller sees: the shell's exit code, or the shell convention for a signal. */
static uint32_t exit_code(int status) {
    if (WIFEXITED(status))
        return (uint32_t)WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return (uint32_t)(128 + WTERMSIG(status));
    return 127;
}

[[noreturn]] static void exec_root_shell(const char* cmd, const struct received* r) {
    /* The daemon is root already (ira_main keeps it), so this is a no-op on the phone's normal
     * path; it is here so that a shell started from this server is root by construction and not by
     * accident of what the daemon happened to be started as. */
    ira_child_signals();
    if (ira_privileges_child(true) != 0) {
        fprintf(stderr, "ira-su: cannot enter root identity: %s\n", strerror(errno));
        _exit(126);
    }

    /* The root shell's stdin is the session's socketpair, not a tty: the shell is told so and
     * runs its own editor over it (vendor/mksh: ira_vtty). */
    setenv("IRA_VTTY", "1", 1);
    setenv("HOME", "/", 1);
    setenv("USER", "root", 1);
    setenv("LOGNAME", "root", 1);
    setenv("PS1", "# ", 1);

    dup2(r->fds[0], STDIN_FILENO);
    dup2(r->fds[1], STDOUT_FILENO);
    dup2(r->fds[2], STDERR_FILENO);
    for (int i = 0; i < 3; i++)
        if (r->fds[i] > STDERR_FILENO)
            close(r->fds[i]);

    /* The session's own shell - the same file the shell service execs for every session it starts
     * (daemon/shell_service.cpp), with the same argv: nothing here runs a second, different shell.
     * It is the only one that works without a pty (prompt, echo, erase, ^C are its own), and the
     * only one with the su builtin, which is what keeps a root shell talking to this server rather
     * than to a binary on some path. A plain path is enough here, unlike in the session child: this
     * process is root, so it can walk into /data/adb, and nothing has dropped privileges yet. */
    if (cmd[0] == '\0')
        execl(IRA_SESSION_SHELL, "sh", "-i", (char*)nullptr);
    else
        execl(IRA_SESSION_SHELL, "sh", "-c", cmd, (char*)nullptr);

    /* One line, naming the file it looked for: "cannot execute the session shell" alone leaves a
     * device log asking which path this build expected. */
    fprintf(stderr, "ira-su: cannot execute the session shell %s: %s\n", IRA_SESSION_SHELL,
            strerror(errno));
    _exit(127);
}

/* One session: the request, the shell, and its status back to the caller. The connection is the
 * caller's - it is closed here, after the status word has been written. */
static void serve(int conn) {
    char cmd[4096];
    struct received r;
    int status = 0;
    pid_t pid;

    memset(&r, 0, sizeof(r));
    if (!read_command(conn, cmd, sizeof(cmd), &r)) {
        fprintf(stderr, "ira-su: no command on the connection\n");
        received_close(&r);
        close(conn);
        return;
    }
    if (!read_fds(conn, &r)) {
        fprintf(stderr, "ira-su: the request did not carry three fds\n");
        received_close(&r);
        close(conn);
        return;
    }

    /* A short line, so that a device's log says what a root shell was asked to do without
     * printing a whole session's worth of anything. */
    fprintf(stderr, "ira-su: session for \"%s\"\n", cmd[0] ? cmd : "sh");

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "ira-su: fork: %s\n", strerror(errno));
        received_close(&r);
        close(conn);
        return;
    }
    if (pid == 0) {
        /* The connection belongs to the parent: a shell that held it open would keep the caller
         * from seeing the end of the session. */
        close(conn);
        exec_root_shell(cmd, &r);
    }

    /* The child has its own copies now (dup2 above made them 0,1,2), so these are the parent's. */
    received_close(&r);

    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR)
            break;

    {
        uint32_t code = exit_code(status);
        uint8_t out[4];

        out[0] = (uint8_t)(code >> 24);
        out[1] = (uint8_t)(code >> 16);
        out[2] = (uint8_t)(code >> 8);
        out[3] = (uint8_t)code;
        for (size_t sent = 0; sent < sizeof(out);) {
            ssize_t n = write(conn, out + sent, sizeof(out) - sent);

            if (n < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            sent += (size_t)n;
        }
    }
    close(conn);
}

/* ------------------------------------------------------------------ *
 * the listener
 * ------------------------------------------------------------------ */

static int su_listener() {
    struct sockaddr_un addr;
    int fd;

    if (!ira_socket_name("su", g_su_name, sizeof(g_su_name))) {
        fprintf(stderr, "ira-su: no su endpoint in the module names file: %s\n", strerror(errno));
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        fprintf(stderr, "ira-su: socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    memcpy(addr.sun_path + 1, g_su_name, strlen(g_su_name));

    if (bind(fd, (struct sockaddr*)&addr, abstract_length(g_su_name)) < 0) {
        fprintf(stderr, "ira-su: cannot bind @%s: %s\n", g_su_name, strerror(errno));
        close(fd);
        return -1;
    }
    /* Four waiting sessions: enough for a client that asks twice while an interactive one is up,
     * and small enough that a caller which never reads the status is noticed as a backlog. */
    if (listen(fd, 4) < 0) {
        fprintf(stderr, "ira-su: listen on @%s: %s\n", g_su_name, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static void su_thread(int listener) {
    for (;;) {
        int conn = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);

        if (conn < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            fprintf(stderr, "ira-su: accept: %s\n", strerror(errno));
            return;
        }
        /* A session can be an interactive root shell and last as long as the caller wants, so it
         * gets its own thread: the listener has to be free for the next one. */
        std::thread(serve, conn).detach();
    }
}

int ira_su_server_start(void) {
    static bool started;
    int fd;

    if (started)
        return 0;
    fd = su_listener();
    if (fd < 0)
        return -1;
    /* The session shell inherits this, so mksh's su builtin dials the same private endpoint without
     * carrying a name of its own. A failure here would leave su unable to work at all. */
    if (setenv("IRA_SU_SOCKET", g_su_name, 1) != 0) {
        fprintf(stderr, "ira-su: cannot publish the endpoint: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    started = true;
    std::thread(su_thread, fd).detach();
    fprintf(stderr, "ira-su: listening on @%s\n", g_su_name);
    return 0;
}
