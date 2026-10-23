// SPDX-License-Identifier: AGPL-3.0-or-later
#include <sys/socket.h>
static int seqpacket_pair(int pair[2]) {
    return socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair);
}
#include "ira_service_backend.h"
#include "ira_platform.h"
#include "ira_privileges.h"
#include "adb.h"
#include "services.h"
#include "socket_spec.h"
#include "transport.h"
#include "sysdeps.h"
#include <array>
#include <errno.h>
#include <fcntl.h>
#include <mutex>
#include <signal.h>
#include <string>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

extern char** environ;

namespace {
constexpr size_t kMaximumRequest = 1024 * 1024;
struct Request { unsigned operation; unsigned length; };
struct Reply { int error; int port; };
bool backend = false;
int executable = -1;
std::mutex requests;

bool reply(int socket, Reply value, int fd = -1) {
    iovec data{&value, sizeof(value)};
    msghdr message{};
    message.msg_iov = &data;
    message.msg_iovlen = 1;
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    if (fd >= 0) {
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        auto* cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    }
    return TEMP_FAILURE_RETRY(sendmsg(socket, &message, MSG_NOSIGNAL)) == sizeof(value);
}
int receive_reply(int socket, Reply* value, bool want_fd) {
    iovec data{value, sizeof(*value)};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int) * 4)]{};
    msghdr message{};
    message.msg_iov = &data; message.msg_iovlen = 1;
    message.msg_control = control; message.msg_controllen = sizeof(control);
    ssize_t length = TEMP_FAILURE_RETRY(recvmsg(socket, &message, MSG_CMSG_CLOEXEC));
    int received = -1;
    unsigned count = 0;
    for (auto* cmsg = CMSG_FIRSTHDR(&message); length >= 0 && cmsg; cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
            cmsg->cmsg_len < CMSG_LEN(0)) continue;
        size_t size = cmsg->cmsg_len - CMSG_LEN(0);
        for (size_t offset = 0; offset + sizeof(int) <= size; offset += sizeof(int)) {
            int fd;
            memcpy(&fd, reinterpret_cast<char*>(CMSG_DATA(cmsg)) + offset, sizeof(fd));
            if (count++ == 0) received = fd; else adb_close(fd);
        }
    }
    if (length != sizeof(*value) || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        count != (want_fd && value->error == 0 ? 1u : 0u)) {
        if (received >= 0) adb_close(received);
        if (length >= 0) errno = EPROTO;
        return -1;
    }
    if (value->error) { errno = value->error; return -1; }
    return want_fd ? received : 0;
}

struct Backend {
    int socket = -1;
    pid_t pid = -1;
    void reset() {
        if (socket >= 0) adb_close(socket);
        socket = -1;
        if (pid > 0) {
            kill(pid, SIGKILL);
            while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
        }
        pid = -1;
    }
    bool start(bool root) {
        if (socket >= 0) return true;
        if (executable < 0) { errno = ENOENT; return false; }
        int pair[2];
        if (seqpacket_pair(pair) < 0) return false;
        int image = fcntl(executable, F_DUPFD_CLOEXEC, 10);
        if (image < 0) { adb_close(pair[0]); adb_close(pair[1]); return false; }
        const char* identity = root ? "root" : "shell";
        char* args[] = {const_cast<char*>("ira-daemon"), const_cast<char*>("--ira-services"),
                        const_cast<char*>(identity), nullptr};
        pid = fork();
        if (pid == 0) {
            adb_close(pair[0]);
            if (dup2(pair[1], 3) < 0) _exit(126);
            if (pair[1] != 3) adb_close(pair[1]);
            ira_child_signals();
            fexecve(image, args, ::environ);
            _exit(127);
        }
        int error = errno;
        adb_close(image); adb_close(pair[1]);
        if (pid < 0) { adb_close(pair[0]); errno = error; return false; }
        socket = pair[0];
        timeval timeout{10, 0};
        adb_setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        adb_setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        Reply ready{};
        if (receive_reply(socket, &ready, false) < 0) {
            error = errno; reset(); errno = error; return false;
        }
        return true;
    }
} backends[2];
}

int ira_service_backend_init() {
    executable = adb_open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    return executable < 0 ? -1 : 0;
}
bool ira_in_service_backend() { return backend; }

int ira_service_request(IraServiceOperation operation, std::string_view name, int* port) {
    if (name.empty() || name.size() > kMaximumRequest - sizeof(Request)) { errno = EINVAL; return -1; }
    std::lock_guard<std::mutex> lock(requests);
    const bool root = ira_root_mode();
    auto& child = backends[root ? 1 : 0];
    if (!child.start(root)) return -1;
    Request request{static_cast<unsigned>(operation), static_cast<unsigned>(name.size())};
    iovec data[] = {{&request, sizeof(request)}, {const_cast<char*>(name.data()), name.size()}};
    msghdr message{};
    message.msg_iov = data; message.msg_iovlen = 2;
    if (TEMP_FAILURE_RETRY(sendmsg(child.socket, &message, MSG_NOSIGNAL)) !=
        static_cast<ssize_t>(sizeof(request) + name.size())) {
        int error = errno; child.reset(); errno = error; return -1;
    }
    Reply response{};
    int fd = receive_reply(child.socket, &response, true);
    if (fd < 0 && (errno == EPIPE || errno == EPROTO || errno == EAGAIN || errno == ECONNRESET)) {
        int error = errno; child.reset(); errno = error;
    }
    if (fd >= 0 && port) *port = response.port;
    return fd;
}

int ira_service_backend_main(bool root) {
    backend = true;
    ira_root_set(root);
    ira_child_signals();
    signal(SIGPIPE, SIG_IGN);
    pid_t parent = getppid();
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || parent == 1 || getppid() != parent) return 126;
    // Preopen the private shell before minijail drops path traversal privileges.
    if (ira_platform_init() < 0 || ira_session_shell_init() < 0 ||
        ira_platform_enter_service_identity(root) < 0) {
        int error = errno ? errno : EPERM;
        fprintf(stderr, "ira-services: identity setup refused: %s\n", strerror(error));
        reply(3, {error, 0});
        return 126;
    }
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent) return 126;
    if (!reply(3, {0, 0})) return 126;
    atransport transport(kTransportUsb, kCsOffline);
    std::vector<char> buffer(kMaximumRequest + 1);
    for (;;) {
        ssize_t size = TEMP_FAILURE_RETRY(recv(3, buffer.data(), buffer.size(), MSG_TRUNC));
        if (size <= 0) return 0;
        if (size < static_cast<ssize_t>(sizeof(Request)) || size > static_cast<ssize_t>(kMaximumRequest))
            return 126;
        buffer[static_cast<size_t>(size)] = '\0'; // AOSP parsers also accept C-string views.
        Request request;
        memcpy(&request, buffer.data(), sizeof(request));
        if (request.length != size - sizeof(request)) return 126;
        std::string_view name(buffer.data() + sizeof(request), request.length);
        unique_fd fd;
        int port = 0;
        errno = 0;
        if (request.operation == static_cast<unsigned>(IraServiceOperation::Listen)) {
            std::string error;
            fd.reset(socket_spec_listen(name, &error, &port));
        } else if (request.operation == static_cast<unsigned>(IraServiceOperation::Open) &&
                   !name.starts_with("root:") && !name.starts_with("unroot:") &&
                   !name.starts_with("reverse:") && name != "reconnect") {
            fd = service_to_fd(name, &transport);
        } else { errno = EINVAL; }
        int error = fd < 0 ? (errno ? errno : ENOSYS) : 0;
        if (!reply(3, {error, port}, fd.get())) return 0;
    }
}
