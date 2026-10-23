// SPDX-License-Identifier: AGPL-3.0-or-later
// Complete production service implementations, with only Android policy APIs supplied by the
// explicit host fixture. Real process credentials, sockets, shell protocol, sync and signals.
#include "ira_platform.h"
#include "ira_privileges.h"
#include "ira_service_backend.h"
#include "transport.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

atransport* ira_bridge_transport() { return nullptr; }
int ira_bridge_relink() { errno = ENOTSUP; return -1; }
static unsigned checks;
static void expect(bool yes, const char* what) {
    if (!yes) { fprintf(stderr, "FAIL: %s (%d: %s)\n", what, errno, strerror(errno)); exit(1); }
    ++checks;
}
static bool exact(int fd, void* buffer, size_t size) {
    auto* p = static_cast<char*>(buffer);
    while (size) {
        pollfd event{fd, POLLIN, 0};
        if (poll(&event, 1, 4000) != 1) return false;
        ssize_t count = recv(fd, p, size, 0);
        if (count <= 0) return false;
        p += count; size -= count;
    }
    return true;
}
static std::string line(int fd) {
    std::string result;
    char byte;
    while (result.size() < 100 && exact(fd, &byte, 1)) {
        if (byte == '\n') return result;
        result.push_back(byte);
    }
    return {};
}
static std::string shell(const std::string& command, int expected_exit = 0) {
    int fd = ira_service_request(IraServiceOperation::Open, "shell,v2,raw:" + command);
    expect(fd >= 0, "shell_v2 service opens");
    std::string result;
    for (;;) {
        unsigned char header[5];
        expect(exact(fd, header, sizeof(header)), "shell frame received");
        uint32_t size; memcpy(&size, header + 1, 4);
        expect(size < 65536, "bounded frame");
        std::string data(size, '\0');
        expect(exact(fd, data.data(), size), "frame payload received");
        if (header[0] == 1) result += data;
        if (header[0] == 3) {
            expect(size == 1 && static_cast<unsigned char>(data[0]) == expected_exit,
                   "upstream one-byte shell exit status preserved");
            break;
        }
    }
    close(fd);
    return result;
}
static void sync_write(const std::string& path, bool allowed) {
    int fd = ira_service_request(IraServiceOperation::Open, "sync:");
    expect(fd >= 0, "production sync service opens");
    std::string request;
    auto record = [&](const char* tag, const std::string& data) {
        uint32_t size = data.size();
        request.append(tag, 4); request.append(reinterpret_cast<char*>(&size), 4); request += data;
    };
    record("SEND", path + ",0600"); record("DATA", "verified"); record("DONE", "");
    expect(send(fd, request.data(), request.size(), MSG_NOSIGNAL) == (ssize_t)request.size(), "sync records sent");
    char response[8];
    expect(exact(fd, response, sizeof(response)), "sync response received");
    expect(memcmp(response, allowed ? "OKAY" : "FAIL", 4) == 0, "sync enforces backend credentials");
    close(fd);
}
static void cancelled(bool protocol) {
    int fd = ira_service_request(IraServiceOperation::Open,
        protocol ? "shell,v2,raw:echo $$; exec sleep 30" : "exec:echo $$; exec sleep 30");
    expect(fd >= 0, "long command service opens");
    std::string text;
    if (protocol) {
        unsigned char header[5];
        expect(exact(fd, header, sizeof(header)) && header[0] == 1, "long command pid stdout frame");
        uint32_t size; memcpy(&size, header + 1, 4); expect(size < 100, "pid bounded");
        text.resize(size); expect(exact(fd, text.data(), size), "pid frame read");
    } else text = line(fd);
    pid_t pid = static_cast<pid_t>(strtol(text.c_str(), nullptr, 10));
    expect(pid > 1, "child pid captured");
    int pidfd = syscall(SYS_pidfd_open, pid, 0);
    expect(pidfd >= 0, "monitor child lifetime without polling");
    close(fd); // exactly what transport socket teardown does
    pollfd dead{pidfd, POLLIN, 0};
    int exited = poll(&dead, 1, 4000);
    if (exited != 1) kill(pid, SIGKILL);
    close(pidfd);
    expect(exited == 1, protocol ? "shell_v2 child exits on disconnect" : "raw exec child exits on disconnect");
}
int main(int argc, char** argv) {
    if (argc == 3 && strcmp(argv[1], "--ira-services") == 0)
        return ira_service_backend_main(strcmp(argv[2], "root") == 0);
    if (argc == 2 && strcmp(argv[1], "--fd-sender") == 0) {
        int fd = memfd_create("ancillary", MFD_CLOEXEC);
        char payload = 'F';
        iovec iov{&payload, 1}; msghdr message{};
        alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
        message.msg_iov = &iov; message.msg_iovlen = 1;
        message.msg_control = control; message.msg_controllen = sizeof(control);
        auto* cmsg = CMSG_FIRSTHDR(&message); cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(fd)); memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
        return sendmsg(1, &message, MSG_NOSIGNAL) == 1 ? 0 : 1;
    }
    alarm(60);
    expect(argc == 2 && geteuid() == 0, "mapped-root integration fixture supplied");
    expect(ira_platform_init() == 0 && ira_service_backend_init() == 0, "production frontend initializes");
    std::string path = std::string(argv[1]) + "/root-only";
    ira_root_set(true);
    expect(shell("id -u") == "0\n", "root shell uid matches service identity");
    expect(shell("printf stdout; printf stderr >&2; exit 37", 37) == "stdout", "shell stdout separate from stderr and exit code");
    sync_write(path, true);
    int raw = ira_service_request(IraServiceOperation::Open, "exec:cat; printf EOF");
    expect(raw >= 0, "raw exec service opens");
    shutdown(raw, SHUT_WR);
    char eof[3];
    expect(exact(raw, eof, 3) && memcmp(eof, "EOF", 3) == 0, "raw stdin half-close preserves output");
    close(raw);
    std::string sender = "exec:" + std::string(argv[0]) + " --fd-sender";
    raw = ira_service_request(IraServiceOperation::Open, sender);
    expect(raw >= 0, "raw ancillary service opens");
    char byte; iovec data{&byte, 1}; msghdr message{};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    message.msg_iov = &data; message.msg_iovlen = 1;
    message.msg_control = control; message.msg_controllen = sizeof(control);
    expect(recvmsg(raw, &message, MSG_CMSG_CLOEXEC) == 1 && byte == 'F', "raw bytes arrive unchanged");
    auto* cmsg = CMSG_FIRSTHDR(&message);
    expect(cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS, "raw path preserves SCM_RIGHTS for abb");
    int passed; memcpy(&passed, CMSG_DATA(cmsg), sizeof(passed)); close(passed); close(raw);
    cancelled(true); cancelled(false);
    ira_root_set(false);
    expect(shell("id -u") == "2000\n", "nonroot shell uid matches service identity");
    expect(ira_service_request(IraServiceOperation::Open, "dev:" + path) < 0, "nonroot dev service cannot open private file");
    sync_write(path + "-denied", false);
    int port = 0;
    int listener = ira_service_request(IraServiceOperation::Listen, "tcp:0", &port);
    struct stat status{};
    if (listener < 0 || port <= 0) fprintf(stderr, "listener fd=%d port=%d errno=%d\n", listener, port, errno);
    expect(listener >= 0 && port > 0 && fstat(listener, &status) == 0 && status.st_uid == 2000,
           "production reverse TCP listener uses nonroot identity");
    int forwarded = ira_service_request(IraServiceOperation::Open, "tcp:" + std::to_string(port));
    expect(forwarded >= 0, "production TCP forwarding connects under backend identity");
    int accepted = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    expect(accepted >= 0, "reverse listener accepts the forwarded connection");
    expect(send(forwarded, "ping", 4, MSG_NOSIGNAL) == 4, "forward sends payload");
    char forwarded_data[4];
    expect(exact(accepted, forwarded_data, 4) && memcmp(forwarded_data, "ping", 4) == 0, "reverse receives exact payload");
    expect(send(accepted, "pong", 4, MSG_NOSIGNAL) == 4, "reverse sends response");
    expect(exact(forwarded, forwarded_data, 4) && memcmp(forwarded_data, "pong", 4) == 0, "forward receives exact response");
    close(accepted); close(forwarded); close(listener);
    cancelled(true); cancelled(false);
    ira_root_set(true);
    expect(shell("id -u") == "0\n" && geteuid() == 0, "backend switching leaves frontend privileged");
    unlink(path.c_str());
    printf("PASS: %u complete production-service integration checks\n", checks);
}
