// SPDX-License-Identifier: AGPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include "../src/adb/ira_ffs.cpp"

extern unsigned test_auth_revocations;
static unsigned checks;
static void expect(bool yes, const char* what) {
    if (!yes) { fprintf(stderr, "FAIL: %s\n", what); exit(1); }
    ++checks;
}
static void request(int listener, const sockaddr_un& address, socklen_t length,
                    const char* command, const char* expected) {
    std::string answer;
    std::thread client([&] {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0 || connect(fd, reinterpret_cast<const sockaddr*>(&address), length) != 0)
            std::abort();
        if (write(fd, command, strlen(command)) != (ssize_t)strlen(command)) std::abort();
        shutdown(fd, SHUT_WR);
        char reply[64];
        ssize_t n = read(fd, reply, sizeof(reply));
        if (n > 0) answer.assign(reply, n);
        close(fd);
    });
    serve_control(listener);
    client.join();
    expect(answer == expected, "control response exact");
}
int main() {
    alarm(10);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    expect(fd >= 0, "control listener created");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1, "ira-revoke-test-%d", getpid());
    socklen_t length = offsetof(sockaddr_un, sun_path) + 1 + strlen(address.sun_path + 1);
    expect(bind(fd, reinterpret_cast<sockaddr*>(&address), length) == 0 && listen(fd, 4) == 0,
           "private abstract control fixture listening");
    const bool allowed = geteuid() == 1000 || geteuid() == 0;
    request(fd, address, length, "auth revoke\n", allowed ? "ok\n" : "err peer\n");
    expect(test_auth_revocations == (allowed ? 1u : 0u), "only privileged peer can revoke");
    request(fd, address, length, "auth revoke", "err unknown request\n");
    request(fd, address, length, "auth revoke\nextra", "err unknown request\n");
    expect(test_auth_revocations == (allowed ? 1u : 0u), "partial or suffixed requests never revoke");
    expect(!g_role_requested.load() && !g_armed.load(), "revoke never changes USB role or descriptors");
    close(fd);
    printf("PASS: %u revocation control socket checks\n", checks);
}
