// SPDX-License-Identifier: AGPL-3.0-or-later
#include <adbd_auth.h>
#include "adbd_auth_internal.h"
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>

static unsigned checks;
static std::mutex lock;
static std::condition_variable changed;
static std::vector<std::pair<void*, uint64_t>> allowed;
static std::vector<std::string> removed;
static void expect(bool yes, const char* what) {
    if (!yes) { fprintf(stderr, "FAIL: %s\n", what); exit(1); }
    ++checks;
}
static void authorized(void* arg, uint64_t id) {
    std::lock_guard<std::mutex> guard(lock); allowed.emplace_back(arg, id); changed.notify_all();
}
static void deleted(const char* key, size_t size) {
    std::lock_guard<std::mutex> guard(lock); removed.emplace_back(key, size); changed.notify_all();
}
static void packet(int fd, const char* expected) {
    pollfd p{fd, POLLIN, 0};
    expect(poll(&p, 1, 2000) == 1, "upstream auth emits packet without polling loop");
    char buffer[512];
    ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
    expect(n == (ssize_t)strlen(expected) && memcmp(buffer, expected, n) == 0,
           "exact upstream auth packet");
}
int main() {
    alarm(15);
    int server = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1, "ira-upstream-auth-%d", getpid());
    socklen_t size = offsetof(sockaddr_un, sun_path) + 1 + strlen(address.sun_path + 1);
    expect(bind(server, reinterpret_cast<sockaddr*>(&address), size) == 0, "private auth fixture bound");
    AdbdAuthCallbacksV1 callbacks{};
    callbacks.version = 1; callbacks.key_authorized = authorized; callbacks.key_removed = deleted;
    AdbdAuthContext context(&callbacks, server);
    context.InitFrameworkHandlers();
    std::thread auth([&] { context.Run(); });
    int framework = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    expect(connect(framework, reinterpret_cast<sockaddr*>(&address), size) == 0, "private framework connected");
    uint64_t first = context.PromptUser("key-A", reinterpret_cast<void*>(7));
    uint64_t second = context.PromptUser("key-B", reinterpret_cast<void*>(9));
    packet(framework, "PKkey-A");
    pollfd no_second{framework, POLLIN, 0};
    expect(poll(&no_second, 1, 30) == 0, "upstream serializes concurrent prompts");
    expect(send(framework, "NO", 2, 0) == 2, "deny first prompt");
    packet(framework, "PKkey-B");
    expect(send(framework, "OK", 2, 0) == 2, "allow second prompt");
    {
        std::unique_lock<std::mutex> guard(lock);
        expect(changed.wait_for(guard, std::chrono::seconds(2), [] { return allowed.size() == 1; }),
               "authorization callback received");
        expect(allowed[0].first == reinterpret_cast<void*>(9) && allowed[0].second == second && first != second,
               "authorization preserves callback cookie and connection id");
    }
    uint64_t used = context.NotifyAuthenticated("key-C");
    context.Interrupt();
    packet(framework, "CKkey-C");
    context.NotifyDisconnected(used);
    context.Interrupt();
    packet(framework, "DCkey-C");
    expect(send(framework, "DDkey-C", 7, 0) == 7, "send per-key removal");
    {
        std::unique_lock<std::mutex> guard(lock);
        expect(changed.wait_for(guard, std::chrono::seconds(2), [] { return !removed.empty(); }),
               "per-key removal callback received");
        expect(removed[0] == "key-C", "exact key identity preserved");
    }
    context.Stop();
    auth.join();
    close(framework);
    printf("PASS: %u USB libadbd_auth lifecycle checks\n", checks);
}
