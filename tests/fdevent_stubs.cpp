// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fdevent/fdevent.h"
#include <vector>

// Model fdevent's ownership of its fd; descriptor tests do not run an event loop.
fdevent* fdevent_create(int fd, fd_func func, void* arg) {
    auto* event = new fdevent{};
    event->fd.reset(fd);
    event->func = func;
    event->arg = arg;
    return event;
}
fdevent* fdevent_create(int fd, fd_func2 func, void* arg) {
    auto* event = new fdevent{};
    event->fd.reset(fd);
    event->func = func;
    event->arg = arg;
    return event;
}
unsigned test_auth_revocations = 0;
void adbd_auth_revoke() { ++test_auth_revocations; }
void fdevent_destroy(fdevent* event) { delete event; }
void fdevent_add(fdevent*, unsigned) {}
bool test_defer_looper = false;
std::vector<std::function<void()>> test_looper_queue;
void fdevent_run_on_looper(std::function<void()> fn) {
    if (test_defer_looper) test_looper_queue.push_back(std::move(fn));
    else fn();
}
