// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ira_privileges.h"
#include "ira_session_shell.h"
#include <atomic>
#include <errno.h>
#include <fcntl.h>
#include <initializer_list>
#include <signal.h>
#include <unistd.h>

static std::atomic<bool> root_mode{false};
static int shell_executable = -1;
bool ira_root_mode() { return root_mode.load(); }
void ira_root_set(bool root) { root_mode.store(root); }

int ira_session_shell_init() {
    shell_executable = open(IRA_SESSION_SHELL, O_RDONLY | O_CLOEXEC);
    if (shell_executable < 0 && errno == EACCES)
        shell_executable = open(IRA_SESSION_SHELL, O_PATH | O_CLOEXEC);
    return shell_executable < 0 ? -1 : 0;
}
int ira_session_shell_fd() { return fcntl(shell_executable, F_DUPFD_CLOEXEC, 3); }
int ira_privileges_child(bool stay_root) {
    // All ADB services already inherited the backend's process-wide minijail identity.
    // The privileged su server is the only caller outside a service backend.
    if (geteuid() != (stay_root || ira_root_mode() ? 0 : 2000)) { errno = EPERM; return -1; }
    return 0;
}
void ira_child_signals() {
    for (int sig : {SIGTERM, SIGINT, SIGHUP, SIGPIPE, SIGUSR1}) {
        struct sigaction action{};
        action.sa_handler = SIG_DFL;
        sigemptyset(&action.sa_mask);
        sigaction(sig, &action, nullptr);
    }
    sigset_t mask;
    sigemptyset(&mask);
    sigprocmask(SIG_SETMASK, &mask, nullptr);
}
