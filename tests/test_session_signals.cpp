// SPDX-License-Identifier: AGPL-3.0-or-later
#include <initializer_list>
#include "../src/adb/ira_privileges.h"
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    unsigned checks = 0;
    for (int sig : {SIGTERM, SIGINT, SIGHUP}) {
        pid_t child = fork();
        if (child == 0) {
            for (int inherited : {SIGTERM, SIGINT, SIGHUP}) signal(inherited, SIG_IGN);
            sigset_t blocked;
            sigfillset(&blocked);
            sigprocmask(SIG_SETMASK, &blocked, nullptr);
            ira_child_signals();
            char command[100];
            snprintf(command, sizeof(command), "kill -%d $$; print survived", sig);
            execl(argv[1], argv[1], argv[2], "-c", command, nullptr);
            _exit(127);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 128 + sig) abort();
        ++checks;
    }
    printf("PASS: %u packaged ARM64 shell signal reset checks\n", checks);
}
