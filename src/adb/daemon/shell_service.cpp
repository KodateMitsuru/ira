// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Functionality for launching and managing shell subprocesses.
//
// There are two types of subprocesses, PTY or raw. PTY is typically used for
// an interactive session, raw for non-interactive. There are also two methods
// of communication with the subprocess, passing raw data or using a simple
// protocol to wrap packets. The protocol allows separating stdout/stderr and
// passing the exit code back, but is not backwards compatible.
//   ----------------+--------------------------------------
//   Type  Protocol  |   Exit code?  Separate stdout/stderr?
//   ----------------+--------------------------------------
//   PTY   No        |   No          No
//   Raw   No        |   No          No
//   PTY   Yes       |   Yes         No
//   Raw   Yes       |   Yes         Yes
//   ----------------+--------------------------------------
//
// Non-protocol subprocesses work by passing subprocess stdin/out/err through
// a single pipe which is registered with a local socket in adbd. The local
// socket uses the fdevent loop to pass raw data between this pipe and the
// transport, which then passes data back to the adb client. Cleanup is done by
// waiting in a separate thread for the subprocesses to exit and then signaling
// a separate fdevent to close out the local socket from the main loop.
//
// ------------------+-------------------------+------------------------------
//   Subprocess      |  adbd subprocess thread |   adbd main fdevent loop
// ------------------+-------------------------+------------------------------
//                   |                         |
//   stdin/out/err <----------------------------->       LocalSocket
//      |            |                         |
//      |            |      Block on exit      |
//      |            |           *             |
//      v            |           *             |
//     Exit         --->      Unblock          |
//                   |           |             |
//                   |           v             |
//                   |   Notify shell exit FD --->    Close LocalSocket
// ------------------+-------------------------+------------------------------
//
// The protocol requires the thread to intercept stdin/out/err in order to
// wrap/unwrap data with shell protocol packets.
//
// ------------------+-------------------------+------------------------------
//   Subprocess      |  adbd subprocess thread |   adbd main fdevent loop
// ------------------+-------------------------+------------------------------
//                   |                         |
//     stdin/out   <--->      Protocol       <--->       LocalSocket
//     stderr       --->      Protocol        --->       LocalSocket
//       |           |                         |
//       v           |                         |
//      Exit        --->  Exit code protocol  --->       LocalSocket
//                   |           |             |
//                   |           v             |
//                   |   Notify shell exit FD --->    Close LocalSocket
// ------------------+-------------------------+------------------------------
//
// An alternate approach is to put the protocol wrapping/unwrapping in the main
// fdevent loop, which has the advantage of being able to re-use the existing
// select() code for handling data streams. However, implementation turned out
// to be more complex due to partial reads and non-blocking I/O so this model
// was chosen instead.

#define TRACE_TAG SHELL

#include "sysdeps.h"

#include "shell_service.h"

#include "ira_privileges.h"

#include <errno.h>
#include <paths.h>
#include <pty.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/eventfd.h>
#include <termios.h>

#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>

#if defined(__ANDROID__)
#include "ira_platform.h"
#endif

#include "adb.h"
#include "adb_io.h"
#include "adb_trace.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "daemon/logging.h"
#include "shell_protocol.h"

#include "ira_session_shell.h"

namespace {

// Reads from |fd| until close or failure.
std::string ReadAll(borrowed_fd fd) {
    char buffer[512];
    std::string received;

    while (1) {
        int bytes = adb_read(fd, buffer, sizeof(buffer));
        if (bytes <= 0) {
            break;
        }
        received.append(buffer, bytes);
    }

    return received;
}

// Creates a socketpair and saves the endpoints to |fd1| and |fd2|.
bool CreateSocketpair(unique_fd* fd1, unique_fd* fd2) {
    int sockets[2];
    if (adb_socketpair(sockets) < 0) {
        PLOG(ERROR) << "cannot create socket pair";
        return false;
    }
    fd1->reset(sockets[0]);
    fd2->reset(sockets[1]);
    return true;
}

struct SubprocessPollfds {
    adb_pollfd pfds[3];

    adb_pollfd* data() { return pfds; }
    size_t size() { return 3; }

    adb_pollfd* begin() { return pfds; }
    adb_pollfd* end() { return pfds + size(); }

    adb_pollfd& stdinout_pfd() { return pfds[0]; }
    adb_pollfd& stderr_pfd() { return pfds[1]; }
    adb_pollfd& protocol_pfd() { return pfds[2]; }
};

class Subprocess {
  public:
    Subprocess(std::string command, const char* terminal_type, SubprocessType type,
               SubprocessProtocol protocol, bool make_pty_raw);
    ~Subprocess();

    const std::string& command() const { return command_; }

    int ReleaseLocalSocket() { return local_socket_sfd_.release(); }

    pid_t pid() const { return pid_; }

    // Sets up FDs, forks a subprocess, starts the subprocess manager thread,
    // and exec's the child. Returns false and sets error on failure.
    bool ForkAndExec(std::string* _Nonnull error);

    // Sets up FDs, starts a thread executing command and the manager thread,
    // Returns false and sets error on failure.
    bool ExecInProcess(Command command, std::string* _Nonnull error);

    // Start the subprocess manager thread. Consumes the subprocess, regardless of success.
    // Returns false and sets error on failure.
    static bool StartThread(std::unique_ptr<Subprocess> subprocess,
                            std::string* _Nonnull error);

  private:
    // Opens the file at |pts_name|.

    bool ConnectProtocolEndpoints(std::string* _Nonnull error);

    static void ThreadHandler(void* userdata);
    void PassDataStreams();
    void WaitForExit();

    unique_fd* PollLoop(SubprocessPollfds* pfds);

    // Input/output stream handlers. Success returns nullptr, failure returns
    // a pointer to the failed FD.
    unique_fd* PassInput();
    unique_fd* PassOutput(unique_fd* sfd, ShellProtocol::Id id);

    const std::string command_;
    const std::string terminal_type_;
    SubprocessType type_;
    SubprocessProtocol protocol_;
    bool make_pty_raw_;
    pid_t pid_ = -1;
    unique_fd local_socket_sfd_;
    unique_fd raw_peer_watch_, raw_wake_;
    std::thread raw_disconnect_;
    /* The daemon's own copy of the shell every session runs: opened before the fork, so the session
     * child is handed an fd and no path has to be reachable for the user it becomes. */
    unique_fd shell_fd_;
    /* Why that open failed, for the message the child and the daemon both report. */
    int shell_fd_errno_ = 0;
    /* True for a session the client asked a terminal for: it runs on a pty, and its output also
     * passes the CRLF rule below. */
    bool ira_terminal_ = false;
    /* True when this session really has the pty above, so window-size requests have something to
     * apply to. */
    /* Carried across reads: a CR ending one read and the LF starting the next belong together. */
    bool ira_prev_cr_[2] = {false, false};

    // Shell protocol variables.
    unique_fd stdinout_sfd_, stderr_sfd_, protocol_sfd_;
    std::unique_ptr<ShellProtocol> input_, output_;
    size_t input_bytes_left_ = 0;

    DISALLOW_COPY_AND_ASSIGN(Subprocess);
};

Subprocess::Subprocess(std::string command, const char* terminal_type, SubprocessType type,
                       SubprocessProtocol protocol, bool make_pty_raw)
    : command_(std::move(command)),
      terminal_type_(terminal_type ? terminal_type : ""),
      type_(type),
      protocol_(protocol),
      make_pty_raw_(make_pty_raw) {}

Subprocess::~Subprocess() {
    WaitForExit();
    if (raw_disconnect_.joinable()) {
        uint64_t wake = 1;
        (void)adb_write(raw_wake_.get(), &wake, sizeof(wake));
        raw_disconnect_.join();
    }
}

static std::string GetHostName() {
    char buf[HOST_NAME_MAX];
    if (gethostname(buf, sizeof(buf)) != -1 && strcmp(buf, "localhost") != 0) return buf;

    return android::base::GetProperty("ro.product.device", "android");
}

bool Subprocess::ForkAndExec(std::string* error) {
    /* One answer and one question.
     *
     *   - Which shell runs: this module's own, for every session without exception - a session with
     *     no command and a session with one, pty or raw, shell:/exec:/abb:/remount:/whatever else
     *     ends in a shell. The su builtin lives only in that shell (mksh, vendor/mksh), so a
     *     session that ran the platform shell had no su in it. That used to depend on the spelling -
     *     "only a session with no command gets the private shell" - and on the pty before that,
     *     which is how a session ended up on /system/bin/sh: AOSP's adb client sends ",raw:"
     *     instead of ",pty:" whenever its stdin is not a terminal (client/commandline.cpp: the type
     *     argument is "raw" when stdin is a pipe, or when the command is not interactive), so
     *     `adb shell` from a script, from an IDE, through a wrapper or under `ssh phone adb shell`
     *     arrives here as SubprocessType::kRaw with an empty command. Nothing about the client's
     *     terminal says which shell it should get.
     *   - |ira_login_shell|: whether this session is the shell itself (no command) or one command
     *     run in it. It decides the argv the shell is given and which side assumes the session's
     *     privileges - not which shell runs.
     *   - |ira_terminal|: whether this side serves the terminal. True for a pty the client asked
     *     for, and false for the one StartSubprocess() synthesises out of a raw, protocol-less
     *     request (that session is a pipe: abb, exec:, `adb shell -T`), whose output correctly has
     *     no CRLF because AOSP disables the pty's ONLCR for it. */
    const bool ira_login_shell = command_.empty();
    const bool ira_terminal = (type_ == SubprocessType::kPty && !make_pty_raw_);

    ira_terminal_ = ira_terminal;
    /* Says what this session is, so a device log answers "which shell did this session get, and
     * with what argv" without a repro: the file is always this module's, and the open/exec failure
     * below is the only way a session ends up with nothing to run. */
    fprintf(stderr,
            "ira-session: type=%d protocol=%d cmd='%s' login=%d pty_raw=%d terminal=%d shell=%s\n",
            (int)type_, (int)protocol_, command_.c_str(), (int)ira_login_shell,
            (int)make_pty_raw_, (int)ira_terminal, IRA_SESSION_SHELL);

    unique_fd child_stdinout_sfd, child_stderr_sfd;
    unique_fd parent_error_sfd, child_error_sfd;


    // Create a socketpair for the fork() child to report any errors back to the parent. Since we
    // use threads, logging directly from the child might deadlock due to locks held in another
    // thread during the fork.
    if (!CreateSocketpair(&parent_error_sfd, &child_error_sfd)) {
        *error = android::base::StringPrintf(
            "failed to create pipe for subprocess error reporting: %s", strerror(errno));
        return false;
    }

    // Construct the environment for the child before we fork.
    /* It belongs to the user the session ends up as, not to the daemon: this process runs as root
     * (it keeps the root it was started with), while every session is the shell user unless root
     * mode was asked for. */
    passwd* pw = ira_root_mode() ? getpwuid(0) : getpwnam("shell");
    std::unordered_map<std::string, std::string> env;
    if (environ) {
        char** current = environ;
        while (char* env_cstr = *current++) {
            std::string env_string = env_cstr;
            char* delimiter = strchr(&env_string[0], '=');

            // Drop any values that don't contain '='.
            if (delimiter) {
                *delimiter++ = '\0';
                env[env_string.c_str()] = delimiter;
            }
        }
    }

    if (pw != nullptr) {
        env["HOME"] = pw->pw_dir;
        env["HOSTNAME"] = GetHostName();
        env["LOGNAME"] = pw->pw_name;
        env["SHELL"] = pw->pw_shell;
        env["TMPDIR"] = "/data/local/tmp";
        env["USER"] = pw->pw_name;
    }

    if (ira_terminal) {
        /* The session has no pty (a tty device is a detection surface): the shell is told that the
         * fd it reads is its terminal, and answers the tty calls from memory with its own line
         * editor, prompt and control characters (vendor/mksh: ira_vtty, misc.c). */
        env["IRA_VTTY"] = "1";
    }

    if (!terminal_type_.empty()) {
        env["TERM"] = terminal_type_;
    }

    std::vector<std::string> joined_env;
    for (const auto& it : env) {
        const char* key = it.first.c_str();
        const char* value = it.second.c_str();
        joined_env.push_back(android::base::StringPrintf("%s=%s", key, value));
    }

    std::vector<const char*> cenv;
    for (const std::string& str : joined_env) {
        cenv.push_back(str.c_str());
    }
    cenv.push_back(nullptr);

    /* The backend preopened the private shell before its process-wide identity transition.
     * Duplicate that fd for the session: a shell-domain child cannot traverse /data/adb,
     * but fexecve() can execute the already-open shell_exec inode. */
    shell_fd_.reset(ira_session_shell_fd());
    if (shell_fd_ < 0) {
        shell_fd_errno_ = errno;
        /* Logged here, before the fork, so that the daemon's log says it even when nothing the
         * client reads survives: a module that is not mounted at this path, a build without the
         * shell in it, a file the module's installer never made executable - all of them are this
         * one line, and the session ends on it (the child reports the same failure to the client). */
        fprintf(stderr,
                "ira-session: cannot open the session shell %s: %d (%s); this session has no"
                " shell and will not be started\n",
                IRA_SESSION_SHELL, shell_fd_errno_, strerror(shell_fd_errno_));
    }

    /* No pty, ever: a terminal session is served over a socketpair like every other session.
     * Allocating a kernel tty would create a pts device node, which is a detection surface this
     * project must not have. The shell is told it is interactive by its argv ("sh -i"), and it
     * runs with job control off because a socketpair is not a tty. */
    if (!CreateSocketpair(&stdinout_sfd_, &child_stdinout_sfd)) {
        *error = android::base::StringPrintf("failed to create socketpair for stdin/out: %s",
                                             strerror(errno));
        return false;
    }

    // Raw subprocess + shell protocol allows for splitting stderr.
    if (protocol_ == SubprocessProtocol::kShell &&
            !CreateSocketpair(&stderr_sfd_, &child_stderr_sfd)) {
        *error = android::base::StringPrintf("failed to create socketpair for stderr: %s",
                                             strerror(errno));
        return false;
    }
    if (protocol_ == SubprocessProtocol::kNone) {
        raw_peer_watch_.reset(fcntl(child_stdinout_sfd.get(), F_DUPFD_CLOEXEC, 3));
        if (raw_peer_watch_ < 0) { *error = "cannot monitor raw session disconnect"; return false; }
    }
    pid_ = fork();

    if (pid_ == -1) {
        *error = android::base::StringPrintf("fork failed: %s", strerror(errno));
        return false;
    }

    if (pid_ == 0) {
        // Subprocess child. The service backend owns this session lifetime.
        if (prctl(PR_SET_PDEATHSIG, SIGHUP) != 0 || getppid() == 1) _exit(126);
        setsid();

        /* A socketpair, not a pty: setsid() gives the child its own session, and nothing here
         * tries to attach a controlling terminal, because there is none to attach. */
        dup2(child_stdinout_sfd.get(), STDIN_FILENO);
        dup2(child_stdinout_sfd.get(), STDOUT_FILENO);
        dup2(child_stderr_sfd != -1 ? child_stderr_sfd.get() : child_stdinout_sfd.get(),
             STDERR_FILENO);

        // exec doesn't trigger destructors, close the FDs manually.
        stdinout_sfd_.reset(-1);
        stderr_sfd_.reset(-1);
        child_stdinout_sfd.reset(-1);
        child_stderr_sfd.reset(-1);
        parent_error_sfd.reset(-1);
        close_on_exec(child_error_sfd);

        // adbd sets SIGPIPE to SIG_IGN to get EPIPE instead, and Linux propagates that to child
        // processes, so we need to manually reset back to SIG_DFL here (http://b/35209888).
        ira_child_signals();

        // Increase oom_score_adj from -1000, so that the child is visible to the OOM-killer.
        // Don't treat failure as an error, because old Android kernels explicitly disabled this.
        int oom_score_adj_fd = adb_open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
        if (oom_score_adj_fd != -1) {
            const char* oom_score_adj_value = "-950";
            TEMP_FAILURE_RETRY(
                adb_write(oom_score_adj_fd, oom_score_adj_value, strlen(oom_score_adj_value)));
        }


        /* Every session executes the private shell with the backend's existing identity.
         * Login versus command mode changes argv; it does not change credentials. */
        char* argv_command[] = {(char*)"sh", (char*)"-c", const_cast<char*>(command_.c_str()),
                                nullptr};
        /* `-i` only where this side serves the terminal: the shell is talking to a socketpair
         * rather than a pty, so it is told it has a prompt to print, line editing to do and no job
         * control to rely on. A raw session ("shell,...,raw:" with no command, which is what a
         * client with a pipe for stdin sends) is a script on stdin and is started without it,
         * exactly as the system shell would have been. */
        char* argv_terminal[] = {(char*)"sh", (char*)"-i", nullptr};
        char* argv_stream[] = {(char*)"sh", nullptr};
        char** argv;
        int exec_errno = shell_fd_errno_ != 0 ? shell_fd_errno_ : ENOENT;

        if (ira_login_shell) {
            argv = ira_terminal ? argv_terminal : argv_stream;
        } else {
            argv = argv_command;
        }
        /* Every session runs as the session's own user, the way adbd's does: the shell is entered
         * already dropped (uid, adbd's supplementary groups, the shell domain) instead of dropping
         * itself, so a session that cannot drop cannot end up as root either. */
        if (ira_privileges_child(false) != 0) {
            WriteFdExactly(child_error_sfd, "cannot enter session identity: ");
            WriteFdExactly(child_error_sfd, strerror(errno));
            _exit(126);
        }
        /* adbd's own sessions start in "/", not in whatever directory the daemon was started
         * from: a shell that starts in the module's directory is a fingerprint of this stack. */
        if (chdir("/") != 0)
            fprintf(stderr, "ira-session: chdir /: %s\n", strerror(errno));

        /* fexecve() and not execle(): the file is the fd opened above, because a path under
         * /data/adb is not one this child can necessarily walk to. */
        if (shell_fd_ >= 0) {
            fexecve(shell_fd_.get(), argv, const_cast<char**>(cenv.data()));
            exec_errno = errno;
        }
        /* No fallback to /system/bin/sh, for any session: swapping in the platform shell silently
         * gives it a different prompt, different job control, a different idea of what a session is
         * - and no su builtin, which is the bug this branch exists to prevent. A session that
         * cannot get its own shell names the file it wanted and ends: this is the error channel
         * AOSP uses for a failed exec, so the daemon logs it and the client is told. */
        WriteFdExactly(child_error_sfd, "cannot execute the session shell '");
        WriteFdExactly(child_error_sfd, IRA_SESSION_SHELL);
        WriteFdExactly(child_error_sfd, "': ");
        WriteFdExactly(child_error_sfd, strerror(exec_errno));
        child_error_sfd.reset(-1);
        _exit(127);
    }

    // Subprocess parent.
    D("subprocess parent: stdin/stdout FD = %d, stderr FD = %d",
      stdinout_sfd_.get(), stderr_sfd_.get());

    // Wait to make sure the subprocess exec'd without error.
    child_error_sfd.reset(-1);
    std::string error_message = ReadAll(parent_error_sfd);
    if (!error_message.empty()) {
        *error = error_message;
        return false;
    }

    D("subprocess parent: exec completed");
    if (!ConnectProtocolEndpoints(error)) {
        kill(pid_, SIGKILL);
        return false;
    }

    D("subprocess parent: completed");
    return true;
}

bool Subprocess::ExecInProcess(Command command, std::string* _Nonnull error) {
    unique_fd child_stdinout_sfd, child_stderr_sfd;

    CHECK(type_ == SubprocessType::kRaw);

    if (!CreateSocketpair(&stdinout_sfd_, &child_stdinout_sfd)) {
        *error = android::base::StringPrintf("failed to create socketpair for stdin/out: %s",
                                             strerror(errno));
        return false;
    }
    if (protocol_ == SubprocessProtocol::kShell) {
        // Shell protocol allows for splitting stderr.
        if (!CreateSocketpair(&stderr_sfd_, &child_stderr_sfd)) {
            *error = android::base::StringPrintf("failed to create socketpair for stderr: %s",
                                                 strerror(errno));
            return false;
        }
    } else {
        // Raw protocol doesn't support multiple output streams, so combine stdout and stderr.
        child_stderr_sfd.reset(dup(child_stdinout_sfd.get()));
    }

    D("execinprocess: stdin/stdout FD = %d, stderr FD = %d", stdinout_sfd_.get(),
      stderr_sfd_.get());

    if (!ConnectProtocolEndpoints(error)) {
        return false;
    }

    std::thread([inout_sfd = std::move(child_stdinout_sfd), err_sfd = std::move(child_stderr_sfd),
                 command = std::move(command),
                 args = command_]() { command(args, inout_sfd, inout_sfd, err_sfd); })
            .detach();

    D("execinprocess: completed");
    return true;
}

bool Subprocess::ConnectProtocolEndpoints(std::string* _Nonnull error) {
    if (protocol_ == SubprocessProtocol::kNone) {
        // No protocol: all streams pass through the stdinout FD and hook
        // directly into the local socket for raw data transfer.
        local_socket_sfd_.reset(stdinout_sfd_.release());
    } else {
        // Required for shell protocol: create another socketpair to intercept data.
        if (!CreateSocketpair(&protocol_sfd_, &local_socket_sfd_)) {
            *error = android::base::StringPrintf(
                    "failed to create socketpair to intercept data: %s", strerror(errno));
            return false;
        }
        D("protocol FD = %d", protocol_sfd_.get());

        input_ = std::make_unique<ShellProtocol>(protocol_sfd_);
        output_ = std::make_unique<ShellProtocol>(protocol_sfd_);
        if (!input_ || !output_) {
            *error = "failed to allocate shell protocol objects";
            return false;
        }

        // Don't let reads/writes to the subprocess block our thread. This isn't
        // likely but could happen under unusual circumstances, such as if we
        // write a ton of data to stdin but the subprocess never reads it and
        // the pipe fills up.
        for (int fd : {stdinout_sfd_.get(), stderr_sfd_.get()}) {
            if (fd >= 0) {
                if (!set_file_block_mode(fd, false)) {
                    *error = android::base::StringPrintf(
                            "failed to set non-blocking mode for fd %d", fd);
                    return false;
                }
            }
        }
    }

    return true;
}

bool Subprocess::StartThread(std::unique_ptr<Subprocess> subprocess, std::string* error) {
    Subprocess* raw = subprocess.release();
    std::thread(ThreadHandler, raw).detach();

    return true;
}


void Subprocess::ThreadHandler(void* userdata) {
    Subprocess* subprocess = reinterpret_cast<Subprocess*>(userdata);

    adb_thread_setname(android::base::StringPrintf("shell svc %d", subprocess->pid()));

    D("passing data streams for PID %d", subprocess->pid());
    subprocess->PassDataStreams();

    D("deleting Subprocess for PID %d", subprocess->pid());
    delete subprocess;
}

void Subprocess::PassDataStreams() {
    if (protocol_sfd_ == -1) {
        // No data relay: preserve raw bytes and SCM_RIGHTS (abb uses descriptor passing).
        // Watch a duplicate of the child endpoint only for peer hangup, and wake on child exit.
        if (raw_peer_watch_ >= 0 && pid_ > 0) {
            raw_wake_.reset(eventfd(0, EFD_CLOEXEC));
            if (raw_wake_ < 0) {
                kill(pid_, SIGHUP);
                return;
            }
            raw_disconnect_ = std::thread([this] {
                adb_pollfd fds[] = {{raw_peer_watch_.get(), 0, 0}, {raw_wake_.get(), POLLIN, 0}};
                int result;
                do { result = adb_poll(fds, 2, -1); } while (result < 0 && errno == EINTR);
                if (result < 0 || (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL)))
                    kill(pid_, SIGHUP);
            });
        }
        return;
    }

    // Start by trying to read from the protocol FD, stdout, and stderr.
    SubprocessPollfds pfds;
    pfds.stdinout_pfd() = {.fd = stdinout_sfd_.get(), .events = POLLIN};
    pfds.stderr_pfd() = {.fd = stderr_sfd_.get(), .events = POLLIN};
    pfds.protocol_pfd() = {.fd = protocol_sfd_.get(), .events = POLLIN};

    // Pass data until the protocol FD or both the subprocess pipes die, at
    // which point we can't pass any more data.
    while (protocol_sfd_ != -1 && (stdinout_sfd_ != -1 || stderr_sfd_ != -1)) {
        unique_fd* dead_sfd = PollLoop(&pfds);
        if (dead_sfd) {
            D("closing FD %d", dead_sfd->get());
            auto it = std::find_if(pfds.begin(), pfds.end(), [=](const adb_pollfd& pfd) {
                return pfd.fd == dead_sfd->get();
            });
            CHECK(it != pfds.end());
            it->fd = -1;
            it->events = 0;
            if (dead_sfd == &protocol_sfd_) {
                // Using SIGHUP is a decent general way to indicate that the
                // controlling process is going away. If specific signals are
                // needed (e.g. SIGINT), pass those through the shell protocol
                // and only fall back on this for unexpected closures.
                D("protocol FD died, sending SIGHUP to pid %d", pid_);
                if (pid_ != -1) {
                    kill(pid_, SIGHUP);
                }

                // We also need to close the pipes connected to the child process
                // so that if it ignores SIGHUP and continues to write data it
                // won't fill up the pipe and block.
                stdinout_sfd_.reset();
                stderr_sfd_.reset();
            }
            dead_sfd->reset();
        }
    }
}

unique_fd* Subprocess::PollLoop(SubprocessPollfds* pfds) {
    unique_fd* dead_sfd = nullptr;
    adb_pollfd& stdinout_pfd = pfds->stdinout_pfd();
    adb_pollfd& stderr_pfd = pfds->stderr_pfd();
    adb_pollfd& protocol_pfd = pfds->protocol_pfd();

    // Keep calling poll() and passing data until an FD closes/errors.
    while (!dead_sfd) {
        if (adb_poll(pfds->data(), pfds->size(), -1) < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                PLOG(ERROR) << "poll failed, closing subprocess pipes";
                stdinout_sfd_.reset(-1);
                stderr_sfd_.reset(-1);
                return nullptr;
            }
        }

        // Read stdout, write to protocol FD.
        if (stdinout_pfd.fd != -1 && (stdinout_pfd.revents & POLLIN)) {
            dead_sfd = PassOutput(&stdinout_sfd_, ShellProtocol::kIdStdout);
        }

        // Read stderr, write to protocol FD.
        if (!dead_sfd && stderr_pfd.fd != 1 && (stderr_pfd.revents & POLLIN)) {
            dead_sfd = PassOutput(&stderr_sfd_, ShellProtocol::kIdStderr);
        }

        // Read protocol FD, write to stdin.
        if (!dead_sfd && protocol_pfd.fd != -1 && (protocol_pfd.revents & POLLIN)) {
            dead_sfd = PassInput();
            // If we didn't finish writing, block on stdin write.
            if (input_bytes_left_) {
                protocol_pfd.events &= ~POLLIN;
                stdinout_pfd.events |= POLLOUT;
            }
        }

        // Continue writing to stdin; only happens if a previous write blocked.
        if (!dead_sfd && stdinout_pfd.fd != -1 && (stdinout_pfd.revents & POLLOUT)) {
            dead_sfd = PassInput();
            // If we finished writing, go back to blocking on protocol read.
            if (!input_bytes_left_) {
                protocol_pfd.events |= POLLIN;
                stdinout_pfd.events &= ~POLLOUT;
            }
        }

        // After handling all of the events we've received, check to see if any fds have died.
        auto poll_finished = [](int events) {
            // Don't return failure until we've read out all of the fd's incoming data.
            return (events & POLLIN) == 0 &&
                   (events & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL)) != 0;
        };

        if (poll_finished(stdinout_pfd.revents)) {
            return &stdinout_sfd_;
        }

        if (poll_finished(stderr_pfd.revents)) {
            return &stderr_sfd_;
        }

        if (poll_finished(protocol_pfd.revents)) {
            return &protocol_sfd_;
        }
    }  // while (!dead_sfd)

    return dead_sfd;
}

unique_fd* Subprocess::PassInput() {
    // Only read a new packet if we've finished writing the last one.
    if (!input_bytes_left_) {
        if (!input_->Read()) {
            // Read() uses ReadFdExactly() which sets errno to 0 on EOF.
            if (errno != 0) {
                PLOG(ERROR) << "error reading protocol FD " << protocol_sfd_.get();
            }
            return &protocol_sfd_;
        }

        if (stdinout_sfd_ != -1) {
            switch (input_->id()) {
                case ShellProtocol::kIdWindowSizeChange:
                    /* A socketpair session has no window size and no pty to apply it to. The
                     * message is accepted and dropped: the client sends it unconditionally. */
                    break;
                case ShellProtocol::kIdStdin:
                    input_bytes_left_ = input_->data_length();
                    break;
                case ShellProtocol::kIdCloseStdin:
                    if (type_ == SubprocessType::kRaw) {
                        if (adb_shutdown(stdinout_sfd_, SHUT_WR) == 0) {
                            return nullptr;
                        }
                        PLOG(ERROR) << "failed to shutdown writes to FD " << stdinout_sfd_.get();
                        return &stdinout_sfd_;
                    } else {
                        // PTYs can't close just input, so rather than close the
                        // FD and risk losing subprocess output, leave it open.
                        // This only happens if the client starts a PTY shell
                        // non-interactively which is rare and unsupported.
                        // If necessary, the client can manually close the shell
                        // with `exit` or by killing the adb client process.
                        D("can't close input for PTY FD %d", stdinout_sfd_.get());
                    }
                    break;
            }
        }
    }

    if (input_bytes_left_ > 0) {
        int index = input_->data_length() - input_bytes_left_;
        int bytes = adb_write(stdinout_sfd_, input_->data() + index, input_bytes_left_);
        if (bytes == 0 || (bytes < 0 && errno != EAGAIN)) {
            if (bytes < 0) {
                PLOG(ERROR) << "error reading stdin FD " << stdinout_sfd_.get();
            }
            // stdin is done, mark this packet as finished and we'll just start
            // dumping any further data received from the protocol FD.
            input_bytes_left_ = 0;
            return &stdinout_sfd_;
        } else if (bytes > 0) {
            input_bytes_left_ -= bytes;
        }
    }

    return nullptr;
}

unique_fd* Subprocess::PassOutput(unique_fd* sfd, ShellProtocol::Id id) {
    int bytes = adb_read(*sfd, output_->data(), output_->data_capacity());
    if (bytes == 0 || (bytes < 0 && errno != EAGAIN)) {
        // read() returns EIO if a PTY closes; don't report this as an error,
        // it just means the subprocess completed.
        if (bytes < 0 && !(type_ == SubprocessType::kPty && errno == EIO)) {
            PLOG(ERROR) << "error reading output FD " << sfd->get();
        }
        return sfd;
    }

    if (bytes > 0 && ira_terminal_) {
        /* No pty means no ONLCR: the child's own output would arrive without a carriage return
         * and a raw-mode client draws it as a staircase. Done in chunks of at most half the
         * protocol buffer, because expanding a whole bufferful of LF doubles it. */
        size_t step = output_->data_capacity() / 2;
        std::string raw(output_->data(), (size_t)bytes);
        bool& prev_cr = ira_prev_cr_[id == ShellProtocol::kIdStderr ? 1 : 0];

        for (size_t off = 0; off < raw.size(); off += step) {
            size_t take = raw.size() - off < step ? raw.size() - off : step;
            std::string converted;

            converted.reserve(take + take / 2);
            for (size_t i = 0; i < take; i++) {
                char c = raw[off + i];

                if (c == '\n' && !prev_cr)
                    converted.push_back('\r');
                converted.push_back(c);
                prev_cr = (c == '\r');
            }
            memcpy(output_->data(), converted.data(), converted.size());
            if (!output_->Write(id, (int)converted.size())) {
                if (errno != 0)
                    PLOG(ERROR) << "error reading protocol FD " << protocol_sfd_.get();
                return &protocol_sfd_;
            }
        }
        return nullptr;
    }

    if (bytes > 0 && !output_->Write(id, bytes)) {
        if (errno != 0) {
            PLOG(ERROR) << "error reading protocol FD " << protocol_sfd_.get();
        }
        return &protocol_sfd_;
    }

    return nullptr;
}

void Subprocess::WaitForExit() {
    int exit_code = 1;

    D("waiting for pid %d", pid_);
    while (pid_ != -1) {
        int status;
        if (pid_ == waitpid(pid_, &status, 0)) {
            D("post waitpid (pid=%d) status=%04x", pid_, status);
            if (WIFSIGNALED(status)) {
                exit_code = 0x80 | WTERMSIG(status);
                ADB_LOG(Shell) << "subprocess " << pid_ << " killed by signal " << WTERMSIG(status);
                break;
            } else if (!WIFEXITED(status)) {
                D("subprocess didn't exit");
                break;
            } else if (WEXITSTATUS(status) >= 0) {
                exit_code = WEXITSTATUS(status);
                ADB_LOG(Shell) << "subprocess " << pid_ << " exited with status " << exit_code;
                break;
            }
        }
    }

    // If we have an open protocol FD send an exit packet.
    if (protocol_sfd_ != -1) {
        output_->data()[0] = exit_code;
        if (output_->Write(ShellProtocol::kIdExit, 1)) {
            D("wrote the exit code packet: %d", exit_code);
        } else {
            PLOG(ERROR) << "failed to write the exit code packet";
        }
        protocol_sfd_.reset(-1);
    }
}

}  // namespace

// Create a pipe containing the error.
unique_fd ReportError(SubprocessProtocol protocol, const std::string& message) {
    unique_fd read, write;
    if (!Pipe(&read, &write)) {
        PLOG(ERROR) << "failed to create pipe to report error";
        return unique_fd{};
    }

    std::string buf = android::base::StringPrintf("error: %s\n", message.c_str());
    if (protocol == SubprocessProtocol::kShell) {
        ShellProtocol::Id id = ShellProtocol::kIdStderr;
        uint32_t length = buf.length();
        WriteFdExactly(write.get(), &id, sizeof(id));
        WriteFdExactly(write.get(), &length, sizeof(length));
    }

    WriteFdExactly(write.get(), buf.data(), buf.length());

    if (protocol == SubprocessProtocol::kShell) {
        ShellProtocol::Id id = ShellProtocol::kIdExit;
        uint32_t length = 1;
        char exit_code = 126;
        WriteFdExactly(write.get(), &id, sizeof(id));
        WriteFdExactly(write.get(), &length, sizeof(length));
        WriteFdExactly(write.get(), &exit_code, sizeof(exit_code));
    }

    return read;
}

unique_fd StartSubprocess(std::string name, const char* terminal_type, SubprocessType type,
                          SubprocessProtocol protocol) {
    // If we aren't using the shell protocol we must allocate a PTY to properly close the
    // subprocess. PTYs automatically send SIGHUP to the slave-side process when the master side
    // of the PTY closes, which we rely on. If we use a raw pipe, processes that don't read/write,
    // e.g. screenrecord, will never notice the broken pipe and terminate.
    // The shell protocol doesn't require a PTY because it's always monitoring the local socket FD
    // with select() and will send SIGHUP manually to the child process.
    bool make_pty_raw = false;
    if (protocol == SubprocessProtocol::kNone && type == SubprocessType::kRaw) {
        // Disable PTY input/output processing since the client is expecting raw data.
        D("Can't create raw subprocess without shell protocol, using PTY in raw mode instead");
        type = SubprocessType::kPty;
        make_pty_raw = true;
    }

    unique_fd error_fd;
    unique_fd fd = StartSubprocess(std::move(name), terminal_type, type, protocol, make_pty_raw,
                                   protocol, &error_fd);
    if (fd == -1) {
        return error_fd;
    }
    return fd;
}

unique_fd StartSubprocess(std::string name, const char* terminal_type, SubprocessType type,
                          SubprocessProtocol protocol, bool make_pty_raw,
                          SubprocessProtocol error_protocol, unique_fd* error_fd) {
    D("starting %s subprocess (protocol=%s, TERM=%s): '%s'",
      type == SubprocessType::kRaw ? "raw" : "PTY",
      protocol == SubprocessProtocol::kNone ? "none" : "shell", terminal_type, name.c_str());

    auto subprocess = std::make_unique<Subprocess>(std::move(name), terminal_type, type, protocol,
                                                   make_pty_raw);
    if (!subprocess) {
        LOG(ERROR) << "failed to allocate new subprocess";
        *error_fd = ReportError(error_protocol, "failed to allocate new subprocess");
        return {};
    }

    std::string error;
    if (!subprocess->ForkAndExec(&error)) {
        LOG(ERROR) << "failed to start subprocess: " << error;
        *error_fd = ReportError(error_protocol, error);
        return {};
    }

    unique_fd local_socket(subprocess->ReleaseLocalSocket());
    D("subprocess creation successful: local_socket_fd=%d, pid=%d", local_socket.get(),
      subprocess->pid());

    if (!Subprocess::StartThread(std::move(subprocess), &error)) {
        LOG(ERROR) << "failed to start subprocess management thread: " << error;
        *error_fd = ReportError(error_protocol, error);
        return {};
    }

    return local_socket;
}

unique_fd StartCommandInProcess(std::string name, Command command, SubprocessProtocol protocol) {
    LOG(INFO) << "StartCommandInProcess(" << dump_hex(name.data(), name.size()) << ")";

    constexpr auto terminal_type = "";
    constexpr auto type = SubprocessType::kRaw;
    constexpr auto make_pty_raw = false;

    auto subprocess = std::make_unique<Subprocess>(std::move(name), terminal_type, type, protocol,
                                                   make_pty_raw);
    if (!subprocess) {
        LOG(ERROR) << "failed to allocate new subprocess";
        return ReportError(protocol, "failed to allocate new subprocess");
    }

    std::string error;
    if (!subprocess->ExecInProcess(std::move(command), &error)) {
        LOG(ERROR) << "failed to start subprocess: " << error;
        return ReportError(protocol, error);
    }

    unique_fd local_socket(subprocess->ReleaseLocalSocket());
    D("inprocess creation successful: local_socket_fd=%d, pid=%d", local_socket.get(),
      subprocess->pid());

    if (!Subprocess::StartThread(std::move(subprocess), &error)) {
        LOG(ERROR) << "failed to start inprocess management thread: " << error;
        return ReportError(protocol, error);
    }

    return local_socket;
}
