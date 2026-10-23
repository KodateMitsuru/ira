// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
/*
 * Copyright (C) 2007 The Android Open Source Project
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

#pragma once

/* this file contains system-dependent definitions used by ADB
 * they're related to threads, sockets and file descriptors
 */


// Include this protobuf header first, because it uses some write() calls
// that we will redefine later. Not all modules that include sysdeps.h use
// protobufs, so only include it if it exists.
#if __has_include("google/protobuf/io/coded_stream.h")
#include "google/protobuf/io/coded_stream.h"
#endif

#include <errno.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Include this before open/close/isatty/unlink are defined as macros below.
#include <android-base/errors.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/off64_t.h>
#include <android-base/unique_fd.h>
#include <android-base/utf8.h>
#if __has_include(<print>)
#include <print>
#endif

#include "adb_unique_fd.h"
#include "sysdeps/errno.h"
#include "sysdeps/network.h"
#include "sysdeps/stat.h"


std::optional<ssize_t> network_peek(borrowed_fd fd);


#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include <cutils/sockets.h>

#define OS_PATH_SEPARATORS "/"
#define OS_PATH_SEPARATOR '/'
#define OS_PATH_SEPARATOR_STR "/"
#define ENV_PATH_SEPARATOR_STR ":"

static inline bool adb_is_separator(char c) {
    return c == '/';
}

static inline int get_fd_flags(borrowed_fd fd) {
    return fcntl(fd.get(), F_GETFD);
}

static inline void close_on_exec(borrowed_fd fd) {
    int flags = get_fd_flags(fd);
    if (flags >= 0 && (flags & FD_CLOEXEC) == 0) {
        fcntl(fd.get(), F_SETFD, flags | FD_CLOEXEC);
    }
}

// Open a file and return a file descriptor that may be used with unix_read(),
// unix_write(), unix_close(), but not adb_read(), adb_write(), adb_close().
//
// On Unix, this is based on open(), so the file descriptor is a real OS file
// descriptor, but the Windows implementation (in sysdeps_win32.cpp) returns a
// file descriptor that can only be used with C Runtime APIs (which are wrapped
// by unix_read(), unix_write(), unix_close()). Also, the C Runtime has
// configurable CR/LF translation which defaults to text mode, but is settable
// with _setmode().
static inline int unix_open(std::string_view path, int options, ...) {
    std::string zero_terminated(path.begin(), path.end());
    if ((options & O_CREAT) == 0) {
        return TEMP_FAILURE_RETRY(open(zero_terminated.c_str(), options));
    } else {
        int mode;
        va_list args;
        va_start(args, options);
        mode = va_arg(args, int);
        va_end(args);
        return TEMP_FAILURE_RETRY(open(zero_terminated.c_str(), options, mode));
    }
}

// Similar to the two-argument adb_open(), but takes a mode parameter for file
// creation. See adb_open() for more info.
static inline int adb_open_mode(const char* pathname, int options, int mode) {
    return TEMP_FAILURE_RETRY(open(pathname, options, mode));
}

// Open a file and return a file descriptor that may be used with adb_read(),
// adb_write(), adb_close(), but not unix_read(), unix_write(), unix_close().
//
// On Unix, this is based on open(), but the Windows implementation (in
// sysdeps_win32.cpp) uses Windows native file I/O and bypasses the C Runtime
// and its CR/LF translation. The returned file descriptor should be used with
// adb_read(), adb_write(), adb_close(), etc.
static inline int adb_open(const char* pathname, int options) {
    int fd = TEMP_FAILURE_RETRY(open(pathname, options));
    if (fd < 0) return -1;
    close_on_exec(fd);
    return fd;
}
#undef open
#define open ___xxx_open

static inline int adb_shutdown(borrowed_fd fd, int direction = SHUT_RDWR) {
    return shutdown(fd.get(), direction);
}

#undef shutdown
#define shutdown ____xxx_shutdown

// Closes a file descriptor that came from adb_open() or adb_open_mode(), but
// not designed to take a file descriptor from unix_open(). See the comments
// for adb_open() for more info.
inline int adb_close(int fd) {
    return close(fd);
}
#undef close
#define close ____xxx_close

// On Windows, ADB has an indirection layer for file descriptors. If we get a
// Win32 SOCKET object from an external library, we have to map it in to that
// indirection layer, which this does.
inline int adb_register_socket(int s) {
    return s;
}

static inline int adb_gethostname(char* name, size_t len) {
    return gethostname(name, len);
}

static inline int adb_getlogin_r(char* buf, size_t bufsize) {
    return getlogin_r(buf, bufsize);
}

static inline int adb_read(borrowed_fd fd, void* buf, size_t len) {
    return TEMP_FAILURE_RETRY(read(fd.get(), buf, len));
}

static inline int adb_pread(borrowed_fd fd, void* buf, size_t len, off64_t offset) {
    return TEMP_FAILURE_RETRY(pread64(fd.get(), buf, len, offset));
}

// Like unix_read(), but does not handle EINTR.
static inline int unix_read_interruptible(borrowed_fd fd, void* buf, size_t len) {
    return read(fd.get(), buf, len);
}

#undef read
#define read ___xxx_read
#undef pread
#define pread ___xxx_pread

static inline int adb_write(borrowed_fd fd, const void* buf, size_t len) {
    return TEMP_FAILURE_RETRY(write(fd.get(), buf, len));
}

static inline int adb_pwrite(int fd, const void* buf, size_t len, off64_t offset) {
    return TEMP_FAILURE_RETRY(pwrite64(fd, buf, len, offset));
}

#undef   write
#define  write  ___xxx_write
#undef pwrite
#define pwrite ___xxx_pwrite

static inline int64_t adb_lseek(borrowed_fd fd, int64_t pos, int where) {
    return lseek64(fd.get(), pos, where);
}
#undef lseek
#define lseek ___xxx_lseek

static inline int adb_unlink(const char* path) {
    return unlink(path);
}
#undef unlink
#define unlink ___xxx_unlink

static inline int adb_creat(const char* path, int mode) {
    int fd = TEMP_FAILURE_RETRY(creat(path, mode));

    if (fd < 0) return -1;

    close_on_exec(fd);
    return fd;
}
#undef creat
#define creat ___xxx_creat

static inline int unix_isatty(borrowed_fd fd) {
    return isatty(fd.get());
}
#define isatty ___xxx_isatty

// Helper for network_* functions.
inline int _fd_set_error_str(int fd, std::string* error) {
    if (fd == -1) {
        *error = strerror(errno);
    }
    return fd;
}

inline int network_inaddr_any_server(int port, int type, std::string* error) {
    return _fd_set_error_str(socket_inaddr_any_server(port, type), error);
}

inline int network_local_client(const char* name, int namespace_id, int type, std::string* error) {
    return _fd_set_error_str(socket_local_client(name, namespace_id, type), error);
}

inline int network_local_server(const char* name, int namespace_id, int type, std::string* error) {
    return _fd_set_error_str(socket_local_server(name, namespace_id, type), error);
}

int network_connect(const std::string& host, int port, int type, int timeout, std::string* error);

static inline int adb_socket_accept(borrowed_fd serverfd, struct sockaddr* addr,
                                    socklen_t* addrlen) {
    int fd;

    fd = TEMP_FAILURE_RETRY(accept(serverfd.get(), addr, addrlen));
    if (fd >= 0) close_on_exec(fd);

    return fd;
}

#undef accept
#define accept ___xxx_accept

inline int adb_getsockname(borrowed_fd fd, struct sockaddr* sockaddr, socklen_t* addrlen) {
    return getsockname(fd.get(), sockaddr, addrlen);
}

inline int adb_socket_get_local_port(borrowed_fd fd) {
    return socket_get_local_port(fd.get());
}

// Operate on a file descriptor returned from unix_open() or a well-known file
// descriptor such as STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO.
//
// On Unix, unix_read(), unix_write(), unix_close() map to adb_read(),
// adb_write(), adb_close() (which all map to Unix system calls), but the
// Windows implementations (in the ifdef above and in sysdeps_win32.cpp) call
// into the C Runtime and its configurable CR/LF translation (which is settable
// via _setmode()).
#define unix_read adb_read
#define unix_write adb_write
#define unix_lseek adb_lseek
#define unix_close adb_close

static inline int adb_thread_setname(const std::string& name) {
    // Both bionic and glibc's pthread_setname_np fails rather than truncating long strings.
    // glibc doesn't have strlcpy, so we have to fake it.
    char buf[16];  // MAX_TASK_COMM_LEN, but that's not exported by the kernel headers.
    strncpy(buf, name.c_str(), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    return pthread_setname_np(pthread_self(), buf);
}

static inline int adb_setsockopt(borrowed_fd fd, int level, int optname, const void* optval,
                                 socklen_t optlen) {
    return setsockopt(fd.get(), level, optname, optval, optlen);
}

#undef setsockopt
#define setsockopt ___xxx_setsockopt

static inline int adb_socket(int domain, int type, int protocol) {
    return socket(domain, type, protocol);
}

static inline int adb_bind(borrowed_fd fd, const sockaddr* addr, int namelen) {
    return bind(fd.get(), addr, namelen);
}

static inline int unix_socketpair(int d, int type, int protocol, int sv[2]) {
    return socketpair(d, type, protocol, sv);
}

static inline int adb_socketpair(int sv[2]) {
    int rc;

    rc = unix_socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    if (rc < 0) return -1;

    close_on_exec(sv[0]);
    close_on_exec(sv[1]);
    return 0;
}

#undef socketpair
#define socketpair ___xxx_socketpair

typedef struct msghdr adb_msghdr;
inline ssize_t adb_sendmsg(borrowed_fd fd, const adb_msghdr* msg, int flags) {
    return sendmsg(fd.get(), msg, flags);
}

inline ssize_t adb_recvmsg(borrowed_fd fd, adb_msghdr* msg, int flags) {
    ssize_t ret = recvmsg(fd.get(), msg, flags);
    if (ret == -1) {
        PLOG(ERROR) << "adb_recmsg error";
    }
    return ret;
}

using adb_cmsghdr = cmsghdr;

inline adb_cmsghdr* adb_CMSG_FIRSTHDR(adb_msghdr* msgh) {
    return CMSG_FIRSTHDR(msgh);
}

inline adb_cmsghdr* adb_CMSG_NXTHDR(adb_msghdr* msgh, adb_cmsghdr* cmsg) {
    return CMSG_NXTHDR(msgh, cmsg);
}

inline unsigned char* adb_CMSG_DATA(adb_cmsghdr* cmsg) {
    return CMSG_DATA(cmsg);
}

typedef struct pollfd adb_pollfd;
static inline int adb_poll(adb_pollfd* fds, size_t nfds, int timeout) {
    return TEMP_FAILURE_RETRY(poll(fds, nfds, timeout));
}

#define poll ___xxx_poll

static inline int adb_mkdir(const std::string& path, int mode) {
    return mkdir(path.c_str(), mode);
}

#undef mkdir
#define mkdir ___xxx_mkdir

static inline int adb_rename(const char* oldpath, const char* newpath) {
    return rename(oldpath, newpath);
}

static inline int adb_is_absolute_host_path(const char* path) {
    return path[0] == '/';
}

static inline int adb_get_os_handle(borrowed_fd fd) {
    return fd.get();
}

static inline int cast_handle_to_int(int fd) {
    return fd;
}

// A very simple wrapper over a launched child process
class Process {
  public:
    constexpr explicit Process(pid_t pid) : pid_(pid) {}
    constexpr Process(Process&& other) : pid_(std::exchange(other.pid_, -1)) {}

    constexpr explicit operator bool() const { return pid_ >= 0; }

    void wait() {
        if (*this) {
            int status;
            ::waitpid(pid_, &status, 0);
            pid_ = -1;
        }
    }
    void kill() {
        if (*this) {
            ::kill(pid_, SIGTERM);
        }
    }

  private:
    DISALLOW_COPY_AND_ASSIGN(Process);

    pid_t pid_;
};

Process adb_launch_process(std::string_view executable, std::vector<std::string> args,
                           std::initializer_list<int> fds_to_inherit = {});


static inline void disable_tcp_nagle(borrowed_fd fd) {
    int off = 1;
    adb_setsockopt(fd.get(), IPPROTO_TCP, TCP_NODELAY, &off, sizeof(off));
}

// Sets TCP socket |fd| to send a keepalive TCP message every |interval_sec| seconds. Set
// |interval_sec| to 0 to disable keepalives. If keepalives are enabled, the connection will be
// configured to drop after 10 missed keepalives. Returns true on success.
bool set_tcp_keepalive(borrowed_fd fd, int interval_sec);

// Returns a human-readable OS version string.
extern std::string GetOSVersion();
