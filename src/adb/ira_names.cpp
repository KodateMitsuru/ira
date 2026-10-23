// SPDX-License-Identifier: AGPL-3.0-or-later
/* The endpoint names of this installation.
 *
 * customize.sh writes one "role=name" line per endpoint into "names" beside this binary. The daemon
 * never looks anywhere else and never falls back to a constant: if the file is missing the endpoint
 * is not served, rather than served under a name a probe can guess. state/ is runtime only (log and
 * boot markers), so nothing needed across reboots lives there.
 *
 * The file is read once, on first use, and kept. It is root-owned and 0600, and it lives in the
 * module directory, which is not traversable by an untrusted app. */
#include "ira_names.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <mutex>
#include <string>

namespace {

std::mutex g_lock;
std::string g_table;
bool g_loaded;

/* Characters the installer produces: lowercase hex, the role suffix and its separator. Anything
 * else is a file that was not written by the installer and is refused rather than used. */
bool valid_name(const char* name, size_t length) {
    if (length == 0 || length > 100) return false;
    for (size_t i = 0; i < length; i++) {
        const char c = name[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || c == '.' || c == '-') continue;
        return false;
    }
    return true;
}

bool read_table(std::string* out) {
    char exe[PATH_MAX];
    const ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

    if (n <= 0) return false;
    exe[n] = 0;
    char* slash = strrchr(exe, '/');
    if (slash == nullptr) return false;
    *slash = 0;

    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/names", exe) >= (int)sizeof(path)) return false;

    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[512];
    const ssize_t got = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (got <= 0) return false;
    buf[got] = 0;
    out->assign(buf, static_cast<size_t>(got));
    return true;
}

}  // namespace

bool ira_socket_name(const char* role, char* out, size_t cap) {
    std::lock_guard<std::mutex> held(g_lock);

    if (!g_loaded) {
        g_loaded = true;
        if (!read_table(&g_table)) g_table.clear();
    }
    const size_t role_length = strlen(role);
    const char* found = nullptr;
    size_t found_length = 0;

    for (size_t at = 0; at < g_table.size();) {
        size_t end = g_table.find('\n', at);
        if (end == std::string::npos) end = g_table.size();
        const size_t equals = g_table.find('=', at);
        if (equals != std::string::npos && equals < end && equals - at == role_length &&
            memcmp(g_table.data() + at, role, role_length) == 0) {
            /* One role, one name. A second line for the same role is a file the installer did not
             * write, and picking either one would hide the mistake. */
            if (found != nullptr) { errno = EINVAL; return false; }
            found = g_table.data() + equals + 1;
            found_length = end - equals - 1;
        }
        at = end + 1;
    }
    if (found == nullptr) { errno = ENOENT; return false; }
    if (!valid_name(found, found_length)) { errno = EINVAL; return false; }
    if (found_length + 1 > cap) { errno = ENAMETOOLONG; return false; }
    memcpy(out, found, found_length);
    out[found_length] = 0;
    return true;
}
