// SPDX-License-Identifier: AGPL-3.0-or-later
/* The one source of endpoint names.
 *
 * ira_socket_name() reads "names" beside /proc/self/exe, so the test runs a copy of itself
 * from a directory it fills: the child is that copy, next to the file under test. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include "ira_names.h"

namespace {

int checks;

void expect(bool ok, const char* what) {
    printf("  %s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) exit(1);
    checks++;
}

std::string self_path() {
    char path[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (n <= 0) { perror("readlink"); exit(1); }
    path[n] = 0;
    return path;
}

bool copy_file(const std::string& from, const std::string& to) {
    FILE* in = fopen(from.c_str(), "rb");
    FILE* out = fopen(to.c_str(), "wb");
    if (in == nullptr || out == nullptr) return false;
    char buffer[65536];
    size_t got;
    bool ok = true;
    while ((got = fread(buffer, 1, sizeof(buffer), in)) != 0)
        if (fwrite(buffer, 1, got, out) != got) { ok = false; break; }
    fclose(in);
    ok = (fclose(out) == 0) && ok;
    return ok && chmod(to.c_str(), 0755) == 0;
}

bool write_file(const std::string& path, const std::string& text) {
    FILE* file = fopen(path.c_str(), "wb");
    if (file == nullptr) return false;
    bool ok = fwrite(text.data(), 1, text.size(), file) == text.size();
    return fclose(file) == 0 && ok;
}

const char* error_name(int error) {
    switch (error) {
        case ENOENT: return "ENOENT";
        case EINVAL: return "EINVAL";
        case ENAMETOOLONG: return "ENAMETOOLONG";
    }
    return "OTHER";
}

std::string run_child(const std::string& binary) {
    int pipefd[2];
    if (pipe(pipefd) != 0) { perror("pipe"); exit(1); }
    pid_t pid = fork();
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execl(binary.c_str(), binary.c_str(), "--child", static_cast<char*>(nullptr));
        _exit(127);
    }
    close(pipefd[1]);
    std::string out;
    char buffer[4096];
    ssize_t got;
    while ((got = read(pipefd[0], buffer, sizeof(buffer))) > 0) out.append(buffer, (size_t)got);
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child failed: %s\n", out.c_str());
        exit(1);
    }
    return out;
}

/* "=name" for a served endpoint, "!EINVAL" for a refusal. */
std::string field(const std::string& out, const char* key) {
    const size_t prefix = strlen(key);
    for (size_t at = 0; at < out.size();) {
        size_t end = out.find('\n', at);
        if (end == std::string::npos) end = out.size();
        if (end - at > prefix && out.compare(at, prefix, key) == 0 &&
            (out[at + prefix] == '=' || out[at + prefix] == '!')) {
            return out.substr(at + prefix, end - at - prefix);
        }
        at = end + 1;
    }
    return "<missing>";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && strcmp(argv[1], "--child") == 0) {
        char name[64];
        for (const char* role : {"ctl", "auth", "su"}) {
            if (ira_socket_name(role, name, sizeof(name))) printf("%s=%s\n", role, name);
            else printf("%s!%s\n", role, error_name(errno));
        }
        char small[8];
        if (ira_socket_name("ctl", small, sizeof(small))) printf("small=%s\n", small);
        else printf("small!%s\n", error_name(errno));
        return 0;
    }

    const std::string dir = self_path().substr(0, self_path().rfind('/'));
    /* A copy, not this file: the child must live next to the names file it is meant to read. */
    const std::string binary = dir + "/endpoint-child";
    const std::string names = dir + "/names";
    unlink(binary.c_str());
    expect(copy_file(self_path(), binary), "test binary copied beside the name table");

    unlink(names.c_str());
    {
        const std::string out = run_child(binary);
        expect(field(out, "ctl") == "!ENOENT", "a missing file serves no endpoint");
    }

    expect(write_file(names, "ctl=0123456789abcdef.ctl\nauth=fedcba9876543210.auth\n"
                             "su=00112233445566aa.su\n"),
           "name table written");
    {
        const std::string out = run_child(binary);
        expect(field(out, "ctl") == "=0123456789abcdef.ctl", "ctl endpoint is the installed name");
        expect(field(out, "auth") == "=fedcba9876543210.auth", "auth endpoint is the installed name");
        expect(field(out, "su") == "=00112233445566aa.su", "su endpoint is the installed name");
        expect(field(out, "small") == "!ENAMETOOLONG", "a short buffer is refused, not truncated");
    }

    expect(write_file(names, "ctl=0123456789abcdef.ctl\nauth=BAD NAME\n"),
           "malformed table written");
    {
        const std::string out = run_child(binary);
        expect(field(out, "auth") == "!EINVAL", "a name with a space is refused");
        expect(field(out, "su") == "!ENOENT", "a role with no line is not invented");
    }

    expect(write_file(names, "ctl=0123456789abcdef.ctl\nctl=fedcba9876543210.ctl\n"),
           "duplicate role written");
    {
        const std::string out = run_child(binary);
        expect(field(out, "ctl") == "!EINVAL", "two lines for one role are refused, not picked between");
    }

    printf("PASS: %d endpoint-name checks\n", checks);
    return 0;
}
