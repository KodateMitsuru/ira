// SPDX-License-Identifier: AGPL-3.0-or-later
// Tests the production IPC/process boundary with real kernel process credentials. The identity
// fixture replaces only platform minijail (unavailable on host); Android API forwarding has a
// separate test, and actual-device coverage is intentionally not claimed by this harness.
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <grp.h>
#include <cstdlib>
#include "../src/adb/ira_service_backend.cpp"

static unsigned checks;
static void expect(bool yes, const char* what) {
    if (!yes) { fprintf(stderr, "FAIL: %s (errno %d: %s)\n", what, errno, strerror(errno)); exit(1); }
    ++checks;
}
void fdevent_check_looper() {}
TransportId NextTransportId() { static TransportId id = 0; return ++id; }
atransport::~atransport() {}
int ira_platform_init() { return 0; }
int ira_platform_enter_service_identity(bool root) {
    if (!root && getenv("IRA_TEST_FAIL_DROP")) { errno = EPERM; return -1; }
    if (root) return 0;
    // Whole disposable process, never a service thread. Mirrors the minijail boundary for this test.
    return setgroups(0, nullptr) || setgid(2000) || setuid(2000) ? -1 : 0;
}
unique_fd service_to_fd(std::string_view name, atransport*) {
    if (name == "identity") {
        int fd = memfd_create("ira-service-identity", MFD_CLOEXEC);
        std::string identity = std::to_string(geteuid()) + ":" + std::to_string(getegid());
        if (fd >= 0 && adb_pwrite(fd, identity.data(), identity.size(), 0) != (ssize_t)identity.size()) abort();
        return unique_fd(fd);
    }
    if (name.starts_with("file:")) return unique_fd(adb_open(std::string(name.substr(5)).c_str(), O_RDONLY | O_CLOEXEC));
    errno = ENOSYS; return {};
}
int socket_spec_listen(std::string_view, std::string*, int* port) {
    // The returned listener's kernel owner proves bind/open ran in the selected process.
    if (port) *port = 31415;
    return memfd_create("ira-listener-identity", MFD_CLOEXEC);
}
int main(int argc, char** argv) {
    if (argc == 3 && strcmp(argv[1], "--ira-services") == 0)
        return ira_service_backend_main(strcmp(argv[2], "root") == 0);
    alarm(30);
    expect(geteuid() == 0, "run inside a mapped-root user namespace");
    expect(ira_service_backend_init() == 0, "capture executable");
    if (argc == 2 && strcmp(argv[1], "--failure") == 0) {
        ira_root_set(false);
        expect(ira_service_request(IraServiceOperation::Open, "identity") < 0 && errno == EPERM,
               "failed drop never opens a service as root");
        expect(geteuid() == 0, "failed backend never alters frontend credentials");
        return 0;
    }
    const char* directory = getenv("IRA_BACKEND_TEST_DIR");
    expect(directory != nullptr, "test directory supplied");
    std::string private_directory = std::string(directory) + "/private";
    expect(adb_mkdir(private_directory, 0700) == 0, "create root-private fixture directory");
    std::string path = private_directory + "/secret";
    int file = adb_open_mode(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    expect(file >= 0, "create root-private fixture file"); adb_close(file);
    for (bool root : {true, false, true, false}) {
        ira_root_set(root);
        int fd = ira_service_request(IraServiceOperation::Open, "identity");
        expect(fd >= 0, "service fd passed back over private IPC");
        struct stat status{};
        expect(fstat(fd, &status) == 0 && status.st_uid == (root ? 0 : 2000),
               "service fd belongs to the chosen process identity");
        char text[32]{};
        ssize_t size = adb_pread(fd, text, sizeof(text), 0);
        expect(size > 0 && std::string_view(text, size) == (root ? "0:0" : "2000:2000"),
               "all service work runs under the selected uid and gid");
        expect(fcntl(fd, F_GETFD) & FD_CLOEXEC, "received service fd is close-on-exec");
        adb_close(fd);
        int port = 0;
        fd = ira_service_request(IraServiceOperation::Listen, "fixture", &port);
        expect(fd >= 0 && port == 31415, "reverse listener result and resolved port preserved");
        expect(fstat(fd, &status) == 0 && status.st_uid == (root ? 0 : 2000),
               "listener creation uses the same identity as services");
        adb_close(fd);
        fd = ira_service_request(IraServiceOperation::Open, "file:" + path);
        expect(root ? fd >= 0 : fd < 0 && errno == EACCES, "root/unroot applies to direct file access");
        if (fd >= 0) adb_close(fd);
        expect(geteuid() == 0 && getegid() == 0, "frontend retains its own credentials");
    }
    pid_t failed = fork();
    if (failed == 0) {
        setenv("IRA_TEST_FAIL_DROP", "1", 1);
        execl("/proc/self/exe", "test_service_backend", "--failure", nullptr);
        _exit(127);
    }
    int result;
    expect(waitpid(failed, &result, 0) == failed && WIFEXITED(result) && WEXITSTATUS(result) == 0,
           "separate backend fails closed on identity setup failure");
    expect(ira_service_request(IraServiceOperation::Open, "") < 0 && errno == EINVAL,
           "empty requests rejected without starting a service");
    // A failed/unsupported request is not retried and does not destroy a healthy backend.
    ira_root_set(true);
    expect(ira_service_request(IraServiceOperation::Open, "unsupported") < 0 && errno == ENOSYS,
           "backend service errno returned unchanged");
    int fd = ira_service_request(IraServiceOperation::Open, "identity");
    expect(fd >= 0, "backend remains usable after ordinary service failure"); adb_close(fd);
    adb_unlink(path.c_str()); rmdir(private_directory.c_str());
    printf("PASS: %u production service-backend process/IPC checks\n", checks);
}
