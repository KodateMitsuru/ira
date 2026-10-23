// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ira_platform.h"
#include "ira_privileges.h"
#include "ira_service_backend.h"
#include "transport.h"
#include <cutils/sockets.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// Unused USB bridge entry points: this probe never mounts FunctionFS or touches USB.
atransport* ira_bridge_transport() { return nullptr; }
int ira_bridge_relink() { errno = ENOTSUP; return -1; }
static unsigned checks;
static void expect(bool value, const char* description) {
    if (!value) { fprintf(stderr, "FAIL: %s (errno %d: %s)\n", description, errno, strerror(errno)); exit(1); }
    ++checks;
}
static bool exact(int fd, void* output, size_t size) {
    auto* data = static_cast<char*>(output);
    while (size) {
        pollfd event{fd, POLLIN, 0};
        if (poll(&event, 1, 5000) != 1) return false;
        ssize_t n = recv(fd, data, size, 0);
        if (n <= 0) return false;
        data += n; size -= n;
    }
    return true;
}
static std::string shell(const char* command) {
    std::string request = "shell,v2,raw:" + std::string(command);
    int fd = ira_service_request(IraServiceOperation::Open, request);
    expect(fd >= 0, "service backend opens shell_v2");
    std::string output;
    for (;;) {
        unsigned char header[5];
        expect(exact(fd, header, sizeof(header)), "shell protocol frame received");
        uint32_t size;
        memcpy(&size, header + 1, 4);
        expect(size <= 65536, "bounded shell protocol frame");
        std::string data(size, '\0');
        expect(exact(fd, data.data(), data.size()), "shell frame payload received");
        if (header[0] == 1) output += data;
        if (header[0] == 2) fprintf(stderr, "shell stderr: %s", data.c_str());
        if (header[0] == 3) {
            uint32_t status = 1;
            if (size == 1) status = static_cast<unsigned char>(data[0]);
            else if (size == 4) memcpy(&status, data.data(), 4);
            expect(status == 0, "shell command exits successfully");
            break;
        }
    }
    close(fd);
    return output;
}
static void sync_write(const std::string& path, bool allowed) {
    int fd = ira_service_request(IraServiceOperation::Open, "sync:");
    expect(fd >= 0, "sync service opened under backend credentials");
    std::string request;
    auto record = [&](const char* id, const std::string& data) {
        char header[8]; uint32_t size = data.size();
        memcpy(header, id, 4); memcpy(header + 4, &size, 4);
        request.append(header, 8); request.append(data);
    };
    record("SEND", path + ",0600"); record("DATA", "verified");
    char done[8] = {'D','O','N','E',0,0,0,0};
    request.append(done, sizeof(done));
    expect(send(fd, request.data(), request.size(), MSG_NOSIGNAL) == (ssize_t)request.size(), "sync request sent atomically");
    char response[8];
    expect(exact(fd, response, sizeof(response)), "sync status returned");
    expect(memcmp(response, allowed ? "OKAY" : "FAIL", 4) == 0,
           allowed ? "root sync writes successfully" : "unroot sync cannot write root-private path");
    close(fd);
}
int main(int argc, char** argv) {
    if (argc == 3 && strcmp(argv[1], "--ira-services") == 0)
        return ira_service_backend_main(strcmp(argv[2], "root") == 0);
    alarm(60);
    expect(argc == 2 && geteuid() == 0, "probe given its own private directory as root");
    expect(ira_platform_init() == 0, "all actual Android platform APIs resolve");
    expect(ira_service_backend_init() == 0, "backend executable captured");
    using Config = bool (*)(const char*, bool, const char*, uid_t*, gid_t*, mode_t*, uint64_t*);
    void* fs = dlopen("libadbd_fs.so", RTLD_NOW | RTLD_LOCAL);
    auto config = fs ? reinterpret_cast<Config>(dlsym(fs, "adbd_fs_config")) : nullptr;
    using LegacyConfig = void (*)(const char*, int, const char*, unsigned*, unsigned*, unsigned*, uint64_t*);
    void* utils = dlopen("libcutils.so", RTLD_NOW | RTLD_LOCAL);
    auto legacy = utils ? reinterpret_cast<LegacyConfig>(dlsym(utils, "fs_config")) : nullptr;
    expect(config != nullptr || legacy != nullptr, "direct modern or legacy device fs policy available");
    for (const char* path : {"/system/bin/sh", "/vendor/bin/hw/test", "/data/local/nonexistent-ira-probe"}) {
        uid_t a_uid = -1, b_uid = -1; gid_t a_gid = -1, b_gid = -1;
        mode_t a_mode = 0640, b_mode = 0640; uint64_t a_cap = 0, b_cap = 0;
        bool a = true;
        if (config) a = config(path, false, nullptr, &a_uid, &a_gid, &a_mode, &a_cap);
        else legacy(path, false, nullptr, &a_uid, &a_gid, &a_mode, &a_cap);
        bool b = adbd_fs_config(path, false, nullptr, &b_uid, &b_gid, &b_mode, &b_cap);
        expect(a == b && a_uid == b_uid && a_gid == b_gid && a_mode == b_mode && a_cap == b_cap,
               "metadata matches direct platform result exactly");
    }
    void* selinux = dlopen("libselinux.so", RTLD_NOW | RTLD_LOCAL);
    using Restore = int (*)(const char*, unsigned);
    auto restore = reinterpret_cast<Restore>(dlsym(selinux, "selinux_android_restorecon"));
    expect(restore && restore("/system/bin/sh", 1) == selinux_android_restorecon("/system/bin/sh", 1),
           "restorecon forwards NOCHANGE/dry-run to the actual device implementation");
    std::string path = std::string(argv[1]) + "/socket";
    int listener = socket_local_server(path.c_str(), ANDROID_SOCKET_NAMESPACE_FILESYSTEM, SOCK_STREAM);
    expect(listener >= 0 && access(path.c_str(), F_OK) == 0, "filesystem Unix listener has a real pathname");
    int client = socket_local_client(path.c_str(), ANDROID_SOCKET_NAMESPACE_FILESYSTEM, SOCK_STREAM);
    expect(client >= 0, "filesystem Unix client reaches the pathname");
    close(client); close(listener); unlink(path.c_str());
    std::string root_file = std::string(argv[1]) + "/root-file";
    ira_root_set(true);
    expect(shell("id -u") == "0\n", "root shell uses root backend");
    sync_write(root_file, true);
    ira_root_set(false);
    expect(shell("id -u; id -Z") == "2000\nu:r:shell:s0\n", "unroot shell inherits minijail and shell exec label");
    expect(ira_service_request(IraServiceOperation::Open, "dev:" + root_file) < 0,
           "unroot direct file open is not privileged");
    sync_write(root_file + "-denied", false);
    ira_root_set(true);
    expect(shell("id -u") == "0\n" && geteuid() == 0, "root reuse and frontend identity remain intact");
    unlink(root_file.c_str());
    printf("PASS: %u actual-device platform/backend checks\n", checks);
}
