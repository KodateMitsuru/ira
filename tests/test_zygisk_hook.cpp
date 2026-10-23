// SPDX-License-Identifier: AGPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

// Only liblog is substituted; the production parser, hook, and socket client run unchanged.
extern "C" int __android_log_print(int, const char*, const char*, ...) { return 0; }
#include "../src/zygisk/ira_zygisk.cpp"

static_assert(std::is_same_v<CheckFn, bool (*)(const void*, void*)>);
static_assert(std::is_same_v<decltype(&hooked_check_interface), CheckFn>);

namespace {
struct ParcelFixture {
    std::vector<uint8_t> bytes;
    size_t position;
    bool accepted = true;
    unsigned accessor_calls = 0;
};

unsigned checks = 0;
void expect(bool condition, const char* label) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", label);
        std::exit(1);
    }
    ++checks;
}

bool check_interface(const void* self, void*) {
    return static_cast<const ParcelFixture*>(self)->accepted;
}
const uint8_t* parcel_data(const void* self) {
    auto* p = const_cast<ParcelFixture*>(static_cast<const ParcelFixture*>(self));
    ++p->accessor_calls;
    return p->bytes.data();
}
size_t parcel_size(const void* self) {
    return static_cast<const ParcelFixture*>(self)->bytes.size();
}
size_t parcel_position(const void* self) {
    return static_cast<const ParcelFixture*>(self)->position;
}
ParcelFixture parcel(size_t prefix, int64_t functions, uint32_t callback = BINDER_TYPE_HANDLE) {
    const int32_t units = sizeof(kGadgetInterface) - 1;
    const size_t position = prefix + 4 + ((units + 1) * 2 + 3) / 4 * 4;
    ParcelFixture p{std::vector<uint8_t>(position + 8 + sizeof(flat_binder_object), 0), position};
    std::memcpy(p.bytes.data() + prefix, &units, sizeof(units));
    for (int32_t i = 0; i < units; ++i)
        p.bytes[prefix + 4 + i * 2] = kGadgetInterface[i];
    std::memcpy(p.bytes.data() + position, &functions, sizeof(functions));
    std::memcpy(p.bytes.data() + position + 8, &callback, sizeof(callback));
    return p;
}

unsigned udc_writes = 0;
ssize_t udc_write(int, const void*, size_t size) {
    ++udc_writes;
    return static_cast<ssize_t>(size);
}

void bind_role(int64_t functions, const char* expected_request, const char* daemon_reply = "ok\n") {
    auto p = parcel(12, functions);
    expect(hooked_check_interface(&p, nullptr), "accepted interface returns true");
    expect(g_requested_functions.load() == functions, "accepted bitmap replaces previous intent");

    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    expect(listener >= 0, "mock daemon socket created");
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(kSocketName, sizeof(kSocketName), "ira-test-%d", static_cast<int>(getpid()));
    const size_t len = std::strlen(kSocketName);
    std::memcpy(addr.sun_path + 1, kSocketName, len);
    expect(bind(listener, reinterpret_cast<sockaddr*>(&addr),
                offsetof(sockaddr_un, sun_path) + 1 + len) == 0, "mock daemon bound");
    expect(listen(listener, 1) == 0, "mock daemon listening");
    std::string received;
    std::thread server([&] {
        pollfd pfd{listener, POLLIN, 0};
        if (poll(&pfd, 1, 3000) <= 0)
            return;
        int fd = accept(listener, nullptr, nullptr);
        if (fd < 0)
            return;
        timeval timeout{3, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        char byte;
        while (received.size() < 32 && read(fd, &byte, 1) == 1) {
            received += byte;
            if (byte == '\n')
                break;
        }
        send(fd, daemon_reply, std::strlen(daemon_reply), MSG_NOSIGNAL);
        close(fd);
    });
    g_write = udc_write;
    g_udc_fd.store(12345);
    const unsigned before = udc_writes;
    const ssize_t result = hooked_write(12345, "controller", 10);
    server.join();
    close(listener);
    expect(received == expected_request, "UDC hook sends the expected role");
    expect(result == 10 && udc_writes == before + 1, "UDC write proceeds after daemon confirmation");
}
}  // namespace

int main() {
    g_check = check_interface;
    g_parcel_data = parcel_data;
    g_parcel_size = parcel_size;
    g_parcel_pos = parcel_position;
    for (size_t prefix : {size_t{0}, size_t{12}}) {
        for (int64_t functions : {int64_t{0}, int64_t{1}, int64_t{4}, int64_t{5}}) {
            auto p = parcel(prefix, functions);
            g_requested_functions.store(-1);
            expect(hooked_check_interface(&p, nullptr), "valid interface succeeds");
            expect(g_requested_functions.load() == functions, "valid function bitmap parsed");
        }
    }
    auto rejected = parcel(12, 4);
    rejected.accepted = false;
    g_requested_functions.store(1);
    expect(!hooked_check_interface(&rejected, nullptr), "failed interface returns false");
    expect(rejected.accessor_calls == 0, "rejected Parcel is not inspected");
    expect(g_requested_functions.load() == 1, "rejected Parcel cannot change role");

    auto invalid = parcel(12, 4);
    invalid.bytes[16] ^= 1;
    expect(hooked_check_interface(&invalid, nullptr), "original result preserved for other tokens");
    expect(g_requested_functions.load() == 1, "wrong interface token cannot change role");
    auto truncated = parcel(12, 4);
    truncated.bytes.resize(truncated.position + 7);
    expect(hooked_check_interface(&truncated, nullptr), "original result preserved for truncated data");
    expect(g_requested_functions.load() == 1, "truncated bitmap cannot change role");
    auto bad_callback = parcel(12, 4, 0);
    hooked_check_interface(&bad_callback, nullptr);
    expect(g_requested_functions.load() == 1, "invalid callback cannot change role");

    bind_role(1, "role idle\n");
    bind_role(4, "role adb\n");
    bind_role(5, "role idle\n");
    bind_role(0, "role adb\n");
    bind_role(1, "role idle\n", "err\n");
    std::printf("PASS: %u HAL hook checks (bool ABI, bitmap parsing, rejection, and UDC role requests)\n", checks);
}
