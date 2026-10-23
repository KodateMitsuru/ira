// SPDX-License-Identifier: AGPL-3.0-or-later
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "../src/adb/ira_ffs.cpp"

namespace {
unsigned checks = 0;
unsigned disconnects = 0;
bool disconnected_after_drain = false;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        std::exit(1);
    }
    ++checks;
}
void lost(const char*) {
    std::lock_guard<std::mutex> lock(g_m);
    ++disconnects;
    disconnected_after_drain = g_in_flight[0] == 0 && g_in_flight[1] == 0 && g_rearming;
}
void event(int writer, int reader, unsigned char type) {
    usb_functionfs_event e{};
    e.type = type;
    expect(write(writer, &e, sizeof(e)) == sizeof(e), "event queued");
    expect(handle_events(reader) == kEp0Continue, "event handled");
}
}

int main() {
    alarm(15);
    struct sigaction action{};
    action.sa_handler = pump_signal;
    sigemptyset(&action.sa_mask);
    expect(sigaction(kPumpSignal, &action, nullptr) == 0, "interrupt handler installed");
    int bulk[2], events[2];
    expect(pipe(bulk) == 0 && pipe(events) == 0, "endpoint and ep0 fixtures created");
    g_ep[kOut] = bulk[0];
    g_armed.store(true);
    g_endpoints.store(true);
    g_lost = lost;

    expect(ira_ffs_wait_endpoints(1) == 0, "disabled endpoints cannot admit a pump");
    char byte;
    errno = 0;
    expect(ira_ffs_read_out_session(&byte, 1, ira_ffs_session_generation()) == -1 && errno == EAGAIN,
           "disabled I/O rejected even if caller bypasses the wait");

    for (unsigned cycle = 0; cycle < 20; ++cycle) {
        event(events[1], events[0], FUNCTIONFS_ENABLE);
        expect(ira_ffs_wait_endpoints(1) == 1, "enable admits a new transfer");
        std::atomic<long> old_result{0};
        std::atomic<int> old_errno{0};
        std::array<char, 4> received{};
        std::atomic<long> new_result{0};
        std::thread pump([&] {
            ira_ffs_pump_register(kOut);
            char old_byte;
            const long result = ira_ffs_read_out_session(&old_byte, 1, ira_ffs_session_generation());
            old_errno.store(errno);
            old_result.store(result);
            while (!ira_ffs_wait_endpoints(10)) {}
            new_result.store(ira_ffs_read_out_session(received.data(), received.size(), ira_ffs_session_generation()));
        });
        bool busy = false;
        for (int n = 0; n < 1000; ++n) {
            {
                std::lock_guard<std::mutex> lock(g_m);
                busy = g_in_flight[kOut] == 1;
            }
            if (busy)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        expect(busy, "old session has a blocked OUT read");
        const unsigned old_generation = g_gen;
        event(events[1], events[0], FUNCTIONFS_DISABLE);
        expect(disconnected_after_drain, "old kernel I/O drained before transport is replaced");
        expect(g_gen != old_generation, "disable invalidates old I/O generation");
        expect(g_armed.load() && g_endpoints.load() && g_ep[kOut] == bulk[0],
               "session reset leaves descriptor set and endpoint fds intact");
        expect(!ira_ffs_wait_endpoints(1), "pump remains stopped until next enable");

        event(events[1], events[0], FUNCTIONFS_ENABLE);
        expect(write(bulk[1], "CNXN", 4) == 4, "next host sends its first packet");
        pump.join();
        expect(old_result.load() == -1 && old_errno.load() == EAGAIN,
               "interrupted old read cannot deliver stale session bytes");
        expect(new_result.load() == 4 && std::memcmp(received.data(), "CNXN", 4) == 0,
               "new session receives the complete first CNXN");
        {
            std::lock_guard<std::mutex> lock(g_m);
            g_pump_known[kOut] = false;
        }
        event(events[1], events[0], FUNCTIONFS_DISABLE);
    }
    const unsigned stale_session = ira_ffs_session_generation();
    event(events[1], events[0], FUNCTIONFS_ENABLE);
    event(events[1], events[0], FUNCTIONFS_DISABLE);
    event(events[1], events[0], FUNCTIONFS_ENABLE);
    expect(write(bulk[1], "CNXN", 4) == 4, "first packet queued after a snapshot race");
    std::array<char, 4> first_packet{};
    errno = 0;
    expect(ira_ffs_read_out_session(first_packet.data(), first_packet.size(), stale_session) == -1 &&
                   errno == EAGAIN,
           "a pre-disconnect snapshot cannot start an I/O in the new session");
    expect(ira_ffs_read_out_session(first_packet.data(), first_packet.size(),
                                  ira_ffs_session_generation()) == 4 &&
                   std::memcmp(first_packet.data(), "CNXN", 4) == 0,
           "rejected stale call leaves the first packet untouched");
    event(events[1], events[0], FUNCTIONFS_DISABLE);
    expect(disconnects == 42, "one disconnect callback per enabled session");
    close_all();
    close(bulk[1]);
    close(events[0]);
    close(events[1]);
    std::printf("PASS: %u FFS session checks, including 20 interrupted-read reconnects\n", checks);
}
