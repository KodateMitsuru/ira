// SPDX-License-Identifier: AGPL-3.0-or-later
/* The pipelined endpoint queue, exercised without a phone.
 *
 * The pumps exist so the endpoint always has more than one request inside the
 * kernel: one outstanding transfer delivers one chunk per round trip.  These
 * checks drive the same submit/reap/cancel calls against a file, which is the
 * only kind of fd that supports aio in a host test (pipes and sockets do not).
 */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <vector>

#include "../src/adb/ira_ffs.cpp"

static unsigned checks;

static void expect(bool ok, const char* what) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s (%d: %s)\n", what, errno, strerror(errno));
        exit(1);
    }
    ++checks;
}

int main() {
    /* A file, not a pipe: aio on a pipe or socket is refused by the kernel, and
     * these calls have to be the ones the pumps really use. */
    const char *path = "ffs-aio-data";
    int out = open(path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);

    expect(out >= 0, "fixture file");
    std::vector<unsigned char> file((size_t)IRA_AIO_DEPTH * IRA_BULK_CHUNK);

    for (size_t i = 0; i < file.size(); i++)
        file[i] = (unsigned char)(i * 7u + 3u);
    expect(write(out, file.data(), file.size()) == (ssize_t)file.size(), "fixture filled");
    close(out);

    g_ep[kOut] = open(path, O_RDONLY | O_CLOEXEC);
    expect(g_ep[kOut] >= 0, "endpoint opened");
    g_enabled = true;
    g_rearming = false;
    g_gen = 100;
    expect(ira_ffs_aio_open(kOut, IRA_AIO_DEPTH) == 0, "aio context opens");

    std::vector<unsigned char> buf((size_t)IRA_AIO_DEPTH * IRA_BULK_CHUNK, 0);

    /* Five requests are submitted before any is reaped: the point of the queue. */
    for (unsigned i = 0; i < 5; i++)
        expect(ira_ffs_aio_submit(kOut, buf.data() + (size_t)i * IRA_BULK_CHUNK, IRA_BULK_CHUNK, i,
                                  100) == 0, "submit keeps the queue full");
    expect(g_in_flight[kOut] == 5, "five requests are inside the kernel");

    struct ira_aio_done done[IRA_AIO_DEPTH];
    int n = ira_ffs_aio_reap(kOut, done, IRA_AIO_DEPTH, 4000);

    expect(n == 5, "every completed request is reported");
    expect(g_in_flight[kOut] == 0, "in-flight count returns to zero");
    bool seen[5] = {};
    for (int i = 0; i < n; i++) {
        expect(done[i].result == (long)IRA_BULK_CHUNK, "a whole chunk per request");
        expect(done[i].tag < 5 && !seen[done[i].tag], "completion carries its own tag");
        if (done[i].tag < 5)
            seen[done[i].tag] = true;
    }
    expect(seen[0] && seen[4], "the queue drains every tag");

    /* A request submitted for one session must not deliver into the next. */
    expect(ira_ffs_aio_submit(kOut, buf.data(), IRA_BULK_CHUNK, 0, g_gen) == 0, "submit for a session");
    g_gen++;
    n = ira_ffs_aio_reap(kOut, done, 1, 4000);
    expect(n == 1 && done[0].result == -1 && done[0].error == EAGAIN,
           "a transfer from a replaced session reports EAGAIN");
    expect(g_in_flight[kOut] == 0, "stale completion still leaves the queue");

    /* Depth: the ninth request is refused rather than silently dropped. */
    for (unsigned i = 0; i < IRA_AIO_DEPTH; i++)
        expect(ira_ffs_aio_submit(kOut, buf.data() + (size_t)i * IRA_BULK_CHUNK, IRA_BULK_CHUNK, i,
                                  g_gen) == 0, "queue depth is available");
    expect(ira_ffs_aio_submit(kOut, buf.data(), IRA_BULK_CHUNK, 99, g_gen) == -1 && errno == EBUSY,
           "a full queue is backpressure, not a lost request");

    /* Re-arm: nothing may stay inside the kernel while the fd is closed. */
    g_rearming = true;
    ira_ffs_aio_cancel(kOut);
    expect(g_in_flight[kOut] == 0, "a re-arm takes every outstanding request back");
    g_rearming = false;

    g_ep[kOut] = -1;
    g_enabled = false;
    unlink(path);
    printf("PASS: %u pipelined endpoint queue checks\n", checks);
    return 0;
}
