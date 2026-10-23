// SPDX-License-Identifier: AGPL-3.0-or-later
/* The only place in this daemon that knows the transport is functionfs.
 *
 * AOSP's adbd reads and writes a Connection; Connection::FromFd turns a
 * socket into one, and the two threads here move the byte stream between that
 * socket and the bulk endpoints FunctionFS gave us.  Everything above it --
 * packet framing, auth, the services -- is AOSP's code, unmodified.
 *
 * The directions are not symmetric.  Host -> device is a stream adbd's own
 * packet reader consumes, so the OUT thread only forwards what ep1 returns.
 * Device -> host is not: the host reads a 24 byte header and then exactly the
 * payload length that header announces, each as its own transfer.  Writing
 * header and payload together would make the host read the payload as the
 * tail of the header transfer and tear the transport down, which is the same
 * framing rule docs/dev/zero_length_packet.md describes for AOSP's own ffs
 * transport.  The IN thread therefore reassembles one adb packet and writes
 * the header and the payload as two separate ep2 writes; the kernel turns
 * each into one USB request.
 *
 * Neither thread owns an endpoint or the socket for longer than one transfer.
 * The descriptor set is re-evaluated and rewritten on every bind (see
 * ira_ffs.cpp), so ep1/ep2 can be closed and reopened under the pumps: each
 * iteration asks ira_ffs_wait_endpoints() whether there is anything to pump,
 * a transfer that a re-arm invalidated comes back as EAGAIN, and the bridge
 * generation below tells a transfer from the session that just ended.  The
 * socket end is handled the same way: a relink installs a fresh one and
 * retires the old one, which is closed as soon as no pump is inside a call on
 * it (see sock_acquire/sock_release).
 */
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "adb.h"
#include "ira_bridge.h"
#include "ira_ffs.h"
#include "transport.h"

/* Bumped by every relink.  A pump that saw generation N must not carry bytes
 * from the session that ended into the one generation N+1 created. */
static std::atomic<unsigned> bridge_gen{0};

/* The pump threads, kept joinable so an arm can take them down and put them back. A pump blocked in
 * read() on ep1 keeps that epfile (and therefore the whole FunctionFS instance) open, which is what
 * makes the kernel refuse a new descriptor set with -ESRCH. */
static std::thread pump_out;
static std::thread pump_in;
static std::mutex pump_lock;
/* Two pumps can notice the same wire loss at once; only the first relinks. */
static std::mutex bridge_lock;

/* The socket end adbd reads and writes.  It is not an atomic<int> because the
 * old end may not be closed while a pump is blocked in a call on it: closing
 * the fd there would free the number for the next socketpair and the bytes of
 * a dead session could land in the live one.  sock_acquire() counts the users,
 * retire() parks an fd until the count drops, and the last user closes it. */
static std::mutex sock_lock;
static int sock_live = -1;
static int sock_users;
static std::vector<int> sock_retired;

static int sock_acquire(void) {
    std::lock_guard<std::mutex> lk(sock_lock);

    if (sock_live < 0)
        return -1;
    sock_users++;
    return sock_live;
}

static void sock_release(void) {
    std::vector<int> dead;

    {
        std::lock_guard<std::mutex> lk(sock_lock);

        if (--sock_users == 0 && !sock_retired.empty())
            dead.swap(sock_retired);
    }
    for (int fd : dead)
        close(fd);
}

/* Every use of the socket end: released, and the retired end closed if this
 * was the last one, on the way out of the scope. */
struct sock_use {
    const int fd;

    explicit sock_use(int f) : fd(f) {}
    ~sock_use() { sock_release(); }
    sock_use(const sock_use &) = delete;
    sock_use &operator=(const sock_use &) = delete;
};

static void sock_install(int fd) {
    std::vector<int> dead;

    {
        std::lock_guard<std::mutex> lk(sock_lock);

        if (sock_live >= 0)
            sock_retired.push_back(sock_live);
        sock_live = fd;
        if (sock_users == 0)
            dead.swap(sock_retired);
    }
    for (int fd : dead)
        close(fd);
}

static void relink_locked(const char *why) {
    fprintf(stderr, "ira-bridge: %s, relinking\n", why);
    int nfd = ira_bridge_relink();

    if (nfd >= 0)
        sock_install(nfd);
    else
        fprintf(stderr, "ira-bridge: cannot relink (%d)\n", errno);
    /* Even a failed relink invalidates the old session: those bytes must not
     * be written into whatever transport is current now. */
    bridge_gen.fetch_add(1);
}

/* Called from the threads that own an endpoint: only the caller whose
 * generation is still current may relink. */
static void wire_lost(const char *why, unsigned seen) {
    std::lock_guard<std::mutex> lock(bridge_lock);

    if (bridge_gen.load() != seen)
        return;
    relink_locked(why);
}

/* Called from the ffs event thread on DISABLE/UNBIND, and before a live
 * descriptor set is replaced. */
static void ffs_lost(const char *why) {
    std::lock_guard<std::mutex> lock(bridge_lock);

    relink_locked(why);
}

static uint32_t get_le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* adb's MAX_PAYLOAD is 1 MiB; a header claiming more is not adb. */
static constexpr uint32_t kMaxPayload = 1024 * 1024;

static bool write_stream(int fd, const unsigned char *p, size_t len) {
    while (len) {
        ssize_t n = write(fd, p, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0) {
            errno = EIO;
            return false;
        }
        p += n;
        len -= (size_t)n;
    }
    return true;
}

/* host -> daemon: ep1 is a byte stream, adbd frames it */
static void ffs_to_adbd(void) {
    std::vector<unsigned char> buf(IRA_BULK_CHUNK);

    /* Registered so a re-arm can take back a read that is blocked inside
     * ffs_epfile_io(); it returns -EINTR and this thread drops the bytes. */
    ira_ffs_pump_register(0);

    for (;;) {
        if (!ira_ffs_wait_endpoints(500))
            continue;

        const unsigned session = ira_ffs_session_generation();
        unsigned gen = bridge_gen.load();
        int fd = sock_acquire();

        if (fd < 0) {
            usleep(20000);
            continue;
        }
        sock_use use(fd);

        long n = ira_ffs_read_out_session(buf.data(), buf.size(), session);

        if (n > 0) {
            /* If the wire or the descriptor set changed while the read was in
             * flight these bytes belong to the session that just ended. */
            if (bridge_gen.load() != gen)
                continue;
            if (!write_stream(fd, buf.data(), (size_t)n))
                wire_lost("adbd's end of the socket is gone", gen);
        } else if (n < 0) {
            switch (errno) {
                case EINTR:
                case EAGAIN:
                    /* Interrupted, or the set was re-armed under the read. */
                    break;
                case ESHUTDOWN:
                    /* DISABLE returned the request; the next read waits inside
                     * ffs_epfile_io() until the endpoints are enabled again. */
                    break;
                default:
                    /* ENODEV/EBADFD: the instance is gone or being torn down.
                     * Do not spin on it; the event thread owns the recovery. */
                    fprintf(stderr, "ira-bridge: ep1 read: %s\n", strerror(errno));
                    usleep(20000);
                    break;
            }
        }
    }
}

/* device -> host: one ep2 write is one USB request.  Large payloads are split
 * into IRA_BULK_CHUNK requests, exactly as AOSP's own ffs transport splits
 * them, so the kernel does not have to allocate one big contiguous buffer.
 * The chunk is a whole number of the largest bulk max packet (ira_ffs.h), so
 * the boundary stays invisible to the host: its read of the payload length
 * stays open across chunks and completes at the length its header announced. */
static bool write_transfer(const unsigned char *p, size_t len, unsigned gen) {
    long n = ira_ffs_write_in(p, len);

    if (n < 0)
        return false;   /* endpoints gone or re-armed: the caller relinks */
    if ((size_t)n != len) {
        errno = EPROTO;
        return false;
    }
    if (bridge_gen.load() != gen) {
        /* The transfer was for a session that ended while it was in flight. */
        errno = ECONNABORTED;
        return false;
    }
    return true;
}

static bool write_payload(const unsigned char *p, size_t len, unsigned gen) {
    while (len) {
        size_t n = len < IRA_BULK_CHUNK ? len : IRA_BULK_CHUNK;

        if (!write_transfer(p, n, gen))
            return false;
        p += n;
        len -= n;
    }
    return true;
}

static void adbd_to_ffs(void) {
    std::vector<unsigned char> rx;
    std::vector<unsigned char> buf(4 * IRA_BULK_CHUNK);
    unsigned gen = bridge_gen.load();

    ira_ffs_pump_register(1);

    for (;;) {
        if (gen != bridge_gen.load()) {
            rx.clear();
            gen = bridge_gen.load();
        }
        if (!ira_ffs_wait_endpoints(500)) {
            rx.clear();
            continue;
        }
        /* Writing before the host selected the configuration would block in
         * the kernel, so the stream is only drained once the endpoints are
         * enabled. */
        if (!ira_ffs_enabled()) {
            rx.clear();
            poll(nullptr, 0, 100);
            continue;
        }

        int fd = sock_acquire();

        if (fd < 0) {
            usleep(20000);
            continue;
        }
        sock_use use(fd);

        struct pollfd p = {fd, POLLIN, 0};
        int rc = poll(&p, 1, 500);

        if (rc < 0) {
            if (errno == EINTR)
                continue;
            wire_lost("poll on adbd's socket failed", gen);
            continue;
        }
        if (rc == 0)
            continue;
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            wire_lost("adbd's socket reported hangup", gen);
            continue;
        }

        ssize_t n = read(fd, buf.data(), buf.size());

        if (n > 0) {
            if (gen != bridge_gen.load()) {
                rx.clear();
                continue;
            }
            rx.insert(rx.end(), buf.begin(), buf.begin() + n);

            while (rx.size() >= 24) {
                const unsigned char *h = rx.data();
                uint32_t cmd = get_le32(h);
                uint32_t payload = get_le32(h + 12);
                uint32_t magic = get_le32(h + 20);

                if (magic != (cmd ^ 0xffffffffu) || payload > kMaxPayload) {
                    fprintf(stderr, "ira-bridge: bad adb header (cmd=%08x len=%u magic=%08x)\n",
                            cmd, payload, magic);
                    rx.clear();
                    wire_lost("adbd's stream lost framing", gen);
                    break;
                }
                if (rx.size() < 24u + payload)
                    break;

                /* The two writes are the two transfers the host reads. */
                if (!write_transfer(h, 24, gen)) {
                    fprintf(stderr, "ira-bridge: ep2 header write: %s\n", strerror(errno));
                    rx.clear();
                    wire_lost("the bulk-in endpoint stopped", gen);
                    break;
                }
                if (payload && !write_payload(h + 24, payload, gen)) {
                    fprintf(stderr, "ira-bridge: ep2 payload write: %s\n", strerror(errno));
                    rx.clear();
                    wire_lost("the bulk-in endpoint stopped", gen);
                    break;
                }
                rx.erase(rx.begin(), rx.begin() + 24 + payload);
            }
        } else if (n == 0) {
            /* EOF is the transport loss. Without relinking here this loop polls the same closed
             * socket forever and the registered atransport never gets a replacement. */
            wire_lost("adbd's end closed the socket", gen);
        } else if (errno != EAGAIN && errno != EINTR) {
            wire_lost("adbd's end of the socket is gone", gen);
        }
    }
}

static void start_pumps(void) {
    std::lock_guard<std::mutex> lk(pump_lock);

    if (!pump_out.joinable())
        pump_out = std::thread(ffs_to_adbd);
    if (!pump_in.joinable())
        pump_in = std::thread(adbd_to_ffs);
}

int ira_bridge_ffs_init(void) {
    return ira_ffs_init(ffs_lost);
}

void ira_bridge_start(int sock) {
    sock_install(sock);

    /* The transport is registered by now; only then may a DISABLE/UNBIND
     * event relink it. */
    ira_ffs_start_events();

    /* Both pumps always run.  Which descriptor set is in use is not decided
     * here and can change at any bind, so "the idle set is armed" is a state
     * the pumps wait out (ira_ffs_wait_endpoints) rather than a reason not to
     * start them: a later bind may well need them. */
    fprintf(stderr, "ira-bridge: starting the pumps (%s)\n",
            ira_ffs_has_endpoints() ? "the adb set has endpoints" : "no endpoints armed yet");

    /* One thread per direction: a thread that both reads ep1 and blocks in a
     * write to adbd stops draining the host, and the host answers a timed-out
     * write by tearing the transport down. */
    start_pumps();
}

/* adb root/unroot: serve the next client on a fresh socketpair without losing
 * the process state (the root flag lives in memory).  The transport the
 * request arrived on is taken offline, which is the disconnect that
 * wait-for-disconnect/wait-for-device see at the adb protocol level, and the
 * next client finds a new one.
 *
 * What this deliberately does NOT do is touch the gadget's pull-up.  Writing
 * "none" and then the controller name back to /config/usb_gadget/g1/UDC would
 * give the host a USB-level disconnect and re-enumeration, and it is what this
 * daemon used to do; it is also what left a real device with no USB at all
 * when the second write did not take (nothing else writes the UDC in this
 * project - the framework's own adbd does its own pull-up/pull-down when it
 * changes mode, and here the daemon stays alive instead). Authorization revoke
 * separately owns a recoverable UDC reset in ira_ffs.cpp. A host that
 * waits for the device to leave the bus - rather than for the adb transport to
 * go offline - sees the device stay enumerated across adb root, and anything
 * the host caches about the USB device (descriptors, port state) survives. */
void ira_bridge_drop(void) {
    std::lock_guard<std::mutex> lock(bridge_lock);

    relink_locked("a fresh session was requested");
}
