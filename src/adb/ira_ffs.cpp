// SPDX-License-Identifier: AGPL-3.0-or-later
/* FunctionFS descriptor and USB-session ownership.
 *
 * init creates ffs.ira and its configuration link before UDC binding. A bootstrap
 * thread mounts the "ira" FunctionFS instance privately; a directory fd pins that
 * mount while services retain init's live mount namespace.
 *
 * Startup arms the endpoint-free ff/00/00 set. The gadget HAL hook supplies the
 * requested role before each platform UDC write: ff/42/01 with two bulk endpoints
 * for IRA, or idle while platform ffs.adb carries ADB. ep0 and control events run
 * on the adb looper; pumps borrow endpoint fds only for one generation/transfer.
 *
 * Re-arming requires every epfile reference to close so ffs_data_reset() returns
 * the kernel state to FFS_READ_DESCRIPTORS. The ep0 watcher must be CLOEXEC or a
 * service backend can pin FFS_ACTIVE and descriptor writes then fail with ESRCH.
 * Pumps are quiesced before fd closure; the watcher duplicate is released first.
 *
 * Authorization revocation additionally pulls UDC down and restores its saved
 * controller after descriptors are ready. A boot-local handoff preserves the
 * role/controller if a failed re-arm requires supervisor process replacement.
 * See docs/functionfs.md for ordering and kernel state-machine references.
 */
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <linux/aio_abi.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <system_error>

#include "ira_ffs.h"
#include "ira_names.h"

#include "adb_auth.h"


#ifndef IRA_GADGET_DIR
#define IRA_GADGET_DIR   "/config/usb_gadget/g1"
#endif
#define IRA_FFS_DIR      IRA_GADGET_DIR "/functions/ffs.ira"
#define IRA_CONFIG_DIR   IRA_GADGET_DIR "/configs/b.1"
#define IRA_UDC_FILE     IRA_GADGET_DIR "/UDC"
#ifndef IRA_STATE_DIR
#define IRA_STATE_DIR "/data/adb/modules/ira/state"
#endif
#define IRA_REVOKE_RESUME IRA_STATE_DIR "/revoke.resume"

/* fs/configfs/mount.c:23 -- configfs has no uapi header for this magic. */
#define IRA_CONFIGFS_MAGIC 0x62656570

/* The instance name, i.e. the suffix configfs strips off "ffs.ira" before
 * calling ffs_set_inst_name().  It is also the mount source. */
static const char kInstance[] = "ira";

#define IRA_EP_OUT 1   /* host -> device, USB_DIR_OUT */
#define IRA_EP_IN  2   /* device -> host, USB_DIR_IN  */

/* Two pumps, one per direction.  These are indices, not fds: the fds change
 * with every arm (see the state below). */
static constexpr int kOut = 0;   /* ep1: the daemon reads */
static constexpr int kIn  = 1;   /* ep2: the daemon writes */
static constexpr int kDirs = 2;

/* The signal that takes a blocked bulk transfer back.  ffs_epfile_io() waits
 * in wait_for_completion_interruptible() (f_fs.c:1090), so a signal is the only
 * way to interrupt one; a handler without SA_RESTART makes the read or write
 * return -EINTR and the request is dequeued (f_fs.c:1091-1106).  AOSP's own
 * ffs transport does the same thing for the same reason
 * (daemon/usb.cpp:722, kInterruptionSignal). */
static const int kPumpSignal = SIGUSR1;

/* Bounded recovery: how many times a lost race is retried, how long a bind may
 * take to show up, and how long the kernel is given to finish an unbind before
 * the files are closed (ffs_func_unbind() queues FUNCTIONFS_UNBIND *before*
 * functionfs_unbind() clears FFS_FL_BOUND, f_fs.c:3634, and closing while that
 * bit is still set would unregister the gadget a second time). */
[[maybe_unused]] constexpr unsigned kUnbindSettleMs = 150;

/* What the adb interface advertises, per speed.  A bulk endpoint's max packet
 * is fixed by the speed - 64 / 512 / 1024 - so the three sets cannot share one
 * value, and the sizes the pumps use are derived from the largest of them
 * (IRA_BULK_CHUNK, ira_ffs.h) so the descriptor, the write chunking and the
 * read buffers cannot drift apart again. */
struct ira_func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_endpoint_descriptor_no_audio sink;
} __attribute__((packed));

struct ira_ss_func_desc {
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor_no_audio source;
    struct usb_ss_ep_comp_descriptor source_comp;
    struct usb_endpoint_descriptor_no_audio sink;
    struct usb_ss_ep_comp_descriptor sink_comp;
} __attribute__((packed));

/* Only the flags we set decide which counts are present: f_fs.c:2519-2550
 * reads eventfd first, then fs/hs/ss counts, then the os count if
 * FUNCTIONFS_HAS_MS_OS_DESC is set. */
struct ira_desc_v2 {
    struct usb_functionfs_descs_head_v2 header;
    __le32 fs_count;
    __le32 hs_count;
    __le32 ss_count;
    struct ira_func_desc fs_descs;
    struct ira_func_desc hs_descs;
    struct ira_ss_func_desc ss_descs;
} __attribute__((packed));

struct ira_desc_v2_idle {
    struct usb_functionfs_descs_head_v2 header;
    __le32 fs_count;
    __le32 hs_count;
    __le32 ss_count;
    struct usb_interface_descriptor fs_intf;
    struct usb_interface_descriptor hs_intf;
    struct usb_interface_descriptor ss_intf;
} __attribute__((packed));

#define IRA_STR_INTERFACE "ADB Interface"

#define IRA_BULK_EP(addr, maxpkt) {                                            \
        .bLength = USB_DT_ENDPOINT_SIZE,                                       \
        .bDescriptorType = USB_DT_ENDPOINT,                                    \
        .bEndpointAddress = (addr),                                            \
        .bmAttributes = USB_ENDPOINT_XFER_BULK,                                \
        .wMaxPacketSize = htole16(maxpkt),                                     \
    }

#define IRA_ADB_INTF {                                                         \
        .bLength = USB_DT_INTERFACE_SIZE,                                      \
        .bDescriptorType = USB_DT_INTERFACE,                                   \
        .bNumEndpoints = 2,                                                    \
        .bInterfaceClass = 0xff,    /* ADB_CLASS */                            \
        .bInterfaceSubClass = 0x42, /* ADB_SUBCLASS */                         \
        .bInterfaceProtocol = 0x01, /* ADB_PROTOCOL */                         \
        .iInterface = 1,                                                       \
    }

#define IRA_IDLE_INTF {                                                        \
        .bLength = USB_DT_INTERFACE_SIZE,                                      \
        .bDescriptorType = USB_DT_INTERFACE,                                   \
        .bNumEndpoints = 0,                                                    \
        .bInterfaceClass = 0xff,                                               \
        .bInterfaceSubClass = 0x00,                                            \
        .bInterfaceProtocol = 0x00,                                            \
    }

#define IRA_SS_EP_COMP {                                                       \
        .bLength = USB_DT_SS_EP_COMP_SIZE,                                     \
        .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,                            \
    }

static const struct ira_desc_v2 kAdbDescs = {
    .header = {
        .magic = htole32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2),
        .length = htole32(sizeof(struct ira_desc_v2)),
        .flags = htole32(FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC |
                         FUNCTIONFS_HAS_SS_DESC),
    },
    .fs_count = htole32(3),
    .hs_count = htole32(3),
    .ss_count = htole32(5),
    .fs_descs = {
        .intf = IRA_ADB_INTF,
        .source = IRA_BULK_EP(IRA_EP_OUT | USB_DIR_OUT, IRA_FS_BULK_MAXPKT),
        .sink = IRA_BULK_EP(IRA_EP_IN | USB_DIR_IN, IRA_FS_BULK_MAXPKT),
    },
    .hs_descs = {
        .intf = IRA_ADB_INTF,
        .source = IRA_BULK_EP(IRA_EP_OUT | USB_DIR_OUT, IRA_HS_BULK_MAXPKT),
        .sink = IRA_BULK_EP(IRA_EP_IN | USB_DIR_IN, IRA_HS_BULK_MAXPKT),
    },
    .ss_descs = {
        .intf = IRA_ADB_INTF,
        .source = IRA_BULK_EP(IRA_EP_OUT | USB_DIR_OUT, IRA_SS_BULK_MAXPKT),
        .source_comp = IRA_SS_EP_COMP,
        .sink = IRA_BULK_EP(IRA_EP_IN | USB_DIR_IN, IRA_SS_BULK_MAXPKT),
        .sink_comp = IRA_SS_EP_COMP,
    },
};

/* The same interface with no endpoints: ff/00/00, which no adb host matches,
 * so the platform's ffs.adb owns the adb role without competition. */
static const struct ira_desc_v2_idle kIdleDescs = {
    .header = {
        .magic = htole32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2),
        .length = htole32(sizeof(struct ira_desc_v2_idle)),
        .flags = htole32(FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC |
                         FUNCTIONFS_HAS_SS_DESC),
    },
    .fs_count = htole32(1),
    .hs_count = htole32(1),
    .ss_count = htole32(1),
    .fs_intf = IRA_IDLE_INTF,
    .hs_intf = IRA_IDLE_INTF,
    .ss_intf = IRA_IDLE_INTF,
};

struct ira_strings {
    struct usb_functionfs_strings_head header;
    struct {
        __le16 code;
        char str1[sizeof(IRA_STR_INTERFACE)];
    } __attribute__((packed)) lang0;
} __attribute__((packed));

static const struct ira_strings kStrings = {
    .header = {
        .magic = htole32(FUNCTIONFS_STRINGS_MAGIC),
        .length = htole32(sizeof(struct ira_strings)),
        .str_count = htole32(1),
        .lang_count = htole32(1),
    },
    .lang0 = {
        .code = htole16(0x0409), /* en-us */
        .str1 = IRA_STR_INTERFACE,
    },
};

/* The wire layout the kernel parses (f_fs.c __ffs_data_got_descs): the
 * header is a fixed 12 bytes, each entry is exactly its descriptor bytes
 * concatenated, and header.length must be the number of bytes written. */
static_assert(sizeof(struct usb_functionfs_descs_head_v2) == 12, "v2 header");
static_assert(sizeof(struct ira_func_desc) == 9 + 7 + 7, "fs/hs descriptor set");
static_assert(sizeof(struct ira_ss_func_desc) == 9 + 7 + 6 + 7 + 6, "ss descriptor set");
static_assert(sizeof(struct ira_desc_v2) == 12 + 12 + 23 + 23 + 35, "adb descriptor block");
static_assert(sizeof(struct ira_desc_v2_idle) == 12 + 12 + 3 * 9, "idle descriptor block");
static_assert(sizeof(struct ira_strings) == 16 + 2 + sizeof(IRA_STR_INTERFACE), "strings block");
/* One transfer has to be a whole number of the largest bulk packet, or a
 * payload split into these would end mid-packet and the host would see the
 * chunk boundary (ira_bridge.cpp). */
static_assert(IRA_BULK_CHUNK % IRA_SS_BULK_MAXPKT == 0, "transfer size vs bulk max packet");
static_assert(IRA_FS_BULK_MAXPKT < IRA_HS_BULK_MAXPKT &&
              IRA_HS_BULK_MAXPKT < IRA_SS_BULK_MAXPKT, "bulk limits per speed");

/* The instance, as one object, because every field changes together at an arm.
 * Only the ep0 thread writes the fds; a pump takes the lock just long enough to
 * snapshot one and to count itself in flight.  The three flags are atomics as
 * well because the bridge reads them from its own threads. */
static std::mutex g_m;
static std::condition_variable g_cv;      /* a pump's transfer came back */
static int g_ffs_dir = -1;                 /* pins the private mount, survives endpoint re-arms */
static int g_ep0 = -1;
static int g_ep[kDirs] = {-1, -1};
static unsigned g_gen = 0;                /* bumped by every arm */
static bool g_rearming = false;
static int g_in_flight[kDirs] = {0, 0};
static pthread_t g_pump[kDirs];
static bool g_pump_known[kDirs] = {false, false};
static std::atomic<bool> g_armed{false};     /* a descriptor set is on ep0 */
static std::atomic<bool> g_endpoints{false}; /* ... and it has ep1/ep2 */
/* The set the configuration wants, as last decided: the framework's own word when the hook in
 * the gadget HAL is running. Startup presents idle until that hook supplies a role. */
static std::atomic<bool> g_desire_adb{false};
/* Whether the hook has ever sent a role. Without it the daemon presents the endpoint-less set for
 * ever, which has to be visible in the log instead of looking like a working setup. */
static std::atomic<bool> g_role_requested{false};
static std::atomic<bool> g_enabled{false};   /* FUNCTIONFS_ENABLE ... DISABLE */
static std::atomic<bool> g_bound{false};     /* FUNCTIONFS_BIND ... UNBIND */

static ira_ffs_lost_fn g_lost;
static std::atomic<bool> g_revoke_reset_pending{false};
// The looper owns a duplicate of ep0; it must be released before the instance is reset.
static fdevent* g_ep0_fde = nullptr;

/* A role request that arrives while the function is still bound cannot be answered yet: replying
 * "queued" lets the HAL write UDC before FUNCTIONFS_UNBIND has been consumed. Keep that client open
 * and complete it from the UNBIND rearm callback, while the ep0 looper remains free to receive the
 * event. All accesses are on that looper. */
static int g_pending_ctl_fd = -1;
static bool g_pending_ctl_want;

static void log_line(const char *what) {
    fprintf(stderr, "ira-ffs: %s: %s\n", what, strerror(errno));
}

/* The transient errors of the ep0 file repeat for as long as the condition
 * does - a cancelled setup, an instance re-entered in the middle of a
 * transfer - so they are logged once per change, not once per event. */
static void log_once(const char *what, int err) {
    static const char *last_what;
    static int last_err;

    if (last_what == what && last_err == err)
        return;
    last_what = what;
    last_err = err;
    fprintf(stderr, "ira-ffs: %s: %s (transient, recovering)\n", what, strerror(err));
}

static bool transient_ep0_error(int err) {
    switch (err) {
    case EAGAIN:
    case EINTR:
    case EIDRM:      /* the setup was cancelled under us */
    case ESRCH:      /* no setup pending any more */
    case EBADFD:     /* the instance left FFS_ACTIVE */
    case ENODEV:
    case ESHUTDOWN:
    case ENOENT:
    case EIO:
    case ECONNRESET:
    case EPROTO:
        return true;
    default:
        return false;
    }
}


static const char *set_name(bool endpoints) {
    return endpoints ? "adb (ff/42/01, ep1+ep2)" : "idle (ff/00/00, no endpoints)";
}

static int make_dir(const char *path) {
    if (mkdir(path, 0755) == 0 || errno == EEXIST)
        return 0;
    log_line(path);
    return -1;
}


/* Reads the current controller; authorization revocation saves and restores this binding. */
static bool gadget_udc(char *out, size_t len) {
    int fd = open(IRA_UDC_FILE, O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        return false;
    ssize_t n = read(fd, out, len - 1);
    close(fd);
    if (n <= 0)
        return false;
    while (n > 0 && isspace((unsigned char)out[n - 1])) --n;
    out[n] = 0;
    return n > 0 && strcmp(out, "none") != 0;
}


/* The framework may already have created the gadget chain; if this daemon
 * wins the race with the vendor's rc, create only what configfs needs to
 * register the ffs instance.  init's own mkdir is idempotent. */
static int ensure_configfs_tree(void) {
    struct statfs st;

    if (statfs("/config", &st) != 0) {
        log_line("statfs /config");
        return -1;
    }
    if ((unsigned long)st.f_type != IRA_CONFIGFS_MAGIC) {
        fprintf(stderr, "ira-ffs: /config is not configfs (type 0x%lx)\n",
                (unsigned long)st.f_type);
        errno = ENODEV;
        return -1;
    }
    if (make_dir(IRA_GADGET_DIR) || make_dir(IRA_GADGET_DIR "/functions") ||
        make_dir(IRA_GADGET_DIR "/configs") || make_dir(IRA_CONFIG_DIR) ||
        make_dir(IRA_FFS_DIR))
        return -1;
    return 0;
}

static int write_all(int fd, const void *buf, size_t len) {
    const char *p = static_cast<const char *>(buf);

    while (len) {
        ssize_t n = write(fd, p, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static bool write_udc(const char *value) {
    int fd = open(IRA_UDC_FILE, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    const bool ok = write_all(fd, value, strlen(value)) == 0;
    const int error = errno;
    close(fd);
    errno = error;
    return ok;
}

/* header.length is what __ffs_data_got_descs checks against the write size
 * (f_fs.c:2506); a stale constant would make ep0 reject the whole block. */
static bool block_length_ok(const void *blob, size_t len) {
    const struct usb_functionfs_descs_head_v2 *h =
        static_cast<const struct usb_functionfs_descs_head_v2 *>(blob);

    if (le32toh(h->magic) != FUNCTIONFS_DESCRIPTORS_MAGIC_V2 ||
        le32toh(h->length) != len) {
        fprintf(stderr, "ira-ffs: descriptor block says %u bytes (magic %#x), built %zu\n",
                le32toh(h->length), le32toh(h->magic), len);
        return false;
    }
    return true;
}

/* One control transfer the kernel handed us.  ffs_ep0_read() gives the event
 * first and the OUT data phase on the next read; an IN request is completed
 * by writing (even zero bytes) to ep0 (f_fs.c:340-470, 507-600). */
static void handle_setup(int ep0, const struct usb_ctrlrequest &setup) {
    unsigned len = setup.wLength;

    if (setup.bRequestType & USB_DIR_IN) {
        if (write(ep0, "", 0) < 0)
            fprintf(stderr, "ira-ffs: setup IN ack: %s\n", strerror(errno));
        return;
    }

    char stack[256];
    char *buf = stack;
    size_t cap = len ? len : 1;

    if (cap > sizeof(stack)) {
        buf = static_cast<char *>(malloc(cap));
        if (!buf) {
            fprintf(stderr, "ira-ffs: setup OUT: no memory for %zu bytes\n", cap);
            return;
        }
    }

    ssize_t n = read(ep0, buf, cap);

    if (n < 0)
        fprintf(stderr, "ira-ffs: setup OUT read: %s\n", strerror(errno));
    else if ((unsigned)n != len)
        fprintf(stderr, "ira-ffs: setup OUT read %zd of %u bytes\n", n, len);
    if (buf != stack)
        free(buf);
}

/* Only this bootstrap thread enters a private namespace. The directory fd pins the mount after
 * the thread exits, so endpoint reopen uses openat() without changing any service's filesystem view. */
static int mount_private(const char* source, const char* target, const char* type) {
    int directory = -1;
    int error = 0;
    try {
        std::thread bootstrap([&] {
            if (unshare(CLONE_NEWNS) != 0 ||
                mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0 ||
                mount(source, target, type, 0, nullptr) != 0) {
                error = errno;
                return;
            }
            directory = open(target, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (directory < 0)
                error = errno;
        });
        bootstrap.join();
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    if (directory < 0)
        errno = error;
    return directory;
}

static int open_ep0(void) {
    for (int i = 0; i < 40; i++) {
        int fd = openat(g_ffs_dir, "ep0", O_RDWR | O_CLOEXEC);

        if (fd >= 0)
            return fd;
        if (errno != EBUSY)
            return -1;
        usleep(5000);
    }
    errno = EBUSY;
    return -1;
}

/* Takes back every bulk transfer a pump has blocked inside the kernel.  The
 * fds are about to be closed, and a transfer still queued on one of them would
 * keep the epfile file open - the instance would never come back to
 * FFS_READ_DESCRIPTORS and the new descriptor set would be refused. */
static bool quiesce_pumps(const char *why) {
    {
        std::lock_guard<std::mutex> lk(g_m);

        g_rearming = true;
        g_gen++;                   /* whatever a pump still holds is void */
        g_cv.notify_all();
    }

    /* Never hold g_m while interrupting a pump. The signal makes ep_io() leave the kernel; ep_io()
     * must then reacquire g_m to decrement g_in_flight. Holding it here was a guaranteed deadlock. */
    for (int i = 0; i < 400; i++) {
        pthread_t targets[kDirs];
        int target_count = 0;
        bool busy = false;

        {
            std::lock_guard<std::mutex> lk(g_m);
            for (int d = 0; d < kDirs; d++) {
                if (g_pump_known[d] && g_in_flight[d] > 0) {
                    targets[target_count++] = g_pump[d];
                    busy = true;
                }
            }
        }
        if (!busy)
            return true;

        for (int n = 0; n < target_count; n++)
            pthread_kill(targets[n], kPumpSignal);

        std::unique_lock<std::mutex> lk(g_m);
        if (g_cv.wait_for(lk, std::chrono::milliseconds(5), [] {
                return g_in_flight[kOut] == 0 && g_in_flight[kIn] == 0;
            }))
            return true;
    }
    fprintf(stderr, "ira-ffs: %s: a bulk transfer did not come back in 2 s\n", why);
    return false;
}

/* Closes every file of the instance.  The order matters twice over: ep0 goes
 * last because the reset to FFS_READ_DESCRIPTORS happens on the close of the
 * last file (f_fs.c:1732-1762, 1854), and because while the function is bound
 * that close is what makes the kernel unregister the gadget item
 * (f_fs.c:3839-3871). */
static void close_all(void) {
    // A surviving dup keeps the old ep0 file open, preventing FFS_READ_DESCRIPTORS.
    // All callers run at startup or on the looper, outside the ep0 event callback.
    if (g_ep0_fde != nullptr) {
        fdevent_destroy(g_ep0_fde);
        g_ep0_fde = nullptr;
    }

    int ep0, out, in;

    {
        std::lock_guard<std::mutex> lk(g_m);
        ep0 = g_ep0;
        out = g_ep[kOut];
        in = g_ep[kIn];
        g_ep0 = -1;
        g_ep[kOut] = -1;
        g_ep[kIn] = -1;
    }
    g_armed.store(false);
    g_endpoints.store(false);
    g_enabled.store(false);
    g_bound.store(false);

    if (in >= 0)
        close(in);
    if (out >= 0)
        close(out);
    if (ep0 >= 0)
        close(ep0);
}

/* Puts the requested descriptor set on ep0. Returns -1 with errno preserved on failure. */

static int arm_instance(const char *why, bool want_adb) {
    const bool was_bound = g_bound.load();

    /* A live session belongs to the set that is being replaced.  Only the
     * still-enabled case is handled here: if the endpoints were already
     * disabled, DISABLE or UNBIND has relinked the transport for this session
     * and a second relink would tear the fresh one down again. */
    if (g_enabled.exchange(false) && g_lost)
        g_lost("the descriptor set is being re-armed");

    if (!quiesce_pumps(why)) {
        /* Closing an endpoint while its kernel I/O is still counted is not a valid re-arm. The
         * control path turns this into a retry and the clean-process path; the initial arm has no
         * registered pumps and therefore cannot reach this branch. */
        errno = ETIMEDOUT;
        return -1;
    }

    close_all();

    int out = -1, in = -1;
    int saved = 0;
    /* Declared before any goto: the failure path jumps past nothing that is initialised below. */
    const bool endpoints = want_adb;
    const void *blob = endpoints ? static_cast<const void *>(&kAdbDescs)
                                 : static_cast<const void *>(&kIdleDescs);
    const size_t blob_len = endpoints ? sizeof(kAdbDescs) : sizeof(kIdleDescs);
    int ep0 = open_ep0();

    if (ep0 < 0) {
        log_line("open ep0");
        saved = errno;
        goto fail;
    }

    if (!block_length_ok(blob, blob_len)) {
        saved = EINVAL;
        goto fail;
    }

    if (write_all(ep0, blob, blob_len) != 0) {
        saved = errno;
        log_line("write descriptors");
        goto fail;
    }
    if (write_all(ep0, &kStrings, sizeof(kStrings)) != 0) {
        saved = errno;
        log_line("write strings");
        goto fail;
    }
    if (endpoints) {
        /* The ep# files exist once the strings write returns (f_fs.c:380). */
        out = openat(g_ffs_dir, "ep1", O_RDONLY | O_CLOEXEC);
        in = openat(g_ffs_dir, "ep2", O_WRONLY | O_CLOEXEC);
        if (out < 0 || in < 0) {
            saved = errno;
            log_line("open bulk endpoints");
            goto fail;
        }
    }

    /* Endpoints first, then the re-arm flag: a pump that wakes up has to see
     * both the new fds and a finished re-arm, or it would spin on the timeout
     * of ira_ffs_wait_endpoints(). */
    g_endpoints.store(endpoints);
    {
        std::lock_guard<std::mutex> lk(g_m);
        g_ep0 = ep0;
        g_ep[kOut] = out;
        g_ep[kIn] = in;
        g_rearming = false;
    }
    g_armed.store(true);
    g_cv.notify_all();

    fprintf(stderr, "ira-ffs: %s: %s is on ep0 (%zu bytes)%s%s\n", why,
            set_name(endpoints), blob_len,
            was_bound ? "; the host is disconnected and the next UDC write binds it" : "",
            endpoints ? "" : "; the platform's ffs.adb carries adb");
    return 0;

fail:
    if (in >= 0)
        close(in);
    if (out >= 0)
        close(out);
    close(ep0);
    {
        std::lock_guard<std::mutex> lk(g_m);
        g_rearming = false;
    }
    g_cv.notify_all();
    errno = saved;
    return -1;
}


static void set_change_exit(void);
static void ep0_watch(void);

struct RevokeResume {
    unsigned version;
    unsigned want_adb;
    char controller[128];
};
static RevokeResume g_revoke_resume{};

/* The clean-process fallback must retain both the requested set and the pull-up it owns.
 * post-fs-data removes this boot-local handoff before the initial daemon starts. */
static bool save_revoke_resume(const char* controller, bool want_adb) {
    RevokeResume resume{};
    resume.version = 1;
    resume.want_adb = want_adb;
    snprintf(resume.controller, sizeof(resume.controller), "%s", controller);
    int fd = open(IRA_REVOKE_RESUME ".new", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    bool ok = write_all(fd, &resume, sizeof(resume)) == 0 && fsync(fd) == 0;
    int error = errno;
    close(fd);
    if (ok) {
        ok = rename(IRA_REVOKE_RESUME ".new", IRA_REVOKE_RESUME) == 0;
        error = errno;
    }
    if (!ok) unlink(IRA_REVOKE_RESUME ".new");
    else g_revoke_resume = resume;
    errno = error;
    return ok;
}

static bool load_revoke_resume() {
    int fd = open(IRA_REVOKE_RESUME, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    RevokeResume resume{};
    const ssize_t n = read(fd, &resume, sizeof(resume));
    char extra;
    const bool exact = n == sizeof(resume) && read(fd, &extra, 1) == 0;
    close(fd);
    if (!exact || resume.version != 1 || resume.want_adb > 1 ||
        !memchr(resume.controller, 0, sizeof(resume.controller))) {
        fprintf(stderr, "ira-ffs: invalid authorization reset handoff; discarding\n");
        unlink(IRA_REVOKE_RESUME);
        return false;
    }
    g_revoke_resume = resume;
    g_desire_adb.store(resume.want_adb != 0);
    g_role_requested.store(true);
    return true;
}

static void finish_revoke_resume() {
    if (g_revoke_resume.version != 1 || !g_armed.load()) return;
    if (g_endpoints.load() != (g_revoke_resume.want_adb != 0)) return;
    if (g_revoke_resume.controller[0]) {
        char current[128]{};
        const bool bound = gadget_udc(current, sizeof(current));
        if (bound && strcmp(current, g_revoke_resume.controller) != 0) {
            fprintf(stderr, "ira-ffs: authorization reset binding superseded by another controller\n");
        } else if (!bound && !write_udc(g_revoke_resume.controller)) {
            fprintf(stderr, "ira-ffs: authorization reset could not restore UDC: %s\n", strerror(errno));
            return; // Keep the handoff available if the process must be replaced again.
        } else {
            fprintf(stderr, "ira-ffs: authorization revoked; UDC restored\n");
        }
    }
    unlink(IRA_REVOKE_RESUME);
    g_revoke_resume = {};
}

static void revoke_usb_reset_cb(void) {
    if (!g_revoke_reset_pending.exchange(false))
        return;

    char controller[128] = {};
    const bool restore = gadget_udc(controller, sizeof(controller));
    bool was_enabled;
    fprintf(stderr, "ira-ffs: authorization revoked; starting USB session reset (UDC %s)\n",
            restore ? "bound" : "unbound");
    {
        std::lock_guard<std::mutex> lk(g_m);
        g_rearming = true;
        was_enabled = g_enabled.exchange(false);
    }

    if (!quiesce_pumps("authorization revoked")) {
        fprintf(stderr, "ira-ffs: authorization revoke could not quiesce USB pumps\n");
        return;
    }

    const bool want_adb = g_desire_adb.load();
    if (!save_revoke_resume(restore ? controller : "", want_adb)) {
        fprintf(stderr, "ira-ffs: cannot save authorization reset recovery: %s\n", strerror(errno));
        std::lock_guard<std::mutex> lk(g_m);
        g_rearming = false;
        g_enabled.store(was_enabled);
        g_cv.notify_all();
        return;
    }

    /* AOSP gets this transition from init when adbd stops. IRA owns the private
     * FunctionFS instance, so perform the same pull-down explicitly before the
     * last ep file is closed. */
    if (restore && !write_udc("none"))
        fprintf(stderr, "ira-ffs: authorization revoke could not pull down UDC: %s\n",
                strerror(errno));

    close_all();
    if (g_lost)
        g_lost("authorization revoked; USB session reset");

    const int rc = arm_instance("authorization revoked; descriptors rearmed", want_adb);
    if (rc != 0) {
        fprintf(stderr, "ira-ffs: authorization revoke could not rearm descriptors: %s;"
                        " restarting with saved role and UDC\n", strerror(errno));
        set_change_exit();
        return;
    }
    ep0_watch();
    finish_revoke_resume();
}

void ira_ffs_reset_usb_session(void) {
    if (g_revoke_reset_pending.exchange(true))
        return;
    fdevent_run_on_looper(revoke_usb_reset_cb);
}

enum {
    kEp0Continue = 0,
    kEp0Rearm = 1,     /* the descriptor set has to be rebuilt */
    kEp0Fatal = -1,    /* not the wire's fault: stop touching this ep0 */
};

/* Reads one batch of ep0 events and acts on them.  Re-arm decisions do not use
 * the "wait until the kernel finishes" delay the UNBIND path needs: this is the
 * bound case, where the whole composite has to come down anyway. */
static void end_usb_session(const char *why) {
    bool was_enabled;
    {
        std::lock_guard<std::mutex> lk(g_m);
        was_enabled = g_enabled.exchange(false);
        g_rearming = true;
    }
    if (!was_enabled) {
        g_cv.notify_all();
        return;
    }

    // Drain old reads before publishing the replacement transport. ENABLE must not admit a new
    // session while a previous kernel read can still consume its first packet.
    if (!quiesce_pumps(why)) {
        fprintf(stderr, "ira-ffs: %s: cannot drain the old USB session; leaving I/O paused\n", why);
        return;
    }
    if (g_lost)
        g_lost(why);
}

static int handle_events(int ep0) {
    struct usb_functionfs_event ev[4];
    ssize_t n = read(ep0, ev, sizeof(ev));

    if (n < 0) {
        int err = errno;

        if (err == EINTR)
            return kEp0Continue;
        if (transient_ep0_error(err)) {
            /* A cancelled setup, a request that is gone, the instance between states: none of
             * this means the descriptor set is wrong, and putting a fresh set on ep0 would take
             * a live function down.  Note it once and keep reading. */
            log_once("ep0 event read", err);
            return kEp0Continue;
        }
        fprintf(stderr, "ira-ffs: ep0 event read: %s\n", strerror(err));
        return kEp0Fatal;
    }
    if (n == 0)
        return kEp0Continue;

    for (size_t i = 0; i < (size_t)n / sizeof(ev[0]); i++) {
        switch (ev[i].type) {
            case FUNCTIONFS_BIND:
                g_bound.store(true);
                if (!g_role_requested.load()) {
                    static std::atomic<bool> warned{false};

                    if (!warned.exchange(true))
                        fprintf(stderr, "ira-ffs: bound while no role was ever requested (the gadget"
                                        " hook is not asking); this daemon is serving nothing\n");
                }
                fprintf(stderr, "ira-ffs: bound (%s set)\n",
                        g_endpoints.load() ? "adb" : "idle");
                /* The set on ep0 is the one the hook asked for, and the hook is the only thing
                 * that ever changes it. Nothing is decided or corrected here: replacing it now
                 * would take a live function down. */
                break;
            case FUNCTIONFS_UNBIND:
                fprintf(stderr, "ira-ffs: unbound\n");
                g_bound.store(false);
                /* DISABLE normally precedes UNBIND; only the transition out of
                 * enabled represents a session that has to be dropped, and only
                 * one relink should happen. */
                end_usb_session("the function was unbound");
                /* The platform takes the gadget down here, so this is the moment the recorded
                 * wish can become descriptors: the next bind then carries the right set. Deferred
                 * to the looper, because arming closes this very ep0 and a callback must not
                 * destroy the descriptor it was handed. */
                fdevent_run_on_looper([]() {
                    const bool want = g_desire_adb.load();
                    int rc = 0;

                    if (!g_armed.load() || g_endpoints.load() != want) {
                        /* FUNCTIONFS_UNBIND is queued before the kernel clears its bound state. Give
                         * that teardown a bounded settle window before closing the last epfile; the
                         * hook remains blocked on the pending control fd during this interval. */
                        usleep(kUnbindSettleMs * 1000);
                        rc = arm_instance("the platform unbound; writing the recorded set", want);
                        if (rc != 0)
                            fprintf(stderr, "ira-ffs: could not write the recorded set after unbind\n");
                    }

                    /* arm_instance replaced g_ep0. The old fdevent duplicate must be destroyed and
                     * a duplicate of the new ep0 installed before the next bind event arrives. */
                    ep0_watch();

                    g_cv.notify_all();

                    if (g_pending_ctl_fd >= 0) {
                        int fd = g_pending_ctl_fd;
                        const bool pending_want = g_pending_ctl_want;
                        g_pending_ctl_fd = -1;
                        const char *reply = rc == 0 && g_armed.load() &&
                                                    g_endpoints.load() == pending_want
                                                ? "ok\n"
                                                : "retry\n";
                        (void)!write(fd, reply, strlen(reply));
                        close(fd);
                        if (rc != 0)
                            set_change_exit();
                    }
                });
                break;
            case FUNCTIONFS_ENABLE:
                fprintf(stderr, "ira-ffs: endpoints enabled\n");
                {
                    std::lock_guard<std::mutex> lk(g_m);
                    if (g_in_flight[kOut] != 0 || g_in_flight[kIn] != 0) {
                        fprintf(stderr, "ira-ffs: enable refused: old session I/O is still in flight\n");
                        break;
                    }
                    g_rearming = false;
                    g_enabled.store(true);
                }
                g_cv.notify_all();
                break;
            case FUNCTIONFS_DISABLE:
                fprintf(stderr, "ira-ffs: endpoints disabled\n");
                end_usb_session("the host went away");
                break;
            case FUNCTIONFS_SETUP:
                handle_setup(ep0, ev[i].u.setup);
                break;
            case FUNCTIONFS_SUSPEND:
                fprintf(stderr, "ira-ffs: suspended\n");
                break;
            case FUNCTIONFS_RESUME:
                fprintf(stderr, "ira-ffs: resumed\n");
                break;
            default:
                fprintf(stderr, "ira-ffs: unknown event %u\n", ev[i].type);
                break;
        }
    }
    return kEp0Continue;
}

/* The event thread: owns ep0, and is the only place a descriptor set is ever
 * written or replaced. */
/* The control socket: how the framework's hook asks for a descriptor set before it lets the
 * platform bind.  One request at a time, answered on this thread - the ep0 owner - and only after
 * the set is on ep0, so "ok" means "the coming bind will find what it asked for".
 *
 * The hook is a ZygiskNext module in the gadget HAL (src/zygisk); it blocks the UDC write
 * that would make the HAL write the UDC until this answers.  Nothing here races the platform: the
 * platform is waiting. */
/* The endpoint this daemon's gadget hook dials, from "names" for this installation. No
 * constant and no fallback: without the file the hook cannot reach us, and a name a probe can
 * guess is a name a probe can dial. */
static bool control_socket_name(char *out, size_t cap) {
    return ira_socket_name("ctl", out, cap);
}



static int start_control_socket(void) {
    char name[64];

    if (!control_socket_name(name, sizeof(name))) {
        fprintf(stderr, "ira-ffs: no ctl endpoint in the module names file; the gadget hook cannot reach us\n");
        errno = ENOENT;
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0) {
        log_line("socket control");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = 0;
    size_t name_len = strlen(name);

    if (name_len == 0 || name_len > sizeof(addr.sun_path) - 2) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    memcpy(addr.sun_path + 1, name, name_len);
    socklen_t len = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;

    if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), len) != 0 ||
        listen(fd, 8) != 0) {
        log_line("bind/listen control");
        close(fd);
        return -1;
    }
    fprintf(stderr, "ira-ffs: listening on @%s for the gadget hook\n", name);
    return fd;
}

/* Serves one request: "role adb\n" or "role idle\n".  The answer goes out only after the set is
 * on ep0, which is what the hook is waiting for. */
static void serve_control(int lfd) {
    int fd = accept4(lfd, nullptr, nullptr, SOCK_CLOEXEC);

    if (fd < 0)
        return;

    /* This runs on the ep0 thread: a peer that opens and never writes, or writes half a word,
     * must not be able to freeze ep0 events and every later arm. Bounded wait, then read until the
     * newline, so a split request is never parsed as something else. */
    struct timeval tv = {1, 0};

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char req[64];
    size_t used = 0;
    struct pollfd ctlp = {fd, POLLIN, 0};

    if (poll(&ctlp, 1, 1000) > 0) {
        while (used < sizeof(req) - 1) {
            ssize_t got = read(fd, req + used, sizeof(req) - 1 - used);

            if (got <= 0)
                break;
            used += (size_t)got;
            if (memchr(req, '\n', used) != nullptr)
                break;
        }
    }
    ssize_t n = used == 0 ? -1 : (ssize_t)used;

    if (n <= 0) {
        close(fd);
        return;
    }
    req[n] = 0;

    if (strcmp(req, "auth revoke\n") == 0) {
        struct ucred peer{};
        socklen_t size = sizeof(peer);
        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 &&
            (peer.uid == 1000 || peer.uid == 0)) {
            adbd_auth_revoke();
            (void)!write(fd, "ok\n", 3);
        } else {
            (void)!write(fd, "err peer\n", 9);
        }
        close(fd);
        return;
    }

    const bool want_adb = strncmp(req, "role adb", 8) == 0;
    const bool known = want_adb || strncmp(req, "role idle", 9) == 0;
    const char *answer = "err unknown request\n";

    if (known) {
        g_role_requested.store(true);
        g_desire_adb.store(want_adb);
        if (g_armed.load() && g_endpoints.load() == want_adb) {
            /* Already the right shape: answering is enough, and the bind stays
             * untouched - no need to take the function down. */
            answer = "ok already\n";
        } else if (g_bound.load()) {
            /* Do not answer yet. The HAL is blocked in the UDC write hook, and the ep0 callback must
             * remain free to consume FUNCTIONFS_UNBIND. The pending fd is completed only after the
             * unbind rearm has written the requested descriptors. */
            if (g_pending_ctl_fd >= 0) {
                (void)!write(g_pending_ctl_fd, "retry\n", 6);
                close(g_pending_ctl_fd);
            }
            g_pending_ctl_fd = fd;
            g_pending_ctl_want = want_adb;
            return;
        } else {
            /* A failed arm leaves the instance without a descriptor set, and the hook would then
             * write the UDC while ep0 is empty - which fails the composite bind and takes the whole
             * gadget down. Three short attempts, then say so plainly. */
            int rc = -1;

            for (int attempt = 0; attempt < 3; attempt++) {
                rc = arm_instance("the framework is about to bind", want_adb);
                if (rc == 0)
                    break;
                usleep(20 * 1000);
            }
            if (rc != 0) {
                /* The client must never be told that a bind is safe when the descriptor write failed.
                 * Send a retry result before ending; the supervisor then starts a clean FunctionFS
                 * instance and the hook can issue a new request. */
                (void)!write(fd, "retry\n", 7);
                close(fd);
                set_change_exit();
                return;
            }
            answer = "ok\n";
        }
    }
    (void)!write(fd, answer, strlen(answer));
    close(fd);
}

/* Both descriptors live on adb own looper, one callback each: ep0 events, and control requests from
 * the gadget hook. There is no polling loop of ours and no fd shared between the two callbacks - an
 * arm started from the control callback only re-points the ep0 watch afterwards, and the ep0 callback
 * always works on the descriptor it was handed. */
/* Only reached when a set change cannot be applied in-process. The file is what the supervisor
 * looks for; the exit itself is the mechanism (see the arm branch above). */
static void set_change_exit(void) {
    /* Role-change callers have replied retry to the HAL. Authorization reset callers
     * have saved their recovery intent and pulled down UDC; the next process owns restoration. */
    int fd = open(IRA_STATE_DIR "/setchange", O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd >= 0)
        close(fd);
    fprintf(stderr, "ira-ffs: the descriptor set has to change out of process; ending so the"
            " supervisor can start a clean one\n");
    fflush(stderr);
    _exit(0);
}

static int g_ctl_listen = -1;
static fdevent* g_ctl_fde = nullptr;

static void ep0_event_cb(int fd, unsigned, void*) {
    if (handle_events(fd) == kEp0Fatal)
        fprintf(stderr, "ira-ffs: ep0 reported a fatal error; leaving it alone\n");
}

/* Points the ep0 watch at whatever arm_instance() left behind. Looper thread only, like every other
 * fdevent call here. */
static void ep0_watch(void) {
    if (g_ep0_fde != nullptr) {
        fdevent_destroy(g_ep0_fde);
        g_ep0_fde = nullptr;
    }

    int ep0;

    {
        std::lock_guard<std::mutex> lk(g_m);
        ep0 = g_ep0;
    }
    if (ep0 < 0)
        return;

    /* fdevent owns the descriptor it is given and closes it when the watch is destroyed. ep0 is
     * ours: arm_instance() closes and reopens it, so registering the original number hands fdevent
     * a descriptor that is already gone the next time - which is what aborted the daemon at startup
     * ("failed to register fd 4 with epoll: Bad file descriptor", then SIGABRT). The dup keeps the
     * two lifetimes apart. */
    // dup() clears CLOEXEC. A long-lived service backend would then retain ep0
    // across exec and prevent FunctionFS last-close reset, making new descriptors fail ESRCH.
    // Set the flag atomically: another thread can fork a service at any moment.
    int watch_fd = fcntl(ep0, F_DUPFD_CLOEXEC, 3);

    if (watch_fd < 0)
        return;
    g_ep0_fde = fdevent_create(watch_fd, ep0_event_cb, nullptr);
    if (g_ep0_fde != nullptr)
        fdevent_add(g_ep0_fde, FDE_READ);
}

static void control_cb(int fd, unsigned, void*) {
    serve_control(fd);
    /* The request may have armed, which replaces ep0: point the watch at the new one. */
    ep0_watch();
}

void ira_ffs_start_events(void) {
    ep0_watch();

    g_ctl_listen = start_control_socket();
    if (g_ctl_listen >= 0) {
        g_ctl_fde = fdevent_create(g_ctl_listen, control_cb, nullptr);
        if (g_ctl_fde != nullptr)
            fdevent_add(g_ctl_fde, FDE_READ);
    }
    // The transport and ep0 watcher now exist; only now can the host come back.
    finish_revoke_resume();
}

/* The pumps block in read()/write() on the bulk endpoints; a re-arm interrupts them so it can close
 * the fds without waiting for the host to send something. */
/* The handler must do nothing. quiesce_pumps() sends the signal to each target explicitly;
 * taking g_m or broadcasting from this handler would deadlock the interrupted ep_io() and can
 * recursively re-queue SIGUSR1 on the current pump. */
static void pump_signal(int) {}

int ira_ffs_init(ira_ffs_lost_fn lost) {
    g_lost = lost;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = pump_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                 /* no SA_RESTART: the interruption is the point */
    if (sigaction(kPumpSignal, &sa, nullptr) != 0) {
        log_line("sigaction");
        return -1;
    }

    if (ensure_configfs_tree() != 0)
        return -1;

    g_ffs_dir = mount_private(kInstance, IRA_FFS_DIR, "functionfs");
    if (g_ffs_dir < 0) {
        log_line("mount private functionfs " IRA_FFS_DIR);
        return -1;
    }
    fprintf(stderr, "ira-ffs: mounted functionfs instance \"%s\" on %s (directory fd %d)\n",
            kInstance, IRA_FFS_DIR, g_ffs_dir);
    /* The first arm: the descriptors have to be on ep0 before anything writes the UDC. A failure is
     * not fatal - the hook next request re-arms, and the ep0 watch is pointed at whatever is there
     * when the looper starts. */
    g_desire_adb.store(false);
    const bool resuming = load_revoke_resume();
    if (arm_instance(resuming ? "authorization reset recovery" : "first arm",
                     g_desire_adb.load()) != 0) {
        int err = errno;

        fprintf(stderr, "ira-ffs: the first arm failed (%s); the next bind request will re-arm\n",
                strerror(err));
    }

    return 0;
}

int ira_ffs_armed(void) {
    return g_armed.load();
}

int ira_ffs_has_endpoints(void) {
    return g_endpoints.load();
}

int ira_ffs_wait_endpoints(unsigned ms) {
    std::unique_lock<std::mutex> lk(g_m);

    if (!g_cv.wait_for(lk, std::chrono::milliseconds(ms), [] {
            return !g_rearming && (!g_endpoints.load() || g_enabled.load());
        }))
        return 0;
    return g_endpoints.load() && g_enabled.load();
}

int ira_ffs_enabled(void) {
    return g_enabled.load();
}

void ira_ffs_pump_register(int dir) {
    if (dir < 0 || dir >= kDirs)
        return;
    std::lock_guard<std::mutex> lk(g_m);

    g_pump[dir] = pthread_self();
    g_pump_known[dir] = true;
}

/* ---- pipelined bulk I/O ---------------------------------------------------
 *
 * The synchronous ep_io() below performs one transfer and waits for the host to
 * take it.  A 16 KiB chunk therefore costs a full round trip, and the link
 * moves one chunk per round trip no matter how fast the controller is.  These
 * wrappers submit up to IRA_AIO_DEPTH requests through the kernel's aio
 * interface and report completions by tag: the same shape AOSP's own ffs
 * transport uses, and the reason real adbd does not slow down like that.
 *
 * Every submitted request is counted in g_in_flight exactly like a blocking
 * transfer, so quiesce_pumps() still refuses to let a re-arm close an endpoint
 * with kernel I/O outstanding.  A request that outlives its generation reports
 * EAGAIN and its bytes are dropped by the pump.
 */
namespace {
struct aio_slot {
    struct iocb cb;
    unsigned long tag;
    unsigned gen;
    bool busy;
};
struct aio_state {
    aio_context_t ctx;
    int efd;
    unsigned depth;
    aio_slot slots[IRA_AIO_DEPTH];
};
} // namespace

static aio_state g_aio[kDirs];

int ira_ffs_rearming(void) {
    std::lock_guard<std::mutex> lk(g_m);
    return g_rearming ? 1 : 0;
}

int ira_ffs_aio_open(int dir, unsigned depth) {
    if (dir < 0 || dir >= kDirs) {
        errno = EINVAL;
        return -1;
    }
    aio_state &a = g_aio[dir];

    if (a.ctx != 0)
        return 0;
    if (depth == 0 || depth > IRA_AIO_DEPTH)
        depth = IRA_AIO_DEPTH;

    aio_context_t ctx = 0;

    /* Older kernels or a seccomp filter may not allow aio at all; the caller
     * then keeps using the single-transfer path. */
    if (syscall(__NR_io_setup, depth * 2, &ctx) != 0)
        return -1;
    int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

    if (efd < 0) {
        int err = errno;

        syscall(__NR_io_destroy, ctx);
        errno = err;
        return -1;
    }
    memset(a.slots, 0, sizeof(a.slots));
    a.ctx = ctx;
    a.efd = efd;
    a.depth = depth;
    return 0;
}

int ira_ffs_aio_event_fd(int dir) {
    if (dir < 0 || dir >= kDirs)
        return -1;
    return g_aio[dir].efd;
}

int ira_ffs_aio_submit(int dir, const void *buf, unsigned long len, unsigned long tag,
                       unsigned session) {
    aio_state &a = g_aio[dir];

    if (a.ctx == 0) {
        errno = EAGAIN;
        return -1;
    }
    aio_slot *slot = nullptr;

    for (unsigned i = 0; i < a.depth; i++) {
        if (!a.slots[i].busy) {
            slot = &a.slots[i];
            break;
        }
    }
    if (slot == nullptr) {
        errno = EBUSY;
        return -1;
    }

    int fd;
    unsigned gen;

    {
        std::lock_guard<std::mutex> lk(g_m);

        if (g_rearming || !g_enabled.load() || g_ep[dir] < 0 || session != g_gen) {
            errno = EAGAIN;
            return -1;
        }
        fd = g_ep[dir];
        gen = g_gen;
        g_in_flight[dir]++;
    }

    memset(&slot->cb, 0, sizeof(slot->cb));
    slot->cb.aio_data = tag;
    slot->cb.aio_lio_opcode = (uint16_t)(dir == kOut ? IOCB_CMD_PREAD : IOCB_CMD_PWRITE);
    slot->cb.aio_fildes = (uint32_t)fd;
    slot->cb.aio_buf = (uint64_t)(uintptr_t)buf;
    slot->cb.aio_nbytes = len;
    slot->cb.aio_offset = 0;
    slot->cb.aio_flags = IOCB_FLAG_RESFD;
    slot->cb.aio_resfd = (uint32_t)a.efd;
    slot->tag = tag;
    slot->gen = gen;
    slot->busy = true;

    struct iocb *cb = &slot->cb;

    if (syscall(__NR_io_submit, a.ctx, 1L, &cb) != 1) {
        int err = errno ? errno : EIO;

        slot->busy = false;
        std::lock_guard<std::mutex> lk(g_m);

        if (g_in_flight[dir] > 0 && --g_in_flight[dir] == 0)
            g_cv.notify_all();
        errno = err;
        return -1;
    }
    return 0;
}

int ira_ffs_aio_reap(int dir, struct ira_aio_done *out, int max, int timeout_ms) {
    aio_state &a = g_aio[dir];

    if (a.ctx == 0 || out == nullptr) {
        errno = EINVAL;
        return -1;
    }
    if (max <= 0 || max > (int)IRA_AIO_DEPTH)
        max = (int)IRA_AIO_DEPTH;

    struct io_event events[IRA_AIO_DEPTH];
    struct timespec ts;
    struct timespec *tsp = nullptr;

    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        tsp = &ts;
    }
    long n = syscall(__NR_io_getevents, a.ctx, 0L, (long)max, events, tsp);

    if (n < 0) {
        errno = (int)-n;
        return -1;
    }
    for (long i = 0; i < n; i++) {
        aio_slot *slot = nullptr;

        for (unsigned j = 0; j < a.depth; j++) {
            if (a.slots[j].busy && (uint64_t)(uintptr_t)&a.slots[j].cb == events[i].obj) {
                slot = &a.slots[j];
                break;
            }
        }

        long result = (long)events[i].res;
        int error = 0;
        bool stale = false;

        if (result < 0) {
            error = (int)-result;
            result = -1;
        }
        {
            std::lock_guard<std::mutex> lk(g_m);

            if (slot != nullptr) {
                stale = g_gen != slot->gen;
                slot->busy = false;
                if (g_in_flight[dir] > 0 && --g_in_flight[dir] == 0)
                    g_cv.notify_all();
            }
        }
        if (stale) {
            /* The set was replaced while this transfer was in flight. */
            result = -1;
            error = EAGAIN;
        }
        out[i].tag = (unsigned long)events[i].data;
        out[i].result = result;
        out[i].error = error;
    }
    return (int)n;
}

void ira_ffs_aio_cancel(int dir) {
    if (dir < 0 || dir >= kDirs)
        return;
    aio_state &a = g_aio[dir];

    if (a.ctx == 0)
        return;
    for (unsigned i = 0; i < a.depth; i++) {
        if (!a.slots[i].busy)
            continue;
        struct io_event ev;

        syscall(__NR_io_cancel, a.ctx, &a.slots[i].cb, &ev);
    }
    /* Reap what came back so the in-flight count reaches zero and the re-arm can
     * close the endpoints.  A request that completes instead of cancelling is
     * reported by io_getevents. */
    struct ira_aio_done done[IRA_AIO_DEPTH];

    for (int i = 0; i < 50; i++) {
        int n = ira_ffs_aio_reap(dir, done, (int)IRA_AIO_DEPTH, 10);

        if (n > 0)
            continue;
        std::lock_guard<std::mutex> lk(g_m);

        if (g_in_flight[dir] == 0)
            return;
    }
}

/* A bulk transfer for one pump. Every transfer is counted in flight while it is inside the kernel, so
 * an arm can wait for it to come back before it closes the fd; a transfer that started under an older
 * generation reports nothing and returns EAGAIN, which is what keeps the bytes of a dead session out
 * of the next one. */
static long ep_io(int dir, void *buf, size_t len, const unsigned *session = nullptr) {
    int fd;
    unsigned gen;

    {
        std::lock_guard<std::mutex> lk(g_m);

        if (g_rearming || !g_enabled.load() || g_ep[dir] < 0 ||
            (session != nullptr && *session != g_gen)) {
            errno = EAGAIN;
            return -1;
        }
        fd = g_ep[dir];
        gen = g_gen;
        g_in_flight[dir]++;
    }

    ssize_t n = dir == kOut ? read(fd, buf, len) : write(fd, buf, len);
    int err = errno;

    {
        std::lock_guard<std::mutex> lk(g_m);

        if (g_in_flight[dir] > 0)
            g_in_flight[dir]--;
        if (g_in_flight[dir] == 0)
            g_cv.notify_all();
        if (g_gen != gen) {
            /* The set was replaced while this transfer was in the kernel: those bytes belong to a
             * session that no longer exists. */
            errno = EAGAIN;
            return -1;
        }
    }
    errno = err;
    return (long)n;
}

unsigned ira_ffs_session_generation(void) {
    std::lock_guard<std::mutex> lk(g_m);
    return g_gen;
}

long ira_ffs_read_out_session(void *buf, unsigned long len, unsigned session) {
    return ep_io(kOut, buf, len, &session);
}

long ira_ffs_write_in(const void *buf, unsigned long len) {
    return ep_io(kIn, const_cast<void *>(buf), len);
}
