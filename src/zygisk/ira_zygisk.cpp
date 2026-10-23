// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * The USB half of this project, on the platform side.
 *
 * A ZygiskNext module injected into the USB gadget HAL (the init service that owns configfs on this
 * device: /vendor/bin/hw/android.hardware.usb.gadget-service.qti). It hooks the write that binds the
 * gadget to the UDC. Before that write is allowed through, the daemon is told which descriptor set
 * the coming bind needs, and it answers only once the set is on ep0 - so the bind the HAL is about
 * to perform always finds what it needs. The framework cannot race us here because it is inside this
 * very process, blocked in this hook.
 *
 * Which set the bind needs is not a guess, and not a filesystem probe: the framework says it, in the
 * binder transaction that carries IUsbGadget::setCurrentUsbFunctions(). The framework's call reaches
 * this process through /dev/binder: the HAL's own binder thread reads it with one
 * ioctl(BINDER_WRITE_READ) per read, and the transactions are in that call's read buffer. Hooking
 * ioctl() and looking at the buffer the kernel filled is how the request is taken off the wire - the
 * same bytes the HAL's generated stub is about to parse, read before anything acted on them.
 *
 * There is exactly one source for that decision (see g_requested_functions), nothing is matched by
 * symbol name, and if the transaction has not been seen the module says so and stays out of the way.
 *
 * Why the HAL and not system_server: ZygiskNext injects into processes forked by init (see
 * $MODDIR/zn_modules.txt), and system_server is a zygote child. The HAL is init's, is a dynamically
 * linked ELF, starts after post-fs-data, and is exactly the process that decides when to bind.
 */
#define LOG_TAG "ira-zn"

#include <android/log.h>
#include <errno.h>
#include <link.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include <atomic>
#include <pthread.h>
#include <unistd.h>

/* The binder ABI, taken from the kernel's own uapi header rather than re-declared here: BINDER_WRITE_READ,
 * struct binder_write_read, struct binder_transaction_data, BR_TRANSACTION / BR_REPLY and the _IOC
 * sizes this file walks the read buffer with all live there. The device tree carries it as
 * include/uapi/linux/android/binder.h, and the NDK sysroot as <linux/android/binder.h>; nothing below
 * re-declares any of it. */
#include <linux/android/binder.h>

#include "zygisk_next_api.h"

namespace {

constexpr char kUdcPath[] = "/config/usb_gadget/g1/UDC";
/* Written in place by the installer, exactly like the framework half: this installation's "ctl"
 * endpoint. Nothing falls back to a constant - a name a probe can guess is a name it can dial. */
char kSocketName[33] = "IRA-SOCKET-NAME-0000000000000000";
/* Longer than the daemon's worst-case arm (quiesce + open + descriptor writes), because a timeout
 * here means the platform writes the UDC while the daemon still has ep0 closed - which fails the
 * composite bind and takes the whole gadget down. */

/* The authoritative intent, kept in memory: the GadgetFunction bitmap the framework last asked this
 * HAL for. -1 until the framework's own request has been read off the binder wire; nothing else ever
 * writes it. */
std::atomic<long long> g_requested_functions{-1};


/* package + interface name: the AIDL descriptor, which is what Parcel::writeInterfaceToken() writes.
 * Matching it is matching the protocol the framework speaks, not a symbol in a .so. */
constexpr char kGadgetInterface[] = "android.hardware.usb.gadget.IUsbGadget";

/* setCurrentUsbFunctions() is the first method declared in IUsbGadget.aidl, so its transaction code
 * is FIRST_CALL_TRANSACTION + 0 = 1 (AIDL numbers declared methods from 1). A code alone is a weak
 * claim - any caller can put 1 in any parcel - so the interface token is required as well, and the
 * code that was seen is logged in probe mode so a surprise is visible instead of silent. */




/* GadgetFunction.ADB, named instead of a bare bit test. */
constexpr long long kGadgetFunctionAdb = 1LL << 0;

/* "none" is how the HAL takes the gadget down; a trailing newline or NUL is the same command, and
 * treating it as a bind would ask the daemon to re-arm while the gadget is still up. */
bool is_none_write(const char *buf, size_t count) {
    size_t n = count;

    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == 0))
        n--;
    return n == 4 && memcmp(buf, "none", 4) == 0;
}
/* The UDC attribute is recognised when the HAL opens it, not when it writes: the decision path then
 * contains no filesystem call at all (it used to be a readlink of /proc/self/fd/<n> per write). */
std::atomic<int> g_udc_fd{-1};

using OpenFn = int (*)(const char *, int, mode_t);
using OpenatFn = int (*)(int, const char *, int, mode_t);
OpenFn g_open = nullptr;
OpenatFn g_openat = nullptr;

bool is_udc_path(const char *path) {
    return path != nullptr && strcmp(path, kUdcPath) == 0;
}

int hooked_open(const char *path, int flags, mode_t mode) {
    int fd = g_open(path, flags, mode);

    if (fd >= 0 && is_udc_path(path))
        g_udc_fd.store(fd);
    return fd;
}

using CloseFn = int (*)(int);
CloseFn g_close = nullptr;

int hooked_close(int fd) {
    /* A recycled descriptor number must not keep looking like the UDC attribute: the HAL closes it
     * right after each write, and the number is in use by something else microseconds later. */
    if (fd >= 0 && fd == g_udc_fd.load())
        g_udc_fd.store(-1);
    return g_close(fd);
}
int hooked_openat(int dirfd, const char *path, int flags, mode_t mode) {
    int fd = g_openat(dirfd, path, flags, mode);

    if (fd >= 0 && is_udc_path(path))
        g_udc_fd.store(fd);
    return fd;
}

static long long monotonic_ms() {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

bool ask_daemon(bool adb, const char **answer_out) {
    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = 0;
    size_t name_len = strlen(kSocketName);

    if (name_len == 0 || name_len > sizeof(addr.sun_path) - 2) {
        *answer_out = "no name";
        return false;
    }
    memcpy(addr.sun_path + 1, kSocketName, name_len);
    socklen_t len = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;
    const char *request = adb ? "role adb\n" : "role idle\n";
    const size_t request_len = strlen(request);
    const long long deadline = monotonic_ms() + 2200;

    /* A successful connection is not enough. The daemon keeps this request pending while it waits
     * for FUNCTIONFS_UNBIND and replies only after the requested descriptors are on the new ep0.
     * Keep the whole operation below the HAL's 2500 ms callback budget. Every failed connect gets a
     * new socket: AF_UNIX stream sockets have no reusable connected state after connect() fails. */
    for (;;) {
        if (monotonic_ms() >= deadline) {
            *answer_out = "timeout";
            return false;
        }

        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            *answer_out = "socket";
            return false;
        }
        if (connect(fd, reinterpret_cast<struct sockaddr *>(&addr), len) != 0) {
            close(fd);
            long long left = deadline - monotonic_ms();
            if (left <= 0) {
                *answer_out = "no daemon";
                return false;
            }
            usleep((useconds_t)((left < 100 ? left : 100) * 1000));
            continue;
        }

        size_t sent = 0;
        while (sent < request_len) {
            ssize_t n = write(fd, request + sent, request_len - sent);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0) {
                close(fd);
                *answer_out = "write";
                return false;
            }
            sent += (size_t)n;
        }

        char reply[32] = {};
        size_t used = 0;
        bool complete = false;
        while (used < sizeof(reply) - 1 && monotonic_ms() < deadline) {
            long long left = deadline - monotonic_ms();
            struct pollfd pfd = {fd, POLLIN | POLLERR | POLLHUP, 0};
            int rc = poll(&pfd, 1, (int)(left > 2000 ? 2000 : left));

            if (rc < 0 && errno == EINTR)
                continue;
            if (rc <= 0)
                break;
            ssize_t n = read(fd, reply + used, sizeof(reply) - 1 - used);
            if (n <= 0)
                break;
            used += (size_t)n;
            if (memchr(reply, '\n', used) != nullptr) {
                complete = true;
                break;
            }
        }
        close(fd);

        if (complete && strncmp(reply, "ok", 2) == 0) {
            *answer_out = "ok";
            return true;
        }
        if (complete && strncmp(reply, "retry", 5) == 0) {
            /* The old daemon deliberately ended after telling us to retry. Wait for its replacement
             * and issue the role request again within the same HAL deadline. */
            continue;
        }
        *answer_out = used ? "daemon error" : "daemon closed";
        return false;
    }
}

using WriteFn = ssize_t (*)(int, const void *, size_t);
WriteFn g_write = nullptr;

thread_local bool g_in_hook = false;
thread_local const void *g_in_buf = nullptr;
thread_local size_t g_in_count = 0;

/* The framework request is read off the binder wire, because the HAL on this device is an AIDL
 * service built with the NDK backend: it never calls Parcel::enforceInterface, so the parsed-parcel
 * hook that works for C++ services is never reached. libbinder_ndk still goes through
 * IPCThreadState and ioctl(BINDER_WRITE_READ) internally, so that layer is the one place every
 * backend passes through. */
constexpr size_t kFunctionsOffsetFromToken = 84;   /* int32 len + pad4(76 + 2), then the int64 */

/* A parcel may start with the kernel IPC header (strict mode, work source, kHeader - the last of
 * which differs per build: SYST/VNDR/RECO/UNKN), or directly with the interface token. Rather than
 * depend on that magic, the token is located by its own content: the length word is 38, the 38
 * UTF-16 units are the descriptor, and the word after the int64 argument is a binder object (the
 * callback). Those three together identify the argument layout unambiguously at offset 0 or 12. */
bool functions_at(const uint8_t *data, size_t size, size_t token_off, long long *out) {
    const size_t chars = sizeof(kGadgetInterface) - 1;

    if (size < token_off + sizeof(int32_t) + chars * sizeof(char16_t))
        return false;

    int32_t units = 0;

    memcpy(&units, data + token_off, sizeof(units));
    if (units != static_cast<int32_t>(chars))
        return false;
    for (size_t i = 0; i < chars; i++) {
        const uint8_t *c = data + token_off + sizeof(int32_t) + i * sizeof(char16_t);

        if (c[0] != static_cast<uint8_t>(kGadgetInterface[i]) || c[1] != 0)
            return false;
    }

    const size_t at = token_off + kFunctionsOffsetFromToken;

    if (size < at + sizeof(int64_t) + sizeof(uint32_t))
        return false;

    uint32_t next = 0;

    memcpy(&next, data + at + sizeof(int64_t), sizeof(next));
    if (next != static_cast<uint32_t>(BINDER_TYPE_HANDLE) &&
        next != static_cast<uint32_t>(BINDER_TYPE_BINDER))
        return false;
    memcpy(out, data + at, sizeof(*out));
    return true;
}

/* The NDK stub (libs/binder/ndk/ibinder.cpp, ABBinder::onTransact) validates the descriptor with
 * Parcel::checkInterface() before it reads any argument, and that call crosses a library boundary -
 * libbinder_ndk into libbinder - so it is a real PLT call to this exported symbol. (Calling
 * enforceInterface instead would be useless: its callers live inside libbinder and may be inlined.)
 *
 * By the time it returns, the kernel header and the token have been consumed, so the parcel position
 * is exactly at the first argument of setCurrentUsbFunctions: the int64 bitmap. */
constexpr char kParcelCheckInterface[] = "_ZNK7android6Parcel14checkInterfaceEPNS_7IBinderE";
constexpr char kParcelData[] = "_ZNK7android6Parcel4dataEv";
constexpr char kParcelDataSize[] = "_ZNK7android6Parcel8dataSizeEv";
constexpr char kParcelDataPosition[] = "_ZNK7android6Parcel12dataPositionEv";

using CheckFn = bool (*)(const void *, void *);
using DataFn = const uint8_t *(*)(const void *);
using SizeFn = size_t (*)(const void *);
using PosFn = size_t (*)(const void *);
CheckFn g_check = nullptr;
DataFn g_parcel_data = nullptr;
SizeFn g_parcel_size = nullptr;
PosFn g_parcel_pos = nullptr;

/* The HAL is built with BTI, and the patched prologue reaches this function through an indirect
 * branch: without a landing pad the CPU raises ILL_ILLOPC and the whole gadget HAL dies. Asking
 * for it per function is not redundant with -mbranch-protection: clang only emits bti for
 * functions it can prove are called indirectly, and this one is reached through a void* cast. */
bool hooked_check_interface(const void *self, void *binder) {
    const bool ok = g_check(self, binder);

    /* Parcel::checkInterface() returns bool, unlike status_t APIs: true means the interface
     * was accepted. Preserve that ABI and never inspect a rejected transaction. */
    if (ok && g_parcel_data != nullptr && g_parcel_pos != nullptr) {
        const uint8_t *base = g_parcel_data(self);
        const size_t pos = g_parcel_pos(self);
        long long functions = 0;

        /* The token that was just consumed ends at pos and is kFunctionsOffsetFromToken bytes long,
         * so it starts at pos - that. functions_at() then checks the descriptor, the layout and the
         * callback object before the value is believed. */
        const size_t total = g_parcel_size != nullptr ? g_parcel_size(self) : 0;

        if (base != nullptr && pos >= kFunctionsOffsetFromToken && total > pos &&
            functions_at(base, total, pos - kFunctionsOffsetFromToken, &functions)) {
            g_requested_functions.store(functions);
        }
    }
    return ok;
}

ssize_t hooked_write(int fd, const void *buf, size_t count) {
    /* A second entry into the hook means the original we saved goes through a patched table
     * again; answer that with the syscall itself instead of recursing. */
    if (g_in_hook)
        return syscall(SYS_write, fd, buf, count);
    g_in_hook = true;
    g_in_buf = buf;
    g_in_count = count;

    /* Only the bind itself is worth waiting for: "none" is the HAL taking the gadget down, and the
     * daemon already learns about that from FUNCTIONFS_UNBIND. */
    if (buf != nullptr && count > 0 && fd == g_udc_fd.load() &&
        !is_none_write(static_cast<const char *>(buf), count)) {
        const long long want = g_requested_functions.load();
        /* Nothing parsed yet means "let the platform serve": the endpoint-less idle set, which is
         * also what this daemon arms at boot. Staying silent instead - what an earlier version did -
         * left the daemon with no instruction at all, so it stayed idle for a reason nobody could
         * see, and no later bind ever corrected it. */
        const bool platform = want < 0 || ((want & kGadgetFunctionAdb) != 0);
        const char *answer = "";

        if (!ask_daemon(!platform, &answer)) {
            __android_log_print(ANDROID_LOG_WARN, LOG_TAG,
                                "daemon did not prepare the %s set (%s); letting the platform bind",
                                platform ? "idle" : "adb", answer);
        }
    }

    ssize_t r = g_write(fd, buf, count);

    g_in_hook = false;
    return r;
}

/* The binder driver is read with ioctl(BINDER_WRITE_READ, &binder_write_read) in this very process;
 * the kernel fills read_buffer with the command stream and sets read_consumed. The original runs
 * first - the buffer is only meaningful once it has returned - and then the stream is inspected. */
/* bionic declares ioctl() as int ioctl(int, int, ...): the request is a 32-bit int, not an
 * unsigned long, so it is taken as one here (an unsigned long parameter would carry whatever the
 * caller left in the upper half of the register) and compared 32 bits wide. */



/* PLT hooking, not inline: a PLT entry is data (the library's GOT), so nothing has to be made
 * executable and the process needs no execmem rule at all.  Every loaded object that imports
 * ioctl(), write(), open() or openat() gets its entry pointed at us; the first original we get back
 * is a working path to the real function for the handler to call. */
int hook_one_library(struct dl_phdr_info *info, size_t, void *data) {
    auto *ctx = static_cast<const ZygiskNextAPI **>(data);
    const ZygiskNextAPI *api = *ctx;

    /* Every object is attempted; the first successful original is the one kept. Patching only the
     * first library that imports the symbol left the real call sites (libbase for write/open,
     * libbinder for ioctl) unhooked whenever the executable or liblog was seen first. */
    void *fn = nullptr;

    if (api->pltHook(reinterpret_cast<void *>(info->dlpi_addr), "write",
                     reinterpret_cast<void *>(hooked_write), &fn) == ZN_SUCCESS &&
        fn != nullptr && g_write == nullptr)
        g_write = reinterpret_cast<WriteFn>(fn);
    fn = nullptr;
    if (api->pltHook(reinterpret_cast<void *>(info->dlpi_addr), "open",
                     reinterpret_cast<void *>(hooked_open), &fn) == ZN_SUCCESS &&
        fn != nullptr && g_open == nullptr)
        g_open = reinterpret_cast<OpenFn>(fn);
    fn = nullptr;
    if (api->pltHook(reinterpret_cast<void *>(info->dlpi_addr), "openat",
                     reinterpret_cast<void *>(hooked_openat), &fn) == ZN_SUCCESS &&
        fn != nullptr && g_openat == nullptr)
        g_openat = reinterpret_cast<OpenatFn>(fn);
    fn = nullptr;
    if (api->pltHook(reinterpret_cast<void *>(info->dlpi_addr), kParcelCheckInterface,
                     reinterpret_cast<void *>(hooked_check_interface), &fn) == ZN_SUCCESS &&
        fn != nullptr && g_check == nullptr)
        g_check = reinterpret_cast<CheckFn>(fn);
    fn = nullptr;
    if (api->pltHook(reinterpret_cast<void *>(info->dlpi_addr), "close",
                     reinterpret_cast<void *>(hooked_close), &fn) == ZN_SUCCESS &&
        fn != nullptr && g_close == nullptr)
        g_close = reinterpret_cast<CloseFn>(fn);
    return 0;   /* every object */
}

void on_module_loaded(void *self, const ZygiskNextAPI *api) {
    (void)self;

    dl_iterate_phdr(hook_one_library, &api);
    if (g_write == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                            "no library in this process imports write(); not hooking");
        return;
    }
    /* Where libbinder has already parsed everything: Parcel::checkInterface() is the descriptor
     * check libbinder_ndk performs before reading any argument. It is a cross-library call, so it is
     * reached through a PLT entry - a PLT hook cannot corrupt the HAL's code, which an inline hook
     * here did (ILL_ILLOPC, HAL dead, no adb for anyone). */
    {
        ZnSymbolResolver *resolver = api->newSymbolResolver("libbinder.so", nullptr);
        void *data_addr = nullptr;
        void *size_addr = nullptr;
        void *pos_addr = nullptr;

        if (resolver != nullptr) {
            data_addr = api->symbolLookup(resolver, kParcelData, false, nullptr);
            size_addr = api->symbolLookup(resolver, kParcelDataSize, false, nullptr);
            pos_addr = api->symbolLookup(resolver, kParcelDataPosition, false, nullptr);
            api->freeSymbolResolver(resolver);
        }
        if (data_addr == nullptr || size_addr == nullptr || pos_addr == nullptr) {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                                "libbinder parcel accessors not found: data=%p size=%p pos=%p",
                                data_addr, size_addr, pos_addr);
            return;
        }
        g_parcel_data = reinterpret_cast<DataFn>(data_addr);
        g_parcel_size = reinterpret_cast<SizeFn>(size_addr);
        g_parcel_pos = reinterpret_cast<PosFn>(pos_addr);
    }
    if (g_check == nullptr)
        __android_log_print(ANDROID_LOG_WARN, LOG_TAG,
                            "no library imports Parcel::checkInterface(); nothing to hook");
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
                        "hooked Parcel::checkInterface() through the PLT; setCurrentUsbFunctions is"
                        " read after the token was consumed");
}

}  // namespace

extern "C" __attribute__((visibility("default"), unused)) ZygiskNextModule zn_module = {
        ZYGISK_NEXT_API_VERSION,
        on_module_loaded,
};
