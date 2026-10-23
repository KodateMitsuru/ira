# Upstream-backed adbd services

## Ownership boundary

`ira-daemon` keeps only USB/FunctionFS, libadb transport ownership, the private framework auth
adapter, and the privileged su endpoint in its frontend. FunctionFS is still mounted by a short-lived
bootstrap thread and pinned through a directory fd; no service inherits a frozen mount namespace.

Actual shell/exec/sync/dev services run in a separate invocation of the same executable:
`--ira-services root|shell`. The frontend uses a private inherited `SOCK_SEQPACKET` socketpair,
not a filesystem or TCP listener, and receives opened service/listener fds with `SCM_RIGHTS`.
Root and nonroot backends are distinct processes. No thread-local credential mutation, metadata
RPC helper executable, or second implementation of sync is used.

The backend preopens the module shell, then uses Android's actual minijail to set supplementary
groups, uid/gid and capabilities. Nonroot workers use the adbd domain; the shell's normal
`shell_exec` transition supplies its shell domain. A failed API resolution or transition refuses
the service; it never continues with frontend/root credentials. The child and raw-session lifetime
adapters reset ignored daemon signals and preserve upstream hangup semantics without a PTY.
The raw watcher does not relay data, so both binary bytes and abb's ancillary fd passing remain intact.

Root/unroot select the backend for subsequent service opens. They do not bounce USB, change system
ADB properties, or secretly mutate an already-running command's credentials. This preserves IRA's
explicit per-session root design while applying it consistently to sync, dev and forwarding too.

## Reused Android policy and source

The device daemon dynamically links bionic/libdl, with C++ kept self-contained. A small ABI adapter
in `src/adb/ira_platform.cpp` delegates to the device's:

- `libcutils.so`: all Unix namespace handling and network helper calls;
- `libselinux.so`: `selinux_android_setcon` and `selinux_android_restorecon`;
- `libadbd_fs.so`: modern `adbd_fs_config`, including valid false/preserve decisions;
- `libcutils.so` `fs_config`: the legacy fallback when that release has no libadbd_fs hook;
- `libminijail.so` and `libcap.so`: the original process-level credential and capability model.

Missing required APIs are errors, not no-op policy shims. This restores the platform call contract;
restorecon can still legitimately fail on a filesystem that does not support labels, as in real adbd.
Platform private-library loading and real SELinux transitions require actual-device acceptance.
Host fixtures test argument/return forwarding, not Android's policy contents.

`src/auth` retains the USB authorization implementation copied from AOSP frameworks/native
revision `ae266dcb706d083868578cfedce381ef44488a07`. Its constructor requires a private listener fd.
System socket discovery, WiFi/TLS/mDNS packets, version factories and unused virtual hooks are deleted
from the source. Prompt queuing, key enumeration, OK/NO, DD and CK/DC retain the upstream implementation.
IRA callbacks resolve libadb weak transport references on the looper, reject stale connection IDs and
close revoked services. `Interrupt()` wakes CK/DC messages after notification methods enqueue them.
The same target also compiles the Android public-key decoder copied from AOSP system/core; its unused
encoder has been removed. Component provenance and original hashes are beside the source.

Framework Java is only the private-channel adapter: PK requests use the actual Handler dialog,
CK/DC use the Handler's runtime message constants, and directory notifications on the real
`adb_keys` report DD changes. The old stream/newline request parser is gone. The reply-thread slot
is borrowed only during the corresponding synchronous allow/deny dispatch on that Handler's looper,
not while waiting for user input. A platform prompt has priority; timeouts and late replies never
borrow the platform response slot.

The TCP primitives in `src/adb/sysdeps/posix/network.cpp` derive from AOSP adb revision
`9084198a2d4b0f6a0f174260fb42da33485b684d`, with direct standard-header dependencies and local
contribution notices retained. These primitives service explicit forward/reverse requests only: TCP adbd, wireless
pairing, Wi-Fi discovery and mDNS are not started. Unimplemented app tracker capabilities are no
longer advertised. No terminal implementation is classified as a defect merely for not using a PTY.

## Private endpoints and how they are named

Three abstract sockets exist, one per role, and none of them is a constant: `ctl` (the gadget HAL
hook asks for a descriptor set), `auth` (upstream libadbd_auth's private channel) and `su` (the
root broker). `customize.sh` generates a separate 64-bit random base for each and writes `names`
in the module root (never in `state/`, which is runtime only):

    ctl=3f1c...b6.ctl
    auth=7bb1...61.auth
    su=8317...7f.su

The suffix is the role, so a log line names what was dialled; the bases are independent, so
learning one endpoint does not reveal the others. The daemon reads the file once
(`src/adb/ira_names.cpp`) and refuses to start an endpoint whose name is missing - there is no
fallback constant to probe for.

## SELinux rules

`module/sepolicy.rule` ships as a comment-only placeholder. The installer rewrites it in full from
two domains it reads on the device: the running USB gadget service and its own (the root manager's)
domain. Nothing device-specific is hardcoded, and if either domain cannot be read the installer
aborts rather than falling back to a name copied from another phone.

Only rules whose source is a restricted domain are written:

    allow <gadget> <root> unix_stream_socket { connectto read write }
    allow <gadget> <gadget> process execmem
    allow system_server <root> unix_stream_socket { connectto read write }
    allow adbd <root> unix_stream_socket { read write }
    allow adbd shell process2 nosuid_transition

These are KernelSU policy statements, not `.te` source. The installer checks each statement with
`ksud sepolicy check` when available and aborts on rejection. The final rule permits the private
`shell_exec` inode on the nosuid `/data` mount to enter the shell domain during exec.

The root domain is unrestricted, so rules *from* it are dead weight and are not emitted; neither
are `fd use`, TCP or signal rules. A pre-opened fd could only replace the `su` endpoint, and even
that would trade its `connectto` rule for fd-use rules across the same boundary while needing a
session-dispatch protocol, so the endpoint stays a socket. `ctl` and `auth` cannot use fds at all:
the gadget HAL and system_server are not started by this daemon, so there is no way to hand them
one.

The two injected images cannot read `/data/adb` (system_server and the gadget HAL have no policy
for it). The HAL image carries `ctl`; the framework image carries independent `auth` and `ctl`
names, written by the installer. The images hold a
fixed-length token (`IRA-SOCKET-NAME-` plus zeros) in a 33-byte array; the installer finds it with
a byte-oriented search that busybox can run (`od -An -v -tx1 | tr -d ' \n'`, then the offset in
the hex text), rewrites it as name plus NUL padding, reads it back, and requires the token to be gone.
It refuses an image with zero or several tokens, and a random-source failure aborts before any
image is touched. No offsets are computed at build time and none are shipped, so a rebuilt image
cannot silently carry a stale offset.

The mksh image needs no install-time name patch: the daemon publishes the `su` name in
`IRA_SU_SOCKET` for the session shell it starts, and the shell's builtin dials that. the native `ira-shell` CMake target checks the built image for `IRA_SU_SOCKET` and rejects
a shell that still contains `ira.su`.

## Reproducible checks

`cmake --build build --target check` includes:

- the retained libadbd_auth USB core: PK serialization, NO/OK, CK/DC, DD, callback identities and no
  use of the system auth listener;
- the production backend under mapped root/shell UIDs, kernel-enforced direct-file permissions,
  descriptor ownership/CLOEXEC, and fail-closed startup;
- complete production services under the explicit host policy fixture: shell_v2, raw EOF,
  ancillary-fd passing, root/nonroot sync/dev/listeners, and child exit on disconnect;
- modern/legacy/missing platform API forwarding and BoringSSL/AOSP Android key verification;
- the packaged ARM64 mksh's signal behavior under QEMU;
- Handler callback chaining, runtime ClassLoader binding, platform prompt races, stale replies,
  timeout cancellation, and the existing FunctionFS lifecycle/namespace suites.

Host fixture tests never claim to validate real SELinux permissions.
`cmake --build build --target platform-device-probe` builds `tests/test_platform_device.cpp`
as `build/android/bin/platform-device-probe`, a non-USB device probe for actual library metadata, restorecon NOCHANGE, Unix filesystem
sockets and backend service identities; it does not mount FunctionFS or change ADB settings.

Device acceptance must identify the IRA endpoint rather than use a system-adbd connection as
proof. Full revocation has been observed to rebuild descriptors, restore UDC and complete a new
CNXN/AUTH handshake within the same daemon. Private-library compatibility, SELinux rules and
UI rendering still require validation on each target device. The shell and both injected
components should be installed together through the module manager and activated by reboot.

Key-file scans and ordered replies run off the ADB Handler. Full revoke delivery uses a separate
retrying ctl client; Android LocalSocket options are set after connect creates the native fd.
Pending prompt timeouts are removed on completion/cancellation. Per-stage logs distinguish
Handler queue time, framework dispatch and socket writes without claiming to measure SystemUI frames.
