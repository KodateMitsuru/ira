# FunctionFS lifecycle

## Mount and descriptor ownership

`module/initrc/ira.rc` creates `functions/ffs.ira` and links it into `configs/b.1` before the UDC
is bound. Configfs refuses adding a function link while `udc_name` is set. The instance suffix
`ira` is also the FunctionFS mount source (`ffs_set_inst_name` / `ffs_acquire_dev`).

Only a bootstrap thread unshares a mount namespace and marks its propagation private. It mounts
FunctionFS over the configfs instance directory and returns an O_CLOEXEC directory fd. Endpoint
opens use `openat()` on that fd; service processes keep the live storage namespace.

Writing the V2 descriptors and then strings moves the kernel through
`FFS_READ_DESCRIPTORS → FFS_READ_STRINGS → FFS_ACTIVE`, creates bulk epfiles and sets descriptor
readiness. Binding a composite before readiness fails with ENODEV. `post-fs-data.sh` waits for
`state/ffs.armed` before returning.

Startup arms idle (`ff/00/00`, no endpoints). The HAL hook records the requested role before its
UDC write: ADB is `ff/42/01` with bulk OUT/IN and packet sizes 64/512/1024 at FS/HS/SS; idle is
51 bytes and carries no endpoints. A descriptor change while bound waits for UNBIND so the HAL
request is not acknowledged before ep0 is ready.

## Closing the last reference matters

`ffs_data_closed()` resets FunctionFS only when its opened-file count reaches zero. In Android
6.1's `drivers/usb/gadget/function/f_fs.c`, `ffs_data_reset()` restores
`FFS_READ_DESCRIPTORS`; in `ffs_ep0_write()`, writing with `FFS_ACTIVE` and `FFS_NO_SETUP` returns
`-ESRCH` (displayed as “No such process”). It does not mean a userspace process could not be found.

The re-arm sequence is:

1. Pause new pump transfers, bump their generation and interrupt/wait for in-flight transfers.
2. Destroy the ep0 watcher, close bulk endpoints, then close ep0.
3. Reopen ep0 and write descriptors/strings; reopen bulk endpoints for the ADB set.
4. Publish the new endpoint generation and install the new ep0 watcher.

The watcher duplicates ep0 with `F_DUPFD_CLOEXEC`. Plain `dup()` leaks ep0 through service backend
exec, pins the old FunctionFS state and prevents re-arm even after the frontend closes its fds.
A fork/exec regression checks that the duplicate disappears in the child.

## Revocation reset and recovery

Full authorization revocation clears active/pending transports, then queues a reset on the
FFS looper. It saves the current role/controller in `state/revoke.resume`, writes UDC `none`,
closes/rebuilds the FunctionFS session and restores the saved controller. This briefly disconnects
the whole composite gadget. Per-key removal closes only matching transports.

If descriptor re-arm fails, the daemon leaves `state/setchange` and exits. The supervisor starts
a clean process, which loads the saved role instead of defaulting to idle. Once descriptors,
transport and ep0 watcher are ready, it restores UDC and consumes the handoff. A bind failure
keeps the handoff for diagnosis/recovery. Initial boot removes stale recovery files.

Unexpected daemon crashes are left down; the supervisor does not loop on arbitrary failures.
Ordinary platform role changes rely on the HAL retry path. `adb root`/`adb unroot` only relink
the transport and select service credentials; they do not reset UDC.

## Checks

- Descriptor parsing validates lengths, interfaces and FS/HS/SS endpoint maps.
- Lifecycle tests cover watcher ownership, actual fork/exec, deferred resets and process-replacement recovery.
- Session tests cover interrupted transfers, reconnect generations and stale data boundaries.
- Namespace tests use real mounts to check live storage inheritance and pinned endpoint reopen.

Host fixtures cannot prove hardware enumeration or device-specific controller timing. On-device
acceptance must check `descriptors rearmed`, `UDC restored`, BIND/ENABLE and a fresh CNXN/AUTH handshake.
