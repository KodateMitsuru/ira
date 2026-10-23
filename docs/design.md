# Runtime design

## USB ownership

IRA adds `ffs.ira` to the existing configfs gadget before its first bind. It does not create a
separate gadget or kernel driver. A short-lived bootstrap thread mounts FunctionFS privately and
returns a directory fd. The frontend and service backends retain init's mount namespace so late
storage mounts remain visible.

A ZygiskNext library in the USB gadget HAL observes requested functions and coordinates descriptor
readiness before the HAL writes UDC. IRA presents `ff/42/01` with two bulk endpoints when it owns
ADB, and `ff/00/00` without endpoints while system `ffs.adb` carries ADB. Startup defaults to idle
until a role request arrives. Ordinary role changes leave the final UDC write to the platform.

Two pumps connect bulk transfers to an AOSP transport socketpair. A session generation prevents
old bytes from reaching a new transport. DISABLE/UNBIND retire the old transport once. Descriptor
replacement quiesces both pumps and closes all epfile references, including the ep0 watcher.

Authorization revocation is the explicit USB-reset exception: it saves the role/controller, pulls
UDC down, recreates descriptors and restores the original binding. Failed re-arms hand recovery
to the supervisor's replacement process. See [FunctionFS lifecycle](functionfs.md).

## Services and credentials

The root frontend owns FunctionFS, authorization and a private su broker. Separate invocations
of the same binary serve `--ira-services root|shell`, communicating through inherited seqpacket
socketpairs and SCM_RIGHTS. Android minijail and libcap set process-wide identities before service
threads start. Required platform API failures refuse startup.

All shell modes execute the same preopened mksh inode. Its `shell_exec` label supplies the normal
`adbd → shell` transition; the module grants `nosuid_transition` because it lives under `/data`.
The shell implements terminal editing over sockets and a built-in su client; no PTY is allocated.
KSU's current `adb_root` feature determines the default credentials at frontend start.
Root/unroot choose credentials for later service opens without bouncing USB or altering
credentials of existing commands. Each replacement frontend reads the KSU default again.

The service set includes shell/exec, sync, abb and explicit forwarding. Wireless pairing, mDNS,
TCP ADB, framebuffer and app tracking are not started or advertised. See
[Android integration](adbd-upstream-reuse.md) for the reused implementations.

## Framework authorization

A Zygisk module embeds a Java payload in system_server. It uses the existing ADB Handler and
confirmation Activity while keeping a separate libadbd_auth connection. The platform response
thread slot is borrowed only during an IRA allow/deny dispatch and restored before the next
message. Platform prompts take priority; stale and timed-out answers do not borrow the slot.

File notifications report removed keys. Key scanning and auth writes run on an ordered worker;
full revocation uses a separate retrying control client. Logs distinguish Handler queuing,
framework dispatch and reply write time. The platform still owns SystemUI rendering and animations.

## App-visible boundary

The intended observer is an ordinary untrusted app. No module-specific kernel object, public
device node, TCP ADB listener or wireless advertisement is introduced. Configfs objects remain
under the platform's protected mount; endpoint files exist only in the private FunctionFS mount.
IRA does not write global ADB settings or system ADB properties.

The `ctl`, `auth` and `su` abstract socket names each use an independent per-install random base.
The root-only `names` file and injected images hold the names; missing/invalid names fail closed.
Visibility depends on actual device policy and must be checked with an untrusted-app probe.
This boundary makes no claim about root, shell, USB hosts or other privileged observers.
