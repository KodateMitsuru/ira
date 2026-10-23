# KSU root default and package installation

Both module launch paths execute `module/start-daemon.sh`. It queries the live kernel feature
through `ksud feature get adb_root` before starting the frontend. A numeric nonzero `Value:`
selects root; zero, unsupported features, malformed output, a missing CLI or a failed/timed-out
query select shell. The query has a one-second deadline and a one-second forced-termination grace.
It never changes KSU settings or `service.adb.root`.

The launcher passes `--ira-root-default root|shell` to the frontend. `adb root` / `adb unroot`
then select the corresponding backend for newly opened services. Existing commands retain their
original identity, including a package installation already in progress. A replacement frontend
reads the current KSU default again. Live KSU toggles do not override an explicit adb command in
a running frontend.

Reference behavior: KernelSU's `manager/app/src/main/cpp/adbroot.cc` makes the system adbd see
`service.adb.root=1` and avoids privilege dropping when the adbroot feature loads that library.
IRA uses the live feature as an input to its own service mode; it does not preload that library.
The CLI query also matches current official KernelSU `userspace/ksud/src/feature.rs` output
(`Value:` plus enabled/disabled status), including boot-config-forced feature values.

References:
- https://github.com/tiann/KernelSU/blob/main/manager/app/src/main/cpp/adbroot.cc
- https://github.com/tiann/KernelSU/blob/main/userspace/ksud/src/feature.rs

## Why root installs can still require USB-install confirmation

An Android package installation is a Binder request to system_server, usually via `abb`/`cmd`.
IRA starts abb inside the selected root or shell backend. AOSP's abb calls cmdMain and preserves
its process identity; it does not independently convert root to shell. Root and shell backends
have separate abb instances.

In AOSP Android 16 `PackageInstallerService.createSessionInternal`, `isRootOrShell(callingUid)`
sets `INSTALL_FROM_ADB` and uses the shell installer package identity. Both UID 0 and UID 2000
therefore count as ADB installations. Root alone does not remove vendor USB-install confirmation
or package verification. The same applies to an `adb install -r` replacement session.

Source: https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-release/services/core/java/com/android/server/pm/PackageInstallerService.java

A waiting host may be waiting for user confirmation, verifier completion or a package-manager
operation. That is distinct from abb failing to start or returning a service FD. The appropriate
fix depends on the active session and system_server log; changing default root cannot resolve
those waits by itself. This implementation does not change verification settings or impersonate
a system-service UID.

## Capture a waiting installation

Keep the waiting host command open and use a second authorized connection to capture:

```sh
adb shell id
adb shell su -c sh < scripts/install-diag.sh > build/install-diag.txt
```

The read-only script records KSU state, frontend/backend/abb real/effective UIDs and domains,
active install sessions, verifier settings, bounded package-manager log and IRA's service log.
The dumpsys and feature queries have deadlines. Inspect whether the abb PID is UID 0, the
session is awaiting user action, or the verifier reports a timeout before changing behavior.
Do not treat root mode as evidence that the installed package bypasses the ROM's installation policy.
