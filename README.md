# ira

IRA serves ADB over USB through a private FunctionFS instance and an AOSP-based daemon. It runs
as a KernelSU module with a Zygisk framework adapter and a ZygiskNext gadget HAL hook. No kernel
module, TCP ADB listener or wireless discovery service is started.

```text
host adb → USB gadget → ffs.ira → libadb transport → service backend → private mksh / sync / abb
                              ↕                    ↕
                       gadget HAL hook       Android policy APIs
                              ↕
                    system_server auth adapter
```

The HAL hook selects an ADB interface when system ADB is disabled and an endpoint-free idle
interface when platform `ffs.adb` owns ADB. Authorization uses Android's existing confirmation
Activity and key store through a private libadbd_auth channel. Revoking authorization closes
tracked sessions and resets the USB session.

## Build

Install an Android NDK, Android SDK platform/build-tools, CMake, a JDK, bash and standard Unix
build tools. No DDK or kernel source is required.

```sh
cmake -S . -B build -DIRA_NDK=/opt/android-ndk
cmake --build build -j2
```

The package is `build/dist/ira-<version>.zip`. Compiler outputs, embedded dex, staging files and
the private shell are generated under the build directory. See [build instructions](docs/build.md).

## Install

```sh
adb push build/dist/ira-<version>.zip /sdcard/ira.zip
adb shell su -c 'ksud module install /sdcard/ira.zip'
```

Reboot through the module manager to activate the update. `scripts/device-handover.sh` performs
the same push/install flow and does not restart the device or switch USB settings.

## Runtime

`post-fs-data.sh` starts the daemon after init creates `ffs.ira`. Only the FunctionFS bootstrap
thread enters a private mount namespace; services retain init's live storage view. Shell and
other services execute in separate root/shell backends with platform minijail credentials.
The session shell is patched mksh with a socket-based terminal and a built-in su client.
At daemon startup the KSU `adb_root` feature selects the default root/shell service mode;
`adb root` and `adb unroot` override it for subsequent services. See
[root defaults and package-install diagnostics](docs/adbroot-install.md).

The supervisor restarts only after an explicit descriptor-change handoff. It leaves an unexpected
crash down. Runtime logs and recovery markers are under `/data/adb/modules/ira/state/`.

## Validation

```sh
cmake --build build --target check
```

The suites cover crypto, upstream auth, descriptor ownership and fork/exec, USB-session recovery,
mount namespaces, service permissions, framework compatibility, routing and installation policy.
Host fixtures do not validate a device's SELinux policy or USB controller. Device validation
should record the active daemon identity; `scripts/audit-adbd.py` provides bounded behavior capture.

[Design](docs/design.md), [FunctionFS lifecycle](docs/functionfs.md) and
[Android service/auth integration](docs/adbd-upstream-reuse.md) describe the active implementation.

## License

Project code is AGPL-3.0-or-later. Imported components retain their licenses and attribution;
see [NOTICE](NOTICE), [LICENSE](LICENSE) and [licensing boundaries](docs/licensing.md).
