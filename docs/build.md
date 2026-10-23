# Build and validation

## Requirements

- Android NDK with ARM64 API 31 support. Daemon, mksh and hooks share this toolchain and API.
- Android SDK with a platform `android.jar` and build-tools `d8`.
- CMake 3.22+, Ninja or Make, JDK 17+, Python 3, bash and host clang/clang++.
- Host checks use OpenSSL CLI for independent crypto fixtures, mapped subordinate UIDs,
  mount namespaces and QEMU ARM64 user-mode execution. Namespace suites report a skip if
  those facilities are unavailable; the shell signal test requires QEMU.

Defaults are `/opt/android-ndk` and `/opt/android-sdk`. Set `IRA_NDK` / `ANDROID_NDK_HOME`
and `IRA_SDK` / `ANDROID_SDK_ROOT` to override. `IRA_ANDROID_API` defaults to 31 for all payloads.

## Build

```sh
cmake -S . -B build -G Ninja -DIRA_NDK=/opt/android-ndk
cmake --build build --target module -j2
cmake --build build --target check -j2
```

All compilation belongs to CMake. The top-level project configures Android and host CMake
sub-builds through `src/CMakeLists.txt`; `src/adb/CMakeLists.txt` owns the daemon source
list used by both.
`ira-daemon`, `ira-shell`, `ira-hooks`, `platform-device-probe`, `module` and `check` are the
public targets. The payload targets share the Android sub-build. mksh is compiled directly
from its 16 C source files using the Android definitions in `src/mksh/CMakeLists.txt`.
Its table generator lives beside the target at `src/mksh/options.py`. Hooks and Java embedding
are owned by `src/zygisk/CMakeLists.txt`; auth/base are built in their respective source directories.
There is no shell configure/build script or separate compiler wrapper.

Only the BoringSSL crypto subset remains under `vendor/boringssl`; its own `CMakeLists.txt`
and explicit source list build the `crypto` target directly. SSL/PKI/tool/test sources and
unused headers are removed. `src/auth` owns the trimmed AOSP authorization core and Android
public-key decoder. NDK libc/libdl/liblog/libc++ and Android/JNI headers are used directly;
NDK r30 provides neither public OpenSSL headers nor `libcrypto`, so crypto remains vendored.
The OpenSSL CLI generates independent host test fixtures and is not linked into the payload.

Artifacts are under the selected binary directory:

- `android/bin/ira-daemon`, `android/bin/mksh`, `android/bin/platform-device-probe`;
- `android/lib/ira-zn.so`, `android/zygisk/arm64-v8a.so`, `android/payload/ira_dex.h`;
- `host/bin/` and `host/tests/work/` for host binaries and runtime fixtures;
- `stage/` and `dist/ira-<version>.zip` for the module package.

Source, Java and CMake dependencies rebuild through their native target dependencies. Hook
endpoint-name invariants and shell endpoint configuration are checked on the built images.
Alternate binary directories work without generating files in `src/`.

The ZIP contains boot scripts, initrc, daemon, mksh, hooks, errno probe and license notices.
Version metadata uses the nearest Git version tag and current hash, adding a dirty suffix when
needed; exported source uses `module/module.prop` as a fallback.

## Validation

`check` builds the Android payload and host tests, then runs CTest. Tests cover wire-format
crypto, upstream auth lifecycle, FunctionFS descriptors and recovery, backend credentials,
service integration, framework routing, hook ABI, installer policy and absence of PTY imports.
The packaged ARM64 mksh's signal behavior runs through QEMU. Fixtures and generated Java
classes remain in the binary directory. Run a focused test with:

```sh
ctest --test-dir build/host -R auth_crypto --output-on-failure
```

Host fixtures do not validate actual device SELinux or USB controller behavior.

## Installation

```sh
adb push build/dist/ira-<version>.zip /sdcard/ira.zip
adb shell su -c 'ksud module install /sdcard/ira.zip'
```

Reboot to activate. `scripts/device-handover.sh` uses the same ZIP install path. The installer
generates independent endpoint names, discovers gadget/root domains and checks each generated
policy statement with `ksud sepolicy check` when available.

## Device diagnostics

`scripts/device-diag.sh` reads USB state, installed hashes and daemon logs. Build
`platform-device-probe` for a non-USB probe of actual Android APIs and backend identities.
`scripts/audit-adbd.py` captures behavior for an explicitly selected device identity.
The packaged `errno_profile.sh` compares path/error profiles before and after activation.
