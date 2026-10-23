# IRA device-side ADB core

This is a selected AOSP packages/modules/adb device source tree. The standalone host ADB client,
wireless discovery/pairing, TLS implementation, platform USB daemon and upstream build/test
harnesses are omitted. IRA owns the FunctionFS transport and authorization adapter; shell,
sync, abb, framing and socket services reuse the selected AOSP implementation.

`CMakeLists.txt` in this directory owns the single source manifest and targets for Android,
host integration tests and the device probe. `src/CMakeLists.txt` connects base/auth/crypto
libraries. See the repository `docs/build.md` for commands.

Authentication uses BoringSSL RAND_bytes, EVP_DecodeBase64 and RSA_verify, with AOSP
the decoder in `src/auth` for the Android public-key format and the directly trimmed
libadbd_auth core for USB key/prompt lifecycle. ADB signs the 20-byte token as a SHA-1 digest; it does not hash that token again.
There are no local SHA/RSA algorithms or placeholder OpenSSL headers.

Android logging links the NDK liblog; AdbLogger selects stderr. Host logging uses the adapted
upstream implementation in `src/base/logging.cpp`. Device policy and credential operations
resolve the real platform libraries in `ira_platform.cpp`.

Upstream code retains its Apache-2.0 notices. IRA files and local changes retain their individual
license headers; project attribution is in the root NOTICE.
