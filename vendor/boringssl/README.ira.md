# BoringSSL crypto source subset

Source: https://github.com/google/boringssl
Revision: `90c6b370770adce64ff435789bfd1940067df415`
Original archive SHA-256: `fa2e423df7e2031e82d71ad7f3ab7dc663b0275ecd80fb507df8fac8fb45c817`

The selected NDK r30 has neither public `openssl/*.h` headers nor a linkable `libcrypto`.
IRA therefore compiles the required upstream crypto sources directly using this directory's
`CMakeLists.txt` and explicit `Sources.cmake`. NDK-supplied libc/libdl/liblog/libc++ and public
Android/JNI headers are used directly; none are duplicated here.

Retained sources cover the upstream crypto target for Linux/Android ARM64 and Linux x86_64,
including architecture assembly and observed/transitive implementation includes. SSL, PKI,
CLI tools, test corpora, fuzzers, Rust, generators and other platforms are omitted. Translation
units empty in both supported builds are deleted. Unused public/private headers are removed.

Local source edits remove prefix-symbol includes and 32-bit/MSVC Fiat include alternatives;
both supported builds use the same existing uint128/64-bit implementations. No crypto algorithm
is reimplemented. Original copyright and licence notices remain; local edits/build metadata
are marked as IRA AGPL-3.0-or-later contributions. See LICENSE for upstream/third-party terms.
