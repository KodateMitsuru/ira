# BoringSSL authorization source subset

Source: https://github.com/google/boringssl
Revision: `90c6b370770adce64ff435789bfd1940067df415`
Original archive SHA-256: `fa2e423df7e2031e82d71ad7f3ab7dc663b0275ecd80fb507df8fac8fb45c817`

NDK r30 has no public `openssl/*.h` headers or linkable `libcrypto`. IRA therefore builds
this source subset for Linux/Android ARM64 and Linux x86_64. Other native libraries and
public Android/JNI headers come directly from the selected NDK.

This directory supplies the APIs actually used by IRA authorization, not a general-purpose
libcrypto. `Sources.cmake` retains 53 original C++/assembly inputs: the union of live source
members in Android ARM64 and Linux x86_64 daemon link maps. It includes Base64, RSA public-key
verification, BIGNUM, RAND_bytes, AES-CTR DRBG, entropy/fork detection, threading, allocation,
error handling and the required architecture assembly. Headers follow actual compiler dependencies.

The upstream `bcm.cc` unity source is omitted. Its required `.cc.inc` files compile directly as
independent C++ units. Function/data sections and linker garbage collection are required because
retained upstream units contain additional uncalled API functions. Both Release/RelWithDebInfo
and Debug host builds are checked; crypto code is not rewritten or replaced with stubs.

SHA-1/SHA-2 implementations, EC/ECDH/ECDSA, X509, ASN.1/PEM, symmetric modes outside the
required RNG support, post-quantum algorithms, SSL, PKI, tools, generators and upstream tests
are omitted. SHA-1 is only the PKCS#1 digest identifier for the supplied 20-byte ADB token;
RSA_verify does not hash it again. AES remains necessary inside the upstream random generator.

Local header/source selection edits remove unused prefix-symbol and unsupported platform
include alternatives. Original copyright and licence notices remain; IRA local contributions
and build metadata are marked separately as AGPL-3.0-or-later. See LICENSE for upstream terms.

Validation covers Android payload/probe builds, all host CTest suites, independent OpenSSL
signature fixtures, production auth key parsing/verification, RAND initialization and parent/child
random-stream separation after fork. These checks do not constitute FIPS validation or real-device
acceptance of a newly built package.
