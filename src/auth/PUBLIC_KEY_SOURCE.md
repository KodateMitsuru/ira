# Android RSA public-key decoder provenance

Source: [AOSP system/core libcrypto_utils](https://android.googlesource.com/platform/system/core/+/545d2487e38192a2ce25040897ced877cf6b4f53/libcrypto_utils/android_pubkey.cpp)
Revision: `545d2487e38192a2ce25040897ced877cf6b4f53` (android17-release).
Input paths: `libcrypto_utils/android_pubkey.cpp` and `libcrypto_utils/include/crypto_utils/android_pubkey.h`.

This code decodes the 524-byte Android ADB public-key blob: modulus size, Montgomery fields,
little-endian RSA modulus and exponent. It uses BoringSSL BIGNUM/RSA APIs; it does not
implement a hash or RSA algorithm. The unused public-key encoder has been deleted.
Original Apache-2.0 headers remain, with IRA contribution notices added separately.

Original upstream SHA-256 (before encoder removal/local notices):

```
31068871b013c250c8cc3595560d415cdc4256c8bda4c9c2401d93835b86a9c5  android_pubkey.cpp
5e04b026c14f0fe94e2403008a1819dd9796b0afffef5ceef953411f1bee66a0  include/crypto_utils/android_pubkey.h
```
