# USB authorization core

Copied from AOSP `platform/frameworks/native`, revision
`ae266dcb706d083868578cfedce381ef44488a07`:
`libs/adbd_auth/adbd_auth.cpp`, `adbd_auth_internal.h`, `include/adbd_auth.h`.
Original Apache-2.0 copyright/licence headers are retained; IRA-specific changes are AGPL-3.0-or-later.

The source is adapted directly: a caller-owned private SOCK_SEQPACKET listener is mandatory,
with ownership transferred to the context. System `adbd` socket discovery, version factories,
WiFi/TLS/mDNS lifecycle, service registration and no-op virtual hooks have been removed.
USB prompt serialization, key enumeration, OK/NO and DD processing, CK/DC notifications,
epoll/eventfd handling and pending queues retain the upstream implementation.

IRA wakes CK/DC queue changes with Interrupt() after the existing notification methods.
`tests/test_upstream_auth.cpp` exercises the retained implementation directly over sockets.
`CMakeLists.txt` in this directory builds the auth library and Android public-key decoder.

Original upstream SHA-256 (before pruning/local notices):

```
a402c02b311bec653527d0f49a216a255dbbeecbb5247ff737916b64f3458979  adbd_auth.cpp
5f9a1e0c2e6e8f0467e57965f6f1a43b5fc79d44bd744a0d0267a0d5ffd50283  adbd_auth_internal.h
339611df286455c8ee51a2c9d65b8eb061dbe8791ea62b8d5db6d93a8552dbce  include/adbd_auth.h
```
