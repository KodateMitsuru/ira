# Licensing and source provenance

IRA-owned source, tests, scripts and build definitions use `AGPL-3.0-or-later`.
The root LICENSE contains the complete AGPLv3 text. File headers mark project code
explicitly; imported files keep their original copyright and licence text.

| Source | Retained upstream terms | IRA treatment |
| --- | --- | --- |
| `src/adb`, `src/base`, `src/auth` | Apache-2.0 | Selected sources are copied into the relevant targets. Local contributions are AGPL; upstream notices remain. |
| `vendor/boringssl` | Apache-2.0 and retained third-party notices | Authorization dependency closure only; upstream internal sources compile separately without algorithm rewrites. Build metadata and local selection changes are AGPL; upstream notices are preserved. |
| `src/mksh` | MirOS/BSD-like and original per-file terms | Terminal changes and build integration are AGPL. Original notices stay in source and NOTICE. |
| Magisk-derived su portions | GPL-3.0-only | Original GPL portions remain GPL. IRA additions are AGPL; the combined work uses the section 13 permissions in GPLv3 and AGPLv3. |
| `src/zygisk/api/zygisk.hpp` | ISC-style permission in the header | Unchanged API header; no replacement licence. |
| `src/zygisk/zygisk_next_api.h` | No licence file published upstream | Preserved interface declaration; no claim of relicensing upstream material. |

Applying AGPL to IRA contributions does not erase the Apache, MirOS, BSD, ISC or GPL
conditions attached to imported portions. GPL-only material is not relabelled AGPL;
its combination with AGPL code is described explicitly. The module ZIP carries the
project licence, GPLv3 text, Apache notice, BoringSSL licence and mksh notice.

Component provenance records are next to the copied code. Their original hashes
identify the upstream inputs, not the deliberately trimmed current files. No update
script overwrites the adapted code with a full upstream library.
