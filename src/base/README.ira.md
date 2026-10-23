# Selected Android base library

Copied from AOSP `system/core/libbase`. Original Apache-2.0 notices are retained in
NOTICE and each file. Only the production sources listed in CMakeLists.txt and the
headers actually required by the Android and host targets are kept. Upstream tests,
fuzzers, benchmarks and unused platform implementations have been removed.

logging.cpp directly selects Android liblog APIs on Android31+ and the existing
StderrLogger/host state on Linux host builds. No compiler builtin is overridden and
no liblog symbols are reimplemented. IRA-specific changes are AGPL-3.0-or-later;
the imported library retains its original terms.
