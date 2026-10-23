#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# No pty, anywhere: a kernel tty would create a /dev/pts entry, which is a detection surface this
# project must not have. Every session, including a terminal one, runs on a socketpair.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
for pat in posix_openpt unlockpt ptsname_r openpty grantpt TIOCSCTTY TIOCSWINSZ '/dev/pts'; do
    if grep -rn --binary-files=without-match -- "$pat" \
            src/adb 2>/dev/null | grep -v '^Binary'; then
        echo "FAIL: '$pat' found in the daemon sources" >&2
        fail=1
    fi
done

for bin in "${1:?usage: test-no-pty.sh path/to/ira-daemon}"; do
    [ -f "$bin" ] || { echo "FAIL: missing daemon: $bin" >&2; exit 1; }
    for sym in posix_openpt unlockpt ptsname TIOCSCTTY TIOCSWINSZ; do
        if command -v llvm-objdump >/dev/null 2>&1; then
            under=$(llvm-objdump -T "$bin" 2>/dev/null | grep -c "$sym" || true)
        else
            under=$(nm -D "$bin" 2>/dev/null | grep -c "$sym" || true)
        fi
        if [ "${under:-0}" != "0" ]; then
            echo "FAIL: the daemon binary imports $sym" >&2
            fail=1
        fi
    done
done

[ "$fail" = 0 ] && echo "PASS: no pty allocation in the daemon"
exit "$fail"
