#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# The invisibility contract, as a test: the *shape* of the filesystem an
# untrusted app can probe must not change, and neither must the errno it gets.
# stat() needs no read permission, so ENOENT versus EACCES is itself the signal.
#
#   scripts/errno_profile.sh save  /data/local/tmp/before
#   ... load ira.ko, start the daemon, connect a host ...
#   scripts/errno_profile.sh diff  /data/local/tmp/before
#
# Run it as an unprivileged uid (adb shell, or from inside the app process) for
# the app's view; run it as root as well to see what a root-only reader sees.
set -e
LC_ALL=C export LC_ALL

PATHS="
/sys/module
/sys/module/ira
/sys/module/ira/sections
/sys/bus/gadget
/sys/bus/gadget/drivers/configfs-gadget.g1
/sys/class/udc
/sys/fs/selinux/enforce
/config
/config/usb_gadget
/config/usb_gadget/g1/UDC
/proc/modules
/proc/kallsyms
/proc/devices
/proc/misc
/proc/slabinfo
/proc/net/netlink
/proc/sys/kernel/tainted
/dev/ira
/dev/ira0
"

probe() {
  for p in $PATHS; do
    if kind=$(stat -c '%F' "$p" 2>/dev/null); then
      echo "$p ok $kind"
    else
      what=$(stat -c '%F' "$p" 2>&1 >/dev/null | head -1)
      echo "$p err $what"
    fi
  done
  echo "-- names below must stay empty --"
  grep -c ira /proc/modules 2>/dev/null || echo "proc/modules unreadable"
  grep -c ira /proc/kallsyms 2>/dev/null || echo "proc/kallsyms unreadable"
}

case "$1" in
  save) probe > "$2"; echo "saved $2" ;;
  diff)
    probe > "$2.now"
    if diff -u "$2" "$2.now"; then
      echo "OK: identical path/errno profile"
    else
      echo "FAIL: observable difference"; exit 1
    fi
    ;;
  *) echo "usage: $0 save <file> | diff <file>"; exit 2 ;;
esac
