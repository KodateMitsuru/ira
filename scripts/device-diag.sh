#!/system/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Read-only runtime diagnostics. Run through an authorized root shell.
echo "== USB properties"
getprop init.svc.adbd
getprop sys.usb.config
getprop sys.usb.state

echo "== UDC"
cat /config/usb_gadget/g1/UDC 2>&1
for path in /sys/class/udc/*/state; do
    [ -e "$path" ] || continue
    printf '%s ' "$path"
    cat "$path"
done

echo "== gadget links"
ls -l /config/usb_gadget/g1/configs/b.1/ 2>&1

echo "== processes"
ps -A 2>/dev/null | grep -E 'ira-daemon|adbd'
echo "== installed build"
cat /data/adb/modules/ira/module.prop 2>&1
sha256sum /data/adb/modules/ira/ira-daemon 2>&1

echo "== runtime state"
ls -l /data/adb/modules/ira/state/ 2>&1
echo "== daemon log"
tail -80 /data/adb/modules/ira/state/sync.log 2>&1
