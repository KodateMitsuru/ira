#!/system/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Read the current KSU feature once per frontend start. Explicit root/unroot commands
# subsequently own the in-memory service mode; neither Android properties nor KSU are changed.
MODDIR=${0%/*}
case "$MODDIR" in
    /*) ;;
    *) MODDIR="$(cd "$MODDIR" 2>/dev/null && pwd)" || exit 1 ;;
esac

mode=shell
ksud=/data/adb/ksud
if [ ! -x "$ksud" ]; then
    ksud=$(command -v ksud 2>/dev/null) || ksud=
fi
if [ -n "$ksud" ] && command -v timeout >/dev/null 2>&1; then
    # Bound the query so unavailable/older KSU cannot hold up FunctionFS bootstrap.
    if result=$(timeout -k 1 1 "$ksud" feature get adb_root 2>/dev/null); then
        value=$(printf '%s\n' "$result" | awk '/^Value: [0-9]+$/ { print $2 }')
        case "$value" in
            ''|0|*[!0-9]*) ;;
            *) mode=root ;;
        esac
        case "$value" in
            ''|*[!0-9]*) echo '[start] KSU adb_root unavailable; defaulting to shell' ;;
            *) echo "[start] KSU adb_root=$value; default mode=$mode" ;;
        esac
    else
        echo '[start] KSU adb_root query failed/timed out; defaulting to shell'
    fi
else
    echo '[start] KSU feature query unavailable; defaulting to shell'
fi
exec "$MODDIR/ira-daemon" --ira-root-default "$mode"
