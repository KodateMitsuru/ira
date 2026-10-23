#!/system/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Read-only capture while an install is waiting. Run via an authorized root shell.
echo '== current identity'
id
cat /proc/self/attr/current

echo '== KSU adbroot'
ksud=/data/adb/ksud
[ -x "$ksud" ] || ksud=$(command -v ksud 2>/dev/null)
[ -n "$ksud" ] && timeout -k 1 2 "$ksud" feature get adb_root 2>&1

echo '== frontend/backend/abb identities'
ps -A -o USER,PID,PPID,NAME,ARGS 2>/dev/null | grep -E 'ira-daemon|/system/bin/abb| adbd|packageinstaller'
for pid in $(pidof ira-daemon abb 2>/dev/null); do
    echo "-- pid=$pid"
    grep -E '^(Name|Pid|PPid|Uid|Gid|Groups|CapEff):' "/proc/$pid/status" 2>/dev/null
    cat "/proc/$pid/attr/current" 2>/dev/null
    echo
 done

echo '== package installer sessions'
timeout -k 1 5 dumpsys package installs 2>&1

echo '== verification configuration'
settings get global verifier_verify_adb_installs
settings get global package_verifier_enable

echo '== bounded package-manager log'
logcat -d -t 1200 -v brief 2>/dev/null | grep -E -i 'PackageInstaller|PackageManager|AdbInstall|INSTALL_FAILED|pending.user.action|verification|install.*(session|confirm|cancel|timeout)'

echo '== IRA startup and service logs'
tail -100 /data/adb/modules/ira/state/sync.log 2>&1
