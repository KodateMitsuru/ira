#!/system/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Start the daemon at the earliest point a script can: it owns the FunctionFS instance.
#
# The function link is created by initrc/ira.rc (post-fs-data) and the UDC is bound later,
# in the vendor's early-boot. A functionfs function whose descriptors have not been written
# makes the composite's bind fail with -ENODEV (f_fs.c ffs_do_functionfs_bind), and that
# fails the whole UDC write - nothing retries it, so adb stays down until something writes
# the UDC again. The daemon therefore mounts functionfs, writes the descriptors and only then
# leaves a marker; this script waits for that marker instead of racing init on its own.
#
# Which descriptors those are is the daemon's business: they follow the configfs link set and
# are re-evaluated on every bind (see src/adb/ira_ffs.cpp), so the framework linking its own
# ffs.adb later needs nothing from here.
MODDIR=${0%/*}
case "$MODDIR" in
	/*) ;;
	*) MODDIR="$(cd "$MODDIR" 2>/dev/null && pwd)" || MODDIR=${0%/*} ;;
esac
LOG="$MODDIR/state/sync.log"
MARKER="$MODDIR/state/ffs.armed"
mkdir -p "$MODDIR/state"

if [ ! -x "$MODDIR/ira-daemon" ]; then
	echo "[post-fs-data] no ira-daemon in $MODDIR" >>"$LOG"
	exit 1
fi

# The socket name in the framework half's image is the installer's business (customize.sh writes it
# once, by the offset the build computed). Nothing here repeats it: one writer, one place to look
# when it is wrong.
# A marker left by a previous boot would make the wait below meaningless.
rm -f "$MARKER" "$MODDIR/state/revoke.resume" "$MODDIR/state/revoke.resume.new"

# Its stdout and stderr go to the log; the daemon itself never returns.
"$MODDIR/start-daemon.sh" >>"$LOG" 2>&1 < /dev/null &
pid=$!
echo "[post-fs-data] ira-daemon pid $pid" >>"$LOG"

# Wait (bounded) for the descriptors to be on ep0, so the UDC write that follows this stage
# cannot lose the race against the mount. The daemon retries arming on its own if it fails, so
# a timeout here is worth a log line and nothing more: don't fail the boot stage.
i=0
while [ "$i" -lt 30 ]; do
	if [ -f "$MARKER" ]; then
		echo "[post-fs-data] descriptors armed after ${i}00 ms" >>"$LOG"
		exit 0
	fi
	kill -0 "$pid" 2>/dev/null || {
		echo "[post-fs-data] ira-daemon exited before arming the descriptors" >>"$LOG"
		exit 1
	}
	sleep 0.1
	i=$((i + 1))
done
echo "[post-fs-data] descriptors not armed after 3 s; the daemon keeps retrying" >>"$LOG"
exit 0
