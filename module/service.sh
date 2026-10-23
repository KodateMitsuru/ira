#!/system/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Supervisor. It starts the daemon exactly once, and after that only when the daemon itself asked for
# a clean process: a FunctionFS instance cannot be reset while a pump is inside a bulk transfer, so a
# descriptor-set change is applied by ending the process and writing the set from a new one - the same
# thing the platform's own adbd does when it switches.
#
# What it never does is bring back a daemon that died on its own: every restart rewrites the instance,
# and a process that keeps dying would therefore keep tearing the composite down (that is how USB adb
# was lost for both stacks, repeatedly). The note the daemon leaves behind is removed before the new
# instance starts, so even that path cannot loop.
MODDIR=${0%/*}
case "$MODDIR" in
	/*) ;;
	*) MODDIR="$(cd "$MODDIR" 2>/dev/null && pwd)" || MODDIR=${0%/*} ;;
esac
LOG="$MODDIR/state/sync.log"
mkdir -p "$MODDIR/state"

[ -x "$MODDIR/ira-daemon" ] || exit 0

start() {
	"$MODDIR/start-daemon.sh" >>"$LOG" 2>&1 < /dev/null &
}

# post-fs-data owns the initial start. Once this late-start script sees that process, it stays
# resident and watches it. A clean descriptor transition leaves setchange immediately before exit;
# an unrequested death is left down so a crash cannot loop and repeatedly tear down the gadget.
if ! pidof ira-daemon >/dev/null 2>&1; then
	echo "[service] ira-daemon is not running; initial start belongs to post-fs-data, leaving it down" >>"$LOG"
	exit 1
fi

echo "[service] supervising ira-daemon" >>"$LOG"
while :; do
	while pidof ira-daemon >/dev/null 2>&1; do
		sleep 0.1
	done

	if [ ! -f "$MODDIR/state/setchange" ]; then
		echo "[service] ira-daemon ended without requesting replacement; leaving it down" >>"$LOG"
		exit 1
	fi

	rm -f "$MODDIR/state/setchange"
	echo "[service] ira-daemon ended for a descriptor-set change; starting a clean one" >>"$LOG"
	start
	# Continue watching the replacement. If it crashes, it has no marker and the loop stops.
done
