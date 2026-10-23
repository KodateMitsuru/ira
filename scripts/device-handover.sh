#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install the module through KernelSU. The only device-side input is a ZIP staged on /sdcard;
# ksud owns extraction, customization, policy generation, and activation.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"

ZIP=$(ls -1t build/dist/ira-*.zip | head -1)
[ -f "$ZIP" ] || { echo "no module ZIP in build/dist" >&2; exit 1; }
NAME=$(basename "$ZIP")

adb get-state >/dev/null
echo "-- pushing $NAME to /sdcard"
adb push "$ZIP" "/sdcard/$NAME"
echo "-- installing through ksud"
adb shell su -c "ksud module install /sdcard/$NAME"
echo "-- module install requested; reboot through KernelSU when ready"
