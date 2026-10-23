#!/system/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Nothing to undo outside the module directory: the state, the log and the daemon all live
# in it, and the manager removes it. The pinned FunctionFS mount is released when
# the daemon exits; reboot to drop the init-created configfs link.
true
