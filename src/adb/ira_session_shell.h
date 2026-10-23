// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef IRA_SESSION_SHELL_H
#define IRA_SESSION_SHELL_H

/* The file every session without a command runs: this module's own mksh, at the path the module is
 * installed under (/data/adb/modules/<module.prop id>/mksh). Both things that start one - the shell
 * service for a session, and the su server for the root half of it - name it here, so a device whose
 * module lives somewhere else fails in one place instead of two, and says which file it looked for.
 *
 * A build can point it elsewhere: outside Android (the VM harness) there is no module installed at
 * that path. */
#ifndef IRA_SESSION_SHELL
#define IRA_SESSION_SHELL "/data/adb/modules/ira/mksh"
#endif

#endif /* IRA_SESSION_SHELL_H */
