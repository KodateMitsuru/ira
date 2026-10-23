// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef IRA_SU_SERVER_H
#define IRA_SU_SERVER_H

/* The privileged side of su: a listener on this installation's "su" endpoint that starts one root
 * shell for each connection that asks for one.
 *
 *   The daemon keeps the root it was started with (see ira_main.cpp), so there is no privileged
 *   channel and no setuid helper to go through: a client that can reach this socket - an app that
 *   was granted the permission, or the module's own tools - sends a command line and three fds,
 *   and gets a shell running as root with exactly that stdio. No pty is ever created here: the
 *   session's stdio is what the caller passed in. */
int ira_su_server_start(void);

#endif /* IRA_SU_SERVER_H */
