// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef IRA_BRIDGE_H
#define IRA_BRIDGE_H

#ifdef __cplusplus

/* Mounts the ffs instance, writes the descriptor set the current configfs link
 * set calls for, then opens ep0 and - when that set has them - the bulk
 * endpoints.  Must run before the transport is registered. */
int ira_bridge_ffs_init(void);

/* Installs the socket end adbd reads and writes, starts the ffs event thread,
 * and starts the two pumps.  The pumps stay up for the life of the daemon:
 * whether they have endpoints is a per-bind property of the descriptor set, so
 * they wait for one instead of being started and stopped. */
void ira_bridge_start(int sock);

struct atransport;

/* The transport the bridge must take offline when the wire goes away, and the
 * fresh one it gets in exchange. */
atransport* ira_bridge_transport(void);
int ira_bridge_relink(void);

/* Drops the client's connection and serves the next one on a fresh
 * socketpair, without restarting the daemon: this is what adb root needs (the
 * flag lives in memory). Authorization revocation separately requests the
 * FunctionFS/UDC reset through ira_ffs_reset_usb_session(). */
void ira_bridge_drop(void);

#endif /* __cplusplus */

#endif /* IRA_BRIDGE_H */
