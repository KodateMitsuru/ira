// SPDX-License-Identifier: AGPL-3.0-or-later
/* FunctionFS: the userspace half of the USB function.
 *
 * The function instance is created by init from module/initrc/ira.rc
 * (functions/ffs.ira, linked into configs/b.1 before the UDC is ever bound).
 * This file mounts a private functionfs instance on that configfs directory,
 * writes the descriptors and strings ep0 asks for, opens the two bulk
 * endpoints, and reports the gadget's lifecycle events.
 *
 * Two things about this instance are easy to get wrong and are why the API is
 * shaped the way it is:
 *
 *   - the descriptor set it presents is a function of the current link set,
 *     not of the mount, so it is written again on every bind and whenever
 *     functions/ffs.adb appears in or disappears from the configuration (see
 *     the top of ira_ffs.cpp);
 *   - a set with endpoints can be replaced at run time.  The pumps that carry
 *     the bytes therefore never own their endpoint fds: they ask for a
 *     transfer, and a re-arm takes the transfer back (with a signal, because
 *     that is the only thing a transfer blocked inside ffs_epfile_io() answers
 *     to) before it closes anything.
 *
 * Why a private mount namespace: /config is configfs and the instance
 * directory is the object the framework's gadget HAL can see.  Mounting
 * functionfs over it in the global namespace would replace that directory for
 * every process in the system.  unshare(CLONE_NEWNS) plus a private
 * propagation tree in a bootstrap thread isolates only the FunctionFS mount.
 * A directory fd pins it after that thread exits; openat() reopens endpoints
 * while the daemon and all services stay in the inherited namespace. configfs
 * itself is shared, so the kernel-side ffs_dev is still the instance init linked.
 */
#ifndef IRA_FFS_H
#define IRA_FFS_H

/* The bulk max packet for each speed the gadget may enumerate at: 64 for full
 * speed, 512 for high speed, 1024 for super speed (USB 2.0 5.8.3, USB 3.2
 * 8.7.1).  bMaxPacketSize0 is ep0's field and appears in no function
 * descriptor, so none of this is related to it. */
#define IRA_FS_BULK_MAXPKT 64
#define IRA_HS_BULK_MAXPKT 512
#define IRA_SS_BULK_MAXPKT 1024

/* One bulk transfer.  A whole number of the largest max packet, so a payload
 * split into these always ends on a packet boundary and the split stays
 * invisible to the host; it is also the size of the read buffer the host ->
 * device pump hands to ep1. */
#define IRA_BULK_CHUNK 16384

#ifdef __cplusplus
extern "C" {
#endif

/* Runs on the ffs event thread whenever the USB session ends (DISABLE/UNBIND)
 * and before a live descriptor set is replaced: the caller drops the adb
 * session that belonged to it. */
typedef void (*ira_ffs_lost_fn)(const char *why);

/* Mounts functionfs and writes the descriptor set the current configfs link
 * set calls for.  Returns 0 once the mount exists; a descriptor write that
 * fails is retried by the event thread, because staying up and recovering
 * beats failing every UDC write from then on.  -1 means the mount itself could
 * not be set up, with the reason on stderr. */
int ira_ffs_init(ira_ffs_lost_fn lost);

/* Registers ep0 and control callbacks on the existing adb looper. They re-arm
 * descriptors through the private directory fd, without switching namespaces.
 * Called after the adb transport exists: a DISABLE/UNBIND event
 * relinks that transport, and it must not race the registration of the first
 * one. */
void ira_ffs_start_events(void);

/* Non-zero once a descriptor set has been written and the instance is ready
 * for the composite to bind. */
int ira_ffs_armed(void);

/* Whether the armed set has endpoints.  The idle set (written when the
 * platform's functions/ffs.adb is linked into the same configuration) has
 * none, so there is nothing for the daemon to pump. */
int ira_ffs_has_endpoints(void);

/* Requests the AOSP-equivalent USB session reset used after authorization revocation:
 * FunctionFS is torn down and rebound so the host observes a real USB disconnect. */
void ira_ffs_reset_usb_session(void);

/* Waits up to `ms` for endpoint state to settle. Returns 1 only when enabled
 * endpoints are available for a transfer; idle or disabled states return 0. */
int ira_ffs_wait_endpoints(unsigned ms);

/* True between FUNCTIONFS_ENABLE and DISABLE. */
int ira_ffs_enabled(void);

/* Registers the calling thread as the pump of one direction, so that a re-arm
 * can interrupt a transfer it has blocked in the kernel.  dir 0 is ep1 (host
 * -> device, the daemon reads), 1 is ep2 (device -> host, it writes). */
void ira_ffs_pump_register(int dir);

/* One bulk transfer. Disabled sessions are rejected before entering the kernel.
 * Returns the byte count, or -1 with errno set:
 *   EAGAIN      nothing to do right now - not armed, the set has no endpoints,
 *               or the set was re-armed while this transfer was in flight (and
 *               its result is void): call ira_ffs_wait_endpoints() and retry;
 *   EINTR       the transfer was interrupted, retry;
 *   ESHUTDOWN / ENODEV  the wire went away; wait for the event thread. */
/* Snapshot the USB session before acquiring a bridge socket. The session-aware read rejects a
 * disconnect/reconnect that happens between that snapshot and entering kernel I/O. */
unsigned ira_ffs_session_generation(void);
long ira_ffs_read_out_session(void *buf, unsigned long len, unsigned session);

long ira_ffs_write_in(const void *buf, unsigned long len);

#ifdef __cplusplus
}
#endif

#endif /* IRA_FFS_H */
