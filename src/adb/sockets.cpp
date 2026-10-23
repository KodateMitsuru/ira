// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TRACE_TAG SOCKETS

#include "sysdeps.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <mutex>
#include <string>
#include <vector>

#include <android-base/strings.h>

#include <android-base/properties.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "transport.h"
#include "types.h"

using namespace std::chrono_literals;

static std::recursive_mutex& local_socket_list_lock = *new std::recursive_mutex();
static unsigned local_socket_next_id = 1;

static auto& local_socket_list = *new std::vector<asocket*>();

/* the the list of currently closing local sockets.
** these have no peer anymore, but still packets to
** write to their fd.
*/
static auto& local_socket_closing_list = *new std::vector<asocket*>();

// Parse the global list of sockets to find one with id |local_id|.
// If |peer_id| is not 0, also check that it is connected to a peer
// with id |peer_id|. Returns an asocket handle on success, NULL on failure.
asocket* find_local_socket(unsigned local_id, unsigned peer_id) {
    asocket* result = nullptr;

    std::lock_guard<std::recursive_mutex> lock(local_socket_list_lock);
    for (asocket* s : local_socket_list) {
        if (s->id != local_id) {
            continue;
        }
        if (peer_id == 0 || (s->peer && s->peer->id == peer_id)) {
            result = s;
        }
        break;
    }

    return result;
}

void install_local_socket(asocket* s) {
    std::lock_guard<std::recursive_mutex> lock(local_socket_list_lock);

    s->id = local_socket_next_id++;

    // Socket ids should never be 0.
    if (local_socket_next_id == 0) {
        LOG(FATAL) << "local socket id overflow";
    }

    local_socket_list.push_back(s);
}

void remove_socket(asocket* s) {
    std::lock_guard<std::recursive_mutex> lock(local_socket_list_lock);
    for (auto list : { &local_socket_list, &local_socket_closing_list }) {
        list->erase(std::remove_if(list->begin(), list->end(), [s](asocket* x) { return x == s; }),
                    list->end());
    }
}

void close_all_sockets(atransport* t) {
    /* this is a little gross, but since s->close() *will* modify
    ** the list out from under you, your options are limited.
    */
    std::lock_guard<std::recursive_mutex> lock(local_socket_list_lock);
restart:
    for (asocket* s : local_socket_list) {
        if (s->transport == t || (s->peer && s->peer->transport == t)) {
            s->close(s);
            goto restart;
        }
    }
}

enum class SocketFlushResult {
    Destroyed,
    TryAgain,
    Completed,
};

static SocketFlushResult local_socket_flush_incoming(asocket* s) {
    D("LS(%u) %s: %zu bytes in queue", s->id, __func__, s->packet_queue.size());
    uint32_t bytes_flushed = 0;
    if (!s->packet_queue.empty()) {
        std::vector<adb_iovec> iov = s->packet_queue.iovecs();
        ssize_t rc = adb_writev(s->fd, iov.data(), iov.size());
        D("LS(%u) %s: rc = %zd", s->id, __func__, rc);
        if (rc > 0) {
            bytes_flushed = rc;
            if (static_cast<size_t>(rc) == s->packet_queue.size()) {
                s->packet_queue.clear();
            } else {
                s->packet_queue.drop_front(rc);
            }
        } else if (rc == -1 && errno == EAGAIN) {
            // fd is full.
        } else {
            // rc == 0, probably.
            // The other side closed its read side of the fd, but it's possible that we can still
            // read from the socket. Give that a try before giving up.
            s->has_write_error = true;
        }
    }

    bool fd_full = !s->packet_queue.empty() && !s->has_write_error;
    if (s->transport && s->peer) {
        if (s->available_send_bytes.has_value()) {
            // Deferred acks are available.
            send_ready(s->id, s->peer->id, s->transport, bytes_flushed);
        } else {
            // Deferred acks aren't available, we should ask for more data as long as we have less
            // than a full packet left in our queue.
            if (bytes_flushed != 0 && s->packet_queue.size() < MAX_PAYLOAD) {
                send_ready(s->id, s->peer->id, s->transport, 0);
            }
        }
    }

    // If we sent the last packet of a closing socket, we can now destroy it.
    if (s->closing && !fd_full) {
        s->close(s);
        return SocketFlushResult::Destroyed;
    }

    if (fd_full) {
        fdevent_add(s->fde, FDE_WRITE);
        return SocketFlushResult::TryAgain;
    } else {
        fdevent_del(s->fde, FDE_WRITE);
        return SocketFlushResult::Completed;
    }
}

// Returns false if the socket has been closed and destroyed as a side-effect of this function.
static bool local_socket_flush_outgoing(asocket* s) {
    const size_t max_payload = s->get_max_payload();
    apacket::payload_type data;
    data.resize(max_payload);
    char* x = &data[0];
    size_t avail = max_payload;
    int r = 0;
    int is_eof = 0;

    while (avail > 0) {
        r = adb_read(s->fd, x, avail);
        D("LS(%d): post adb_read(fd=%d,...) r=%d (errno=%d) avail=%zu", s->id, s->fd, r,
          r < 0 ? errno : 0, avail);
#ifdef IRA_VM
	if (r > 0)
		fprintf(stderr, "ira-sock: %d bytes from the service, %zu room left\n", r, avail);
#endif
        if (r == -1) {
            if (errno == EAGAIN) {
                break;
            }
        } else if (r > 0) {
            avail -= r;
            x += r;
            continue;
        }

        /* r = 0 or unhandled error */
        is_eof = 1;
        break;
    }
    D("LS(%d): fd=%d post avail loop. r=%d is_eof=%d", s->id, s->fd, r, is_eof);

    if (avail != max_payload && s->peer) {
        data.resize(max_payload - avail);

        // s->peer->enqueue() may call s->close() and free s,
        // so save variables for debug printing below.
        unsigned saved_id = s->id;
        int saved_fd = s->fd;

        if (s->available_send_bytes) {
            *s->available_send_bytes -= data.size();
        }

        r = s->peer->enqueue(s->peer, std::move(data));
        D("LS(%u): fd=%d post peer->enqueue(). r=%d", saved_id, saved_fd, r);
#ifdef IRA_VM
		fprintf(stderr, "ira-sock: handed %zu bytes to the transport side -> %d\n", data.size(),
		        r);
#endif

        if (r < 0) {
            // Error return means they closed us as a side-effect and we must
            // return immediately.
            //
            // Note that if we still have buffered packets, the socket will be
            // placed on the closing socket list. This handler function will be
            // called again to process FDE_WRITE events.
            return false;
        }

        if (r > 0) {
            if (s->available_send_bytes) {
                if (*s->available_send_bytes <= 0) {
                    D("LS(%u): send buffer full (%" PRId64 ")", saved_id, *s->available_send_bytes);
                    fdevent_del(s->fde, FDE_READ);
                }
            } else {
                D("LS(%u): acks not deferred, blocking", saved_id);
                fdevent_del(s->fde, FDE_READ);
            }
        }
    }

    if (is_eof) {
        D(" closing because is_eof=%d", is_eof);
        s->close(s);
        return false;
    }

    return true;
}

static int local_socket_enqueue(asocket* s, apacket::payload_type data) {
    D("LS(%d): enqueue %zu", s->id, data.size());

    s->packet_queue.append(std::move(data));
    switch (local_socket_flush_incoming(s)) {
        case SocketFlushResult::Destroyed:
            return -1;

        case SocketFlushResult::TryAgain:
            return 1;

        case SocketFlushResult::Completed:
            return 0;
    }

    return !s->packet_queue.empty();
}

static void local_socket_ready(asocket* s) {
#ifdef IRA_VM
	/* The only way reading from the service is turned back on. If a transfer stalls with the
	 * service still holding data, this is the event that never arrived. */
	fprintf(stderr, "ira-sock: local_socket_ready LS(%d) -> reading again\n", s->id);
#endif
    /* far side is ready for data, pay attention to
       readable events */
    fdevent_add(s->fde, FDE_READ);
}

struct ClosingSocket {
    std::chrono::steady_clock::time_point begin;
};

// The standard (RFC 1122 - 4.2.2.13) says that if we call close on a
// socket while we have pending data, a TCP RST should be sent to the
// other end to notify it that we didn't read all of its data. However,
// this can result in data that we've successfully written out to be dropped
// on the other end. To avoid this, instead of immediately closing a
// socket, call shutdown on it instead, and then read from the file
// descriptor until we hit EOF or an error before closing.
static void deferred_close(unique_fd fd) {
    // Shutdown the socket in the outgoing direction only, so that
    // we don't have the same problem on the opposite end.
    adb_shutdown(fd.get(), SHUT_WR);
    auto callback = [](fdevent* fde, unsigned event, void* arg) {
        auto socket_info = static_cast<ClosingSocket*>(arg);
        if (event & FDE_READ) {
            ssize_t rc;
            char buf[BUFSIZ];
            while ((rc = adb_read(fde->fd.get(), buf, sizeof(buf))) > 0) {
                continue;
            }

            if (rc == -1 && errno == EAGAIN) {
                // There's potentially more data to read.
                auto duration = std::chrono::steady_clock::now() - socket_info->begin;
                if (duration > 1s) {
                    LOG(WARNING) << "timeout expired while reading data after flushing socket, closing";
                } else {
                    return;
                }
            }
        } else if (event & FDE_TIMEOUT) {
            LOG(WARNING) << "timeout expired while flushing socket, closing";
        }

        // Either there was an error, we hit the end of the socket, or our timeout expired.
        fdevent_destroy(fde);
        delete socket_info;
    };

    ClosingSocket* socket_info = new ClosingSocket{
            .begin = std::chrono::steady_clock::now(),
    };

    fdevent* fde = fdevent_create(fd.release(), callback, socket_info);
    fdevent_add(fde, FDE_READ);
    fdevent_set_timeout(fde, 1s);
}

// be sure to hold the socket list lock when calling this
static void local_socket_destroy(asocket* s) {
    int exit_on_close = s->exit_on_close;

    D("LS(%d): destroying fde.fd=%d", s->id, s->fd);

    deferred_close(fdevent_release(s->fde));

    remove_socket(s);
    delete s;

    if (exit_on_close) {
        D("local_socket_destroy: exiting");
        exit(0);
    }
}

static void local_socket_close(asocket* s) {
#ifdef IRA_VM
	/* Why this socket is going away. A write error means a packet could not be handed to the
	 * transport, which separates "the service finished" from "the transport refused us". */
	fprintf(stderr, "ira-close: LS(%d) closing (write_error=%d, queued=%zu)\n", s->id,
	        s->has_write_error, s->packet_queue.size());
#endif
    D("entered local_socket_close. LS(%d) fd=%d", s->id, s->fd);
    std::lock_guard<std::recursive_mutex> lock(local_socket_list_lock);
    if (s->peer) {
        D("LS(%d): closing peer. peer->id=%d peer->fd=%d", s->id, s->peer->id, s->peer->fd);
        /* Note: it's important to call shutdown before disconnecting from
         * the peer, this ensures that remote sockets can still get the id
         * of the local socket they're connected to, to send a CLOSE()
         * protocol event. */
        if (s->peer->shutdown) {
            s->peer->shutdown(s->peer);
        }
        s->peer->peer = nullptr;
        s->peer->close(s->peer);
        s->peer = nullptr;
    }

    /* If we are already closing, or if there are no
    ** pending packets, destroy immediately
    */
    if (s->closing || s->has_write_error || s->packet_queue.empty()) {
        int id = s->id;
        local_socket_destroy(s);
        D("LS(%d): closed", id);
        return;
    }

    /* otherwise, put on the closing list
    */
    D("LS(%d): closing", s->id);
    s->closing = true;
    fdevent_del(s->fde, FDE_READ);
    remove_socket(s);
    D("LS(%d): put on socket_closing_list fd=%d", s->id, s->fd);
    local_socket_closing_list.push_back(s);
    CHECK_EQ(FDE_WRITE, s->fde->state & FDE_WRITE);
}

static void local_socket_event_func(int fd, unsigned ev, void* _s) {
    asocket* s = reinterpret_cast<asocket*>(_s);
    D("LS(%d): event_func(fd=%d(==%d), ev=%04x)", s->id, s->fd, fd, ev);

    /* put the FDE_WRITE processing before the FDE_READ
    ** in order to simplify the code.
    */
    if (ev & FDE_WRITE) {
        switch (local_socket_flush_incoming(s)) {
            case SocketFlushResult::Destroyed:
                return;

            case SocketFlushResult::TryAgain:
                break;

            case SocketFlushResult::Completed:
                break;
        }
    }

    if (ev & FDE_READ) {
        if (!local_socket_flush_outgoing(s)) {
            return;
        }
    }

    if (ev & FDE_ERROR) {
        /* this should be caught be the next read or write
        ** catching it here means we may skip the last few
        ** bytes of readable data.
        */
        D("LS(%d): FDE_ERROR (fd=%d)", s->id, s->fd);
        return;
    }
}

void local_socket_ack(asocket* s, std::optional<int32_t> acked_bytes) {
    // acked_bytes can be negative!
    //
    // In the future, we can use this to preemptively supply backpressure, instead
    // of waiting for the writer to hit its limit.
    if (s->available_send_bytes.has_value() != acked_bytes.has_value()) {
        LOG(ERROR) << "delayed ack mismatch: socket = " << s->available_send_bytes.has_value()
                   << ", payload = " << acked_bytes.has_value();
        return;
    }

    if (s->available_send_bytes.has_value()) {
        D("LS(%d) received delayed ack, available bytes: %" PRId64 " += %" PRIu32, s->id,
          *s->available_send_bytes, *acked_bytes);

        // This can't (reasonably) overflow: available_send_bytes is 64-bit.
        *s->available_send_bytes += *acked_bytes;
        if (*s->available_send_bytes > 0) {
            s->ready(s);
        }
    } else {
        D("LS(%d) received ack", s->id);
        s->ready(s);
    }
}

asocket* create_local_socket(unique_fd ufd) {
    int fd = ufd.release();
    asocket* s = new asocket();
    s->fd = fd;
    s->enqueue = local_socket_enqueue;
    s->ready = local_socket_ready;
    s->shutdown = nullptr;
    s->close = local_socket_close;
    install_local_socket(s);

    s->fde = fdevent_create(fd, local_socket_event_func, s);
    D("LS(%d): created (fd=%d)", s->id, s->fd);
    return s;
}

asocket* create_local_service_socket(std::string_view name, atransport* transport) {
    if (asocket* s = daemon_service_to_socket(name, transport); s) {
        return s;
    }
    unique_fd fd = service_to_fd(name, transport);
    if (fd < 0) {
        return nullptr;
    }

    int fd_value = fd.get();
    asocket* s = create_local_socket(std::move(fd));
    s->transport = transport;
    VLOG(SERVICES) << "LS(" << s->id << "): bound to '" << name << "' via " << fd_value;

    /* Nothing here exits on close, and that is a decision, not an omission.
     *
     * Upstream marks root:/unroot:/usb:/tcpip: with exit_on_close because in its world adbd is a
     * service init restarts: the service answers, the socket closes, adbd exits, init starts it
     * again with the new identity. This daemon has no init behind it and no restart to survive:
     * it owns the FunctionFS instance the configuration's link points at, so a process that exits
     * leaves that link pointing at an instance that no longer exists, the next UDC write fails
     * with -ENODEV (f_fs.c:3107) and the whole gadget stays down until the device is rebooted.
     * root and unroot change a flag in this process's memory (services.cpp) and nothing else, so
     * the service socket closing must end nothing. */

    return s;
}

static int remote_socket_enqueue(asocket* s, apacket::payload_type data) {
    D("entered remote_socket_enqueue RS(%d) WRITE fd=%d peer.fd=%d", s->id, s->fd, s->peer->fd);
    apacket* p = get_apacket();

    p->msg.command = A_WRTE;
    p->msg.arg0 = s->peer->id;
    p->msg.arg1 = s->id;

    if (data.size() > MAX_PAYLOAD) {
        put_apacket(p);
        return -1;
    }

    p->payload = std::move(data);
    p->msg.data_length = p->payload.size();

    send_packet(p, s->transport);
    return 1;
}

static void remote_socket_ready(asocket* s) {
#ifdef IRA_VM
	fprintf(stderr, "ira-sock: remote_socket_ready RS(%d) (the host acknowledged)\n", s->id);
#endif
    D("entered remote_socket_ready RS(%d) OKAY fd=%d peer.fd=%d", s->id, s->fd, s->peer->fd);
    apacket* p = get_apacket();
    p->msg.command = A_OKAY;
    p->msg.arg0 = s->peer->id;
    p->msg.arg1 = s->id;
    send_packet(p, s->transport);
}

static void remote_socket_shutdown(asocket* s) {
    D("entered remote_socket_shutdown RS(%d) CLOSE fd=%d peer->fd=%d", s->id, s->fd,
      s->peer ? s->peer->fd : -1);
    apacket* p = get_apacket();
    p->msg.command = A_CLSE;
    if (s->peer) {
        p->msg.arg0 = s->peer->id;
    }
    p->msg.arg1 = s->id;
    send_packet(p, s->transport);
}

static void remote_socket_close(asocket* s) {
    if (s->peer) {
        s->peer->peer = nullptr;
        D("RS(%d) peer->close()ing peer->id=%d peer->fd=%d", s->id, s->peer->id, s->peer->fd);
        s->peer->close(s->peer);
    }
    D("entered remote_socket_close RS(%d) CLOSE fd=%d peer->fd=%d", s->id, s->fd,
      s->peer ? s->peer->fd : -1);
    D("RS(%d): closed", s->id);
    delete s;
}

// Create a remote socket to exchange packets with a remote service through transport
// |t|. Where |id| is the socket id of the corresponding service on the other
//  side of the transport (it is allocated by the remote side and _cannot_ be 0).
// Returns a new non-NULL asocket handle.
asocket* create_remote_socket(unsigned id, atransport* t) {
    if (id == 0) {
        LOG(FATAL) << "invalid remote socket id (0)";
    }
    asocket* s = new asocket();
    s->id = id;
    s->enqueue = remote_socket_enqueue;
    s->ready = remote_socket_ready;
    s->shutdown = remote_socket_shutdown;
    s->close = remote_socket_close;
    s->transport = t;

    D("RS(%d): created", s->id);
    return s;
}

void connect_to_remote(asocket* s, std::string_view destination) {
    D("Connect_to_remote call RS(%d) fd=%d", s->id, s->fd);
    apacket* p = get_apacket();

    LOG(VERBOSE) << "LS(" << s->id << ": connect(" << destination << ")";
    p->msg.command = A_OPEN;
    p->msg.arg0 = s->id;

    if (s->transport->SupportsDelayedAck()) {
        p->msg.arg1 = INITIAL_DELAYED_ACK_BYTES;
        s->available_send_bytes = 0;
    }

    // adbd used to expect a null-terminated string.
    // Keep doing so to maintain backward compatibility.
    p->payload.resize(destination.size() + 1);
    memcpy(p->payload.data(), destination.data(), destination.size());
    p->payload[destination.size()] = '\0';
    p->msg.data_length = p->payload.size();

    CHECK_LE(p->msg.data_length, s->get_max_payload());

    send_packet(p, s->transport);
}


size_t asocket::get_max_payload() const {
    size_t max_payload = MAX_PAYLOAD;
    if (transport) {
        max_payload = std::min(max_payload, transport->get_max_payload());
    }
    if (peer && peer->transport) {
        max_payload = std::min(max_payload, peer->transport->get_max_payload());
    }
    return max_payload;
}
