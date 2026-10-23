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

#define TRACE_TAG ADB

#include "sysdeps.h"
#include "adb.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <android-base/errors.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/utf8.h>

#include "ira_version.h"

#include "adb_auth.h"
#include "adb_io.h"
#include "adb_listeners.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "socket_spec.h"
#include "sysdeps/chrono.h"
#include "transport.h"

#include <sys/mount.h>
#include <android-base/properties.h>
using namespace std::chrono_literals;

#include "daemon/logging.h"


/* Nothing here counts connections for a watchdog: adbd's watchdog exists to restart a daemon whose
 * start/stop is driven by Android properties, and this stack neither reads nor writes properties. */

std::string adb_version() {
    // Don't change the format of this --- it's parsed by ddmlib.
    return android::base::StringPrintf(
            "Android Debug Bridge version %d.%d.%d\n"
            "Version %s-%s\n"
            "Installed as %s\n"
            "Running on %s\n",
            ADB_VERSION_MAJOR, ADB_VERSION_MINOR, ADB_SERVER_VERSION, PLATFORM_TOOLS_VERSION,
            IRA_BUILD_VERSION, android::base::GetExecutablePath().c_str(),
            GetOSVersion().c_str());
}

uint32_t calculate_apacket_checksum(const apacket* p) {
    uint32_t sum = 0;
    for (size_t i = 0; i < p->msg.data_length; ++i) {
        sum += static_cast<uint8_t>(p->payload[i]);
    }
    return sum;
}

std::string command_to_string(uint32_t cmd) {
    switch (cmd) {
        case A_SYNC:
            return "A_SYNC";
        case A_CNXN:
            return "A_CNXN";
        case A_OPEN:
            return "A_OPEN";
        case A_OKAY:
            return "A_OKAY";
        case A_CLSE:
            return "A_CLSE";
        case A_WRTE:
            return "A_WRTE";
        case A_AUTH:
            return "A_AUTH";
        default:
            return "UNKNOWN (" + std::to_string(cmd) + ")";
    }
}

std::string to_string(ConnectionState state) {
    switch (state) {
        case kCsOffline:
            return "offline";
        case kCsBootloader:
            return "bootloader";
        case kCsDevice:
            return "device";
        case kCsHost:
            return "host";
        case kCsRecovery:
            return "recovery";
        case kCsRescue:
            return "rescue";
        case kCsNoPerm:
            return "no permissions";
        case kCsSideload:
            return "sideload";
        case kCsUnauthorized:
            return "unauthorized";
        case kCsAuthorizing:
            return "authorizing";
        case kCsConnecting:
            return "connecting";
        case kCsDetached:
            return "detached";
        case kCsAny:
            return "any";
    }
}

apacket* get_apacket() {
    apacket* p = new apacket();
    if (p == nullptr) {
        LOG(FATAL) << "failed to allocate an apacket";
    }

    memset(&p->msg, 0, sizeof(p->msg));
    return p;
}

void put_apacket(apacket *p)
{
    delete p;
}

void handle_online(atransport *t)
{
    D("adb: online");
    t->online = 1;
#if   defined(__ANDROID__)
#endif
}

void handle_offline(atransport *t)
{
    if (t->GetConnectionState() == kCsOffline) {
        VLOG(ADB) << t->serial_name() << ": already offline";
        return;
    }

    VLOG(ADB) << t->serial_name() << ": offline";

#if defined(__ANDROID__)
#endif

    t->SetConnectionState(kCsOffline);

    // Close the associated usb
    t->online = 0;

    // This is necessary to avoid a race condition that occurred when a transport closes
    // while a client socket is still active.
    close_all_sockets(t);

    t->RunDisconnects();
}

#if DEBUG_PACKETS
#define DUMPMAX 32
void print_packet(const char *label, apacket *p)
{
    const char* tag;
    unsigned count;

    switch(p->msg.command){
    case A_SYNC: tag = "SYNC"; break;
    case A_CNXN: tag = "CNXN" ; break;
    case A_OPEN: tag = "OPEN"; break;
    case A_OKAY: tag = "OKAY"; break;
    case A_CLSE: tag = "CLSE"; break;
    case A_WRTE: tag = "WRTE"; break;
    case A_AUTH: tag = "AUTH"; break;
    default: tag = "????"; break;
    }

    fprintf(stderr, "%s: %s %08x %08x %04x \"",
            label, tag, p->msg.arg0, p->msg.arg1, p->msg.data_length);
    count = p->msg.data_length;
    const char* x = p->payload.data();
    if (count > DUMPMAX) {
        count = DUMPMAX;
        tag = "\n";
    } else {
        tag = "\"\n";
    }
    while (count-- > 0) {
        if ((*x >= ' ') && (*x < 127)) {
            fputc(*x, stderr);
        } else {
            fputc('.', stderr);
        }
        x++;
    }
    fputs(tag, stderr);
}
#endif

void send_ready(unsigned local, unsigned remote, atransport* t, uint32_t ack_bytes) {
    D("Calling send_ready");
    apacket *p = get_apacket();
    p->msg.command = A_OKAY;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    if (t->SupportsDelayedAck()) {
        p->msg.data_length = sizeof(ack_bytes);
        p->payload.resize(sizeof(ack_bytes));
        memcpy(p->payload.data(), &ack_bytes, sizeof(ack_bytes));
    }

    send_packet(p, t);
}

static void send_close(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_close");
    apacket *p = get_apacket();
    p->msg.command = A_CLSE;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

std::string get_connection_string() {
    std::vector<std::string> connection_properties;

    static const char* cnxn_props[] = {
        "ro.product.name",
        "ro.product.model",
        "ro.product.device",
    };

    for (const auto& prop : cnxn_props) {
        std::string value = std::string(prop) + "=" + android::base::GetProperty(prop, "");
        connection_properties.push_back(value);
    }

    connection_properties.push_back(android::base::StringPrintf(
        "features=%s", FeatureSetToString(supported_features()).c_str()));

    return android::base::StringPrintf(
        "%s::%s", adb_device_banner,
        android::base::Join(connection_properties, ';').c_str());
}

void send_connect(atransport* t) {
    D("Calling send_connect");
    apacket* cp = get_apacket();
    cp->msg.command = A_CNXN;
    // Send the max supported version, but because the transport is
    // initialized to A_VERSION_MIN, this will be compatible with every
    // device.
    cp->msg.arg0 = A_VERSION;
    cp->msg.arg1 = t->get_max_payload();

    std::string connection_str = get_connection_string();
    // Connect and auth packets are limited to MAX_PAYLOAD_V1 because we don't
    // yet know how much data the other size is willing to accept.
    if (connection_str.length() > MAX_PAYLOAD_V1) {
        LOG(FATAL) << "Connection banner is too long (length = "
                   << connection_str.length() << ")";
    }

    cp->payload.assign(connection_str.begin(), connection_str.end());
    cp->msg.data_length = cp->payload.size();

    send_packet(cp, t);
}

void parse_banner(const std::string& banner, atransport* t) {
    D("parse_banner: %s", banner.c_str());

    // The format is something like:
    // "device::ro.product.name=x;ro.product.model=y;ro.product.device=z;".
    std::vector<std::string> pieces = android::base::Split(banner, ":");

    // Reset the features list or else if the server sends no features we may
    // keep the existing feature set (http://b/24405971).
    t->SetFeatures("");

    if (pieces.size() > 2) {
        const std::string& props = pieces[2];
        for (const auto& prop : android::base::Split(props, ";")) {
            // The list of properties was traditionally ;-terminated rather than ;-separated.
            if (prop.empty()) continue;

            std::vector<std::string> key_value = android::base::Split(prop, "=");
            if (key_value.size() != 2) continue;

            const std::string& key = key_value[0];
            const std::string& value = key_value[1];
            if (key == "ro.product.name") {
                t->product = value;
            } else if (key == "ro.product.model") {
                t->model = value;
            } else if (key == "ro.product.device") {
                t->device = value;
            } else if (key == "features") {
                t->SetFeatures(value);
            }
        }
    }

    const std::string& type = pieces[0];
    if (type == "bootloader") {
        D("setting connection_state to kCsBootloader");
        t->SetConnectionState(kCsBootloader);
    } else if (type == "device") {
        D("setting connection_state to kCsDevice");
        t->SetConnectionState(kCsDevice);
    } else if (type == "recovery") {
        D("setting connection_state to kCsRecovery");
        t->SetConnectionState(kCsRecovery);
    } else if (type == "sideload") {
        D("setting connection_state to kCsSideload");
        t->SetConnectionState(kCsSideload);
    } else if (type == "rescue") {
        D("setting connection_state to kCsRescue");
        t->SetConnectionState(kCsRescue);
    } else {
        D("setting connection_state to kCsHost");
        t->SetConnectionState(kCsHost);
    }
}

static void handle_new_connection(atransport* t, apacket* p) {
    handle_offline(t);

    t->update_version(p->msg.arg0, p->msg.arg1);
    std::string banner(p->payload.begin(), p->payload.end());
    parse_banner(banner, t);


    fprintf(stderr, "ira-auth: received CNXN; starting connection handshake\n");
    ADB_LOG(Connection) << "received CNXN: version=" << p->msg.arg0 << ", maxdata = " << p->msg.arg1
                        << ", banner = '" << banner << "'";

    if (!auth_required) {
        LOG(INFO) << "authentication not required";
        handle_online(t);
        send_connect(t);
    } else {
        send_auth_request(t);
    }
}

void handle_packet(apacket *p, atransport *t)
{
    D("handle_packet() %c%c%c%c", ((char*) (&(p->msg.command)))[0],
            ((char*) (&(p->msg.command)))[1],
            ((char*) (&(p->msg.command)))[2],
            ((char*) (&(p->msg.command)))[3]);
    print_packet("recv", p);
    CHECK_EQ(p->payload.size(), p->msg.data_length);

    switch(p->msg.command){
    case A_CNXN:  // CONNECT(version, maxdata, "system-id-string")
        handle_new_connection(t, p);
        break;
    case A_AUTH:
        switch (p->msg.arg0) {
            case ADB_AUTH_SIGNATURE: {
                // TODO: Switch to string_view.
                std::string signature(p->payload.begin(), p->payload.end());
                std::string auth_key;
                if (adbd_auth_verify(t->token, sizeof(t->token), signature, &auth_key)) {
                    adbd_auth_verified(t);
                    t->failed_auth_attempts = 0;
                    t->auth_key = auth_key;
                    adbd_notify_framework_connected_key(t);
                } else {
                    /* A signature this device cannot check is answered with another token and
                     * nothing else: a real host has no case for ADB_AUTH_RSAPUBLICKEY as a device
                     * reply and drops the transport on the unknown type (adb.cpp:493), and it
                     * offers its public key by itself once it has run out of keys to sign with -
                     * that is what brings the key here and raises the prompt. */
                    if (t->failed_auth_attempts++ > 256) std::this_thread::sleep_for(1s);
                    send_auth_request(t);
                }
                break;
            }

            case ADB_AUTH_RSAPUBLICKEY:
                fprintf(stderr, "ira-auth: received host public key (%zu bytes)\n", p->payload.size());
                if (p->payload.empty() || p->payload.size() > 8192 || p->payload[p->payload.size() - 1] != '\0') {
                    kick_transport(t, false);
                    break;
                }
                t->auth_key.assign(p->payload.data(), p->payload.size() - 1);
                adbd_auth_confirm_key(t);
                break;
            default:
                t->SetConnectionState(kCsOffline);
                handle_offline(t);
                break;
        }
        break;

    case A_OPEN: {
        /* OPEN(local-id, [send-buffer], "destination") */
        if (!t->online || p->msg.arg0 == 0) {
            break;
        }

        uint32_t send_bytes = static_cast<uint32_t>(p->msg.arg1);
        if (t->SupportsDelayedAck() != static_cast<bool>(send_bytes)) {
            LOG(ERROR) << "unexpected value of A_OPEN arg1: " << send_bytes
                       << " (delayed acks = " << t->SupportsDelayedAck() << ")";
            send_close(0, p->msg.arg0, t);
            break;
        }

        std::string_view address(p->payload.begin(), p->payload.size());

        // Historically, we received service names as a char*, and stopped at the first NUL
        // byte. The client sent strings with null termination, which post-string_view, start
        // being interpreted as part of the string, unless we explicitly strip them.
        address = StripTrailingNulls(address);
        asocket* s = create_local_service_socket(address, t);
        if (s == nullptr) {
            send_close(0, p->msg.arg0, t);
            break;
        }

        s->peer = create_remote_socket(p->msg.arg0, t);
        s->peer->peer = s;

        if (t->SupportsDelayedAck()) {
            VLOG(PACKETS) << "delayed ack available: send buffer = " << send_bytes;
            s->available_send_bytes = send_bytes;

            // TODO: Make this adjustable at connection time?
            send_ready(s->id, s->peer->id, t, INITIAL_DELAYED_ACK_BYTES);
        } else {
            VLOG(PACKETS) << "delayed ack unavailable";
            send_ready(s->id, s->peer->id, t, 0);
        }

        s->ready(s);
        break;
    }

    case A_OKAY: /* READY(local-id, remote-id, "") */
        if (t->online && p->msg.arg0 != 0 && p->msg.arg1 != 0) {
            asocket* s = find_local_socket(p->msg.arg1, 0);
            if (s) {
                std::optional<int32_t> acked_bytes;
                if (p->payload.size() == sizeof(int32_t)) {
                    int32_t value;
                    memcpy(&value, p->payload.data(), sizeof(value));
                    // acked_bytes can be negative!
                    //
                    // In the future, we can use this to preemptively supply backpressure, instead
                    // of waiting for the writer to hit its limit.
                    acked_bytes = value;
                } else if (p->payload.size() != 0) {
                    LOG(ERROR) << "invalid A_OKAY payload size: " << p->payload.size();
                    return;
                }

                if (s->peer == nullptr) {
                    /* On first READY message, create the connection. */
                    s->peer = create_remote_socket(p->msg.arg0, t);
                    s->peer->peer = s;

                    local_socket_ack(s, acked_bytes);
                } else if (s->peer->id == p->msg.arg0) {
                    /* Other READY messages must use the same local-id */
                    local_socket_ack(s, acked_bytes);
                } else {
                    D("Invalid A_OKAY(%d,%d), expected A_OKAY(%d,%d) on transport %s", p->msg.arg0,
                      p->msg.arg1, s->peer->id, p->msg.arg1, t->serial.c_str());
                }
            } else {
                // When receiving A_OKAY from device for A_OPEN request, the host server may
                // have closed the local socket because of client disconnection. Then we need
                // to send A_CLSE back to device to close the service on device.
                send_close(p->msg.arg1, p->msg.arg0, t);
            }
        }
        break;

    case A_CLSE: /* CLOSE(local-id, remote-id, "") or CLOSE(0, remote-id, "") */
        if (t->online && p->msg.arg1 != 0) {
            asocket* s = find_local_socket(p->msg.arg1, p->msg.arg0);
            if (s) {
                /* According to protocol.txt, p->msg.arg0 might be 0 to indicate
                 * a failed OPEN only. However, due to a bug in previous ADB
                 * versions, CLOSE(0, remote-id, "") was also used for normal
                 * CLOSE() operations.
                 *
                 * This is bad because it means a compromised adbd could
                 * send packets to close connections between the host and
                 * other devices. To avoid this, only allow this if the local
                 * socket has a peer on the same transport.
                 */
                if (p->msg.arg0 == 0 && s->peer && s->peer->transport != t) {
                    D("Invalid A_CLSE(0, %u) from transport %s, expected transport %s", p->msg.arg1,
                      t->serial.c_str(), s->peer->transport->serial.c_str());
                } else {
                    s->close(s);
                }
            }
        }
        break;

    case A_WRTE: /* WRITE(local-id, remote-id, <data>) */
        if (t->online && p->msg.arg0 != 0 && p->msg.arg1 != 0) {
            asocket* s = find_local_socket(p->msg.arg1, p->msg.arg0);
            if (s) {
                s->enqueue(s, std::move(p->payload));
            }
        }
        break;

    default:
        printf("handle_packet: what is %08x?!\n", p->msg.command);
    }

    put_apacket(p);
}


bool handle_forward_request(const char* service, atransport* transport, int reply_fd) {
    return handle_forward_request(service, [transport](std::string*) { return transport; },
                                  reply_fd);
}

// Try to handle a network forwarding request.
bool handle_forward_request(const char* service,
                            std::function<atransport*(std::string* error)> transport_acquirer,
                            int reply_fd) {
    if (!strcmp(service, "list-forward")) {
        // Create the list of forward redirections.
        std::string listeners = format_listeners();
        SendProtocolString(reply_fd, listeners);
        return true;
    }

    if (!strcmp(service, "killforward-all")) {
        remove_all_listeners();
        SendOkay(reply_fd);
        return true;
    }

    if (!strncmp(service, "forward:", 8) || !strncmp(service, "killforward:", 12)) {
        // killforward:local
        // forward:(norebind:)?local;remote
        std::string error;
        atransport* transport = transport_acquirer(&error);
        if (!transport) {
            SendFail(reply_fd, error);
            return true;
        }

        bool kill_forward = false;
        bool no_rebind = false;
        if (android::base::StartsWith(service, "killforward:")) {
            kill_forward = true;
            service += 12;
        } else {
            service += 8;   // skip past "forward:"
            if (android::base::StartsWith(service, "norebind:")) {
                no_rebind = true;
                service += 9;
            }
        }

        std::vector<std::string> pieces = android::base::Split(service, ";");

        if (kill_forward) {
            // Check killforward: parameter format: '<local>'
            if (pieces.size() != 1 || pieces[0].empty()) {
                SendFail(reply_fd, android::base::StringPrintf("bad killforward: %s", service));
                return true;
            }
        } else {
            // Check forward: parameter format: '<local>;<remote>'
            if (pieces.size() != 2 || pieces[0].empty() || pieces[1].empty() || pieces[1][0] == '*') {
                SendFail(reply_fd, android::base::StringPrintf("bad forward: %s", service));
                return true;
            }
        }

        InstallStatus r;
        int resolved_tcp_port = 0;
        if (kill_forward) {
            r = remove_listener(pieces[0].c_str(), transport);
        } else {
            int flags = 0;
            if (no_rebind) {
                flags |= INSTALL_LISTENER_NO_REBIND;
            }
            r = install_listener(pieces[0], pieces[1].c_str(), transport, flags, &resolved_tcp_port,
                                 &error);
        }
        if (r == INSTALL_STATUS_OK) {
            SendOkay(reply_fd);

            // If a TCP port was resolved, send the actual port number back.
            if (resolved_tcp_port != 0) {
                SendProtocolString(reply_fd, android::base::StringPrintf("%d", resolved_tcp_port));
            }

            return true;
        }

        std::string message;
        switch (r) {
          case INSTALL_STATUS_OK: message = "success (!)"; break;
          case INSTALL_STATUS_INTERNAL_ERROR: message = "internal error"; break;
          case INSTALL_STATUS_CANNOT_BIND:
            message = android::base::StringPrintf("cannot bind listener: %s",
                                                  error.c_str());
            break;
          case INSTALL_STATUS_CANNOT_REBIND:
            message = android::base::StringPrintf("cannot rebind existing socket");
            break;
          case INSTALL_STATUS_LISTENER_NOT_FOUND:
            message = android::base::StringPrintf("listener '%s' not found", service);
            break;
        }
        SendFail(reply_fd, message);
        return true;
    }

    return false;
}
