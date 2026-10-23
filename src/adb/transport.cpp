// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
#include <cstdio>
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

#define TRACE_TAG TRANSPORT

#include "sysdeps.h"

#include "transport.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <list>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include <android-base/logging.h>
#include <android-base/no_destructor.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/thread_annotations.h>

#include "adb.h"
#include "adb_auth.h"
#include "adb_io.h"
#include "adb_trace.h"
#include "adb_utils.h"
#include "fdevent/fdevent.h"
#include "sysdeps/chrono.h"


using namespace std::string_literals;
using android::base::ScopedLockAssertion;

static void remove_transport(atransport* transport);
static void transport_destroy(atransport* transport);

static auto& transport_lock = *new std::recursive_mutex();
// When a tranport is created, it is not started yet (and in the case of the host side, it has
// not yet sent CNXN). These transports are staged in the pending list.
static auto& pending_list = *new std::list<atransport*>();
// TODO: unordered_map<TransportId, atransport*>
static auto& transport_list = *new std::list<atransport*>();

const char* const kFeatureShell2 = "shell_v2";
const char* const kFeatureCmd = "cmd";
const char* const kFeatureStat2 = "stat_v2";
const char* const kFeatureLs2 = "ls_v2";
const char* const kFeatureApex = "apex";
const char* const kFeatureFixedPushMkdir = "fixed_push_mkdir";
const char* const kFeatureAbb = "abb";
const char* const kFeatureFixedPushSymlinkTimestamp = "fixed_push_symlink_timestamp";
const char* const kFeatureAbbExec = "abb_exec";
const char* const kFeatureRemountShell = "remount_shell";
const char* const kFeatureSendRecv2 = "sendrecv_v2";
const char* const kFeatureSendRecv2DryRunSend = "sendrecv_v2_dry_run_send";
const char* const kFeatureDelayedAck = "delayed_ack";
const char* const kFeatureDevRaw = "devraw";

namespace {


}  // namespace

TransportId NextTransportId() {
    static std::atomic<TransportId> next(1);
    return next++;
}

void Connection::Reset() {
    LOG(INFO) << "Connection::Reset(): stopping";
    Stop();
}

std::string Connection::Serial() const {
    return transport_ ? transport_->serial_name() : "<unknown>";
}

BlockingConnectionAdapter::BlockingConnectionAdapter(std::unique_ptr<BlockingConnection> connection)
    : underlying_(std::move(connection)) {}

BlockingConnectionAdapter::~BlockingConnectionAdapter() {
    LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): destructing";
    Stop();
}

bool BlockingConnectionAdapter::Start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (started_) {
        LOG(FATAL) << "BlockingConnectionAdapter(" << Serial() << "): started multiple times";
    }

    StartReadThread();

    write_thread_ = std::thread([this]() {
        LOG(INFO) << Serial() << ": write thread spawning";
        while (true) {
            std::unique_lock<std::mutex> lock(mutex_);
            ScopedLockAssertion assume_locked(mutex_);
            cv_.wait(lock, [this]() REQUIRES(mutex_) {
                return this->stopped_ || !this->write_queue_.empty();
            });

            if (this->stopped_) {
                return;
            }

            std::unique_ptr<apacket> packet = std::move(this->write_queue_.front());
            this->write_queue_.pop_front();
            lock.unlock();

            if (!this->underlying_->Write(packet.get())) {
                break;
            }
        }
        std::call_once(this->error_flag_, [this]() { transport_->HandleError("write failed"); });
    });

    started_ = true;
    return true;
}

void BlockingConnectionAdapter::StartReadThread() {
    read_thread_ = std::thread([this]() {
        LOG(INFO) << Serial() << ": read thread spawning";
        while (true) {
            auto packet = std::make_unique<apacket>();
            if (!underlying_->Read(packet.get())) {
                PLOG(INFO) << Serial() << ": read failed";
                break;
            }

            transport_->HandleRead(std::move(packet));
        }
        std::call_once(this->error_flag_, [this]() { transport_->HandleError("read failed"); });
    });
}

void BlockingConnectionAdapter::Reset() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!started_) {
            LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): not started";
            return;
        }

        if (stopped_) {
            LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): already stopped";
            return;
        }
    }

    LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): resetting";
    this->underlying_->Reset();
    Stop();
}

void BlockingConnectionAdapter::Stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!started_) {
            LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): not started";
            return;
        }

        if (stopped_) {
            LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): already stopped";
            return;
        }

        stopped_ = true;
    }

    LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): stopping";

    this->underlying_->Close();
    this->cv_.notify_one();

    // Move the threads out into locals with the lock taken, and then unlock to let them exit.
    std::thread read_thread;
    std::thread write_thread;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        read_thread = std::move(read_thread_);
        write_thread = std::move(write_thread_);
    }

    read_thread.join();
    write_thread.join();

    LOG(INFO) << "BlockingConnectionAdapter(" << Serial() << "): stopped";
    std::call_once(this->error_flag_, [this]() { transport_->HandleError("requested stop"); });
}

bool BlockingConnectionAdapter::Write(std::unique_ptr<apacket> packet) {
    {
        std::lock_guard<std::mutex> lock(this->mutex_);
        write_queue_.emplace_back(std::move(packet));
    }

    cv_.notify_one();
    return true;
}

FdConnection::FdConnection(unique_fd fd) : fd_(std::move(fd)) {}

FdConnection::~FdConnection() {}

bool FdConnection::DispatchRead(void* buf, size_t len) {
    return ReadFdExactly(fd_.get(), buf, len);
}

bool FdConnection::DispatchWrite(void* buf, size_t len) {
    return WriteFdExactly(fd_.get(), buf, len);
}

bool FdConnection::Read(apacket* packet) {
    if (!DispatchRead(&packet->msg, sizeof(amessage))) {
        D("remote local: read terminated (message)");
        return false;
    }

    if (packet->msg.data_length > MAX_PAYLOAD) {
        D("remote local: read overflow (data length = %" PRIu32 ")", packet->msg.data_length);
        return false;
    }

    packet->payload.resize(packet->msg.data_length);

    if (!DispatchRead(&packet->payload[0], packet->payload.size())) {
        D("remote local: terminated (data)");
        return false;
    }

    return true;
}

bool FdConnection::Write(apacket* packet) {
#ifdef IRA_VM
    /* Every packet the device hands to the wire passes here. If this stops while the host is
     * still waiting, the stall is above this line and not in the transport below it. */
    fprintf(stderr, "ira-write: cmd=0x%08x payload=%u\n", packet->msg.command,
            packet->msg.data_length);
#endif
    if (!DispatchWrite(&packet->msg, sizeof(packet->msg))) {
        D("remote local: write terminated");
        return false;
    }

    if (packet->msg.data_length) {
        if (!DispatchWrite(&packet->payload[0], packet->msg.data_length)) {
            D("remote local: write terminated");
            return false;
        }
    }

    return true;
}

void FdConnection::Close() {
    adb_shutdown(fd_.get());
    fd_.reset();
}

void send_packet(apacket* p, atransport* t) {
#ifdef IRA_VM
    /* The one place every outgoing packet passes on its way to a transport. A probe here settles
     * whether the device stopped producing packets or whether they stopped being delivered. */
    fprintf(stderr, "ira-send: cmd=0x%08x payload=%u\n", p->msg.command, p->msg.data_length);
#endif
    p->msg.magic = p->msg.command ^ 0xffffffff;
    // compute a checksum for connection/auth packets for compatibility reasons
    if (t->get_protocol_version() >= A_VERSION_SKIP_CHECKSUM) {
        p->msg.data_check = 0;
    } else {
        p->msg.data_check = calculate_apacket_checksum(p);
    }

    VLOG(TRANSPORT) << dump_packet(t->serial.c_str(), "to remote", p);

    if (t == nullptr) {
        LOG(FATAL) << "Transport is null";
    }

    if (t->Write(p) != 0) {
        D("%s: failed to enqueue packet, closing transport", t->serial.c_str());
        t->Kick();
    }
}

void kick_transport(atransport* t, bool reset) {
    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    // As kick_transport() can be called from threads without guarantee that t is valid,
    // check if the transport is in transport_list first.
    //
    // TODO(jmgao): WTF? Is this actually true?
    if (std::find(transport_list.begin(), transport_list.end(), t) != transport_list.end()) {
        if (reset) {
            t->Reset();
        } else {
            t->Kick();
        }
    }

}




static void fdevent_unregister_transport(atransport* t) {
    VLOG(TRANSPORT) << "unregistering transport: " << t->serial;

    {
        std::lock_guard<std::recursive_mutex> lock(transport_lock);
        transport_list.remove(t);
        pending_list.remove(t);
    }

    delete t;

}

static void fdevent_register_transport(atransport* t) {
    auto state = to_string(t->GetConnectionState());
    VLOG(TRANSPORT) << "registering: " << t->serial.c_str() << " state=" << state
                    << " type=" << t->type;

    /* don't create transport threads for inaccessible devices */
    if (t->GetConnectionState() != kCsNoPerm) {
        t->connection()->SetTransport(t);

        VLOG(TRANSPORT) << "Starting transport:" << t->serial;
        t->connection()->Start();
    }

    {
        std::lock_guard<std::recursive_mutex> lock(transport_lock);
        auto it = std::find(pending_list.begin(), pending_list.end(), t);
        if (it != pending_list.end()) {
            pending_list.remove(t);
            transport_list.push_front(t);
        }
    }

}


void kick_all_transports() {
    // To avoid only writing part of a packet to a transport after exit, kick all transports.
    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    for (auto t : transport_list) {
        t->Kick();
    }
}

void kick_all_transports_by_auth_key(std::string_view auth_key) {
    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    for (auto t : transport_list) {
        if (auth_key == t->auth_key) {
            t->Kick();
        }
    }
}

void register_transport(atransport* transport) {
    fdevent_run_on_looper([=]() { fdevent_register_transport(transport); });
}

static void remove_transport(atransport* transport) {
    fdevent_run_on_looper([=]() { fdevent_unregister_transport(transport); });
}

static void transport_destroy(atransport* t) {
    fdevent_check_looper();
    CHECK(t != nullptr);

    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    VLOG(TRANSPORT) << "destroying transport " << t->serial_name();
    t->connection()->Stop();

    D("transport: %s destroy (kicking and closing)", t->serial.c_str());
    remove_transport(t);
}


atransport::~atransport() {
}

int atransport::Write(apacket* p) {
    return this->connection()->Write(std::unique_ptr<apacket>(p)) ? 0 : -1;
}

void atransport::Reset() {
    if (!kicked_.exchange(true)) {
        LOG(INFO) << "resetting transport " << this << " " << this->serial;
        this->connection()->Reset();
    }
}

void atransport::Kick() {
    if (!kicked_.exchange(true)) {
        LOG(INFO) << "kicking transport " << this << " " << this->serial;
        this->connection()->Stop();
    }
}

ConnectionState atransport::GetConnectionState() const {
    return connection_state_;
}

void atransport::SetConnectionState(ConnectionState state) {
    fdevent_check_looper();
    connection_state_ = state;
}


void atransport::SetConnection(std::shared_ptr<Connection> connection) {
    std::lock_guard<std::mutex> lock(mutex_);
    connection_ = std::shared_ptr<Connection>(std::move(connection));
}

bool atransport::HandleRead(std::unique_ptr<apacket> p) {
    if (!check_header(p.get(), this)) {
        D("%s: remote read: bad header", serial.c_str());
        return false;
    }

    VLOG(TRANSPORT) << dump_packet(serial.c_str(), "from remote", p.get());
    apacket* packet = p.release();

    // This needs to run on the looper thread since the associated fdevent
    // message pump exists in that context.
    fdevent_run_on_looper([packet, this]() { handle_packet(packet, this); });

    return true;
}

void atransport::HandleError(const std::string& error) {
    LOG(INFO) << serial_name() << ": connection terminated: " << error;
    fdevent_run_on_looper([this]() {
        handle_offline(this);
        transport_destroy(this);
    });
}

void atransport::update_version(int version, size_t payload) {
    protocol_version = std::min(version, A_VERSION);
    /* How much this side puts in one packet. AOSP offers MAX_PAYLOAD here and
     * leaves splitting to the transport, and so does this: ira_bridge breaks a
     * payload into 16 KiB bulk requests, so a large packet is still many small
     * USB transfers rather than one oversized request that a controller may
     * refuse. The earlier 16 KiB cap made every packet pay the framing and
     * round-trip cost of a whole packet for 16 KiB of data. */
    max_payload = std::min(payload, (size_t)MAX_PAYLOAD);
}

int atransport::get_protocol_version() const {
    return protocol_version;
}


size_t atransport::get_max_payload() const {
    return max_payload;
}


const FeatureSet& supported_features() {
    static const android::base::NoDestructor<FeatureSet> features([]() {
        // Increment ADB_SERVER_VERSION when adding a feature that adbd needs
        // to know about. Otherwise, the client can be stuck running an old
        // version of the server even after upgrading their copy of adb.
        // (http://b/24370690)

        // clang-format off
        FeatureSet result {
            kFeatureShell2,
            kFeatureCmd,
            kFeatureStat2,
            kFeatureLs2,
            kFeatureFixedPushMkdir,
            kFeatureApex,
            kFeatureAbb,
            kFeatureFixedPushSymlinkTimestamp,
            kFeatureAbbExec,
            kFeatureRemountShell,
            kFeatureSendRecv2,
            kFeatureSendRecv2DryRunSend,
            kFeatureDevRaw,
/* kFeatureDelayedAck is not advertised from here: byte-granular window accounting for this
             * side's own output has never been verified end to end, and a window that closes early
             * looks exactly like a transfer that stops with both ends alive. The classic
             * per-packet acknowledgement is what this advertises instead. */
        };
        // clang-format on

        return result;
    }());

    return *features;
}

std::string FeatureSetToString(const FeatureSet& features) {
    return android::base::Join(features, ',');
}

FeatureSet StringToFeatureSet(const std::string& features_string) {
    if (features_string.empty()) {
        return FeatureSet();
    }

    return android::base::Split(features_string, ",");
}

template <class Range, class Value>
static bool contains(const Range& r, const Value& v) {
    return std::find(std::begin(r), std::end(r), v) != std::end(r);
}

bool CanUseFeature(const FeatureSet& feature_set, const std::string& feature) {
    return contains(feature_set, feature) && contains(supported_features(), feature);
}

bool atransport::has_feature(const std::string& feature) const {
    return contains(features_, feature);
}

void atransport::SetFeatures(const std::string& features_string) {
    features_ = StringToFeatureSet(features_string);
    delayed_ack_ = CanUseFeature(features_, kFeatureDelayedAck);
}

void atransport::AddDisconnect(adisconnect* disconnect) {
    disconnects_.push_back(disconnect);
}

void atransport::RemoveDisconnect(adisconnect* disconnect) {
    disconnects_.remove(disconnect);
}

void atransport::RunDisconnects() {
    for (const auto& disconnect : disconnects_) {
        disconnect->func(disconnect->opaque, this);
    }
    disconnects_.clear();
}


bool check_header(apacket* p, atransport* t) {
    if (p->msg.magic != (p->msg.command ^ 0xffffffff)) {
        VLOG(RWX) << "check_header(): invalid magic command = " << std::hex << p->msg.command
                  << ", magic = " << p->msg.magic;
        return false;
    }

    if (p->msg.data_length > t->get_max_payload()) {
        VLOG(RWX) << "check_header(): " << p->msg.data_length
                  << " atransport::max_payload = " << t->get_max_payload();
        return false;
    }

    return true;
}
