// SPDX-License-Identifier: AGPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include <vector>
#include "../src/adb/ira_auth.cpp"

// These stubs test only IRA's looper/weak-reference adapter. The separate upstream-auth test
// exercises the actual library over sockets.
static uint64_t next_connection = 100;
static unsigned connected_notices, disconnected_notices;
void AdbdAuthContext::Interrupt() {}
extern "C" void adbd_auth_notify_disconnect(AdbdAuthContext*, uint64_t) { ++disconnected_notices; }
extern "C" uint64_t adbd_auth_notify_auth(AdbdAuthContext*, const char*, size_t) {
    ++connected_notices; return next_connection++;
}
extern "C" uint64_t adbd_auth_prompt_user_with_id(AdbdAuthContext*, const char*, size_t, void*) {
    return next_connection++;
}

static unsigned checks, closed, stopped, reset_requests;
void ira_ffs_reset_usb_session() { ++reset_requests; }
static std::vector<std::function<void()>> queued;
static std::map<atransport*, std::vector<adisconnect*>> callbacks;
static void expect(bool yes, const char* what) {
    if (!yes) { fprintf(stderr, "FAIL: %s\n", what); exit(1); }
    ++checks;
}
void fdevent_check_looper() {}
void fdevent_run_on_looper(std::function<void()> fn) { queued.push_back(std::move(fn)); }
TransportId NextTransportId() { static TransportId id = 1; return id++; }
atransport::~atransport() { callbacks.erase(this); }
void atransport::AddDisconnect(adisconnect* cb) { callbacks[this].push_back(cb); }
void handle_online(atransport* t) { t->online = true; }
void send_connect(atransport*) {}
void handle_offline(atransport* t) {
    t->online = false;
    ++closed;
    auto list = std::move(callbacks[t]);
    callbacks[t].clear();
    for (auto cb : list) cb->func(cb->opaque, t);
}
void kick_transport(atransport* t, bool reset) {
    expect(!t->online, "services offline before transport stop");
    expect(!reset, "transport kick leaves USB reset to the dedicated FFS hook");
    ++stopped;
}
int main() {
    atransport saved(kTransportUsb), once(kTransportUsb), pending(kTransportUsb);
    saved.auth_key = "saved";
    once.auth_key = "once";
    pending.auth_key = "pending";
    adbd_auth_verified(&saved);
    adbd_auth_verified(&once);
    track_auth_transport(&pending);
    track_auth_transport(&saved);
    expect(callbacks[&saved].size() == 1, "one cleanup callback per transport");
    const auto id = g_next_auth_id++;
    g_auth_transports[id] = pending.weak();
    queued.push_back([id] { finish_auth_confirmation(id, true); });
    adbd_auth_revoke();
    expect(!saved.online && !once.online && !pending.online, "saved, temporary and pending offline");
    expect(closed == 3 && stopped == 3, "each tracked transport closed and stopped immediately");
    expect(reset_requests == 1, "full revoke requests FunctionFS USB reset");
    expect(g_auth_transports.empty() && g_live_auth_transports.empty(), "all auth bookkeeping cleared");
    for (auto& fn : queued) fn();
    expect(!pending.online, "late approval cannot resurrect revoked connection");
    adbd_auth_revoke();
    expect(stopped == 3, "repeated revoke is idempotent");
    expect(reset_requests == 2, "revoke still resets USB when transport tracking is empty");
    auto* dead = new atransport(kTransportUsb);
    adbd_auth_verified(dead);
    delete dead;
    adbd_auth_revoke();
    expect(stopped == 3, "expired weak transport never dereferenced");
    auto* unplugged = new atransport(kTransportUsb);
    adbd_auth_verified(unplugged);
    handle_offline(unplugged);
    expect(g_live_auth_transports.empty(), "ordinary disconnect removes tracked auth state");
    delete unplugged;
    // Test the production callback adapter, not just a manually populated pending map.
    auth_context = reinterpret_cast<AdbdAuthContext*>(1);
    atransport pending_real(kTransportUsb);
    pending_real.auth_key = "real";
    const uint64_t cookie = g_next_auth_id;
    adbd_auth_confirm_key(&pending_real);
    expect(pending_real.auth_id.has_value(), "upstream prompt id attached to transport");
    finish_auth_confirmation(cookie, *pending_real.auth_id + 1);
    expect(!pending_real.online, "mismatched authorization id cannot approve a transport");
    const uint64_t retry = g_next_auth_id;
    adbd_auth_confirm_key(&pending_real);
    finish_auth_confirmation(retry, *pending_real.auth_id);
    expect(pending_real.online, "matching upstream callback approves the pending transport");
    handle_offline(&pending_real);
    expect(disconnected_notices == 1, "prompt-authorized disconnect is reported upstream");
    atransport used(kTransportUsb);
    used.auth_key = "saved-blob comment";
    adbd_auth_verified(&used);
    adbd_notify_framework_connected_key(&used);
    adbd_notify_framework_connected_key(&used);
    expect(connected_notices == 1, "key usage reported once per connection");
    revoke_key("different-key comment");
    expect(used.online, "removing unrelated key does not affect connection");
    revoke_key("saved-blob other-comment");
    expect(!used.online, "per-key removal uses cryptographic key identity");
    expect(disconnected_notices == 2, "per-key revoke reports disconnect exactly once");
    auth_context = nullptr;
    printf("PASS: %u daemon authorization revocation checks\n", checks);
}
