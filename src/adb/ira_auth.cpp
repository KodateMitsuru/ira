// SPDX-License-Identifier: AGPL-3.0-or-later
// AOSP libadbd_auth owns key enumeration, prompt serialization and lifecycle packets. IRA only
// supplies a private listener and maps its callbacks onto libadb's looper-owned transports.
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <map>
#include <string>
#include <thread>
#include <vector>
#include <adbd_auth.h>
#include "adbd_auth_internal.h"
#include "adb.h"
#include "adb_auth.h"
#include "sysdeps.h"
#include "transport.h"
#include "ira_names.h"
#include <crypto_utils/android_pubkey.h>
#include <openssl/base64.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/nid.h>
#include "ira_ffs.h"

bool auth_required = true;
bool socket_access_allowed = true;
static AdbdAuthContext* auth_context;
static std::map<uint64_t, weak_ptr<atransport>> g_auth_transports;
static std::map<atransport*, weak_ptr<atransport>> g_live_auth_transports;
static uint64_t g_next_auth_id = 1;

static std::string_view key_blob(std::string_view key) {
    return key.substr(0, key.find_first_of(" \t\r\n"));
}
static bool decode_key(std::string_view input, std::string* output) {
    size_t capacity = 0;
    if (!EVP_DecodedLength(&capacity, input.size())) return false;
    output->resize(capacity);
    size_t size = 0;
    if (!EVP_DecodeBase64(reinterpret_cast<uint8_t*>(output->data()), &size, capacity,
                          reinterpret_cast<const uint8_t*>(input.data()), input.size()) ||
        size != ANDROID_PUBKEY_ENCODED_SIZE) return false;
    output->resize(size);
    return true;
}

bool adbd_auth_verify(const char* token, size_t token_size, const std::string& signature,
                      std::string* key) {
    if (!auth_context) return false;
    struct Verify { const char* token; size_t size; const std::string& signature; std::string* key; bool ok; };
    Verify verify{token, token_size, signature, key, false};
    adbd_auth_get_public_keys(auth_context, [](void* opaque, const char* line, size_t length) {
        auto& v = *static_cast<Verify*>(opaque);
        std::string_view text(line, length);
        std::string decoded;
        if (!decode_key(key_blob(text), &decoded)) return true;
        RSA* raw = nullptr;
        if (!android_pubkey_decode(reinterpret_cast<const uint8_t*>(decoded.data()), decoded.size(), &raw))
            return true;
        bssl::UniquePtr<RSA> public_key(raw);
        if (!RSA_verify(NID_sha1, reinterpret_cast<const uint8_t*>(v.token), v.size,
                        reinterpret_cast<const uint8_t*>(v.signature.data()), v.signature.size(),
                        public_key.get())) return true;
        v.key->assign(line, length);
        v.ok = true;
        return false;
    }, &verify);
    return verify.ok;
}

static void auth_disconnected(void*, atransport* t) {
    if (t->auth_id && auth_context) {
        adbd_auth_notify_disconnect(auth_context, *t->auth_id);
        auth_context->Interrupt();
    }
    t->auth_id.reset();
    g_live_auth_transports.erase(t);
    for (auto it = g_auth_transports.begin(); it != g_auth_transports.end();) {
        if (it->second.get() == t) it = g_auth_transports.erase(it); else ++it;
    }
}
static adisconnect g_auth_disconnect = {auth_disconnected, nullptr};
static void track_auth_transport(atransport* t) {
    if (g_live_auth_transports.emplace(t, t->weak()).second) t->AddDisconnect(&g_auth_disconnect);
}

void adbd_auth_verified(atransport* t) {
    track_auth_transport(t);
    handle_online(t);
    send_connect(t);
}
static void finish_auth_confirmation(uint64_t cookie, uint64_t id) {
    auto it = g_auth_transports.find(cookie);
    if (it == g_auth_transports.end()) return;
    atransport* t = it->second.get();
    g_auth_transports.erase(it);
    if (!t || !t->auth_id || *t->auth_id != id) return;
    adbd_auth_verified(t);
}
static void key_authorized(void* opaque, uint64_t id) {
    uint64_t cookie = reinterpret_cast<uintptr_t>(opaque);
    fdevent_run_on_looper([cookie, id] { finish_auth_confirmation(cookie, id); });
}
static void revoke_key(std::string key) {
    std::vector<weak_ptr<atransport>> targets;
    for (auto& [identity, weak] : g_live_auth_transports) {
        auto* t = weak.get();
        if (t && key_blob(t->auth_key) == key_blob(key)) targets.push_back(t->weak());
    }
    for (auto& weak : targets) {
        if (auto* t = weak.get()) { handle_offline(t); kick_transport(t, false); }
    }
}
static void key_removed(const char* key, size_t length) {
    std::string copy(key, length);
    fdevent_run_on_looper([copy = std::move(copy)] { revoke_key(copy); });
}
void adbd_auth_revoke() {
    g_auth_transports.clear();
    auto transports = std::move(g_live_auth_transports);
    g_live_auth_transports.clear();
    for (auto& [identity, weak] : transports) {
        if (auto* t = weak.get()) { handle_offline(t); kick_transport(t, false); }
    }
    fprintf(stderr, "ira-auth: revoked %zu active/pending transport(s)\n", transports.size());
    extern void ira_ffs_reset_usb_session(void) __attribute__((weak));
    if (ira_ffs_reset_usb_session)
        ira_ffs_reset_usb_session();
}

/* The framework half dials the "auth" endpoint named in the module's names file. Its name is this
 * installation's, so the image the framework loads carries a per-install name rather than a
 * constant the platform could be probed for. */
static int private_auth_listener() {
    char name[108];
    if (!ira_socket_name("auth", name, sizeof(name))) return -1;
    const size_t length = strlen(name);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path + 1, name, length);
    unique_fd listener(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
    if (listener < 0 || bind(listener.get(), reinterpret_cast<sockaddr*>(&address),
                          offsetof(sockaddr_un, sun_path) + 1 + length) < 0) return -1;
    return listener.release();
}
void adbd_auth_init() {
    int listener = private_auth_listener();
    if (listener < 0) { fprintf(stderr, "ira-auth: no auth endpoint in the module names file: %s\n", strerror(errno)); abort(); }
    AdbdAuthCallbacksV1 callbacks{};
    callbacks.version = 1;
    callbacks.key_authorized = key_authorized;
    callbacks.key_removed = key_removed;
    auth_context = new AdbdAuthContext(&callbacks, listener);
    auth_context->InitFrameworkHandlers();
    std::thread([] { auth_context->Run(); }).detach();
}
void adbd_auth_confirm_key(atransport* t) {
    if (!auth_context || !t || t->auth_key.empty()) return;
    const uint64_t cookie = g_next_auth_id++;
    g_auth_transports[cookie] = t->weak();
    track_auth_transport(t);
    t->auth_id = adbd_auth_prompt_user_with_id(auth_context, t->auth_key.data(), t->auth_key.size(),
                                               reinterpret_cast<void*>(cookie));
}
void adbd_notify_framework_connected_key(atransport* t) {
    if (!auth_context || t->auth_id) return;
    track_auth_transport(t);
    t->auth_id = adbd_auth_notify_auth(auth_context, t->auth_key.data(), t->auth_key.size());
    auth_context->Interrupt();
}
void send_auth_key_request(atransport* t) {
    apacket* p = get_apacket();
    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_RSAPUBLICKEY;
    p->msg.magic = A_AUTH ^ 0xffffffff;
    send_packet(p, t);
}
void send_auth_request(atransport* t) {
    char token[TOKEN_SIZE];
    if (RAND_bytes(reinterpret_cast<uint8_t*>(token), sizeof(token)) != 1) {
        memset(t->token, 0, sizeof(t->token));
        fprintf(stderr, "ira-auth: secure random source failed: %s\n", strerror(errno));
        kick_transport(t, false);
        return;
    }
    apacket* p = get_apacket();
    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_TOKEN;
    p->msg.data_length = TOKEN_SIZE;
    p->msg.magic = A_AUTH ^ 0xffffffff;
    p->payload.assign(token, token + sizeof(token));
    memcpy(t->token, token, sizeof(token));
    send_packet(p, t);
}
