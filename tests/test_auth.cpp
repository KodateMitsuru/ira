// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify Android wire-format keys and ADB's pre-hashed token signature with upstream crypto.
#include "../src/adb/ira_auth.cpp"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <array>
#include <sys/wait.h>

// This fixture enumerates keys synchronously and never creates a transport/event loop.
void fdevent_check_looper() {}
static std::vector<std::string> candidate_keys;
extern "C" void adbd_auth_get_public_keys(AdbdAuthContext*,
    bool (*callback)(void*, const char*, size_t), void* opaque) {
    for (const auto& line : candidate_keys)
        if (!callback(opaque, line.data(), line.size())) break;
}

static std::vector<uint8_t> read_file(const std::string& path) {
    FILE* file = fopen(path.c_str(), "rb");
    if (!file) { perror(path.c_str()); exit(1); }
    std::vector<uint8_t> bytes(4096);
    bytes.resize(fread(bytes.data(), 1, bytes.size(), file));
    fclose(file);
    return bytes;
}
static void check(bool ok, const char* what) {
    if (!ok) { fprintf(stderr, "FAIL: %s\n", what); exit(1); }
}
static void check_random_after_fork() {
    // Exercise CTR-DRBG initialization and copied process state, not just RSA verification.
    std::array<uint8_t, TOKEN_SIZE> first{}, parent{}, child{};
    check(RAND_bytes(first.data(), first.size()) == 1, "token RNG initializes");
    int fds[2];
    check(pipe(fds) == 0, "RNG fork pipe opens");
    pid_t pid = fork();
    check(pid >= 0, "RNG fixture forks");
    if (pid == 0) {
        adb_close(fds[0]);
        if (RAND_bytes(child.data(), child.size()) != 1) _exit(1);
        ssize_t n = adb_write(fds[1], child.data(), child.size());
        _exit(n == static_cast<ssize_t>(child.size()) ? 0 : 1);
    }
    adb_close(fds[1]);
    check(RAND_bytes(parent.data(), parent.size()) == 1, "parent token RNG continues");
    size_t received = 0;
    while (received < child.size()) {
        ssize_t n = adb_read(fds[0], child.data() + received, child.size() - received);
        if (n < 0 && errno == EINTR) continue;
        check(n > 0, "child token bytes received");
        received += static_cast<size_t>(n);
    }
    adb_close(fds[0]);
    int status;
    check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child token RNG succeeds");
    check(first != std::array<uint8_t, TOKEN_SIZE>{} && first != parent && parent != child,
          "tokens differ across successive calls and copied process state");
}

int main(int argc, char** argv) {
    check(argc == 2, "fixture directory provided");
    check_random_after_fork();
    std::string dir = argv[1];
    auto blob = read_file(dir + "/blob.bin");
    auto token = read_file(dir + "/token.bin");
    auto signature = read_file(dir + "/sig-raw.bin");
    RSA* raw = nullptr;
    check(android_pubkey_decode(blob.data(), blob.size(), &raw), "Android key decodes");
    bssl::UniquePtr<RSA> key(raw);
    auto verify = [&] { return RSA_verify(NID_sha1, token.data(), token.size(),
                                          signature.data(), signature.size(), key.get()) == 1; };
    check(verify(), "ADB token signature verifies");
    token[0] ^= 1;
    check(!verify(), "modified token is rejected");
    token[0] ^= 1;
    signature[0] ^= 1;
    check(!verify(), "modified signature is rejected");
    signature.pop_back();
    check(!verify(), "truncated signature is rejected");
    signature = read_file(dir + "/sig-sha1.bin");
    check(!verify(), "non-ADB double-hashed signature is rejected");
    raw = nullptr;
    check(!android_pubkey_decode(blob.data(), 16, &raw), "truncated Android key is rejected");
    blob[0] ^= 1;
    check(!android_pubkey_decode(blob.data(), blob.size(), &raw), "invalid modulus size is rejected");
    blob[0] ^= 1;
    size_t capacity = 0;
    check(EVP_EncodedLength(&capacity, blob.size()), "base64 capacity");
    std::string encoded(capacity, '\0');
    encoded.resize(EVP_EncodeBlock(reinterpret_cast<uint8_t*>(encoded.data()), blob.data(), blob.size()));
    candidate_keys = {"invalid!! comment", "YQ== short-key", encoded + " host@fixture"};
    signature = read_file(dir + "/sig-raw.bin");
    std::string signature_text(reinterpret_cast<const char*>(signature.data()), signature.size());
    std::string matched;
    auth_context = reinterpret_cast<AdbdAuthContext*>(1);
    check(adbd_auth_verify(reinterpret_cast<const char*>(token.data()), token.size(), signature_text, &matched),
          "production adapter skips invalid keys and verifies the ADB token");
    check(matched == candidate_keys.back(), "production adapter preserves authorized key identity");
    signature_text[0] ^= 1;
    check(!adbd_auth_verify(reinterpret_cast<const char*>(token.data()), token.size(), signature_text, &matched),
          "production adapter rejects modified signature");
    auth_context = nullptr;
    puts("PASS: token RNG/fork separation, Android key format, ADB signature and production auth adapter");
}
