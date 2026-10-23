// SPDX-License-Identifier: AGPL-3.0-or-later
#include <cstdio>
#include <cstdlib>

extern "C" int __android_log_print(int, const char*, const char*, ...) { return 0; }
#include "../src/zygisk/ira_fw.cpp"

namespace {
zygisk::internal::module_abi* registered = nullptr;
unsigned unload_requests = 0;
void expect(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}
bool register_module(zygisk::internal::api_table*, zygisk::internal::module_abi* abi) {
    registered = abi;
    return true;
}
void set_option(void*, zygisk::Option option) {
    expect(option == zygisk::Option::DLCLOSE_MODULE_LIBRARY, "only module unload is requested");
    ++unload_requests;
}
}
int main() {
    zygisk::internal::api_table api{};
    api.registerModule = register_module;
    api.setOption = set_option;
    // A null JNI env also proves app callbacks do not load or execute the dex.
    zygisk_module_entry(&api, nullptr);
    expect(registered != nullptr, "framework module registers through the real entry point");
    expect(unload_requests == 0, "onLoad does not unload the server module");
    registered->preServerSpecialize(registered->impl, nullptr);
    expect(unload_requests == 0, "server specialization keeps its module resident");
    registered->preAppSpecialize(registered->impl, nullptr);
    expect(unload_requests == 1, "all app specializations request module unload");
    registered->postAppSpecialize(registered->impl, nullptr);
    expect(unload_requests == 1, "app post-specialization does not initialize a payload");
    expect(g_vm == nullptr && g_payload == nullptr && g_main == nullptr,
           "no Java VM, payload, or worker initialized for app processes");
    std::puts("PASS: application callbacks request unload without executing the framework payload");
}
