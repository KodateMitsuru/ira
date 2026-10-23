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

#define TRACE_TAG SERVICES

#include "sysdeps.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cstring>
#include <thread>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "services.h"
#include "socket_spec.h"
#include "sysdeps.h"
#include "transport.h"
#include "ira_service_backend.h"

namespace {

void service_bootstrap_func(std::string service_name, std::function<void(unique_fd)> func,
                            unique_fd fd) {
    adb_thread_setname(android::base::StringPrintf("%s svc %d", service_name.c_str(), fd.get()));
    func(std::move(fd));
}

}  // namespace

unique_fd create_service_thread(const char* service_name, std::function<void(unique_fd)> func) {
    int s[2];
    if (adb_socketpair(s)) {
        printf("cannot create service socket pair\n");
        return unique_fd();
    }
    D("socketpair: (%d,%d)", s[0], s[1]);

    if (strcmp(service_name, "sync") == 0) {
        // Set file sync service socket to maximum size
        int max_buf = LINUX_MAX_SOCKET_SIZE;
        adb_setsockopt(s[0], SOL_SOCKET, SO_SNDBUF, &max_buf, sizeof(max_buf));
        adb_setsockopt(s[1], SOL_SOCKET, SO_SNDBUF, &max_buf, sizeof(max_buf));
    }

    std::thread(service_bootstrap_func, service_name, func, unique_fd(s[1])).detach();

    D("service thread started, %d:%d", s[0], s[1]);
    return unique_fd(s[0]);
}

unique_fd service_to_fd(std::string_view name, atransport* transport) {
    if (!ira_in_service_backend() && !name.starts_with("root:") &&
        !name.starts_with("unroot:") && !name.starts_with("reverse:") && name != "reconnect") {
        return unique_fd(ira_service_request(IraServiceOperation::Open, name));
    }
    unique_fd ret;

    if (is_socket_spec(name)) {
        std::string error;
        if (!socket_spec_connect(&ret, name, nullptr, nullptr, &error)) {
            LOG(ERROR) << "failed to connect to socket '" << name << "': " << error;
        }
    } else {
        ret = daemon_service_to_fd(name, transport);
    }

    if (ret >= 0) {
        close_on_exec(ret.get());
    }
    return ret;
}
