// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <stdlib.h>

#include "sysdeps/env.h"


#include <android-base/utf8.h>

namespace adb {
namespace sysdeps {

std::optional<std::string> GetEnvironmentVariable(std::string_view var) {
    if (var.empty()) {
        return std::nullopt;
    }

    const char* val = getenv(var.data());
    if (val == nullptr) {
        return std::nullopt;
    }

    return std::make_optional(std::string(val));
}

constexpr char kHostNameEnvVar[] = "HOSTNAME";
constexpr char kUserNameEnvVar[] = "LOGNAME";

std::string GetHostNameUTF8() {
    const auto hostName = GetEnvironmentVariable(kHostNameEnvVar);
    if (hostName && !hostName->empty()) {
        return *hostName;
    }

    char buf[256];
    return (gethostname(buf, sizeof(buf)) == -1) ? "" : buf;
}

std::string GetLoginNameUTF8() {
    const auto userName = GetEnvironmentVariable(kUserNameEnvVar);
    if (userName && !userName->empty()) {
        return *userName;
    }

    const char* login = getlogin();
    return login ? login : "";
}

}  // namespace sysdeps
}  // namespace adb
