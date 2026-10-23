// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
#pragma once

/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once
#include <stddef.h>
#include <stdint.h>

// USB-only subset of AOSP libadbd_auth. The private listener is mandatory;
// wireless lifecycle, mDNS, service factories and API-version discovery are omitted.
struct AdbdAuthCallbacksV1 {
    uint32_t version;
    void (*key_authorized)(void* opaque, uint64_t id);
    void (*key_removed)(const char* public_key, size_t length);
};
struct AdbdAuthContext;
extern "C" {
void adbd_auth_get_public_keys(AdbdAuthContext* ctx,
    bool (*callback)(void*, const char*, size_t), void* opaque);
uint64_t adbd_auth_notify_auth(AdbdAuthContext* ctx, const char* public_key, size_t len);
void adbd_auth_notify_disconnect(AdbdAuthContext* ctx, uint64_t id);
uint64_t adbd_auth_prompt_user_with_id(AdbdAuthContext* ctx,
    const char* public_key, size_t len, void* opaque);
}
