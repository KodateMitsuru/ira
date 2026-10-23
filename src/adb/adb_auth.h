// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef __ADB_AUTH_H
#define __ADB_AUTH_H

#include "adb.h"


/* AUTH packets first argument */
/* Request */
#define ADB_AUTH_TOKEN         1
/* Response */
#define ADB_AUTH_SIGNATURE     2
#define ADB_AUTH_RSAPUBLICKEY  3


extern bool auth_required;
extern bool socket_access_allowed;

void adbd_auth_init();

// Called on the looper after the framework clears USB debugging authorizations.
void adbd_auth_revoke();

void adbd_auth_verified(atransport *t);

bool adbd_auth_verify(const char* token, size_t token_size, const std::string& sig,
                      std::string* auth_key);
void adbd_auth_confirm_key(atransport* t);
void adbd_notify_framework_connected_key(atransport* t);

void send_auth_request(atransport *t);

/* The other half of the exchange: what the device sends to be told the host's public key. */
void send_auth_key_request(atransport* t);



#endif // __ADB_AUTH_H
