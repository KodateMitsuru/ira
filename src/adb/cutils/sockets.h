// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
/*
 * Copyright (C) 2006 The Android Open Source Project
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

// Selected libcutils socket ABI used by the platform library adapter.
#define ANDROID_SOCKET_NAMESPACE_ABSTRACT 0
#define ANDROID_SOCKET_NAMESPACE_RESERVED 1
#define ANDROID_SOCKET_NAMESPACE_FILESYSTEM 2

#ifdef __cplusplus
extern "C" {
#endif
int socket_network_client_timeout(const char* host, int port, int type,
                                  int timeout, int* getaddrinfo_error);
int socket_local_server(const char* name, int namespace_id, int type);
int socket_local_client(const char* name, int namespace_id, int type);
int socket_inaddr_any_server(int port, int type);
int socket_get_local_port(int fd);
#ifdef __cplusplus
}
#endif
