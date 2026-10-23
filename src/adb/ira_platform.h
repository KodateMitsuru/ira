// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// Thin ABI adapters to the device's libcutils, libselinux, libadbd_fs and minijail.
#include <stdint.h>
#include <sys/types.h>

// Platform ABI declarations used by the dynamically resolved implementations.
bool adbd_fs_config(const char* path, bool is_dir, const char* context, uid_t* uid, gid_t* gid,
                    mode_t* mode, uint64_t* capabilities);
extern "C" int selinux_android_restorecon(const char* path, unsigned int flags);
extern "C" int selinux_android_setcon(const char* context);

int ira_platform_init();
int ira_platform_enter_service_identity(bool root);
