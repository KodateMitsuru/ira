// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


// Make sure that host file mode values match the ones on the device.
static_assert(S_IFMT == 00170000, "");
static_assert(S_IFLNK == 0120000, "");
static_assert(S_IFREG == 0100000, "");
static_assert(S_IFBLK == 0060000, "");
static_assert(S_IFDIR == 0040000, "");
static_assert(S_IFCHR == 0020000, "");
