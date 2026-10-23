// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef IRA_NAMES_H
#define IRA_NAMES_H

#include <stddef.h>

/* One endpoint of this installation. `role` is "ctl", "auth" or "su"; the name comes from
 * names, written once per install next to the daemon. A name is never a constant and has no
 * fallback: a name a probe can guess is a name a probe can dial. Returns false and sets errno when
 * the file, the role or the name is not usable. */
bool ira_socket_name(const char* role, char* out, size_t cap);

#endif /* IRA_NAMES_H */
