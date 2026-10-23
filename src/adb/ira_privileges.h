// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
bool ira_root_mode();
void ira_root_set(bool on);
int ira_privileges_child(bool stay_root);
void ira_child_signals();
int ira_session_shell_init();
int ira_session_shell_fd();
