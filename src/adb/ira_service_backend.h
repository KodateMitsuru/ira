// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
#include <string_view>
enum class IraServiceOperation : unsigned { Open = 1, Listen = 2 };
int ira_service_backend_init();
bool ira_in_service_backend();
int ira_service_backend_main(bool root);
int ira_service_request(IraServiceOperation operation, std::string_view name, int* port = nullptr);
