# SPDX-License-Identifier: AGPL-3.0-or-later
add_library(android-pubkey STATIC android_pubkey.cpp)
target_include_directories(android-pubkey PUBLIC include)
target_link_libraries(android-pubkey PUBLIC crypto)
add_library(adbd-auth-headers INTERFACE)
target_include_directories(adbd-auth-headers INTERFACE include "${CMAKE_CURRENT_SOURCE_DIR}")
add_library(adbd-auth STATIC adbd_auth.cpp)
target_link_libraries(adbd-auth PUBLIC android-base adbd-auth-headers)
