# SPDX-License-Identifier: AGPL-3.0-or-later
set(_sources
  adb.cpp adb_io.cpp adb_listeners.cpp adb_trace.cpp adb_utils.cpp
  apacket_reader.cpp fdevent/fdevent.cpp fdevent/fdevent_epoll.cpp services.cpp sockets.cpp
  socket_spec.cpp sysdeps/env.cpp sysdeps/errno.cpp sysdeps_unix.cpp sysdeps/posix/network.cpp
  transport.cpp transport_fd.cpp types.cpp daemon/services.cpp daemon/shell_service.cpp
  daemon/file_sync_service.cpp daemon/abb_service.cpp daemon/logging.cpp shell_service_protocol.cpp
  ira_bridge.cpp ira_ffs.cpp ira_auth.cpp ira_privileges.cpp ira_names.cpp
  ira_su_server.cpp ira_platform.cpp
  ira_service_backend.cpp)

add_library(ira-adb-options INTERFACE)
target_include_directories(ira-adb-options INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(ira-adb-options INTERFACE android-base adbd-auth-headers android-pubkey)
if(NOT ANDROID)
  target_compile_definitions(ira-adb-options INTERFACE IRA_VM=1 IRA_SESSION_SHELL="/bin/sh")
endif()
add_library(ira-adb OBJECT ${_sources})
target_link_libraries(ira-adb PUBLIC ira-adb-options)
target_compile_options(ira-adb PRIVATE -O2 -Wno-everything)
add_executable(ira-daemon ira_main.cpp $<TARGET_OBJECTS:ira-adb>)
target_link_libraries(ira-daemon PRIVATE ira-adb-options adbd-auth dl)
if(ANDROID)
  target_link_options(ira-daemon PRIVATE -Wl,--strip-all)
  add_executable(platform-device-probe EXCLUDE_FROM_ALL
    "${IRA_ROOT}/tests/test_platform_device.cpp" $<TARGET_OBJECTS:ira-adb>)
  target_link_libraries(platform-device-probe PRIVATE ira-adb-options adbd-auth dl)
endif()
