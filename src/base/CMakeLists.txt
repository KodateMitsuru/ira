# SPDX-License-Identifier: AGPL-3.0-or-later
add_library(android-base STATIC
  chrono_utils.cpp cmsg.cpp errors_unix.cpp file.cpp hex.cpp mapped_file.cpp
  parsebool.cpp parsenetaddress.cpp process.cpp properties.cpp stringprintf.cpp
  strings.cpp threads.cpp posix_strerror_r.cpp logging.cpp)
target_include_directories(android-base PUBLIC include PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(android-base PUBLIC ira-platform-options)
target_compile_options(android-base PRIVATE -Wno-everything)
if(ANDROID)
  target_link_libraries(android-base PUBLIC log)
endif()
