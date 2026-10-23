# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is included only in the NDK sub-build. CMake owns C/C++ flags and dependencies.
find_package(Java 17 REQUIRED COMPONENTS Development)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(IRA_SDK "/opt/android-sdk" CACHE PATH "Android SDK root")
file(GLOB _jars "${IRA_SDK}/platforms/*/android.jar")
file(GLOB _dexers "${IRA_SDK}/build-tools/*/d8")
list(SORT _jars COMPARE NATURAL ORDER DESCENDING)
list(SORT _dexers COMPARE NATURAL ORDER DESCENDING)
if(NOT _jars OR NOT _dexers)
  message(FATAL_ERROR "android.jar and d8 are required under IRA_SDK=${IRA_SDK}")
endif()
list(GET _jars 0 IRA_ANDROID_JAR)
list(GET _dexers 0 IRA_D8)
file(GLOB_RECURSE _java CONFIGURE_DEPENDS "${IRA_ROOT}/src/zygisk/java/*.java")
set(_payload "${CMAKE_BINARY_DIR}/payload")
add_custom_command(OUTPUT "${_payload}/ira_dex.h"
  COMMAND ${CMAKE_COMMAND} -DROOT=${IRA_ROOT} -DOUT=${_payload}
          -DJAVAC=${Java_JAVAC_EXECUTABLE} -DD8=${IRA_D8} -DJAR=${IRA_ANDROID_JAR}
          -DPYTHON=${Python3_EXECUTABLE} -P "${CMAKE_CURRENT_SOURCE_DIR}/EmbedJava.cmake"
  DEPENDS ${_java} "${CMAKE_CURRENT_SOURCE_DIR}/EmbedJava.cmake" "${IRA_ROOT}/scripts/payload.py"
  VERBATIM)
add_library(ira-framework SHARED "${IRA_ROOT}/src/zygisk/ira_fw.cpp" "${_payload}/ira_dex.h")
add_library(ira-gadget SHARED "${IRA_ROOT}/src/zygisk/ira_zygisk.cpp")
foreach(_target ira-framework ira-gadget)
  target_compile_features(${_target} PRIVATE cxx_std_20)
  target_compile_options(${_target} PRIVATE -O2 -fvisibility=hidden -fno-exceptions -fno-rtti
    -mbranch-protection=standard -Wall -Wextra -Wno-unused-parameter)
  target_include_directories(${_target} PRIVATE "${IRA_ROOT}/src/zygisk" "${_payload}")
  target_link_libraries(${_target} PRIVATE log)
  target_link_options(${_target} PRIVATE -Wl,--strip-all)
endforeach()
set_target_properties(ira-framework PROPERTIES PREFIX "" OUTPUT_NAME "arm64-v8a"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/zygisk")
set_target_properties(ira-gadget PROPERTIES PREFIX "" OUTPUT_NAME "ira-zn"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
add_custom_command(TARGET ira-framework POST_BUILD
  COMMAND ${Python3_EXECUTABLE} "${IRA_ROOT}/scripts/payload.py" check $<TARGET_FILE:ira-framework> framework VERBATIM)
add_custom_command(TARGET ira-gadget POST_BUILD
  COMMAND ${Python3_EXECUTABLE} "${IRA_ROOT}/scripts/payload.py" check $<TARGET_FILE:ira-gadget> gadget VERBATIM)
