# SPDX-License-Identifier: AGPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)
project(ira LANGUAGES NONE)

# Builds the FunctionFS daemon, private shell, hook libraries and KernelSU ZIP.
# All generated files are kept in the selected CMake binary directory.
include(ExternalProject)
set(IRA_ANDROID_API 31 CACHE STRING "Android API for all native payloads (31 or newer)")
if(IRA_ANDROID_API LESS 31)
  message(FATAL_ERROR "IRA requires Android API 31 or newer")
endif()
set(IRA_SDK "$ENV{ANDROID_SDK_ROOT}" CACHE PATH "Android SDK root")
if(NOT IRA_SDK)
  set(IRA_SDK "/opt/android-sdk")
endif()
find_program(IRA_HOST_CC NAMES clang REQUIRED)
find_program(IRA_HOST_CXX NAMES clang++ REQUIRED)
set(IRA_NDK "" CACHE PATH "Android NDK root")
if(NOT IRA_NDK)
  set(IRA_NDK "$ENV{ANDROID_NDK_HOME}")
endif()
if(NOT IRA_NDK AND EXISTS "/opt/android-ndk/build/cmake/android.toolchain.cmake")
  set(IRA_NDK "/opt/android-ndk")
endif()
if(NOT EXISTS "${IRA_NDK}/build/cmake/android.toolchain.cmake")
  message(FATAL_ERROR "Android NDK required: -DIRA_NDK=/path/to/ndk or set ANDROID_NDK_HOME")
endif()
find_program(IRA_BASH NAMES bash REQUIRED)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
             "${CMAKE_CURRENT_SOURCE_DIR}/module/module.prop")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/module/module.prop" _prop)
foreach(_line IN LISTS _prop)
  if(_line MATCHES "^id=(.+)$")
    set(IRA_ID "${CMAKE_MATCH_1}")
  elseif(_line MATCHES "^version=(.+)$")
    set(IRA_BASE "${CMAKE_MATCH_1}")
  elseif(_line MATCHES "^versionCode=(.+)$")
    set(IRA_BASE_CODE "${CMAKE_MATCH_1}")
  endif()
endforeach()

function(ira_git out)
  execute_process(COMMAND git -C "${CMAKE_CURRENT_SOURCE_DIR}" ${ARGN}
                  OUTPUT_VARIABLE _out OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
                  RESULT_VARIABLE _rc)
  if(_rc EQUAL 0)
    set(${out} "${_out}" PARENT_SCOPE)
  else()
    set(${out} "" PARENT_SCOPE)
  endif()
endfunction()

ira_git(_tag describe --tags --abbrev=0)
ira_git(_hash rev-parse --short HEAD)
if(_tag)
  string(REGEX REPLACE "^v" "" _tag "${_tag}")
else()
  set(_tag "${IRA_BASE}")
endif()
if(_hash)
  ira_git(_dirty status --porcelain)
  if(_dirty)
    set(_hash "${_hash}-dirty")
  endif()
  set(IRA_VER "${_tag}+${_hash}")
else()
  set(IRA_VER "${_tag}")
endif()
if(_tag MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
  math(EXPR IRA_VERCODE "${CMAKE_MATCH_1} * 1000000 + ${CMAKE_MATCH_2} * 1000 + ${CMAKE_MATCH_3}")
else()
  set(IRA_VERCODE "${IRA_BASE_CODE}")
endif()
# Resolve paths through git so linked worktrees are supported as well as normal checkouts.
foreach(_ref HEAD packed-refs)
  ira_git(_ref_path rev-parse --git-path "${_ref}")
  if(_ref_path)
    get_filename_component(_ref_path "${_ref_path}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    if(EXISTS "${_ref_path}")
      set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_ref_path}")
    endif()
  endif()
endforeach()
ira_git(_branch symbolic-ref -q HEAD)
if(_branch)
  ira_git(_branch_path rev-parse --git-path "${_branch}")
  get_filename_component(_branch_path "${_branch_path}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
  if(EXISTS "${_branch_path}")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_branch_path}")
  endif()
endif()
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/module/module.prop" _prop_text)
string(REPLACE "version=${IRA_BASE}" "version=${IRA_VER}" _prop_text "${_prop_text}")
string(REPLACE "versionCode=${IRA_BASE_CODE}" "versionCode=${IRA_VERCODE}" _prop_text "${_prop_text}")
file(WRITE "${CMAKE_BINARY_DIR}/module.prop" "${_prop_text}")

set(IRA_ANDROID_DIR "${CMAKE_BINARY_DIR}/android")
set(IRA_HOST_DIR "${CMAKE_BINARY_DIR}/host")
set(IRA_STAGE "${CMAKE_BINARY_DIR}/stage")
set(IRA_ZIP "${CMAKE_BINARY_DIR}/dist/${IRA_ID}-${IRA_VER}.zip")
ExternalProject_Add(ira-android-build
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src" BINARY_DIR "${IRA_ANDROID_DIR}"
  CMAKE_ARGS "-DCMAKE_TOOLCHAIN_FILE=${IRA_NDK}/build/cmake/android.toolchain.cmake"
    -DANDROID_ABI=arm64-v8a "-DANDROID_PLATFORM=android-${IRA_ANDROID_API}" -DANDROID_STL=c++_static
    -DCMAKE_BUILD_TYPE=Release "-DIRA_SDK=${IRA_SDK}"
  BUILD_ALWAYS TRUE INSTALL_COMMAND "")
add_custom_target(ira-daemon DEPENDS ira-android-build)
add_custom_target(ira-shell DEPENDS ira-android-build)
add_custom_target(ira-hooks DEPENDS ira-android-build)
add_custom_target(platform-device-probe
  COMMAND ${CMAKE_COMMAND} --build "${IRA_ANDROID_DIR}" --target platform-device-probe
  DEPENDS ira-android-build VERBATIM)

ExternalProject_Add(ira-host-build EXCLUDE_FROM_ALL TRUE
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src" BINARY_DIR "${IRA_HOST_DIR}"
  CMAKE_ARGS "-DCMAKE_C_COMPILER=${IRA_HOST_CC}" "-DCMAKE_CXX_COMPILER=${IRA_HOST_CXX}"
    -DCMAKE_BUILD_TYPE=RelWithDebInfo "-DIRA_NDK=${IRA_NDK}"
    "-DIRA_SHELL=${IRA_ANDROID_DIR}/bin/mksh"
  BUILD_ALWAYS TRUE INSTALL_COMMAND "")
add_custom_target(check
  COMMAND ${CMAKE_CTEST_COMMAND} --test-dir "${IRA_HOST_DIR}" --output-on-failure
  DEPENDS ira-host-build ira-android-build USES_TERMINAL VERBATIM)

file(GLOB IRA_MODULE_FILES CONFIGURE_DEPENDS LIST_DIRECTORIES false
     "${CMAKE_CURRENT_SOURCE_DIR}/module/*")
set(IRA_MODULE_ITEMS)
foreach(_file IN LISTS IRA_MODULE_FILES)
  get_filename_component(_name "${_file}" NAME)
  list(APPEND IRA_MODULE_ITEMS "${_name}")
endforeach()
add_custom_target(module ALL
  COMMAND ${CMAKE_COMMAND} -E rm -rf "${IRA_STAGE}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${IRA_STAGE}/lib" "${IRA_STAGE}/zygisk" "${CMAKE_BINARY_DIR}/dist"
  COMMAND ${CMAKE_COMMAND} -E copy ${IRA_MODULE_FILES} "${IRA_STAGE}"
  COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/module/initrc" "${IRA_STAGE}/initrc"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_BINARY_DIR}/module.prop" "${IRA_STAGE}/module.prop"
  COMMAND ${CMAKE_COMMAND} -E copy "${IRA_ANDROID_DIR}/bin/ira-daemon" "${IRA_STAGE}/ira-daemon"
  COMMAND ${CMAKE_COMMAND} -E copy "${IRA_ANDROID_DIR}/bin/mksh" "${IRA_STAGE}/mksh"
  COMMAND ${CMAKE_COMMAND} -E copy "${IRA_ANDROID_DIR}/lib/ira-zn.so" "${IRA_STAGE}/lib/ira-zn.so"
  COMMAND ${CMAKE_COMMAND} -E copy "${IRA_ANDROID_DIR}/zygisk/arm64-v8a.so" "${IRA_STAGE}/zygisk/arm64-v8a.so"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/scripts/errno_profile.sh" "${IRA_STAGE}/errno_profile.sh"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/NOTICE" "${IRA_STAGE}/NOTICE"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" "${IRA_STAGE}/LICENSE"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/src/adb/NOTICE" "${IRA_STAGE}/Apache-2.0.txt"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/vendor/boringssl/LICENSE" "${IRA_STAGE}/BoringSSL-LICENSE.txt"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/src/mksh/NOTICE" "${IRA_STAGE}/mksh-NOTICE.txt"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/LICENSES/GPL-3.0-only.txt" "${IRA_STAGE}/GPL-3.0.txt"
  COMMAND ${CMAKE_COMMAND} -E rm -f "${IRA_ZIP}"
  COMMAND ${CMAKE_COMMAND} -E chdir "${IRA_STAGE}"
          ${CMAKE_COMMAND} -E tar cf "${IRA_ZIP}" --format=zip -- ${IRA_MODULE_ITEMS}
          initrc ira-daemon mksh errno_profile.sh lib zygisk NOTICE LICENSE Apache-2.0.txt BoringSSL-LICENSE.txt mksh-NOTICE.txt GPL-3.0.txt
  DEPENDS ira-android-build
  COMMENT "packing ${IRA_ZIP}" VERBATIM)
