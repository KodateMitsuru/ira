# SPDX-License-Identifier: AGPL-3.0-or-later
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_package(Java 17 REQUIRED COMPONENTS Development Runtime)
set(IRA_TEST_WORK "${CMAKE_CURRENT_BINARY_DIR}/work")
file(MAKE_DIRECTORY "${IRA_TEST_WORK}")
function(ira_test name)
  add_executable(${name} ${ARGN})
  target_compile_options(${name} PRIVATE -Wno-everything)
  target_link_libraries(${name} PRIVATE Threads::Threads ira-adb-options)
endfunction()
function(ira_run name)
  add_test(NAME ${name} COMMAND ${ARGN})
  set_tests_properties(${name} PROPERTIES WORKING_DIRECTORY "${IRA_TEST_WORK}"
    ENVIRONMENT "TMPDIR=${IRA_TEST_WORK}" TIMEOUT 120)
endfunction()
set(_names "${IRA_ROOT}/src/adb/ira_names.cpp")
set(_fde "${CMAKE_CURRENT_SOURCE_DIR}/fdevent_stubs.cpp")
foreach(_case ffs_desc ffs_lifecycle ffs_session auth_revoke_control)
  ira_test(test_${_case} test_${_case}.cpp ${_fde} ${_names})
  ira_run(${_case} $<TARGET_FILE:test_${_case}>)
endforeach()
file(MAKE_DIRECTORY "${IRA_TEST_WORK}/lifecycle")
target_compile_definitions(test_ffs_lifecycle PRIVATE
  IRA_GADGET_DIR="${IRA_TEST_WORK}/lifecycle/gadget" IRA_STATE_DIR="${IRA_TEST_WORK}/lifecycle")
ira_test(test_ffs_namespace test_ffs_namespace.cpp ${_fde} ${_names})
ira_run(ffs_namespace ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/run.py" namespace
  $<TARGET_FILE:test_ffs_namespace> "${IRA_TEST_WORK}/namespace")
set_tests_properties(ffs_namespace PROPERTIES SKIP_RETURN_CODE 77)

ira_test(test_auth test_auth.cpp)
target_link_libraries(test_auth PRIVATE android-pubkey)
target_compile_options(test_auth PRIVATE -ffunction-sections -fdata-sections)
target_link_options(test_auth PRIVATE -Wl,--gc-sections)
ira_run(auth_crypto ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/run.py" crypto
  $<TARGET_FILE:test_auth> "${IRA_TEST_WORK}/crypto")

ira_test(test_auth_revocation test_auth_revocation.cpp ${_names})
target_link_libraries(test_auth_revocation PRIVATE ira-adb-options)
target_compile_options(test_auth_revocation PRIVATE -ffunction-sections -fdata-sections)
target_link_options(test_auth_revocation PRIVATE -Wl,--gc-sections)
ira_run(auth_revocation $<TARGET_FILE:test_auth_revocation>)
ira_test(test_ira_names test_ira_names.cpp ${_names})
ira_run(endpoint_names $<TARGET_FILE:test_ira_names>)
ira_test(test_service_backend test_service_backend.cpp "${IRA_ROOT}/src/adb/ira_privileges.cpp")
target_link_libraries(test_service_backend PRIVATE ira-adb-options)
ira_run(service_backend ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/run.py" credentials
  $<TARGET_FILE:test_service_backend> "${IRA_TEST_WORK}/backend")
set_tests_properties(service_backend PROPERTIES SKIP_RETURN_CODE 77)
ira_test(test_session_signals test_session_signals.cpp "${IRA_ROOT}/src/adb/ira_privileges.cpp")
find_program(IRA_QEMU NAMES qemu-aarch64-static qemu-aarch64)
if(IRA_QEMU AND IRA_SHELL)
  ira_run(session_signals $<TARGET_FILE:test_session_signals> "${IRA_QEMU}" "${IRA_SHELL}")
endif()

ira_test(test_zygisk_hook test_zygisk_hook.cpp)
target_link_libraries(test_zygisk_hook PRIVATE dl)
ira_run(zygisk_hook $<TARGET_FILE:test_zygisk_hook>)
ira_test(test_zygisk_scope test_zygisk_scope.cpp)
target_include_directories(test_zygisk_scope PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/zygisk")
ira_run(zygisk_scope $<TARGET_FILE:test_zygisk_scope>)

ira_test(test_upstream_auth test_upstream_auth.cpp)
target_link_libraries(test_upstream_auth PRIVATE adbd-auth)
ira_run(upstream_auth $<TARGET_FILE:test_upstream_auth>)

ira_test(test_platform_api test_platform_api.cpp "${IRA_ROOT}/src/adb/ira_platform.cpp")
target_link_libraries(test_platform_api PRIVATE dl)
foreach(_mode modern legacy missing)
  set(_dir "${IRA_TEST_WORK}/platform/${_mode}")
  file(MAKE_DIRECTORY "${_dir}")
  add_library(fixture-${_mode} SHARED fixtures/platform_api.c)
  set_target_properties(fixture-${_mode} PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${_dir}" OUTPUT_NAME fixture)
  if(_mode STREQUAL legacy)
    target_compile_definitions(fixture-${_mode} PRIVATE IRA_LEGACY_POLICY)
  elseif(_mode STREQUAL missing)
    target_compile_definitions(fixture-${_mode} PRIVATE IRA_MISSING_API)
  endif()
  foreach(_lib libcutils libselinux libadbd_fs libminijail libcap)
    file(CREATE_LINK libfixture.so "${_dir}/${_lib}.so" SYMBOLIC)
  endforeach()
  ira_run(platform_${_mode} ${CMAKE_COMMAND} -E env "LD_LIBRARY_PATH=${_dir}" $<TARGET_FILE:test_platform_api> ${_mode})
endforeach()
ira_test(test_services_integration test_services_integration.cpp $<TARGET_OBJECTS:ira-adb>)
target_link_libraries(test_services_integration PRIVATE ira-adb-options adbd-auth dl)
ira_run(services_integration ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/run.py" integration
  $<TARGET_FILE:test_services_integration> "${IRA_TEST_WORK}/integration" "${IRA_TEST_WORK}/platform/modern")
set_tests_properties(services_integration PROPERTIES SKIP_RETURN_CODE 77)

file(GLOB _java_fixtures CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/android/*/*.java")
file(GLOB _java_tests CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/java/ira/fw/*.java")
file(GLOB _java_sources CONFIGURE_DEPENDS "${IRA_ROOT}/src/zygisk/java/ira/fw/Adb*.java")
set(_java_dir "${CMAKE_CURRENT_BINARY_DIR}/java")
add_custom_command(OUTPUT "${_java_dir}/.stamp"
  COMMAND ${CMAKE_COMMAND} -E rm -rf "${_java_dir}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${_java_dir}/classes" "${_java_dir}/framework"
  COMMAND ${Java_JAVAC_EXECUTABLE} -d "${_java_dir}/framework"
          "${CMAKE_CURRENT_SOURCE_DIR}/java/framework/fixture/PlatformAuthFixture.java"
  COMMAND ${Java_JAVAC_EXECUTABLE} -d "${_java_dir}/classes" ${_java_fixtures} ${_java_sources} ${_java_tests}
  COMMAND ${CMAKE_COMMAND} -E touch "${_java_dir}/.stamp"
  DEPENDS ${_java_fixtures} ${_java_sources} ${_java_tests}
    "${CMAKE_CURRENT_SOURCE_DIR}/java/framework/fixture/PlatformAuthFixture.java" VERBATIM)
add_custom_target(java-tests ALL DEPENDS "${_java_dir}/.stamp")
foreach(_class AdbResponseThreadBinding AdbRevocationObserver AdbPromptRouter AdbRevocationClient AdbAuthWriter AdbRevocationCommand)
  ira_run(java_${_class} ${Java_JAVA_EXECUTABLE} -cp "${_java_dir}/classes" ira.fw.${_class}Test "${_java_dir}/framework")
endforeach()
ira_run(root_default ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/test_root_default.py"
  "${IRA_TEST_WORK}/root-default" $<TARGET_FILE:ira-daemon>)
ira_run(installer ${CMAKE_COMMAND} -E env "IRA_TEST_WORK=${IRA_TEST_WORK}/installer"
  ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/test_installer_policy.py")
get_filename_component(_android_bin "${IRA_SHELL}" DIRECTORY)
ira_run(no_pty bash "${IRA_ROOT}/scripts/test-no-pty.sh" "${_android_bin}/ira-daemon")
