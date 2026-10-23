# SPDX-License-Identifier: AGPL-3.0-or-later
# Build the retained upstream crypto sources directly. No SSL/PKI/tool/test targets.
enable_language(ASM)
include("${CMAKE_CURRENT_SOURCE_DIR}/Sources.cmake")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
  set(_crypto_asm ${IRA_CRYPTO_ARM64})
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  set(_crypto_asm ${IRA_CRYPTO_X86_64})
else()
  message(FATAL_ERROR "Crypto source subset supports Linux/Android ARM64 and Linux x86_64")
endif()
set(_crypto_sources ${IRA_CRYPTO_COMMON} ${_crypto_asm})
list(TRANSFORM _crypto_sources PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
add_library(crypto STATIC ${_crypto_sources})
target_include_directories(crypto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(crypto PRIVATE BORINGSSL_IMPLEMENTATION)
target_compile_options(crypto PRIVATE
  "$<$<COMPILE_LANGUAGE:C,CXX>:-fno-strict-aliasing;-fno-common;-fvisibility=hidden>"
  "$<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions;-fno-rtti>"
  "$<$<COMPILE_LANGUAGE:ASM>:-Wa,--noexecstack>")
if(NOT ANDROID)
  target_compile_definitions(crypto PRIVATE _XOPEN_SOURCE=700)
endif()
