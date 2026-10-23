# SPDX-License-Identifier: AGPL-3.0-or-later
# Build only the authorization crypto source closure; upstream algorithms are unchanged.
# Function sections and linker GC are required: retained upstream units still declare other APIs.
enable_language(ASM)
include("${CMAKE_CURRENT_SOURCE_DIR}/Sources.cmake")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
  set(_crypto_asm ${IRA_CRYPTO_ARM64})
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  set(_crypto_asm ${IRA_CRYPTO_X86_64})
else()
  message(FATAL_ERROR "Crypto source subset supports Linux/Android ARM64 and Linux x86_64")
endif()
set(_crypto_sources ${IRA_CRYPTO_COMMON} ${IRA_CRYPTO_BCM} ${_crypto_asm})
list(TRANSFORM _crypto_sources PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")
set_source_files_properties(${_crypto_sources} PROPERTIES LANGUAGE CXX)
# Assembly retains its own language; .cc.inc inputs are compiled as independent C++ units.
foreach(_source IN LISTS _crypto_sources)
  if(_source MATCHES "[.]S$")
    set_source_files_properties("${_source}" PROPERTIES LANGUAGE ASM)
  endif()
endforeach()
add_library(crypto STATIC ${_crypto_sources})
target_link_options(crypto INTERFACE -Wl,--gc-sections)
target_include_directories(crypto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(crypto PRIVATE BORINGSSL_IMPLEMENTATION)
target_compile_options(crypto PRIVATE
  "$<$<COMPILE_LANGUAGE:C,CXX>:-fno-strict-aliasing;-fno-common;-fvisibility=hidden;-ffunction-sections;-fdata-sections>"
  "$<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions;-fno-rtti>"
  "$<$<COMPILE_LANGUAGE:ASM>:-Wa,--noexecstack>")
if(NOT ANDROID)
  target_compile_definitions(crypto PRIVATE _XOPEN_SOURCE=700)
endif()
