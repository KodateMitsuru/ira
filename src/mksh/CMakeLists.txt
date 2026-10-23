# SPDX-License-Identifier: AGPL-3.0-or-later
# Native CMake translation of Android sh-defaults; no Build.sh/configure invocation.
set(_mksh_generated "${CMAKE_BINARY_DIR}/mksh-generated")
set(_mksh_tables)
foreach(_table sh_flags rlimits ulimits)
  set(_output "${_mksh_generated}/${_table}.gen")
  add_custom_command(OUTPUT "${_output}"
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/options.py"
            "${IRA_ROOT}/src/mksh/src/${_table}.opt" "${_output}"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/options.py" "${IRA_ROOT}/src/mksh/src/${_table}.opt"
    VERBATIM)
  list(APPEND _mksh_tables "${_output}")
endforeach()

add_executable(ira-shell
  "${IRA_ROOT}/src/mksh/src/lalloc.c"
  "${IRA_ROOT}/src/mksh/src/edit.c"
  "${IRA_ROOT}/src/mksh/src/eval.c"
  "${IRA_ROOT}/src/mksh/src/exec.c"
  "${IRA_ROOT}/src/mksh/src/expr.c"
  "${IRA_ROOT}/src/mksh/src/funcs.c"
  "${IRA_ROOT}/src/mksh/src/histrap.c"
  "${IRA_ROOT}/src/mksh/src/jobs.c"
  "${IRA_ROOT}/src/mksh/src/lex.c"
  "${IRA_ROOT}/src/mksh/src/main.c"
  "${IRA_ROOT}/src/mksh/src/misc.c"
  "${IRA_ROOT}/src/mksh/src/shf.c"
  "${IRA_ROOT}/src/mksh/src/syn.c"
  "${IRA_ROOT}/src/mksh/src/tree.c"
  "${IRA_ROOT}/src/mksh/src/ulimit.c"
  "${IRA_ROOT}/src/mksh/src/var.c"
  ${_mksh_tables}
)
target_include_directories(ira-shell PRIVATE "${_mksh_generated}" "${IRA_ROOT}/src/mksh/src")
target_compile_options(ira-shell PRIVATE -O2 -Wall -Wno-deprecated-declarations -Wno-unused-function -Wno-unknown-warning-option -fno-asynchronous-unwind-tables -fno-strict-aliasing -fwrapv
  [=[-DDEBUG_LEAKS]=]
  [=[-DMKSH_ASSUME_UTF8]=]
  [=[-DMKSH_DONT_EMIT_IDSTRING]=]
  [=[-DKSH_VERSIONNAME_VENDOR_EXT=" Android"]=]
  [=[-DMKSH_BUILDSH]=]
  [=[-D_GNU_SOURCE]=]
  [=[-DSETUID_CAN_FAIL_WITH_EAGAIN]=]
  [=[-DHAVE_STRING_POOLING=2]=]
  [=[-DHAVE_ATTRIBUTE_BOUNDED=1]=]
  [=[-DHAVE_ATTRIBUTE_FORMAT=1]=]
  [=[-DHAVE_ATTRIBUTE_NORETURN=1]=]
  [=[-DHAVE_ATTRIBUTE_PURE=1]=]
  [=[-DHAVE_ATTRIBUTE_UNUSED=1]=]
  [=[-DHAVE_ATTRIBUTE_USED=1]=]
  [=[-DHAVE_SYS_TIME_H=1]=]
  [=[-DHAVE_TIME_H=1]=]
  [=[-DHAVE_BOTH_TIME_H=1]=]
  [=[-DHAVE_SYS_BSDTYPES_H=0]=]
  [=[-DHAVE_SYS_FILE_H=1]=]
  [=[-DHAVE_SYS_MKDEV_H=0]=]
  [=[-DHAVE_SYS_MMAN_H=1]=]
  [=[-DHAVE_SYS_PARAM_H=1]=]
  [=[-DHAVE_SYS_RESOURCE_H=1]=]
  [=[-DHAVE_SYS_SELECT_H=1]=]
  [=[-DHAVE_SYS_SYSMACROS_H=1]=]
  [=[-DHAVE_BSTRING_H=0]=]
  [=[-DHAVE_GRP_H=1]=]
  [=[-DHAVE_IO_H=0]=]
  [=[-DHAVE_LIBGEN_H=1]=]
  [=[-DHAVE_LIBUTIL_H=0]=]
  [=[-DHAVE_PATHS_H=1]=]
  [=[-DHAVE_STDINT_H=1]=]
  [=[-DHAVE_STRINGS_H=1]=]
  [=[-DHAVE_TERMIOS_H=1]=]
  [=[-DHAVE_ULIMIT_H=0]=]
  [=[-DHAVE_VALUES_H=0]=]
  [=[-DHAVE_CAN_INTTYPES=1]=]
  [=[-DHAVE_CAN_UCBINTS=1]=]
  [=[-DHAVE_CAN_INT8TYPE=1]=]
  [=[-DHAVE_CAN_UCBINT8=1]=]
  [=[-DHAVE_SIG_T=1]=]
  [=[-DHAVE_SYS_ERRLIST=0]=]
  [=[-DHAVE_SYS_SIGNAME=1]=]
  [=[-DHAVE_SYS_SIGLIST=1]=]
  [=[-DHAVE_FLOCK=1]=]
  [=[-DHAVE_LOCK_FCNTL=1]=]
  [=[-DHAVE_RLIMIT=1]=]
  [=[-DHAVE_RLIM_T=1]=]
  [=[-DHAVE_GETRUSAGE=1]=]
  [=[-DHAVE_GETSID=1]=]
  [=[-DHAVE_GETTIMEOFDAY=1]=]
  [=[-DHAVE_KILLPG=1]=]
  [=[-DHAVE_MEMMOVE=1]=]
  [=[-DHAVE_MKNOD=0]=]
  [=[-DHAVE_MMAP=1]=]
  [=[-DHAVE_FTRUNCATE=1]=]
  [=[-DHAVE_NICE=1]=]
  [=[-DHAVE_REVOKE=0]=]
  [=[-DHAVE_SETLOCALE_CTYPE=1]=]
  [=[-DHAVE_LANGINFO_CODESET=1]=]
  [=[-DHAVE_SELECT=1]=]
  [=[-DHAVE_SETRESUGID=1]=]
  [=[-DHAVE_SETGROUPS=1]=]
  [=[-DHAVE_STRERROR=1]=]
  [=[-DHAVE_STRSIGNAL=1]=]
  [=[-DHAVE_STRLCPY=1]=]
  [=[-DHAVE_FLOCK_DECL=1]=]
  [=[-DHAVE_REVOKE_DECL=1]=]
  [=[-DHAVE_SYS_ERRLIST_DECL=0]=]
  [=[-DHAVE_SYS_SIGLIST_DECL=1]=]
  [=[-DHAVE_ST_MTIM=1]=]
  [=[-DHAVE_ST_MTIMENSEC=0]=]
  [=[-DHAVE_PERSISTENT_HISTORY=0]=]
  [=[-DMKSH_BUILD_R=593]=]
  [=[-DMKSH_DEFAULT_PROFILEDIR="/system/etc"]=]
  [=[-DMKSHRC_PATH="/system/etc/mkshrc"]=]
  [=[-DMKSH_DEFAULT_EXECSHELL="/system/bin/sh"]=]
  [=[-DMKSH_DEFAULT_TMPDIR="/data/local"]=]
)
target_link_options(ira-shell PRIVATE -static -Wl,--strip-all)
set_target_properties(ira-shell PROPERTIES OUTPUT_NAME mksh RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
add_custom_command(TARGET ira-shell POST_BUILD COMMAND ${Python3_EXECUTABLE} "${IRA_ROOT}/scripts/payload.py" check $<TARGET_FILE:ira-shell> shell VERBATIM)
