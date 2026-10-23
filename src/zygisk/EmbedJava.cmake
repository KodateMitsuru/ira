# SPDX-License-Identifier: AGPL-3.0-or-later
file(REMOVE_RECURSE "${OUT}/classes" "${OUT}/dex")
file(MAKE_DIRECTORY "${OUT}/classes" "${OUT}/dex")
file(GLOB_RECURSE _java "${ROOT}/src/zygisk/java/*.java")
execute_process(COMMAND "${JAVAC}" -nowarn -source 17 -target 17 -classpath "${JAR}"
  -d "${OUT}/classes" ${_java} COMMAND_ERROR_IS_FATAL ANY)
file(GLOB_RECURSE _classes "${OUT}/classes/*.class")
execute_process(COMMAND "${D8}" --lib "${JAR}" --output "${OUT}/dex" ${_classes}
  COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${PYTHON}" "${ROOT}/scripts/payload.py" embed
  "${OUT}/dex/classes.dex" "${OUT}/ira_dex.h" COMMAND_ERROR_IS_FATAL ANY)
