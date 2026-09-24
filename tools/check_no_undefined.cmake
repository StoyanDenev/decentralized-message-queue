# Freestanding audit, run by the build (cmake -P). Every object in OBJECTS must
# reference no external symbol: no C library, no compiler-emitted memcpy or
# memset, no stack-protector runtime. With CHECK_DATA=ON (ELF targets) it must
# also define no writable data or bss, that is no global state. CANARY is an
# object that does both, so each active check is shown able to fail on every
# run. Writes STAMP on success.
foreach(required NM OBJECTS CANARY CHECK_DATA STAMP)
  if("${${required}}" STREQUAL "")
    message(FATAL_ERROR "check_no_undefined: ${required} is required")
  endif()
endforeach()

function(nm_lines object flag result)
  execute_process(COMMAND "${NM}" ${flag} "${object}"
                  RESULT_VARIABLE status OUTPUT_VARIABLE text ERROR_VARIABLE error)
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "check_no_undefined: ${NM} ${flag} ${object} failed: ${error}")
  endif()
  string(STRIP "${text}" text)
  set(${result} "${text}" PARENT_SCOPE)
endfunction()

# ELF nm letters for writable data, bss and common symbols: B/b bss, C common,
# D/d data, G/g and S/s small-data sections. COFF and Mach-O use some of these
# letters for section or literal-pool symbols, so the check is ELF-only.
function(writable_symbols object result)
  nm_lines("${object}" "" text)
  string(REGEX MATCHALL "[^\n]* [BbCDdGgSs] [^\n]*" found "${text}")
  set(${result} "${found}" PARENT_SCOPE)
endfunction()

nm_lines("${CANARY}" -u canary_undefined)
if(canary_undefined STREQUAL "")
  message(FATAL_ERROR "check_no_undefined: the canary shows no undefined symbol, so the audit cannot fail")
endif()
if(CHECK_DATA)
  writable_symbols("${CANARY}" canary_writable)
  if(canary_writable STREQUAL "")
    message(FATAL_ERROR "check_no_undefined: the canary shows no writable data, so the data check cannot fail")
  endif()
endif()
foreach(object IN LISTS OBJECTS)
  nm_lines("${object}" -u undefined)
  if(NOT undefined STREQUAL "")
    message(FATAL_ERROR "check_no_undefined: ${object} needs external symbols:\n${undefined}")
  endif()
  if(CHECK_DATA)
    writable_symbols("${object}" writable)
    if(NOT writable STREQUAL "")
      message(FATAL_ERROR "check_no_undefined: ${object} defines writable data:\n${writable}")
    endif()
  endif()
endforeach()
if(CHECK_DATA)
  file(WRITE "${STAMP}" "no undefined symbols, no writable data\n")
else()
  file(WRITE "${STAMP}" "no undefined symbols (writable-data check not applied)\n")
endif()
