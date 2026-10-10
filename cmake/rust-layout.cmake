# rust-layout.cmake -- write Rust assertions from the layout records in a compiled probe
# Licensed under the Zlib license, see LICENSE.md for details
#
# PROBE is the object file, CHECKS lists one Rust expression per record, and OUTPUT is the Rust
# source to write. A check that starts with const declares a constant with the value of the record.

file(STRINGS "${PROBE}" records REGEX "ZNGLAYOUT:[0-9]+=[0-9]+;")
foreach(record IN LISTS records)
    string(REGEX MATCH "ZNGLAYOUT:([0-9]+)=([0-9]+);" matched "${record}")
    # Every regex command resets the match variables, so take both before stripping the zeros.
    set(index "${CMAKE_MATCH_1}")
    set(value "${CMAKE_MATCH_2}")
    string(REGEX MATCH "[1-9][0-9]*$|0$" index "${index}")
    string(REGEX MATCH "[1-9][0-9]*$|0$" value "${value}")
    set(value_${index} ${value})
endforeach()

file(STRINGS "${CHECKS}" checks)
set(content "// Generated from the C sources by cmake/rust-layout.cmake.\n")
set(index 0)
foreach(check IN LISTS checks)
    if(NOT DEFINED value_${index})
        message(FATAL_ERROR "No layout record for ${check} in ${PROBE}")
    endif()
    if(check MATCHES "^const ")
        string(APPEND content "pub(crate) ${check} = ${value_${index}};\n")
    else()
        string(APPEND content "const _: () = assert!(${check} == ${value_${index}});\n")
    endif()
    math(EXPR index "${index} + 1")
endforeach()
file(WRITE "${OUTPUT}" "${content}")
