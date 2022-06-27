find_package(Git)

execute_process(COMMAND
        "${GIT_EXECUTABLE}" describe --match=NeVeRmAtCh --always --abbrev=40 --dirty
        WORKING_DIRECTORY "${FLAT_SOURCE_DIR}"
        OUTPUT_VARIABLE flat_git_sha_string
        OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(COMMAND
        "${GIT_EXECUTABLE}" log -1 --format=%ct
        WORKING_DIRECTORY "${FLAT_SOURCE_DIR}"
        OUTPUT_VARIABLE flat_git_unixtime
        OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "${GIT_EXECUTABLE} flat_git_unixtime ${flat_git_unixtime} flat_git_sha_string ${flat_git_sha_string}")

configure_file("${FLAT_SOURCE_DIR}/cmake_variables.hpp.in" "${FLAT_BINARY_DIR}/cmake_variables.hpp" @ONLY)
