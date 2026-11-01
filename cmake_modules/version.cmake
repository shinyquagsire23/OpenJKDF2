set(OPENJKDF2_PROJECT_VERSION 0.9.9.0)
# Existing build scripts export empty values when Git cannot identify the
# source. Preserve the original Git fallback when neither value is supplied.
# Nonempty overrides must still supply a complete, consistent pair.
if(NOT "$ENV{OPENJKDF2_RELEASE_COMMIT}" STREQUAL "" OR
   NOT "$ENV{OPENJKDF2_RELEASE_COMMIT_SHORT}" STREQUAL "")
    set(OPENJKDF2_RELEASE_COMMIT "$ENV{OPENJKDF2_RELEASE_COMMIT}")
    set(OPENJKDF2_RELEASE_COMMIT_SHORT "$ENV{OPENJKDF2_RELEASE_COMMIT_SHORT}")
    string(LENGTH "${OPENJKDF2_RELEASE_COMMIT}" _release_commit_length)
    string(LENGTH "${OPENJKDF2_RELEASE_COMMIT_SHORT}" _release_short_length)
    if(NOT _release_commit_length EQUAL 40 OR
       NOT OPENJKDF2_RELEASE_COMMIT MATCHES "^[0-9a-fA-F]+$" OR
       _release_short_length LESS 8 OR _release_short_length GREATER 40 OR
       NOT OPENJKDF2_RELEASE_COMMIT_SHORT MATCHES "^[0-9a-fA-F]+$")
        message(FATAL_ERROR "Release commit overrides require a 40-hex commit and an 8-to-40-hex matching prefix")
    endif()
    string(TOLOWER "${OPENJKDF2_RELEASE_COMMIT}" OPENJKDF2_RELEASE_COMMIT)
    string(TOLOWER "${OPENJKDF2_RELEASE_COMMIT_SHORT}" OPENJKDF2_RELEASE_COMMIT_SHORT)
    string(SUBSTRING "${OPENJKDF2_RELEASE_COMMIT}" 0 ${_release_short_length} _release_expected_prefix)
    if(NOT OPENJKDF2_RELEASE_COMMIT_SHORT STREQUAL _release_expected_prefix)
        message(FATAL_ERROR "Release commit short override must match the full commit prefix")
    endif()
else()
    find_package(Git)
    execute_process(
        COMMAND git log -1 --format=%H
        OUTPUT_VARIABLE OPENJKDF2_RELEASE_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process(
        COMMAND git rev-parse --short=8 HEAD
        OUTPUT_VARIABLE OPENJKDF2_RELEASE_COMMIT_SHORT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()
