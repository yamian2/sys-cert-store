find_package(Git REQUIRED)

# Export only the pinned, committed public sources. Patches never modify submodules.
function(scs_patched_dependency name revision patch output)
    set(source "${PROJECT_SOURCE_DIR}/third_party/${name}")
    execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${source}" rev-parse HEAD
        OUTPUT_VARIABLE head OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
    if(NOT head STREQUAL revision)
        message(FATAL_ERROR "${name} must be at pinned revision ${revision}; run git submodule update --init --recursive.")
    endif()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${patch}")
    file(SHA256 "${patch}" patch_hash)
    file(SHA256 "${CMAKE_CURRENT_FUNCTION_LIST_FILE}" helper_hash)
    string(SHA256 snapshot_hash "${revision};${patch_hash};${helper_hash}")
    set(destination "${PROJECT_BINARY_DIR}/dependencies/${name}-${snapshot_hash}")
    set(apply_command "${CMAKE_COMMAND}" -E env
        "GIT_CEILING_DIRECTORIES=${PROJECT_BINARY_DIR}/dependencies"
        "${GIT_EXECUTABLE}" -C "${destination}" apply)
    if(NOT EXISTS "${destination}/.scs-patched")
        file(MAKE_DIRECTORY "${destination}")
        execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${source}" archive
            --format=tar "--output=${destination}/source.tar" "${revision}"
            COMMAND_ERROR_IS_FATAL ANY)
        file(ARCHIVE_EXTRACT INPUT "${destination}/source.tar" DESTINATION "${destination}")
        file(REMOVE "${destination}/source.tar")
        execute_process(COMMAND ${apply_command} "${patch}" COMMAND_ERROR_IS_FATAL ANY)
        file(WRITE "${destination}/.scs-patched" "${revision}\n${patch_hash}\n")
    endif()
    execute_process(COMMAND ${apply_command} --reverse --check "${patch}"
        COMMAND_ERROR_IS_FATAL ANY)
    set(${output} "${destination}" PARENT_SCOPE)
endfunction()
