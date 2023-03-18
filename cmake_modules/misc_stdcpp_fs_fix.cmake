# stdc++fs experimental stuff for ancient compilers
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" )
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
        add_definitions(-DFILESYSTEM_TS)
        target_link_libraries(${BIN_NAME} PRIVATE stdc++fs)
    endif(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
endif (CMAKE_CXX_COMPILER_ID MATCHES "Clang" )

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
        add_definitions(-DFILESYSTEM_TS)
        target_link_libraries(${BIN_NAME} PRIVATE stdc++fs)
        # Here clang uses libstdc++ as STL in Linux, which in OSX and FreeBSD should be libc++, and thus it should link c++fs. However, I have neither machine nor time to verify it.
    endif(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
endif()
# end stdc++fs experimental stuff for ancient compilers