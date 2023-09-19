macro(plat_initialize)
    message( STATUS "Targeting Win64 MSVC" )

    set(BIN_NAME "openjkdf2-64")

    add_compile_definitions(WINVER=0x0600 _WIN32_WINNT=0x0600)
    add_compile_definitions(WIN64)
    add_compile_definitions(WIN64_STANDALONE)
    add_compile_definitions(ARCH_64BIT)
    add_compile_definitions(WIN32)

    include(cmake_modules/plat_feat_full_sdl2.cmake)
    set(TARGET_USE_PHYSFS FALSE)
    set(TARGET_USE_CURL FALSE)
    set(TARGET_COMPILE_FREEGLUT TRUE)
    set(TARGET_FIND_OPENAL FALSE)
    set(SDL2_COMMON_LIBS SDL2main SDL::SDL)
    
    set(TARGET_WIN32 TRUE)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /std:c11")
endmacro()

macro(plat_specific_deps)
    set(SDL2_COMMON_LIBS SDL2main SDL::SDL)
endmacro()

macro(plat_link_and_package)
    set_target_properties(${BIN_NAME} PROPERTIES
        ENABLE_EXPORTS FALSE
        WINDOWS_EXPORT_ALL_SYMBOLS FALSE
        # CMake missbehaives here because the PE image version field actually
        # specifies the version of the PE specification the PE image has been
        # built to and has NOTHING to do with the application version.
        # Traditionally, the PE image version has followed the internal release
        # version of Windows. Consequently, becuase the linker is the last tool
        # to build a PE image it is supposed to be the linker who should set
        # the PE image version field.
        VERSION ${CMAKE_SYSTEM_VERSION}
    )
    if(CMAKE_BUILD_TYPE STREQUAL Release OR
       CMAKE_BUILD_TYPE STREQUAL MinSizeRel OR
       CMAKE_BUILD_TYPE STREQUAL RelWithDebInfo)
        # TODO: Implement WinMain() for this to work nicely
        set_target_properties(${BIN_NAME} PROPERTIES WIN32_EXECUTABLE TRUE)
    elseif(CMAKE_BUILD_TYPE STREQUAL Debug)
        set_target_properties(${BIN_NAME} PROPERTIES WIN32_EXECUTABLE FALSE)
    endif()

    set_target_properties(${BIN_NAME} PROPERTIES
      LINK_SEARCH_START_STATIC ON
      LINK_SEARCH_END_STATIC ON
    )
    set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
    set(THREADS_PREFER_PTHREAD_FLAG TRUE)
    find_package(Threads REQUIRED)
    target_link_libraries(${BIN_NAME} PRIVATE -static)
    set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")
    target_link_libraries(sith_engine PRIVATE Threads::Threads)

    target_link_libraries(sith_engine PRIVATE GLUT::GLUT)
    target_link_libraries(sith_engine PRIVATE GLEW::glew_s)
    target_link_libraries(${BIN_NAME} PRIVATE GLEW::glew_s)
    target_link_libraries(sith_engine PRIVATE ${SDL2_COMMON_LIBS} version imm32 setupapi gdi32 winmm imm32 ole32 oleaut32 shell32 winmm user32 crypt32 advapi32) # SDL2’s peculiarity that you have to link mingw32 before SDL2main

    if(TARGET_CAN_JKGM)
        target_link_libraries(sith_engine PRIVATE PNG::PNG ZLIB::ZLIB)
    endif()

    if (TARGET_USE_OPENAL)
        target_link_libraries(sith_engine PRIVATE ${SDL_MIXER_DEPS} SDL::Mixer)
        if (OPENAL_COMPILING_FROM_SRC)
            target_link_libraries(sith_engine PRIVATE OpenAL::OpenAL)
        else()
            target_link_libraries(sith_engine PRIVATE ${OPENAL_LIBRARIES})
        endif()
    endif()
    target_link_libraries(sith_engine PRIVATE nlohmann_json::nlohmann_json)
    if(TARGET_USE_GAMENETWORKINGSOCKETS)
        target_link_libraries(sith_engine PRIVATE GameNetworkingSockets::GameNetworkingSockets)
    endif()
    if(TARGET_USE_PHYSFS)
        target_link_libraries(sith_engine PRIVATE PhysFS::PhysFS_s)
        target_link_libraries(${BIN_NAME} PRIVATE PhysFS::PhysFS_s)
    endif()
    target_link_libraries(sith_engine PRIVATE opengl32 ws2_32 uuid ole32)

    if (TARGET_USE_OPENAL)
        add_custom_command(
            TARGET ${BIN_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_BINARY_DIR}/openal/bin/OpenAL32.dll ${PROJECT_BINARY_DIR}
        )
    endif()

    add_custom_command(
        TARGET ${BIN_NAME}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/exchndl.dll ${PROJECT_BINARY_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/symsrv.dll ${PROJECT_BINARY_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/mgwhelp.dll ${PROJECT_BINARY_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/symsrv.yes ${PROJECT_BINARY_DIR}
    )

    if(TARGET_USE_GAMENETWORKINGSOCKETS)
        add_custom_command(
            TARGET ${BIN_NAME}
            POST_BUILD 
            COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_BINARY_DIR}/GameNetworkingSockets/bin/GameNetworkingSockets.dll ${PROJECT_BINARY_DIR}
        )
    endif()
endmacro()