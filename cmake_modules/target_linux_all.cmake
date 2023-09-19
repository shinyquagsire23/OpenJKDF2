macro(plat_link_and_package)
    target_link_libraries(sith_engine PRIVATE PNG::PNG ZLIB::ZLIB)
    target_link_libraries(sith_engine PRIVATE ${SDL2_COMMON_LIBS} GL ${OPENAL_LIBRARY} GLEW::GLEW ${GTK3_LIBRARIES})
     
    if(TARGET_USE_PHYSFS)
        target_link_libraries(sith_engine PRIVATE PhysFS::PhysFS_s)
        target_link_libraries(${BIN_NAME} PRIVATE PhysFS::PhysFS_s)
    endif()
    if(TARGET_USE_GAMENETWORKINGSOCKETS)
        target_link_libraries(sith_engine PRIVATE GameNetworkingSockets::GameNetworkingSockets)
    endif()

    target_link_libraries(sith_engine PRIVATE nlohmann_json::nlohmann_json)
    target_link_libraries(sith_engine PRIVATE dl) # dlopen, dlsym

    if(TARGET_USE_CURL)
        target_link_libraries(sith_engine PRIVATE curl)
    endif()
endmacro()

macro(plat_extra_deps)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
    include_directories(${GTK3_INCLUDE_DIRS})
    link_directories(${GTK3_LIBRARY_DIRS})
    add_definitions(${GTK3_CFLAGS_OTHER})

    if(TARGET_USE_CURL)
        pkg_check_modules(LIBCURL REQUIRED libcurl)
        include_directories(${LIBCURL_STATIC_INCLUDE_DIRS})
        link_directories(${LIBCURL_STATIC_LIBRARY_DIRS})
        add_definitions(${LIBCURL_STATIC_CFLAGS_OTHER})
    endif()

    if(TARGET_USE_GAMENETWORKINGSOCKETS)
        add_custom_command(
            TARGET ${BIN_NAME}
            POST_BUILD 
            COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_BINARY_DIR}/GameNetworkingSockets/bin/libGameNetworkingSockets.so ${PROJECT_BINARY_DIR}
        )
    endif()
endmacro()