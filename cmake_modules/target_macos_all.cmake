function(macos_target_add_standard_deps target_name)
    if(TARGET_MACOS)
        set_target_properties(${target_name} PROPERTIES
          LINK_SEARCH_START_STATIC ON
          LINK_SEARCH_END_STATIC ON
        )
        target_link_libraries(${target_name} PRIVATE "-framework AppKit")
        target_link_libraries(${target_name} PRIVATE "-framework Carbon")
        target_link_libraries(${target_name} PRIVATE "-framework SystemConfiguration")
        target_link_libraries(${target_name} PRIVATE "-framework CoreAudio")
        target_link_libraries(${target_name} PRIVATE "-framework AudioToolbox")
        target_link_libraries(${target_name} PRIVATE "-framework CoreVideo")
        target_link_libraries(${target_name} PRIVATE "-framework Cocoa")
        target_link_libraries(${target_name} PRIVATE "-framework Metal")
        target_link_libraries(${target_name} PRIVATE "-framework CoreHaptics")
        target_link_libraries(${target_name} PRIVATE "-framework IOKit")
        target_link_libraries(${target_name} PRIVATE "-framework ForceFeedback")
        target_link_libraries(${target_name} PRIVATE "-framework GameController")
        target_link_libraries(${target_name} PRIVATE iconv GLEW::GLEW)
    endif()
endfunction()

macro(plat_link_and_package)
    if(TARGET_CAN_JKGM)
        target_link_libraries(sith_engine PRIVATE PNG::PNG ZLIB::ZLIB)
    endif()

    target_link_libraries(sith_engine PRIVATE ${SDL2_COMMON_LIBS} ${OPENGL_LIBRARY} ${OPENAL_LIBRARY} GLEW::GLEW)
    target_link_libraries(${BIN_NAME} PRIVATE GLEW::GLEW)
    target_link_libraries(sith_engine PRIVATE nlohmann_json::nlohmann_json)

    if(TARGET_USE_PHYSFS)
        target_link_libraries(sith_engine PRIVATE PhysFS::PhysFS_s)
        target_link_libraries(${BIN_NAME} PRIVATE PhysFS::PhysFS_s)
    endif()
    if(TARGET_USE_GAMENETWORKINGSOCKETS)
        target_link_libraries(sith_engine PRIVATE GameNetworkingSockets::GameNetworkingSockets)
    endif()

    #
    # macOS post-build packaging
    #
    postcompile_macos()
endmacro()

macro(plat_extra_deps)
    macos_target_add_standard_deps(${BIN_NAME})

    find_package(PkgConfig REQUIRED)

    if(TARGET_USE_GAMENETWORKINGSOCKETS)
        find_package(OpenSSL REQUIRED)
        target_link_libraries(sith_engine PUBLIC OpenSSL::Crypto)
    endif()
endmacro()