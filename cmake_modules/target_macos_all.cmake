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

macro(postcompile_macos)
    add_custom_command(TARGET ${BIN_NAME}
        POST_BUILD
        COMMAND dsymutil ${CMAKE_CURRENT_BINARY_DIR}/${BIN_NAME} -o ${CMAKE_CURRENT_BINARY_DIR}/${BIN_NAME}.dsym
        COMMAND rm -rf ${BUNDLE}
        COMMAND rm -rf ${PROJECT_SOURCE_DIR}/packaging/icon.iconset
        COMMAND rm -rf ${PROJECT_SOURCE_DIR}/packaging/icon.icns
        COMMAND mkdir -p ${BUNDLE}
        COMMAND cp -r ${PROJECT_SOURCE_DIR}/packaging/macos/* ${BUNDLE}/
        COMMAND mkdir -p ${BUNDLE}/Contents/MacOS/
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/${BIN_NAME} ${BUNDLE}/Contents/MacOS
        
        
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/GameNetworkingSockets/bin/libGameNetworkingSockets.dylib ${BUNDLE}/Contents/MacOS
        COMMAND install_name_tool -change @rpath/libGameNetworkingSockets.dylib @executable_path/libGameNetworkingSockets.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}

        # zlib
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/zlib/*/*/libz.1.dylib ${BUNDLE}/Contents/MacOS
        COMMAND install_name_tool -change libz.1.dylib @executable_path/libz.1.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}

        COMMAND install_name_tool -change ${OPENSSL_CRYPTO_LIBRARY} @executable_path/libcrypto.dylib ${BUNDLE}/Contents/MacOS/libGameNetworkingSockets.dylib
        COMMAND install_name_tool -change ${OPENSSL_CRYPTO_LIBRARY} @executable_path/libcrypto.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
        COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/openssl@3/lib/libcrypto.3.dylib @executable_path/libcrypto.dylib ${BUNDLE}/Contents/MacOS/libGameNetworkingSockets.dylib
        COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/openssl@3/lib/libcrypto.3.dylib @executable_path/libcrypto.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
        COMMAND cp ${OPENSSL_CRYPTO_LIBRARY} ${BUNDLE}/Contents/MacOS/libcrypto.dylib

        COMMAND chmod 774 ${BUNDLE}/Contents/MacOS/*.dylib
        COMMAND cp -r ${CMAKE_CURRENT_BINARY_DIR}/openjkdf2-64.dsym ${BUNDLE}/Contents/MacOS/openjkdf2-64.dsym
        COMMAND chmod 774 ${BUNDLE}/Contents/MacOS/${BIN_NAME}
        COMMAND generate-iconset ${PROJECT_SOURCE_DIR}/packaging/icon.png
        COMMAND mkdir -p ${BUNDLE}/Contents/Resources/
        COMMAND cp ${PROJECT_SOURCE_DIR}/packaging/icon.icns ${BUNDLE}/Contents/Resources/OpenJKDF2.icns
        COMMAND cp -r ${PROJECT_SOURCE_DIR}/resource/ ${BUNDLE}/Contents/Resources/resource/
        COMMAND rm -rf ${PROJECT_SOURCE_DIR}/packaging/icon.iconset
        COMMAND rm -rf ${PROJECT_SOURCE_DIR}/packaging/icon.icns
        )
endmacro()

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
        find_package(OpenSSL REQUIRED Crypto)
        target_link_libraries(sith_engine PUBLIC OpenSSL::Crypto)
        
    endif()
endmacro()