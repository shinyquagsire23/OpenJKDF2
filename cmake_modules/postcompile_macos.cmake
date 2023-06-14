if(TARGET_MACOS)
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

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/openssl@1.1/lib/libcrypto.1.1.dylib @executable_path/libcrypto.1.1.dylib ${BUNDLE}/Contents/MacOS/libGameNetworkingSockets.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/openssl@1.1/lib/libcrypto.1.1.dylib @executable_path/libcrypto.1.1.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    COMMAND cp ${HOMEBREW_PREFIX}/opt/openssl@1.1/lib/libcrypto.1.1.dylib ${BUNDLE}/Contents/MacOS

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
endif()