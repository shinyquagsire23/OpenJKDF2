include(cmake_modules/target_macos_all.cmake)

macro(plat_initialize)
    message( STATUS "Targeting MacOS" )
    set(BIN_NAME "openjkdf2-64")

    add_definitions(-DARCH_64BIT)

    # macOS specific options
    set(MACOSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum OS X deployment version" FORCE)

    include(cmake_modules/plat_feat_full_sdl2.cmake)

    set(TARGET_MACOS TRUE)

    set(BUNDLE "${PROJECT_SOURCE_DIR}/OpenJKDF2.app")
    set(HOMEBREW_PREFIX $ENV{HOMEBREW_PREFIX})

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c11 -O2 -Wuninitialized -fshort-wchar -Wall -Wno-unused-variable -Wno-parentheses -Wno-missing-braces -Werror=implicit-function-declaration")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fshort-wchar")

    add_link_options(-fshort-wchar -Wl,-map,openjkdf2.map)
endmacro()

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
endmacro()

macro(plat_specific_deps)
    plat_sdl2_deps()
endmacro()