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
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/sdl2_mixer/lib/libSDL2_mixer-2.0.0.dylib @executable_path/libSDL2_mixer-2.0.0.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/sdl2/lib/libSDL2-2.0.0.dylib @executable_path/libSDL2-2.0.0.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/glew/lib/libGLEW.2.2.dylib @executable_path/libGLEW.2.2.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    COMMAND cp ${HOMEBREW_PREFIX}/opt/sdl2/lib/libSDL2-2.0.0.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${HOMEBREW_PREFIX}/opt/sdl2_mixer/lib/libSDL2_mixer-2.0.0.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${HOMEBREW_PREFIX}/opt/glew/lib/libGLEW.2.2.dylib ${BUNDLE}/Contents/MacOS
    
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/build_gns/bin/libGameNetworkingSockets.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/build_protobuf/libprotobuf.3.21.4.0.dylib ${BUNDLE}/Contents/MacOS
    COMMAND install_name_tool -change @rpath/libGameNetworkingSockets.dylib @executable_path/libGameNetworkingSockets.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    COMMAND install_name_tool -change @rpath/libprotobuf.3.21.4.0.dylib @executable_path/libprotobuf.3.21.4.0.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/sdl2/lib/libSDL2-2.0.0.dylib @executable_path/libSDL2-2.0.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/sdl2_mixer/lib/libSDL2_mixer-2.0.0.dylib @executable_path/libSDL2_mixer-2.0.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libmodplug/lib/libmodplug.1.dylib @executable_path/libmodplug.1.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libmodplug/lib/libmodplug.1.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/mpg123/lib/libmpg123.0.dylib @executable_path/libmpg123.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/mpg123/lib/libmpg123.0.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbis.0.dylib @executable_path/libvorbis.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbis.0.dylib ${BUNDLE}/Contents/MacOS
    
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbisfile.3.dylib @executable_path/libvorbisfile.3.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbisfile.3.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/openssl@1.1/lib/libcrypto.1.1.dylib @executable_path/libcrypto.1.1.dylib ${BUNDLE}/Contents/MacOS/libGameNetworkingSockets.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/openssl@1.1/lib/libcrypto.1.1.dylib @executable_path/libcrypto.1.1.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    COMMAND cp ${HOMEBREW_PREFIX}/opt/openssl@1.1/lib/libcrypto.1.1.dylib ${BUNDLE}/Contents/MacOS
    
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/flac/lib/libFLAC.12.dylib @executable_path/libFLAC.12.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/flac/lib/libFLAC.12.dylib ${BUNDLE}/Contents/MacOS
    
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libFLAC.12.dylib
    
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libvorbis.0.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/Cellar/libvorbis/1.3.7/lib/libvorbis.0.dylib @executable_path/libvorbis.0.dylib ${BUNDLE}/Contents/MacOS/libvorbisfile.3.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libvorbisfile.3.dylib

    COMMAND cp ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib ${BUNDLE}/Contents/MacOS
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