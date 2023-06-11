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
    
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/GameNetworkingSockets/bin/libGameNetworkingSockets.dylib ${BUNDLE}/Contents/MacOS
    #COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/build_protobuf/libprotobuf.3.21.4.0.dylib ${BUNDLE}/Contents/MacOS
    COMMAND install_name_tool -change @rpath/libGameNetworkingSockets.dylib @executable_path/libGameNetworkingSockets.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    #COMMAND install_name_tool -change @rpath/libprotobuf.3.21.4.0.dylib @executable_path/libprotobuf.3.21.4.0.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}

    # zlib
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/zlib/*/*/libz.1.dylib ${BUNDLE}/Contents/MacOS
    COMMAND install_name_tool -change libz.1.dylib @executable_path/libz.1.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}

    # libpng
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/libpng/libpng16.16.39.0.dylib ${BUNDLE}/Contents/MacOS/libpng16.16.dylib
    COMMAND install_name_tool -change @rpath/libpng16.16.dylib @executable_path/libpng16.16.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}

    #COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/sdl2/lib/libSDL2-2.0.0.dylib @executable_path/libSDL2-2.0.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/sdl2_mixer/lib/libSDL2_mixer-2.0.0.dylib @executable_path/libSDL2_mixer-2.0.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libmodplug/lib/libmodplug.1.dylib @executable_path/libmodplug.1.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libmodplug/lib/libmodplug.1.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/mpg123/lib/libmpg123.0.dylib @executable_path/libmpg123.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/mpg123/lib/libmpg123.0.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbis.0.dylib @executable_path/libvorbis.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbis.0.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libxmp/lib/libxmp.4.dylib @executable_path/libxmp.4.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libxmp/lib/libxmp.4.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/fluid-synth/lib/libfluidsynth.3.dylib @executable_path/libfluidsynth.3.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/fluid-synth/lib/libfluidsynth.3.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/opusfile/lib/libopusfile.0.dylib @executable_path/libopusfile.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/opusfile/lib/libopusfile.0.dylib ${BUNDLE}/Contents/MacOS
    
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbisfile.3.dylib @executable_path/libvorbisfile.3.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbisfile.3.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/openssl@1.1/lib/libcrypto.1.1.dylib @executable_path/libcrypto.1.1.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/openssl@1.1/lib/libcrypto.1.1.dylib @executable_path/libcrypto.1.1.dylib ${BUNDLE}/Contents/MacOS/libGameNetworkingSockets.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/openssl@1.1/lib/libcrypto.1.1.dylib @executable_path/libcrypto.1.1.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    COMMAND cp ${HOMEBREW_PREFIX}/opt/openssl@1.1/lib/libcrypto.1.1.dylib ${BUNDLE}/Contents/MacOS
    
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/flac/lib/libFLAC.12.dylib @executable_path/libFLAC.12.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/flac/lib/libFLAC.12.dylib ${BUNDLE}/Contents/MacOS
    
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libFLAC.12.dylib
    
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libvorbis.0.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/Cellar/libvorbis/1.3.7/lib/libvorbis.0.dylib @executable_path/libvorbis.0.dylib ${BUNDLE}/Contents/MacOS/libvorbisfile.3.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libvorbisfile.3.dylib

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libvorbisfile.3.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib ${BUNDLE}/Contents/MacOS

    # Ehhhhhhhhhhh
    #
    # libfluidsynth
    #
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/glib/lib/libglib-2.0.0.dylib @executable_path/libglib-2.0.0.dylib ${BUNDLE}/Contents/MacOS/libfluidsynth.3.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/glib/lib/libgthread-2.0.0.dylib @executable_path/libgthread-2.0.0.dylib  ${BUNDLE}/Contents/MacOS/libfluidsynth.3.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/gettext/lib/libintl.8.dylib @executable_path/libintl.8.dylib ${BUNDLE}/Contents/MacOS/libfluidsynth.3.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libsndfile/lib/libsndfile.1.dylib @executable_path/libsndfile.1.dylib  ${BUNDLE}/Contents/MacOS/libfluidsynth.3.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/portaudio/lib/libportaudio.2.dylib @executable_path/libportaudio.2.dylib  ${BUNDLE}/Contents/MacOS/libfluidsynth.3.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/readline/lib/libreadline.8.dylib @executable_path/libreadline.8.dylib ${BUNDLE}/Contents/MacOS/libfluidsynth.3.dylib

    COMMAND cp ${HOMEBREW_PREFIX}/opt/glib/lib/libglib-2.0.0.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${HOMEBREW_PREFIX}/opt/glib/lib/libgthread-2.0.0.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${HOMEBREW_PREFIX}/opt/gettext/lib/libintl.8.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libsndfile/lib/libsndfile.1.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${HOMEBREW_PREFIX}/opt/portaudio/lib/libportaudio.2.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${HOMEBREW_PREFIX}/opt/readline/lib/libreadline.8.dylib ${BUNDLE}/Contents/MacOS

    #
    # libsndfile
    #
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/flac/lib/libFLAC.12.dylib @executable_path/libFLAC.12.dylib ${BUNDLE}/Contents/MacOS/libsndfile.1.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbisenc.2.dylib @executable_path/libvorbisenc.2.dylib ${BUNDLE}/Contents/MacOS/libsndfile.1.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/opus/lib/libopus.0.dylib @executable_path/libopus.0.dylib ${BUNDLE}/Contents/MacOS/libsndfile.1.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/mpg123/lib/libmpg123.0.dylib @executable_path/libmpg123.0.dylib ${BUNDLE}/Contents/MacOS/libsndfile.1.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/lame/lib/libmp3lame.0.dylib @executable_path/libmp3lame.0.dylib ${BUNDLE}/Contents/MacOS/libsndfile.1.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbis.0.dylib @executable_path/libvorbis.0.dylib ${BUNDLE}/Contents/MacOS/libsndfile.1.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libsndfile.1.dylib

    COMMAND cp ${HOMEBREW_PREFIX}/opt/opus/lib/libopus.0.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbisenc.2.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${HOMEBREW_PREFIX}/opt/lame/lib/libmp3lame.0.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/Cellar/libvorbis/1.3.7/lib/libvorbis.0.dylib @executable_path/libvorbis.0.dylib ${BUNDLE}/Contents/MacOS/libvorbisenc.2.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libvorbisenc.2.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libopusfile.0.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/opus/lib/libopus.0.dylib @executable_path/libopus.0.dylib ${BUNDLE}/Contents/MacOS/libopusfile.0.dylib

    #
    # libgthread
    #
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/Cellar/glib/2.76.3/lib/libglib-2.0.0.dylib @executable_path/libglib-2.0.0.dylib ${BUNDLE}/Contents/MacOS/libgthread-2.0.0.dylib

    #
    # libglib-2.0.0.dylib
    #
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/gettext/lib/libintl.8.dylib @executable_path/libintl.8.dylib ${BUNDLE}/Contents/MacOS/libglib-2.0.0.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/pcre2/lib/libpcre2-8.0.dylib @executable_path/libpcre2-8.0.dylib ${BUNDLE}/Contents/MacOS/libglib-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/pcre2/lib/libpcre2-8.0.dylib ${BUNDLE}/Contents/MacOS

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