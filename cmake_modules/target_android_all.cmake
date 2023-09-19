macro(plat_link_and_package)
    target_link_libraries(sith_engine PRIVATE PNG::PNG)
    target_link_libraries(sith_engine PRIVATE ${SDL2_COMMON_LIBS} GLESv1_CM GLESv2 GLESv3 log EGL ${GTK3_LIBRARIES} android jnigraphics nativewindow OpenSLES) #${OPENAL_LIBRARY} GLEW::GLEW
     
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