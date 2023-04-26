set(GameNetworkingSockets_ROOT ${CMAKE_BINARY_DIR}/GameNetworkingSockets)
if(WIN32)
    set(USE_CRYPTO BCrypt)
else()
    set(USE_CRYPTO OpenSSL)
endif()
ExternalProject_Add(
    GAMENETWORKINGSOCKETS
    SOURCE_DIR             ${CMAKE_SOURCE_DIR}/lib/GameNetworkingSockets
    BINARY_DIR             ${GameNetworkingSockets_ROOT}
    INSTALL_DIR            ${GameNetworkingSockets_ROOT}
    UPDATE_DISCONNECTED    TRUE
    CMAKE_ARGS             "--toolchain ${CMAKE_TOOLCHAIN_FILE}"
                           "--install-prefix ${GameNetworkingSockets_ROOT}"
    CMAKE_CACHE_ARGS       -DCMAKE_BUILD_TYPE:STRING=Release
                           -DCMAKE_POLICY_DEFAULT_CMP0074:STRING=NEW
                           -DBUILD_STATIC_LIB:BOOL=FALSE
                           -DBUILD_SHARED_LIB:BOOL=TRUE
                           -DUSE_CRYPTO:STRING=${USE_CRYPTO}
                           -DUSE_STEAMWEBRTC:BOOL=FALSE
                           -DProtobuf_USE_STATIC_LIBS:BOOL=TRUE
                           -DProtobuf_ROOT:PATH=${Protobuf_ROOT}
                           ${GAMENETWORKINGSOCKETS_PROTOC_EXECUTABLE}
    DEPENDS                PROTOBUF ${GAMENETWORKINGSOCKETS_DEPENDS}
    PATCH_COMMAND          git restore CMakeLists.txt src/CMakeLists.txt &&
                           git apply -v ${CMAKE_SOURCE_DIR}/cmake_modules/GameNetworkingSockets_v1.4.1.patch
)

set(GameNetworkingSockets_FOUND TRUE)
set(GameNetworkingSockets_VERSION 1.4.1)
set(GameNetworkingSockets_INCLUDE_DIRS ${GameNetworkingSockets_ROOT}/include/GameNetworkingSockets)
set(GameNetworkingSockets_SHARED_LIBRARIES GameNetworkingSockets)
set(GameNetworkingSockets_STATIC_LIBRARIES GameNetworkingSockets_s)

if(NOT TARGET GameNetworkingSockets::GameNetworkingSockets)
    add_library(GameNetworkingSockets::GameNetworkingSockets SHARED IMPORTED)
endif()
add_dependencies(GameNetworkingSockets::GameNetworkingSockets GAMENETWORKINGSOCKETS)
file(MAKE_DIRECTORY ${GameNetworkingSockets_INCLUDE_DIRS})
set_target_properties(
    GameNetworkingSockets::GameNetworkingSockets PROPERTIES
    IMPORTED_LOCATION
    ${GameNetworkingSockets_ROOT}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}${GameNetworkingSockets_SHARED_LIBRARIES}${CMAKE_SHARED_LIBRARY_SUFFIX}
    IMPORTED_IMPLIB
    ${GameNetworkingSockets_ROOT}/lib/${CMAKE_IMPORT_LIBRARY_PREFIX}${GameNetworkingSockets_SHARED_LIBRARIES}${CMAKE_IMPORT_LIBRARY_SUFFIX}
)
target_include_directories(
    GameNetworkingSockets::GameNetworkingSockets INTERFACE
    ${GameNetworkingSockets_INCLUDE_DIRS}
)
target_link_directories(
    GameNetworkingSockets::GameNetworkingSockets INTERFACE
    ${GameNetworkingSockets_ROOT}/lib
)
if(NOT TARGET GameNetworkingSockets::GameNetworkingSockets_s)
    add_library(GameNetworkingSockets::GameNetworkingSockets_s STATIC IMPORTED)
endif()
add_dependencies(GameNetworkingSockets::GameNetworkingSockets_s GAMENETWORKINGSOCKETS)
set_property(
    TARGET GameNetworkingSockets::GameNetworkingSockets_s
    PROPERTY IMPORTED_LOCATION
    ${GameNetworkingSockets_ROOT}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}${GameNetworkingSockets_STATIC_LIBRARIES}${CMAKE_STATIC_LIBRARY_SUFFIX}
)
target_include_directories(
    GameNetworkingSockets::GameNetworkingSockets_s INTERFACE
    ${GameNetworkingSockets_INCLUDE_DIRS}
)
target_link_directories(
    GameNetworkingSockets::GameNetworkingSockets_s INTERFACE
    ${GameNetworkingSockets_ROOT}/lib
)
