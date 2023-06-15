set(Protoc_ROOT ${CMAKE_BINARY_DIR}/protoc)
ExternalProject_Add(
    PROTOC
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/lib/protobuf
    BINARY_DIR          ${Protoc_ROOT}
    INSTALL_DIR         ${Protoc_ROOT}
    UPDATE_DISCONNECTED TRUE
    CMAKE_ARGS          --install-prefix ${Protoc_ROOT}
                        -DCMAKE_BUILD_TYPE:STRING=Release
                        -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
                        -DCMAKE_POLICY_DEFAULT_CMP0074:STRING=NEW
                        -Dprotobuf_BUILD_TESTS:BOOL=FALSE
                        -Dprotobuf_BUILD_SHARED_LIBS:BOOL=FALSE
                        -Dprotobuf_BUILD_CONFORMANCE:BOOL=FALSE
                        -Dprotobuf_BUILD_EXAMPLES:BOOL=FALSE
                        -Dprotobuf_BUILD_PROTOC_BINARIES:BOOL=TRUE
                        -Dprotobuf_DISABLE_RTTI:BOOL=TRUE
                        -DZLIB_ROOT:PATH=${ZLIB_HOST_ROOT}
    BUILD_COMMAND       ${CMAKE_MAKE_PROGRAM} protoc
    DEPENDS             ${PROTOC_DEPENDS}
    BUILD_BYPRODUCTS    ${TODO}
)
set(Protoc_PROTOC_EXECUTABLE ${Protoc_ROOT}/bin/protoc)

if(NOT TARGET protobuf::protoc)
    add_executable(protobuf::protoc IMPORTED)
endif()
add_dependencies(protobuf::protoc PROTOC)
set_target_properties(
    protobuf::protoc PROPERTIES
    IMPORTED_LOCATION
    ${Protoc_PROTOC_EXECUTABLE}
    IMPORTED_LOCATION_Release
    ${Protoc_PROTOC_EXECUTABLE}
    IMPORTED_LOCATION_Debug
    ${Protoc_PROTOC_EXECUTABLE}
)
