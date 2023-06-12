set(PNG_ROOT ${CMAKE_BINARY_DIR}/libpng)

set(LIBPNG_DEPENDS ZLIB::ZLIB)

ExternalProject_Add(
    LIBPNG
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/lib/libpng
    BINARY_DIR          ${PNG_ROOT}
    INSTALL_DIR         ${PNG_ROOT}
    UPDATE_DISCONNECTED TRUE
    CMAKE_ARGS          --toolchain ${CMAKE_TOOLCHAIN_FILE}
                        --install-prefix ${PNG_ROOT}
                        -DCMAKE_BUILD_TYPE:STRING=Release
                        -DCMAKE_POLICY_DEFAULT_CMP0074:STRING=NEW
                        -DPNG_STATIC:BOOL=FALSE
                        -DPNG_EXECUTABLES:BOOL=FALSE
                        -DPNG_TESTS:BOOL=FALSE
                        -DZLIB_ROOT:PATH=${ZLIB_ROOT}
    DEPENDS             ${LIBPNG_DEPENDS}
)
# *Replicate* variables generated by `FindPNG`
set(PNG_FOUND TRUE)
set(PNG_INCLUDE_DIRS ${PNG_ROOT}/include)
set(PNG_INCLUDE_DIR ${PNG_INCLUDE_DIRS})
set(PNG_LIBRARIES png)
set(PNG_LIBRARY ${PNG_LIBRARIES})
set(PNG_DEFINITIONS)
set(PNG_VERSION_STRING 1.6.39)

# *Replicate* targets generated by `FindPNG`
if(NOT TARGET PNG::PNG)
    add_library(PNG::PNG SHARED IMPORTED)
endif()
add_dependencies(PNG::PNG LIBPNG)
file(MAKE_DIRECTORY ${PNG_INCLUDE_DIRS})
set_target_properties(
    PNG::PNG PROPERTIES
    IMPORTED_LOCATION ${PNG_ROOT}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}${PNG_LIBRARIES}${CMAKE_SHARED_LIBRARY_SUFFIX}
    IMPORTED_IMPLIB ${PNG_ROOT}/lib/${CMAKE_IMPORT_LIBRARY_PREFIX}${PNG_LIBRARIES}${CMAKE_IMPORT_LIBRARY_SUFFIX}
)
target_include_directories(PNG::PNG INTERFACE ${PNG_INCLUDE_DIRS})
target_link_directories(PNG::PNG INTERFACE ${PNG_ROOT}/lib)