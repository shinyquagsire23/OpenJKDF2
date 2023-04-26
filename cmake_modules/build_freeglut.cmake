set(FreeGLUT_ROOT ${CMAKE_BINARY_DIR}/freeglut)
ExternalProject_Add(
    FREEGLUT
    SOURCE_DIR          ${CMAKE_SOURCE_DIR}/lib/freeglut
    BINARY_DIR          ${FreeGLUT_ROOT}
    INSTALL_DIR         ${FreeGLUT_ROOT}
    UPDATE_DISCONNECTED TRUE
    CMAKE_ARGS          --toolchain ${CMAKE_TOOLCHAIN_FILE}
                        --install-prefix ${FreeGLUT_ROOT}
                        -DCMAKE_BUILD_TYPE:STRING=Release
                        -DFREEGLUT_BUILD_STATIC_LIBS:BOOL=FALSE
    # We have to pass `LIBS` via `CMAKE_CACHE_ARGS` because CMake’s 3.26.3
    # ExternalProject_Add() has a bug that ruthlessly swallows `;` when used
    # with `CMAKE_ARGS`
    CMAKE_CACHE_ARGS    -DLIBS:STRING=advapi32;user32
)
# *Replicate* variables generated by `FindGLUT`
set(GLUT_FOUND TRUE)
set(GLUT_INCLUDE_DIRS ${FreeGLUT_ROOT}/include)
set(GLUT_LIBRARIES freeglut)
set(GLUT_INCLUDE_DIR ${GLUT_INCLUDE_DIRS} CACHE PATH GLUT_INCLUDE_DIR)
set(GLUT_glut_LIBRARY ${FreeGLUT_ROOT}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}${GLUT_LIBRARIES}${CMAKE_SHARED_LIBRARY_SUFFIX})

# *Replicate* targets generated by `FindGLUT`
if(NOT TARGET GLUT::GLUT)
    add_library(GLUT::GLUT SHARED IMPORTED)
endif()
add_dependencies(GLUT::GLUT FREEGLUT)
file(MAKE_DIRECTORY ${GLUT_INCLUDE_DIRS})
set_target_properties(
    GLUT::GLUT PROPERTIES
    IMPORTED_LOCATION ${GLUT_glut_LIBRARY}
    IMPORTED_IMPLIB ${FreeGLUT_ROOT}/lib/${CMAKE_IMPORT_LIBRARY_PREFIX}${GLUT_LIBRARIES}${CMAKE_IMPORT_LIBRARY_SUFFIX}
)
target_include_directories(GLUT::GLUT INTERFACE ${GLUT_INCLUDE_DIRS})
target_link_directories(GLUT::GLUT INTERFACE ${FreeGLUT_ROOT}/lib)
