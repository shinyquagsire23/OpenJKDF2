# FindOpenAL.cmake override for Nintendo Switch
# This helps CMake find OpenAL in the devkitPro portlibs

if(SWITCH)
    set(OPENAL_FOUND TRUE)
    set(OPENAL_INCLUDE_DIR "${PORTLIBS}/include")
    set(OPENAL_LIBRARY "openal")
    set(OPENAL_LIBRARIES "openal")
    
    # Create imported target
    if(NOT TARGET OpenAL::OpenAL)
        add_library(OpenAL::OpenAL INTERFACE IMPORTED)
        set_target_properties(OpenAL::OpenAL PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${OPENAL_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES "${OPENAL_LIBRARY}"
        )
    endif()
    
    mark_as_advanced(OPENAL_INCLUDE_DIR OPENAL_LIBRARY)
else()
    # Fall back to the standard FindOpenAL
    include(${CMAKE_ROOT}/Modules/FindOpenAL.cmake OPTIONAL)
endif()
