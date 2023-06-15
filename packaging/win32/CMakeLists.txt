if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL x86_64) # the assemblyIdentity element’s processorArchitecture attribute only accepts x64 or AMD64 but not x86_64
    set(
        OPENJKDF2_ASSEMBLY_PROCESSOR_ARCHITECTURE
        AMD64
        CACHE INTERNAL
        "The assemblyIdentity element’s processorArchitecture attribute"
    )
else()
    set(
        OPENJKDF2_ASSEMBLY_PROCESSOR_ARCHITECTURE
        ${CMAKE_SYSTEM_PROCESSOR}
        CACHE INTERNAL
        "The assemblyIdentity element’s processorArchitecture attribute"
    )
endif()
configure_file(
    openjkdf2.manifest.in
    ${CMAKE_CURRENT_SOURCE_DIR}/${BIN_NAME}.exe.manifest
)
