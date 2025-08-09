if(NOT SWITCH)
    message(FATAL_ERROR "This helper can only be used when cross-compiling for the Switch")
endif()

# The directory of this file, which is needed to generate bin2s header files.
get_filename_component(__SWITCH_TOOLS_DIR ${CMAKE_CURRENT_LIST_FILE} PATH)

## A macro to find tools that come with devkitPro which are
## used for working with Switch file formats.
macro(find_tool tool)
    if(NOT ${tool})
        find_program(${tool} ${tool})
        if (${tool})
            message(STATUS "${tool} - found")
        else()
            message(WARNING "${tool} - not found")
        endif()
    endif()
endmacro()

## elf2kip
find_tool(elf2kip)

## elf2nro
find_tool(elf2nro)

## elf2nso
find_tool(elf2nso)

## nacptool
find_tool(nacptool)

## npdmtool
find_tool(npdmtool)

## nxlink
find_tool(nxlink)

## build_pfs0
find_tool(build_pfs0)

## build_romfs
find_tool(build_romfs)

## bin2s
find_tool(bin2s)

## A macro to set the title of the application.
## if `title` is empty, the title will be set
## to the value of `CMAKE_PROJECT_NAME`.
macro(set_app_title title)
    if("${title}" STREQUAL "title-NOTFOUND")
        set(__HOMEBREW_APP_TITLE "${CMAKE_PROJECT_NAME}")
        message(WARNING "The title of the application is unspecified")
    else()
        set(__HOMEBREW_APP_TITLE ${title})
    endif()
endmacro()

## A macro to set the author of the application.
## If `author` is empty, the author will be set
## to "Unspecified author".
macro(set_app_author author)
    if("${author}" STREQUAL "author-NOTFOUND")
        set(__HOMEBREW_APP_AUTHOR "Unspecified author")
        message(WARNING "The author of the application is unspecified")
    else()
        set(__HOMEBREW_APP_AUTHOR ${author})
    endif()
endmacro()

## A macro to set the version of the application.
## If `version` is empty, the version will be set
## to "1.0.0".
macro(set_app_version version)
    if("${version}" STREQUAL "version-NOTFOUND")
        set(__HOMEBREW_APP_VERSION "1.0.0")
        message(WARNING "The version of the application is unspecified")
    else()
        set(__HOMEBREW_APP_VERSION ${version})
    endif()
endmacro()

## A macro to resolve the icon for the homebrew application.
## If an icon was given, it will check for its existence and
## use it.
##
## If the icon doesn't exist, the project root will be checked
## for an icon.jpg that can be used. Otherwise, libnx/default_icon.jpg
## will be acquired. If that doesn't exist as well, no icon will be used.
##
## No icon will be resolved, if a variable called `NO_ICON` is set to
## anything.
macro(set_app_icon file)
    if(NOT NO_ICON)
        if(EXISTS ${file})
            set(__HOMEBREW_ICON ${file})
        elseif(EXISTS ${PROJECT_SOURCE_DIR}/icon.jpg)
            set(__HOMEBREW_ICON ${PROJECT_SOURCE_DIR}/icon.jpg)
        elseif(LIBNX)
            set(__HOMEBREW_ICON ${LIBNX}/default_icon.jpg)
        else()
            # Purposefully don't set `__HOMEBREW_ICON` to anything.
            message(WARNING "Failed to resolve application icon")
        endif()
    endif()
endmacro()

## A macro to specify the NPDM JSON configuration for a system module.
## If a path was given, it will validate it and use the file.
## If the file doesn't exist, the project root will be checked for an
## config.json that can be used.
macro(set_app_json file)
    if(EXISTS ${file})
        set(__HOMEBREW_JSON_CONFIG ${file})
    elseif(EXISTS ${PROJECT_SOURCE_DIR}/config.json)
        set(__HOMEBREW_JSON_CONFIG ${PROJECT_SOURCE_DIR}/config.json)
    else()
        # Purposefully don't set `__HOMEBREW_JSON_CONFIG` to anything.
        message(WARNING "Failed to resolve the JSON config")
    endif()
endmacro()

## Adds a binary library target with the supplied name.
## The macro takes a variable amount of binary files
## within ARGN and passes them to bin2s to create
## a library target from binary files that can be linked.
macro(__add_binary_library target)
    if(NOT ${ARGC} GREATER 1)
        message(FATAL_ERROR "No input files provided")
    endif()

    # Check if ASM is an enabled project language.
    get_cmake_property(ENABLED_LANGUAGES ENABLED_LANGUAGES)
    if(NOT ENABLED_LANGUAGES MATCHES ".*ASM.*")
        message(FATAL_ERROR "To use this macro, call enable_language(ASM) first")
    endif()

    # Generate the bin2s header files.
    foreach(__file ${ARGN})
        # Extract and compose the file name for the header.
        get_filename_component(__file_name ${__file} NAME)
        string(REGEX REPLACE "^([0-9])" "_\\1" __BINARY_FILE ${__file_name})
        string(REGEX REPLACE "[-./]" "_" __BINARY_FILE ${__BINARY_FILE})

        # Generate the header.
        configure_file(${__SWITCH_TOOLS_DIR}/bin2s_header.h.in ${CMAKE_CURRENT_BINARY_DIR}/bin2s_include/${__BINARY_FILE}.h)
    endforeach()

    # Build the Assembly file.
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin2s_lib)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/bin2s_lib/${target}.s
        COMMAND ${bin2s} ${ARGN} > ${CMAKE_CURRENT_BINARY_DIR}/bin2s_lib/${target}.s
        DEPENDS ${ARGN}
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    )

    # Add the respective library target.
    add_library(${target} ${CMAKE_CURRENT_BINARY_DIR}/bin2s_lib/${target}.s)
    target_include_directories(${target} INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/bin2s_include)
endmacro()

## Embeds binary files into a given target.
## The function takes a variable amount of binary files
## within ARGN, which will be passed to bin2s to create
## a library target which will be linked against the
## `target` argument.
function(target_embed_binaries target)
    if(NOT ${ARGC} GREATER 1)
        message(FATAL_ERROR "No input files provided")
    endif()

    get_filename_component(__1st_bin_file ${ARGV1} NAME)
    __add_binary_library(__${target}_embed_${__1st_bin_file} ${ARGN})
    target_link_libraries(${target} __${target}_embed_${__1st_bin_file})
endfunction()

## Generates a .nacp file from a given target.
##
## NACPs hold various application metadata, such as author or version,
## which get embedded into Nintendo Relocatable Object (.nro) files.
##
## It tries to extract `APP_TITLE`, `APP_AUTHOR`, `APP_VERSION` and
## `TITLE_ID` properties from the supplied target, all of them are
## however optional.
function(__generate_nacp target)
    get_filename_component(target_we ${target} NAME_WE)

    # Extract and validate metadata from the target.
    get_target_property(title ${target} "APP_TITLE")
    get_target_property(author ${target} "APP_AUTHOR")
    get_target_property(version ${target} "APP_VERSION")
    get_target_property(title_id ${target} "TITLE_ID")

    set_app_title(${title})
    set_app_author(${author})
    set_app_version(${version})

    # Title ID is mostly irrelevant, that's why it has no
    # special definition routine and is only parsed here.
    if(NOT "${title_id}" STREQUAL "")
        set(NACPFLAGS "--titleid=\"${title_id}\"")
    else()
        set(NACPFLAGS "")  # Purposefully empty.
    endif()

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nacp
        COMMAND ${nacptool} --create ${__HOMEBREW_APP_TITLE} ${__HOMEBREW_APP_AUTHOR} ${__HOMEBREW_APP_VERSION} ${target_we}.nacp ${NACPFLAGS}
        DEPENDS ${target}
        VERBATIM
    )
endfunction()

## Generates a .npdm file from a given target.
##
## NPDMs are found in Switch ExeFS and contain various metadata,
## related to how sysmodules get executed.
##
## It tries to extract a `CONFIG_JSON` property from the supplied
## target, which is required to acquire all the configuration
## mappings that are needed to construct the format.
function(__generate_npdm target)
    get_filename_component(target_we ${target} NAME_WE)

    # Extract and validate metadata from the target.
    get_target_property(config_json ${target} "CONFIG_JSON")

    set_app_json(${config_json})

    # The JSON configuration is crucial, we cannot continue without it.
    if(NOT __HOMEBREW_JSON_CONFIG)
        message(FATAL_ERROR "Cannot generate a NPDM file without the \"CONFIG_JSON\" property being set for the target")
    endif()

    # Build the NPDM file.
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.npdm
        COMMAND ${npdmtool} ${__HOMEBREW_JSON_CONFIG} ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.npdm
        DEPENDS ${target} ${__HOMEBREW_JSON_CONFIG}
        VERBATIM
    )
endfunction()

## Builds a .nro file from a given target.
##
## NROs are the main executable format for homebrew as they allow
## embedding various metadata and a RomFS image.
##
## It tries to extract `ICON` and `ROMFS` properties from the
## supplied target, these are however optional.
function(add_nro_target target)
    get_filename_component(target_we ${target} NAME_WE)

    # Extract metadata from the target.
    get_target_property(icon ${target} "ICON")
    get_target_property(romfs ${target} "ROMFS")

    set_app_icon(${icon})

    # Construct the `NROFLAGS` to invoke elf2nro with.
    set(NROFLAGS "")

    # Set icon for the NRO, if given.
    if(__HOMEBREW_ICON)
        string(APPEND NROFLAGS "--icon=${__HOMEBREW_ICON}")
    endif()

    # Add RomFS to the NRO, if given.
    if(NOT "${romfs}" STREQUAL "romfs-NOTFOUND")
        if(IS_DIRECTORY ${romfs})
            # RomFS is a directory, pass --romfsdir to
            # elf2nro and let it build an image for us.
            string(APPEND NROFLAGS " --romfsdir=${romfs}")
        else()
            # A RomFS image was provided, which can be
            # supplied to the --romfs flag.
            if(EXISTS ${romfs})
                string(APPEND NROFLAGS " --romfs=${romfs}")
            else()
                message(WARNING "The provided RomFS image at ${romfs} doesn't exist")
            endif()
        endif()
    endif()

    # Build the NRO file.
    if(NOT NO_NACP)
        __generate_nacp(${target})

        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nro
            COMMAND ${elf2nro} $<TARGET_FILE:${target}> ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nro --nacp=${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nacp ${NROFLAGS}
            DEPENDS ${target} ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nacp
            VERBATIM
        )
    else()
        message(STATUS "No .nacp file will be generated for ${target_we}.nro")

        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nro
            COMMAND ${elf2nro} $<TARGET_FILE:${target}> ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nro ${NROFLAGS}
            DEPENDS ${target}
            VERBATIM
        )
    endif()

    # Add the respective NRO target and set the required linker flags for the original target.
    add_custom_target(${target_we}_nro ALL SOURCES ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nro)
    set_target_properties(${target} PROPERTIES LINK_FLAGS "-specs=${LIBNX}/switch.specs")
endfunction()

## Builds a .nso file from a given target.
##
## NSOs are the main executable format on the Switch, however
## rarely used outside of NSPs where they represent an important
## component of the ExeFS.
function(add_nso_target target)
    get_filename_component(target_we ${target} NAME_WE)

    # Build the NSO file.
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nso
        COMMAND ${elf2nso} $<TARGET_FILE:${target}> ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nso
        DEPENDS ${target}
        VERBATIM
    )

    # Add the respective NSO target and set the required linker flags for the original target.
    add_custom_target(${target_we}_nso ALL SOURCES ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nso)
    set_target_properties(${target} PROPERTIES LINK_FLAGS "-specs=${LIBNX}/switch.specs")
endfunction()

## Builds a .nsp file from a given target.
##
## NSPs is the file format for system modules, which run as
## background processes.
##
## Building sysmodules depends on a .npdm file (see
## `__generate_npdm`), and a .nso file (see `add_nso_target`),
## so the supplied target needs to fulfill the imposed
## requirements of each of them.
function(add_nsp_target target)
    get_filename_component(target_we ${target} NAME_WE)

    # Build a NPDM for the PFS0 ExeFS, if missing.
    __generate_npdm(${target})

    # Add the required NSO target, if not configured yet.
    if(NOT TARGET ${target_we}_nso)
        add_nso_target(${target})
    endif()

    # Build the NSP file.
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nsp
        PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/exefs
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nso ${CMAKE_CURRENT_BINARY_DIR}/exefs/main
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.npdm ${CMAKE_CURRENT_BINARY_DIR}/exefs/main.npdm
        COMMAND ${build_pfs0} ${CMAKE_CURRENT_BINARY_DIR}/exefs ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nsp
        DEPENDS ${target} ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nso ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.npdm
        VERBATIM
    )

    # Add the respective NSP target and set the required linker flags for the original target.
    add_custom_target(${target_we}_nsp ALL SOURCES ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.nsp)
    set_target_properties(${target} PROPERTIES LINK_FLAGS "-specs=${LIBNX}/switch.specs")
endfunction()

## Builds a .kip file from a given target.
##
## KIPs are initial processes that are loaded by
## the kernel and generally are the first system
## modules to run on the Switch.
##
## Building a KIP file depends on a JSON configuration,
## similar to the one used for .npdm files (see
## `__generate_npdm`).
function(add_kip_target target)
    get_filename_component(target_we ${target} NAME_WE)

    # Extract and validate metadata from the target.
    get_target_property(config_json ${target} "CONFIG_JSON")

    set_app_json(${config_json})

    # The JSON configuration is crucial, we cannot continue without it.
    if(NOT __HOMEBREW_JSON_CONFIG)
        message(FATAL_ERROR "Cannot generate a KIP file without the \"CONFIG_JSON\" property being set for the target")
    endif()

    # Build the KIP file.
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.kip
        COMMAND ${elf2kip} $<TARGET_FILE:${target}> ${__HOMEBREW_JSON_CONFIG} ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.kip
        DEPENDS ${target} ${__HOMEBREW_JSON_CONFIG}
        VERBATIM
    )

    # Add the respective KIP target and set the required linker flags for the original target.
    add_custom_target(${target_we}_kip ALL SOURCES ${CMAKE_CURRENT_BINARY_DIR}/${target_we}.kip)
    set_target_properties(${target} PROPERTIES LINK_FLAGS "-specs=${LIBNX}/switch.specs")
endfunction()
