# Filename: FindGameNetworkingSockets.cmake
# Authors: lachbr (13 May, 2020)
#
# Usage:
#   find_package(GameNetworkingSockets [REQUIRED] [QUIET])
#
# Once done this will define:
#   GNS_FOUND       - system has GNS
#   GNS_INCLUDE_DIR - the include directory containing steam/isteamnetworkingsockets.h
#   GNS_LIBRARY     - the path to the GNS library
#

find_path(
    GameNetworkingSockets_INCLUDE_DIRS
    NAMES steam/isteamnetworkingsockets.h
    PATH_SUFFIXES /GameNetworkingSockets
)

find_library(
    GameNetworkingSockets_SHARED_LIBRARIES
    NAMES GameNetworkingSockets
)

find_library(
    GameNetworkingSockets_STATIC_LIBRARIES
    NAMES GameNetworkingSockets_s
)

add_library(GameNetworkingSockets::GameNetworkingSockets SHARED IMPORTED)
set_property(
    TARGET GameNetworkingSockets::GameNetworkingSockets
    PROPERTY IMPORTED_LOCATION ${GameNetworkingSockets_SHARED_LIBRARIES}
)
set_property(
    TARGET GameNetworkingSockets::GameNetworkingSockets
    PROPERTY IMPORTED_IMPLIB ${GameNetworkingSockets_SHARED_LIBRARIES}
)
add_library(GameNetworkingSockets::GameNetworkingSockets_s STATIC IMPORTED)
set_property(
    TARGET GameNetworkingSockets::GameNetworkingSockets_s
    PROPERTY IMPORTED_LOCATION ${GameNetworkingSockets_STATIC_LIBRARIES}
)

mark_as_advanced(
    GameNetworkingSockets_INCLUDE_DIRS
    GameNetworkingSockets_SHARED_LIBRARIES
    GameNetworkingSockets_STATIC_LIBRARIES
    GameNetworkingSockets_VERSION
)
# TODO: Add version detection
# set(GameNetworkingSockets_VERSION )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    GameNetworkingSockets
    DEFAULT_MSG
    GameNetworkingSockets_INCLUDE_DIRS
    GameNetworkingSockets_SHARED_LIBRARIES
    GameNetworkingSockets_STATIC_LIBRARIES
#   VERSION_VAR GameNetworkingSockets_VERSION
)
