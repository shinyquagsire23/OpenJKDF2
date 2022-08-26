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

find_path(GAMENETWORKINGSOCKETS_INCLUDE_DIR
  NAMES "steam/isteamnetworkingsockets.h"
  PATH_SUFFIXES "GameNetworkingSockets/include")

find_library(GAMENETWORKINGSOCKETS_LIBRARY
  NAMES "GameNetworkingSockets_s"
  PATH_SUFFIXES "GameNetworkingSockets/lib")

mark_as_advanced(GAMENETWORKINGSOCKETS_INCLUDE_DIR GAMENETWORKINGSOCKETS_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GameNetworkingSockets DEFAULT_MSG GAMENETWORKINGSOCKETS_INCLUDE_DIR GAMENETWORKINGSOCKETS_LIBRARY)
