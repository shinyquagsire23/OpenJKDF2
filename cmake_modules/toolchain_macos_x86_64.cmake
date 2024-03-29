set(CMAKE_OSX_ARCHITECTURES "x86_64")
set(PLAT_MACOS_X86_64 TRUE)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(GLEW_PATH "/usr/local/opt/glew")
set(CMAKE_IGNORE_PATH "/opt/homebrew")
set(CMAKE_IGNORE_PATH "/opt/homebrew/include")
set(CMAKE_IGNORE_PATH "/opt/homebrew/lib")

list(APPEND CMAKE_PREFIX_PATH /usr/local)