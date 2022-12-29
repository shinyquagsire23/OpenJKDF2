cmake_minimum_required(VERSION 3.7)

add_library(libsmusher_static STATIC src/codec48.c src/smush.c)

find_package(SDL2 REQUIRED)
find_package(SDL2_mixer REQUIRED)

add_executable(libsmusher_standalone src/main.c)
include_directories(libsmusher_standalone ${SDL2_INCLUDE_DIR} ${SDL2_MIXER_INCLUDE_DIR})
target_link_libraries(libsmusher_standalone PRIVATE libsmusher_static)
target_link_libraries(libsmusher_standalone PRIVATE ${SDL2_LIBRARIES} ${SDL2_MIXER_LIBRARIES})