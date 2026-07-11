#!/usr/bin/env python3
# Patches lib/SDL_mixer/CMakeLists.txt (run via PATCH_COMMAND in build_sdl_mixer.cmake).
#
# SDL3_mixer's own CMakeLists tries to fold every vendored codec (ogg, vorbis, opus,
# opusfile, gme, mpg123, ...) into ONE unified export set (SDL3MixerTargets) for
# find_package(SDL3_mixer) consumers. But several of those vendored subprojects (ogg
# in particular) also do their OWN install(TARGETS ... EXPORT ...) as standalone
# projects, and a CMake target can't belong to two export sets -- so the combination
# errors out at the Generate step ("target exported in more than one export set").
#
# We never consume SDL3_mixer via find_package() -- this project reads the built
# static libs directly by path (see build_sdl_mixer.cmake) -- so none of this
# package/export machinery is needed. This strips it while leaving the plain
# ARCHIVE/LIBRARY/RUNTIME DESTINATION install(TARGETS ...) calls in place, which is
# what actually copies the .a files into the shared lib/ output directory.
import re
import sys

path = sys.argv[1]
with open(path) as f:
    original = f.read()

text = original

# 1) Main library's install(TARGETS ${sdl3_mixer_target_name} ...) -- drop just the
#    "EXPORT SDL3MixerTargets" line (8-space indent), keep the DESTINATION clauses.
text = text.replace(
    "    install(\n"
    "        TARGETS ${sdl3_mixer_target_name}\n"
    "        EXPORT SDL3MixerTargets\n",
    "    install(\n"
    "        TARGETS ${sdl3_mixer_target_name}\n",
    1,
)

# 2) Extra vendored-codec targets install(TARGETS ${INSTALL_EXTRA_TARGETS} ...) --
#    drop the "EXPORT SDL3MixerTargets" line (12-space indent). This block has no
#    ARCHIVE DESTINATION anyway (each vendored dep installs its own .a via its own
#    CMakeLists), so it was only ever registering export-set metadata we don't use.
text = text.replace(
    "        install(TARGETS ${INSTALL_EXTRA_TARGETS}\n"
    "            EXPORT SDL3MixerTargets\n",
    "        install(TARGETS ${INSTALL_EXTRA_TARGETS}\n",
    1,
)

# 3) Drop the standalone install(EXPORT SDL3MixerTargets ...) block that writes the
#    CMake package config target file -- nothing claims that export set anymore after
#    (1)/(2), and we don't consume it.
text = re.sub(
    r"    install\(EXPORT SDL3MixerTargets\n(?:.*\n)*?    \)\n\n",
    "",
    text,
    count=1,
)

# 4) Drop the build-tree export(TARGETS ...) call (writes a similar file into the
#    build dir for use by other in-tree consumers via add_subdirectory -- not us).
text = text.replace(
    '    export(TARGETS ${sdl3_mixer_target_name} ${INSTALL_EXTRA_TARGETS} NAMESPACE "SDL3_mixer::" FILE "${sdl3_mixer_target_name}-targets.cmake")\n\n',
    "",
    1,
)

if text != original:
    with open(path, "w") as f:
        f.write(text)
    print(f"patch_sdl_mixer_cmakelists.py: patched {path}")
else:
    print(f"patch_sdl_mixer_cmakelists.py: no changes needed in {path} (already patched or upstream changed)")
