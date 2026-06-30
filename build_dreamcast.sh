#!/bin/bash
# Build OpenJKDF2 for the Sega Dreamcast (KallistiOS).
#
# Requires the KallistiOS toolchain. Adjust DC_KOS_BASE if yours lives elsewhere.

DC_KOS_BASE="${KOS_BASE:-/opt/toolchains/dc/kos}"

# Bring the KallistiOS environment into scope (exports KOS_BASE, KOS_CC_BASE,
# KOS_ARCH, etc. that the CMake toolchain reads).
source "${DC_KOS_BASE}/environ.sh"

export OPENJKDF2_RELEASE_COMMIT=$(git log -1 --format="%H")
export OPENJKDF2_RELEASE_COMMIT_SHORT=$(git rev-parse --short=8 HEAD)

mkdir -p build_dreamcast && pushd build_dreamcast

# Prevent host (macOS/Linux) SDK headers from leaking into the cross build
export -n SDKROOT MACOSX_DEPLOYMENT_TARGET CPLUS_INCLUDE_PATH C_INCLUDE_PATH

EXPERIMENTAL_FIXED_POINT=0
DEBUG_QOL_CHEATS=0

# Make ~/.local/bin discoverable so CMake's find_program picks up mkdcdisc there.
export PATH="$HOME/.local/bin:$PATH"

# The "openjkdf2.cdi" target (defined in plat_dreamcast.cmake) builds the ELF and
# then runs mkdcdisc to produce the bootable DiscJuggler .cdi. Fall back to the bare
# ELF target if mkdcdisc wasn't found at configure time.
CDI_TARGET="openjkdf2.cdi"

(EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS cmake .. --toolchain $(pwd)/../cmake_modules/toolchain_dreamcast.cmake || \
 EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS cmake .. --toolchain $(pwd)/../cmake_modules/toolchain_dreamcast.cmake) &&
(EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS make -j $(nproc 2>/dev/null || sysctl -n hw.ncpu) $CDI_TARGET || \
 EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS make -j1 $CDI_TARGET || \
 EXPERIMENTAL_FIXED_POINT=$EXPERIMENTAL_FIXED_POINT DEBUG_QOL_CHEATS=$DEBUG_QOL_CHEATS make -j1 openjkdf2)
RC=$?

if [ $RC -eq 0 ]; then
    echo ""
    echo "Built artifacts:"
    echo "  openjkdf2.cdi - bootable disc image (load this in Flycast/redream)"
    echo "  openjkdf2.elf - unstripped ELF (for addr2line symbolication)"
    ls -lh openjkdf2.cdi openjkdf2.elf 2>/dev/null
fi

popd
exit $RC
