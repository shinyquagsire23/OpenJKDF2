// SPDX-License-Identifier: Zlib
// SPDX-FileNotice: Modified from the original version by the BlocksDS project.
//
// Copyright (C) 2009-2017 Dave Murphy (WinterMute)
// Copyright (C) 2017 fincs
// Copyright (C) 2023 Antonio Niño Díaz

// List of MPU regions
// ===================
//
// The base addresses of ITCM and DTCM are defined by the linkerscript.
//
// The base address of ITCM is fixed at 0x00000000, but it is mirrored for 32 MB
// every 32 KB. This means that 0x01000000 is a valid base address.
//
// Num |    Base    |  Size  | System    | Access | Cache | WB | Description
// ====+============+========+===========+========+=======+====+=======================
//   0 | 0x04000000 |  64 MB | All       |  R/W   |   N   | N  | I/O registers
// ----+------------+--------+-----------+--------+-------+----+-----------------------
//   1 | 0xFFFF0000 |  64 KB | All       |  RO    |   Y   | N  | System ROM
// ----+------------+--------+-----------+--------+-------+----+-----------------------
//   2 | 0x00000000 |   4 KB | All       |  RO[3] |   N   | N  | Alternate vector base
// ----+------------+--------+-----------+--------+-------+----+-----------------------
//   3 | 0x08000000 | 128 MB | DS, DSd   |  R/W   |   N   | N  | DS Accessory (GBA Cart)
//     | 0x03000000 |   8 MB | DSI, DSId |        |       |    | DSi switchable IWRAM
// ----+------------+--------+-----------+--------+-------+----+-----------------------
//   4 | 0x01000000 |  32 KB | All       |  R/W   |   N   | N  | ITCM
// ----+------------+--------+-----------+--------+-------+----+-----------------------
//   5 | 0x02000000 |  16 MB | DS    [1] |  R/W   |   N   | N  | Non-cacheable main RAM
//     | 0x02800000 |   8 MB | DSd       |        |       |    |
//     | 0x0C000000 |  16 MB | DSI       |        |       |    |
//     | 0x0C000000 |  32 MB | DSId      |        |       |    | DSi debugger extended IWRAM
// ----+------------+--------+-----------+--------+-------+----+-----------------------
//   6 | 0x02000000 |   4 MB | DS        |  R/W   |   Y   | Y  | Cacheable main RAM
//     | 0x02000000 |   8 MB | DSd   [2] |        |       |    |
//     | 0x02000000 |  16 MB | DSI, DSId |        |       |    |
// ----+------------+--------+-----------+--------+-------+----+-----------------------
//   7 | 0x02FF0000 |  16 KB | All       |  R/W   |   N   | N  | DTCM
//
// [1]: The size of the main RAM of the DS is 4 MB. This is mirrored up to
// 0x03000000 (4 times in total). The last mirror is often used for
// optimizations that involve accessing the end of main RAM (like the BIOS
// interrupt flags). The other two mirrors aren't used by libnds, but the mirror
// at 0x02400000 is used by some legacy applications built with libnds.
//
// Also, note that this section overlaps with the cacheable main RAM (region 7).
// This is required because the size of the regions must be a power of two (and
// 12 MB isn't a power of two), and regions with a higher index have priority
// over regions with a lower index (so the cacheable region has priority).
//
// It also overlaps with the DTCM region, which has a higher priority than both
// the cacheable and non-cacheable regions. This region is required to disable
// the data cache in DTCM.
//
// [2]: The actual size of the main RAM of the DSi debugger version is 32 MB,
// but it isn't possible to map everything at 0x02000000 because shared WRAM is
// mapped at 0x03000000, so there are only 16 MB available. The last 16 MB of
// the main RAM can only be accessed from their non-cachable mirror. This isn't
// a problem in a regular retail DSi because it has exactly 16 MB of RAM.
//
// [3]: Normally, access to this region is disabled. If the alternate vector
// base is enabled via setVectorBase(), code and data read access is enabled.
// This allows us to detect null pointer access attempts. However, writes are
// always disabled, as the alternate vector base is written to via the ITCM
// mirror at 0x01000000.
//
// In theory, data fetches could be disabled by using a B opcode to jump to
// (readable) ITCM first, but this would have the side effect of marginally
// slowing down IRQ performance.
//
// Legend:
//
//   Access: Data and instruction access permissions (same for privileged and user)
//   Cache: Data and instruction cacheable
//   WB: Write buffer enable
//
//   DS: Regular DS
//   DSd: Debugger DS
//   DSI: Regular DSi
//   DSId: Debugger DSi

#include <nds/arm9/cp15_asm.h>
#include <nds/asminc.h>

#include "mpu_internal.h"

    .syntax  unified
    .arch    armv5te
    .cpu     arm946e-s

    .arm

// Enables data cache for extended main ram
BEGIN_ASM_FUNC debugRamEnableCache

    // Enable data cache for this region
    mrc     CP15_REG2_DATA_CACHE_CONFIG(r1)
    orr     r1, CP15_CONFIG_AREA_IS_CACHABLE(REGION_RAM_UNCACHED)
    mcr     CP15_REG2_DATA_CACHE_CONFIG(r1)

    // Write buffer enable if requested (write-back instead of write-through)
    mrc     CP15_REG3_WRITE_BUFFER_CONTROL(r1)
    orr     r1, CP15_CONFIG_AREA_IS_BUFFERABLE(REGION_RAM_UNCACHED)
    mcr     CP15_REG3_WRITE_BUFFER_CONTROL(r1)

    bx      lr

// Enables data cache for NWRAM
BEGIN_ASM_FUNC nwramEnableCache

    // Enable data cache for this region
    mrc     CP15_REG2_DATA_CACHE_CONFIG(r1)
    orr     r1, CP15_CONFIG_AREA_IS_CACHABLE(REGION_SLOT_2_DSI_IWRAM)
    mcr     CP15_REG2_DATA_CACHE_CONFIG(r1)

    // Write buffer enable if requested (write-back instead of write-through)
    mrc     CP15_REG3_WRITE_BUFFER_CONTROL(r1)
    orr     r1, CP15_CONFIG_AREA_IS_BUFFERABLE(REGION_SLOT_2_DSI_IWRAM)
    mcr     CP15_REG3_WRITE_BUFFER_CONTROL(r1)

    bx      lr
