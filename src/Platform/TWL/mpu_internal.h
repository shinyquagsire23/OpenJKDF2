// SPDX-License-Identifier: Zlib
//
// Copyright (C) 2023 Antonio Niño Díaz

#ifndef ARM9_SYSTEM_MPU_INTERNAL_H__
#define ARM9_SYSTEM_MPU_INTERNAL_H__

#define REGION_IO_REGISTERS         0
#define REGION_SYSTEM_ROM           1
#define REGION_ALT_VECTORS          2
#define REGION_SLOT_2_DSI_IWRAM     3 // DS: Slot-2 | DSi: Switchable IWRAM.
#define REGION_ITCM                 4
#define REGION_RAM_UNCACHED         5
#define REGION_RAM_CACHED           6
#define REGION_DTCM                 7

#endif // ARM9_SYSTEM_MPU_INTERNAL_H__
