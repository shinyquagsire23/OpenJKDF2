// dcRamFat: RAM-backed FAT12 filesystem. See header.
#include "dcRamFat.h"

#ifdef TARGET_DREAMCAST

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <kos/blockdev.h>
#include <fat/fs_fat.h>

#include "stdPlatform.h"

// FAT16 geometry. FAT12 is unusable here: this KOS's libkosfat FAT12 cluster
// allocator (fat.c fat_allocate_cluster) never returns the allocated cluster and
// always falls through to ENOSPC, so mkdir/writes fail. FAT16 (nc >= 4085) takes
// the working allocator path. The minimum FAT16 volume with 512B clusters is
// ~2MB; we use ~2.25MB (tiny vs. 16MB main RAM).
#define DCRF_SECTOR_SIZE   512u
#define DCRF_TOTAL_SECTORS 4600u          // ~2.25 MiB
#define DCRF_RESERVED      1u
#define DCRF_NUM_FATS      2u
#define DCRF_ROOT_ENTRIES  512u
#define DCRF_ROOT_SECTORS  32u            // (512*32)/512
#define DCRF_FAT_SECTORS   18u            // FAT16: 18*512=9216B = 4608 entries
// -> data clusters = 4600 - (1 + 2*18 + 32) = 4531  (>= 4085 => FAT16)

static uint8_t* dcRamFat_img = NULL;

// --- RAM block device ---------------------------------------------------------
static int dcRamFat_bdInit(kos_blockdev_t* d)     { (void)d; return 0; }
static int dcRamFat_bdShutdown(kos_blockdev_t* d) { (void)d; return 0; }
static int dcRamFat_bdFlush(kos_blockdev_t* d)    { (void)d; return 0; }

static int dcRamFat_bdRead(const kos_blockdev_t* d, uint64_t block, size_t count, void* buf)
{
    (void)d;
    if ((block + count) > DCRF_TOTAL_SECTORS) return -1;
    memcpy(buf, dcRamFat_img + block * DCRF_SECTOR_SIZE, count * DCRF_SECTOR_SIZE);
    return 0;
}
static int dcRamFat_bdWrite(const kos_blockdev_t* d, uint64_t block, size_t count, const void* buf)
{
    (void)d;
    if ((block + count) > DCRF_TOTAL_SECTORS) return -1;
    memcpy(dcRamFat_img + block * DCRF_SECTOR_SIZE, buf, count * DCRF_SECTOR_SIZE);
    return 0;
}
static uint64_t dcRamFat_bdCount(const kos_blockdev_t* d) { (void)d; return DCRF_TOTAL_SECTORS; }

static kos_blockdev_t dcRamFat_bd = {
    NULL,                 // dev_data
    9,                    // l_block_size (512 = 1<<9)
    dcRamFat_bdInit,
    dcRamFat_bdShutdown,
    dcRamFat_bdRead,
    dcRamFat_bdWrite,
    dcRamFat_bdCount,
    dcRamFat_bdFlush,
};

// --- blank FAT12 formatting ---------------------------------------------------
static void dcRamFat_put16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

static void dcRamFat_Format(uint8_t* img)
{
    memset(img, 0, DCRF_TOTAL_SECTORS * DCRF_SECTOR_SIZE);

    uint8_t* bs = img; // boot sector / BPB
    bs[0] = 0xEB; bs[1] = 0x3C; bs[2] = 0x90;      // jump
    memcpy(bs + 0x03, "OPENJKDF", 8);              // OEM name
    dcRamFat_put16(bs + 0x0B, DCRF_SECTOR_SIZE);   // bytes/sector
    bs[0x0D] = 1;                                  // sectors/cluster
    dcRamFat_put16(bs + 0x0E, DCRF_RESERVED);      // reserved sectors
    bs[0x10] = DCRF_NUM_FATS;                      // number of FATs
    dcRamFat_put16(bs + 0x11, DCRF_ROOT_ENTRIES);  // root dir entries
    dcRamFat_put16(bs + 0x13, DCRF_TOTAL_SECTORS); // total sectors (16-bit)
    bs[0x15] = 0xF8;                               // media descriptor
    dcRamFat_put16(bs + 0x16, DCRF_FAT_SECTORS);   // sectors/FAT
    dcRamFat_put16(bs + 0x18, 63);                 // sectors/track
    dcRamFat_put16(bs + 0x1A, 255);                // heads
    bs[0x24] = 0x80;                               // drive number
    bs[0x26] = 0x29;                               // extended boot signature
    bs[0x27] = 0x78; bs[0x28] = 0x56; bs[0x29] = 0x34; bs[0x2A] = 0x12; // volume ID
    memcpy(bs + 0x2B, "OPENJKDF2  ", 11);          // volume label
    memcpy(bs + 0x36, "FAT16   ", 8);              // fs type
    bs[0x1FE] = 0x55; bs[0x1FF] = 0xAA;            // boot signature

    // FAT copies (FAT16, little-endian): cluster 0 = 0xFFF8 (media), cluster 1 =
    // 0xFFFF (EOC), all remaining entries 0 (free).
    for (unsigned i = 0; i < DCRF_NUM_FATS; i++) {
        uint8_t* fat = img + (DCRF_RESERVED + i * DCRF_FAT_SECTORS) * DCRF_SECTOR_SIZE;
        fat[0] = 0xF8; fat[1] = 0xFF; fat[2] = 0xFF; fat[3] = 0xFF;
    }
    // Root directory region stays zeroed (empty).
}

int dcRamFat_Mount(const char* pMountPoint)
{
    if (!dcRamFat_img) {
        dcRamFat_img = (uint8_t*)malloc(DCRF_TOTAL_SECTORS * DCRF_SECTOR_SIZE);
        if (!dcRamFat_img) {
            stdPlatform_Printf("dcRamFat: out of memory for the RAM disk\n");
            return 0;
        }
    }
    dcRamFat_Format(dcRamFat_img);

    if (fs_fat_init() != 0) {
        stdPlatform_Printf("dcRamFat: fs_fat_init failed\n");
        return 0;
    }
    if (fs_fat_mount(pMountPoint, &dcRamFat_bd, FS_FAT_MOUNT_READWRITE) != 0) {
        stdPlatform_Printf("dcRamFat: fs_fat_mount(%s) failed\n", pMountPoint);
        return 0;
    }
    stdPlatform_Printf("dcRamFat: mounted %uKB FAT16 RAM disk at %s\n",
                       (unsigned)(DCRF_TOTAL_SECTORS * DCRF_SECTOR_SIZE / 1024), pMountPoint);
    return 1;
}

#endif // TARGET_DREAMCAST
