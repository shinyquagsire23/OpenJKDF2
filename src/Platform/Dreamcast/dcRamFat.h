// dcRamFat: a small RAM-backed FAT12 filesystem for the Dreamcast.
//
// KOS's /ram (fs_ramdisk) is a flat, root-only filesystem -- it has no mkdir, so
// the game's player/<name>/ profile tree can't be created there. When there's no
// SD card we instead format a ~1MB FAT12 image in RAM and mount it (via a RAM
// block device + libkosfat), giving a real read/write filesystem WITH
// subdirectories. The VMU snapshot then persists this tree across power cycles.
//
// Dreamcast port only.
#ifndef DC_RAMFAT_H
#define DC_RAMFAT_H

#ifdef TARGET_DREAMCAST

// Format a fresh FAT12 image in RAM and mount it at pMountPoint (e.g. "/rw").
// Returns 1 on success, 0 on failure (out of memory / mount error).
int dcRamFat_Mount(const char* pMountPoint);

#endif // TARGET_DREAMCAST
#endif // DC_RAMFAT_H
