// dcVmu: persist the Dreamcast writable tree to a VMU save (no-SD fallback).
//
// Without an SD card the writable store is a volatile RAM disk. This module gives
// it persistence by packing the whole writable tree (player/ profiles, config
// JSON, the single autosave) into one flat archive, wrapping it in a VMS package,
// and storing it as a single VMU save file -- sidestepping the VMU's flat, tiny,
// 12-char-name filesystem. On boot the save is unpacked back into the RAM disk.
//
// Entirely Added code (Dreamcast port only).
#ifndef DC_VMU_H
#define DC_VMU_H

#ifdef TARGET_DREAMCAST

// 1 if at least one VMU (maple memory card) is connected.
int dcVmu_Available(void);

// If a VMU carrying our save is present, unpack it into pWritableRoot (creating
// the player/ tree there). Returns 1 if a save was loaded, 0 otherwise.
int dcVmu_Load(const char* pWritableRoot);

// Pack everything under pWritableRoot into the VMU save. Returns 1 on success, 0
// on failure (no VMU, too big for the card, or a write error).
int dcVmu_Save(const char* pWritableRoot);

#endif // TARGET_DREAMCAST
#endif // DC_VMU_H
