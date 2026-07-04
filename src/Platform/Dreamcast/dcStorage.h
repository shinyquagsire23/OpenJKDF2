// dcStorage: Dreamcast writable-storage selection + read-only asset routing.
//
// The game's assets ship read-only on the GD-ROM (under /cd/jk1 or /cd/mots),
// but the engine also needs to WRITE -- the player/ profile tree, game saves,
// and config/registry JSON. This module picks a writable backing store at
// startup (an SD card if one is mounted, otherwise a RAM disk) and makes it the
// working directory, while assets continue to load read-only from the GD-ROM via
// an asset-root prefix. This mirrors the desktop "install dir vs. CD path" split.
//
// Entirely Added code (no JK.EXE equivalent); Dreamcast port only.
#ifndef DC_STORAGE_H
#define DC_STORAGE_H

#ifdef TARGET_DREAMCAST

#include <stddef.h>

// Probe for writable storage (SD card, else RAM disk) and record the writable
// root. Call once early in main() (uses the system heap, not DC_alloc). Does not
// chdir yet -- InstallHelper_SetCwd drives that once the game dir is known.
void dcStorage_Init(void);

// Record the read-only asset root (e.g. "/cd/jk1"), then create and chdir into
// the writable root chosen by dcStorage_Init. After this, relative writable paths
// (player/, config JSON) land on writable storage and relative asset paths are
// routed back to pAssetRoot by dcStorage_ResolveAssetPath.
void dcStorage_UseWritableCwd(const char* pAssetRoot);

// 1 if the writable store is a real read/write filesystem with room to spare (an
// SD card). 0 for the size-constrained fallback (RAM disk today, VMU later) --
// this is what caps autosaves to a single slot.
int dcStorage_HasFilesystem(void);

// 1 if a VMU (maple memory card) is connected.
int dcStorage_VmuPresent(void);

// Snapshot the writable tree (config + the slim autosave) to the VMU whenever a
// card is present -- including alongside an SD card. No-op with no VMU. Call
// after the game writes a slim save or a profile.
void dcStorage_Flush(void);

// If pInPath is a relative READ-ONLY asset path (i.e. not writable data and not
// already absolute), fill pOut with "<assetRoot>/<pInPath>" and return 1.
// Otherwise return 0 and the caller uses pInPath unchanged (writable data, which
// lives in the writable CWD).
int dcStorage_ResolveAssetPath(const char* pInPath, char* pOut, size_t outSz);

// Like dcStorage_ResolveAssetPath, but also case-corrects the result against the
// actual on-disk name. Use at call sites that hand the path to an external
// library which fopen()s it directly (libsmacker, smush), bypassing the engine's
// fileOpen + fcaseopen. Returns 1 if the path was rewritten.
int dcStorage_ResolveAssetPathCased(const char* pInPath, char* pOut, size_t outSz);

#endif // TARGET_DREAMCAST
#endif // DC_STORAGE_H
