// dcStorage: Dreamcast writable-storage selection + asset routing. See header.
#include "dcStorage.h"

#ifdef TARGET_DREAMCAST

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include <dc/sd.h>
#include <fat/fs_fat.h>
#include <kos/blockdev.h>

#include "stdPlatform.h"
#include "external/fcaseopen/fcaseopen.h" // casepath() for external-lib call sites
#include "dcVmu.h"                         // VMU persistence for the no-SD fallback
#include "dcRamFat.h"                      // RAM-backed FAT disk for the no-SD fallback

// Writable root, e.g. "/sd/openjkdf2" or "/ram/openjkdf2". Becomes the CWD.
static char dcStorage_writableRoot[64] = "";
// Read-only asset root on the GD-ROM, e.g. "/cd/jk1". Relative asset reads are
// routed here since the CWD is now the (asset-free) writable store.
static char dcStorage_assetRoot[128] = "";
static int  dcStorage_bHasSD = 0;
static int  dcStorage_bInit  = 0;

static kos_blockdev_t dcStorage_sdDev;

// Bring up the SCIF SD adapter and mount its first partition read/write at /sd.
// Returns 1 on success. Any failure (no adapter, no card, not FAT) is expected
// and just means we fall back to the RAM disk.
static int dcStorage_MountSD(void)
{
    uint8_t partitionType = 0;

    if (sd_init() != 0)
        return 0; // no SD adapter / no card

    if (sd_blockdev_for_partition(0, &dcStorage_sdDev, &partitionType) != 0) {
        sd_shutdown();
        return 0;
    }

    if (fs_fat_init() != 0) {
        sd_shutdown();
        return 0;
    }

    if (fs_fat_mount("/sd", &dcStorage_sdDev, FS_FAT_MOUNT_READWRITE) != 0) {
        fs_fat_shutdown();
        sd_shutdown();
        return 0;
    }
    return 1;
}

void dcStorage_Init(void)
{
    if (dcStorage_bInit)
        return;
    dcStorage_bInit = 1;

    if (dcStorage_MountSD()) {
        dcStorage_bHasSD = 1;
        strncpy(dcStorage_writableRoot, "/sd/openjkdf2", sizeof(dcStorage_writableRoot) - 1);
        stdPlatform_Printf("dcStorage: SD card mounted, writable root %s\n", dcStorage_writableRoot);
    }
    else {
        // No SD: mount a RAM-backed FAT12 disk. KOS's /ram (fs_ramdisk) is flat --
        // it has no mkdir, so the player/<name>/ profile tree can't live there. The
        // FAT disk gives real subdirectories; the VMU snapshot persists it across
        // power-off. If the FAT mount somehow fails, fall back to flat /ram so the
        // session at least limps along (no nested writes, but no crash).
        dcStorage_bHasSD = 0;
        if (dcRamFat_Mount("/rw"))
            strncpy(dcStorage_writableRoot, "/rw/openjkdf2", sizeof(dcStorage_writableRoot) - 1);
        else
            strncpy(dcStorage_writableRoot, "/ram/openjkdf2", sizeof(dcStorage_writableRoot) - 1);
        stdPlatform_Printf("dcStorage: no SD card, writable root %s (VMU-persisted)\n", dcStorage_writableRoot);
    }
    dcStorage_writableRoot[sizeof(dcStorage_writableRoot) - 1] = 0;
}

void dcStorage_UseWritableCwd(const char* pAssetRoot)
{
    if (!dcStorage_bInit)
        dcStorage_Init();

    if (pAssetRoot) {
        strncpy(dcStorage_assetRoot, pAssetRoot, sizeof(dcStorage_assetRoot) - 1);
        dcStorage_assetRoot[sizeof(dcStorage_assetRoot) - 1] = 0;
    }

    // Create the writable root and make it the working directory. player/,
    // persist/, saves, and registry.json now resolve here; assets are routed to
    // dcStorage_assetRoot by dcStorage_ResolveAssetPath.
    mkdir(dcStorage_writableRoot, 0777);
    if (chdir(dcStorage_writableRoot) != 0) {
        stdPlatform_Printf("dcStorage: chdir(%s) failed, staying on asset root\n", dcStorage_writableRoot);
        // Fall back to the asset root so the game at least runs (writes will fail).
        if (dcStorage_assetRoot[0])
            chdir(dcStorage_assetRoot);
    }
    else {
        stdPlatform_Printf("dcStorage: CWD=%s assets=%s\n", dcStorage_writableRoot, dcStorage_assetRoot);
        // No SD: repopulate the volatile RAM disk from the VMU save, if any.
        if (!dcStorage_bHasSD) {
            stdPlatform_Printf("dcStorage: VMU present=%d (persistence %s)\n",
                dcVmu_Available(), dcVmu_Available() ? "via VMU" : "OFF -- volatile");
            dcVmu_Load(dcStorage_writableRoot);
        }
    }
}

int dcStorage_HasFilesystem(void)
{
    return dcStorage_bHasSD;
}

int dcStorage_VmuPresent(void)
{
    return dcVmu_Available();
}

void dcStorage_Flush(void)
{
    // Snapshot the writable tree to the VMU whenever a card is present -- even
    // alongside SD (the pack keeps only the slim save + config, so it's tiny).
    if (!dcStorage_writableRoot[0])
        return;
    if (dcVmu_Available())
        dcVmu_Save(dcStorage_writableRoot);
}

// Writable data = the player/ (or persist/) tree, or a root-level *.json
// (registry.json, openjkdf2_*.json). Everything else is a read-only asset.
static int dcStorage_IsWritable(const char* p)
{
    if (!strncasecmp(p, "player", 6) && (p[6] == '/' || p[6] == '\\' || p[6] == 0))
        return 1;
    if (!strncasecmp(p, "persist", 7) && (p[7] == '/' || p[7] == '\\' || p[7] == 0))
        return 1;
    if (!strpbrk(p, "/\\")) {
        const char* dot = strrchr(p, '.');
        if (dot && !strcasecmp(dot, ".json"))
            return 1;
    }
    return 0;
}

int dcStorage_ResolveAssetPath(const char* pInPath, char* pOut, size_t outSz)
{
    if (!dcStorage_bInit || !dcStorage_assetRoot[0] || !pInPath || !pOut || outSz == 0)
        return 0;

    const char* p = pInPath;
    if (p[0] == '.' && (p[1] == '/' || p[1] == '\\'))
        p += 2;

    // Absolute paths (/cd/..., /sd/..., /ram/...) and writable data are left as-is.
    if (p[0] == '/' || dcStorage_IsWritable(p))
        return 0;

    size_t n = snprintf(pOut, outSz, "%s/%s", dcStorage_assetRoot, p);
    if (n >= outSz)
        pOut[outSz - 1] = 0;
    for (char* c = pOut; *c; c++) {
        if (*c == '\\')
            *c = '/';
    }
    return 1;
}

int dcStorage_ResolveAssetPathCased(const char* pInPath, char* pOut, size_t outSz)
{
    if (!dcStorage_ResolveAssetPath(pInPath, pOut, outSz))
        return 0;

    // Correct the case against the on-disk name (the GD-ROM is case-sensitive and
    // the engine requests lowercased paths). casepath needs strlen+2 bytes.
    char cased[600];
    if (strlen(pOut) + 2 <= sizeof(cased) && casepath(pOut, cased) && strlen(cased) < outSz) {
        strcpy(pOut, cased);
    }
    return 1;
}

#endif // TARGET_DREAMCAST
