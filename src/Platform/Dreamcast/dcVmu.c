// dcVmu: persist the Dreamcast writable tree to a VMU save. See header.
#include "dcVmu.h"

#ifdef TARGET_DREAMCAST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>

#include <fcntl.h>
#include <kos/fs.h>
#include <dc/maple.h>
#include <dc/vmu_pkg.h>
#include <dc/fs_vmu.h>
#include <zlib.h>

#include "stdPlatform.h"

// One VMU save file holds the whole tree. 12-char max on the VMU; keep it short.
#define DCVMU_SAVE_NAME  "OPENJKDF2"
// The only game save the VMU carries: the slim (bin-only) autosave. Full per-map
// saves (written to SD) are excluded so the snapshot stays tiny.
#define DCVMU_SLIM_SAVE  "_JKAUTO_dcauto.jks"
// Flat archive of the writable tree inside the VMS payload.
#define DCVMU_MAGIC      "OJDF2VM1"
// The VMS payload wraps the (raw) archive in zlib: "OJDF2VZ1" + u32 rawLen +
// deflate stream. The cvar/registry/plr JSON compress well, so this keeps the
// snapshot comfortably inside a 128KB card.
#define DCVMU_ZMAGIC     "OJDF2VZ1"
// Blobs bigger than this can't fit a stock 128KB card; give up rather than churn.
#define DCVMU_MAX_BLOB   (120 * 1024)

// --- VMU discovery ------------------------------------------------------------
// Build "/vmu/aX" for the first connected memory card. Returns 1 if one exists.
static int dcVmu_FindPath(char* pOut, size_t outSz)
{
    maple_device_t* dev = maple_enum_type(0, MAPLE_FUNC_MEMCARD);
    if (!dev)
        return 0;
    snprintf(pOut, outSz, "/vmu/%c%d", 'a' + dev->port, dev->unit);
    return 1;
}

int dcVmu_Available(void)
{
    return maple_enum_type(0, MAPLE_FUNC_MEMCARD) != NULL;
}

// --- little-endian helpers ----------------------------------------------------
static int dcVmu_PutU32(uint8_t* buf, size_t bufSz, size_t* pOff, uint32_t v)
{
    if (*pOff + 4 > bufSz) return 0;
    buf[*pOff + 0] = (uint8_t)(v);
    buf[*pOff + 1] = (uint8_t)(v >> 8);
    buf[*pOff + 2] = (uint8_t)(v >> 16);
    buf[*pOff + 3] = (uint8_t)(v >> 24);
    *pOff += 4;
    return 1;
}
static int dcVmu_PutBytes(uint8_t* buf, size_t bufSz, size_t* pOff, const void* src, size_t len)
{
    if (*pOff + len > bufSz) return 0;
    memcpy(buf + *pOff, src, len);
    *pOff += len;
    return 1;
}
static uint32_t dcVmu_GetU32(const uint8_t* buf, size_t bufSz, size_t* pOff)
{
    if (*pOff + 4 > bufSz) { *pOff = bufSz + 1; return 0; }
    uint32_t v = (uint32_t)buf[*pOff] | ((uint32_t)buf[*pOff + 1] << 8) |
                 ((uint32_t)buf[*pOff + 2] << 16) | ((uint32_t)buf[*pOff + 3] << 24);
    *pOff += 4;
    return v;
}

// --- archive packing ----------------------------------------------------------
// Append every regular file under <fsRoot>/<relDir> to the archive buffer, using
// the relative path as the record key. Recurses into subdirectories.
static int dcVmu_PackDir(const char* fsRoot, const char* relDir,
                         uint8_t* buf, size_t bufSz, size_t* pOff, uint32_t* pCount)
{
    char fsDir[256];
    if (relDir[0])
        snprintf(fsDir, sizeof(fsDir), "%s/%s", fsRoot, relDir);
    else
        snprintf(fsDir, sizeof(fsDir), "%s", fsRoot);

    DIR* d = opendir(fsDir);
    if (!d)
        return 1; // nothing here yet -- not an error

    struct dirent* e;
    int ok = 1;
    while (ok && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') // skip "." ".."
            continue;

        char rel[256];
        if (relDir[0])
            snprintf(rel, sizeof(rel), "%s/%s", relDir, e->d_name);
        else
            snprintf(rel, sizeof(rel), "%s", e->d_name);

        char fsPath[256];
        snprintf(fsPath, sizeof(fsPath), "%s/%s", fsRoot, rel);

        struct stat st;
        if (stat(fsPath, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            ok = dcVmu_PackDir(fsRoot, rel, buf, bufSz, pOff, pCount);
            continue;
        }

        // Skip full game saves -- only the slim autosave belongs on the card.
        {
            size_t nl = strlen(e->d_name);
            if (nl >= 4 && !strcasecmp(e->d_name + nl - 4, ".jks") &&
                strcasecmp(e->d_name, DCVMU_SLIM_SAVE) != 0)
                continue;
        }

        // Regular file: [u32 pathLen][path][u32 dataLen][data]
        FILE* f = fopen(fsPath, "rb");
        if (!f)
            continue;
        uint32_t pathLen = (uint32_t)strlen(rel);
        uint32_t dataLen = (uint32_t)st.st_size;

        if (!dcVmu_PutU32(buf, bufSz, pOff, pathLen) ||
            !dcVmu_PutBytes(buf, bufSz, pOff, rel, pathLen) ||
            !dcVmu_PutU32(buf, bufSz, pOff, dataLen)) {
            fclose(f);
            ok = 0; // out of space
            break;
        }
        if (*pOff + dataLen > bufSz) {
            fclose(f);
            ok = 0;
            break;
        }
        size_t rd = fread(buf + *pOff, 1, dataLen, f);
        fclose(f);
        *pOff += rd;
        (*pCount)++;
    }
    closedir(d);
    return ok;
}

// --- archive unpacking --------------------------------------------------------
// Create <fsRoot>/<rel>, making any intermediate directories first.
static FILE* dcVmu_CreateFile(const char* fsRoot, const char* rel)
{
    char full[256];
    snprintf(full, sizeof(full), "%s/%s", fsRoot, rel);

    // mkdir each parent component.
    for (char* c = full + strlen(fsRoot) + 1; *c; c++) {
        if (*c == '/') {
            *c = 0;
            mkdir(full, 0777);
            *c = '/';
        }
    }
    return fopen(full, "wb");
}

static int dcVmu_UnpackBlob(const char* fsRoot, const uint8_t* buf, size_t len)
{
    size_t off = 0;
    if (len < 12 || memcmp(buf, DCVMU_MAGIC, 8) != 0)
        return 0;
    off = 8;
    uint32_t count = dcVmu_GetU32(buf, len, &off);

    for (uint32_t i = 0; i < count; i++) {
        uint32_t pathLen = dcVmu_GetU32(buf, len, &off);
        if (off + pathLen > len || pathLen >= 256)
            return 0;
        char rel[256];
        memcpy(rel, buf + off, pathLen);
        rel[pathLen] = 0;
        off += pathLen;

        uint32_t dataLen = dcVmu_GetU32(buf, len, &off);
        if (off + dataLen > len)
            return 0;

        FILE* f = dcVmu_CreateFile(fsRoot, rel);
        if (f) {
            fwrite(buf + off, 1, dataLen, f);
            fclose(f);
        }
        off += dataLen;
    }
    return 1;
}

// --- public: load/save --------------------------------------------------------
int dcVmu_Load(const char* pWritableRoot)
{
    char vmuPath[32], savePath[64];
    if (!dcVmu_FindPath(vmuPath, sizeof(vmuPath)))
        return 0;
    snprintf(savePath, sizeof(savePath), "%s/%s", vmuPath, DCVMU_SAVE_NAME);

    FILE* f = fopen(savePath, "rb");
    if (!f)
        return 0; // no save yet

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > DCVMU_MAX_BLOB + 4096) { fclose(f); return 0; }

    uint8_t* vms = (uint8_t*)malloc(sz);
    if (!vms) { fclose(f); return 0; }
    size_t rd = fread(vms, 1, sz, f);
    fclose(f);

    // fs_vmu already stripped the VMS wrapper, so `vms` is our raw payload:
    // "OJDF2VZ1" + u32 rawLen + deflate stream (or a legacy uncompressed archive).
    const uint8_t* p = vms;
    size_t plen = rd;
    int ok = 0;
    if (plen >= 12 && memcmp(p, DCVMU_ZMAGIC, 8) == 0) {
        uint32_t rawLen = (uint32_t)p[8] | ((uint32_t)p[9] << 8) |
                          ((uint32_t)p[10] << 16) | ((uint32_t)p[11] << 24);
        if (rawLen > 0 && rawLen <= DCVMU_MAX_BLOB) {
            uint8_t* raw = (uint8_t*)malloc(rawLen);
            if (raw) {
                uLongf destLen = rawLen;
                // Padding past the deflate stream (block-rounded read) is ignored.
                if (uncompress(raw, &destLen, p + 12, (uLong)(plen - 12)) == Z_OK)
                    ok = dcVmu_UnpackBlob(pWritableRoot, raw, destLen);
                free(raw);
            }
        }
    }
    else if (plen >= 8 && memcmp(p, DCVMU_MAGIC, 8) == 0) {
        ok = dcVmu_UnpackBlob(pWritableRoot, p, plen); // uncompressed archive
    }
    free(vms);
    if (ok)
        stdPlatform_Printf("dcVmu: loaded save from %s\n", savePath);
    return ok;
}

int dcVmu_Save(const char* pWritableRoot)
{
    char vmuPath[32], savePath[64];
    if (!dcVmu_FindPath(vmuPath, sizeof(vmuPath)))
        return 0;
    snprintf(savePath, sizeof(savePath), "%s/%s", vmuPath, DCVMU_SAVE_NAME);

    uint8_t* payload = (uint8_t*)malloc(DCVMU_MAX_BLOB);
    if (!payload)
        return 0;

    size_t off = 0;
    uint32_t count = 0;
    // Reserve header, pack files, then backfill the count.
    dcVmu_PutBytes(payload, DCVMU_MAX_BLOB, &off, DCVMU_MAGIC, 8);
    size_t countOff = off;
    dcVmu_PutU32(payload, DCVMU_MAX_BLOB, &off, 0);

    if (!dcVmu_PackDir(pWritableRoot, "", payload, DCVMU_MAX_BLOB, &off, &count)) {
        stdPlatform_Printf("dcVmu: writable tree too big for VMU, not saved\n");
        free(payload);
        return 0;
    }
    // Backfill file count.
    payload[countOff + 0] = (uint8_t)(count);
    payload[countOff + 1] = (uint8_t)(count >> 8);
    payload[countOff + 2] = (uint8_t)(count >> 16);
    payload[countOff + 3] = (uint8_t)(count >> 24);

    // zlib-compress the raw archive into the VMS payload: "OJDF2VZ1" + rawLen +
    // deflate stream.
    uLongf capacity = compressBound((uLong)off);
    uint8_t* zbuf = (uint8_t*)malloc(12 + capacity);
    if (!zbuf) { free(payload); return 0; }
    memcpy(zbuf, DCVMU_ZMAGIC, 8);
    zbuf[8]  = (uint8_t)(off);
    zbuf[9]  = (uint8_t)(off >> 8);
    zbuf[10] = (uint8_t)(off >> 16);
    zbuf[11] = (uint8_t)(off >> 24);
    uLongf zlen = capacity;
    int zrc = compress2(zbuf + 12, &zlen, payload, (uLong)off, Z_BEST_COMPRESSION);
    free(payload);
    if (zrc != Z_OK) {
        stdPlatform_Printf("dcVmu: compress failed (%d)\n", zrc);
        free(zbuf);
        return 0;
    }
    size_t vmsPayloadLen = 12 + zlen;

    // fs_vmu wraps our raw payload in a VMS itself (and strips it on read). We only
    // hand it a header so the save is BIOS-visible; the low-level fs API is needed
    // because fs_vmu_set_header takes a KOS file_t, not a stdio FILE*.
    vmu_pkg_t pkg;
    memset(&pkg, 0, sizeof(pkg));
    strncpy(pkg.desc_short, "OpenJKDF2", sizeof(pkg.desc_short) - 1);
    strncpy(pkg.desc_long, "OpenJKDF2 save data", sizeof(pkg.desc_long) - 1);
    strncpy(pkg.app_id, "OPENJKDF2", sizeof(pkg.app_id) - 1);
    pkg.icon_cnt = 0;
    pkg.eyecatch_type = VMUPKG_EC_NONE;

    int ok = 0;
    file_t fd = fs_open(savePath, O_WRONLY | O_TRUNC);
    if (fd != FILEHND_INVALID) {
        fs_vmu_set_header(fd, &pkg);
        ssize_t wr = fs_write(fd, zbuf, vmsPayloadLen);
        fs_close(fd);
        ok = (wr == (ssize_t)vmsPayloadLen);
    }
    free(zbuf);

    if (ok)
        stdPlatform_Printf("dcVmu: saved %u files (%u->%u bytes) to %s\n",
                           count, (unsigned)off, (unsigned)vmsPayloadLen, savePath);
    else
        stdPlatform_Printf("dcVmu: save to %s FAILED (card full?)\n", savePath);
    return ok;
}

#endif // TARGET_DREAMCAST
