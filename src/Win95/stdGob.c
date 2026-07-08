#include "stdGob.h"

#include <stdio.h>

#include "jk.h"
#include "stdPlatform.h"

#include "General/stdHashtbl.h"
#include "General/stdString.h"
#include "Platform/Common/stdEmbeddedRes.h"

static HostServices gobHS;
static HostServices* pGobHS;
static int stdGob_bInit;
static char stdGob_fpath[128];

int stdGob_Startup(HostServices *pHS_in)
{
    _memcpy(&gobHS, pHS_in, sizeof(gobHS));
    pGobHS = &gobHS;
    stdGob_bInit = 1;
    return 1;
}

void stdGob_Shutdown()
{
    stdGob_bInit = 0;
}

Gob* stdGob_Load(char *fpath, int a2, int a3)
{
    Gob* gob = (Gob*)STD_ALLOC(sizeof(Gob));
    if (gob)
    {
        _memset(gob, 0, sizeof(Gob)); // TODO why was this needed
        stdGob_LoadEntry(gob, fpath, a2, a3); // TODO verify this? it does weird stuff
        return gob;
    }
    return NULL;
}

int stdGob_LoadEntry(Gob *gob, char *fname, int a3, int a4)
{
    int v8; // edx
    GobFileHandle *v9; // eax
    stdGobHeader header; // [esp+10h] [ebp-Ch]

    stdString_SafeStrCopy(gob->fpath, fname, 128);
    gob->numHandles = a3;
    gob->pCurHandle = 0;

    //TODO fix this? WINE/df2_reimpl.dll keeps corrupting the gobs? Might be something else idk.
#if 0
    if ( a4 )
    {
        HANDLE v6 = jk_CreateFileA(gob->fpath, 0x80000000, 1u, 0, 3u, 0x10000000u, 0);
        gob->hFile = v6;
        HANDLE v7 = jk_CreateFileMappingA(v6, 0, 2u, 0, 0, 0);
        gob->hMapFile = v7;
        if ( v7 )
        {
            v8 = gob->numHandles;
            gob->bFileMap = 1;
            v9 = (GobFileHandle *)jk_LocalAlloc(0x40u, 16 * v8);
            gob->aHandles = v9;
            if ( v9 )
            {
                gob->pBase = jk_MapViewOfFile(gob->hMapFile, 4u, 0, 0, 0);
                return 1;
            }
            else
            {
                jk_UnmapViewOfFile(gob->pBase);
                jk_CloseHandle(gob->hMapFile);
            }
        }
        else
        {
            jk_CloseHandle(gob->hFile);
        }
    }
#endif

    gob->bFileMap = 0;
    gob->hGobFile = pGobHS->fileOpen(gob->fpath, "rb"); // Added: r+b -> rb, we don't actually need to write GOBs
    if ( !gob->hGobFile ) {
        stdPlatform_Printf("OpenJKDF2: Gob failed to open `%s`.\n", gob->fpath); // Added
        return 0;
    }
    else {
        stdPlatform_Printf("OpenJKDF2: Gob opened `%s`.\n", gob->fpath); // Added
    }
    gob->aHandles = (GobFileHandle *)STD_ALLOC(sizeof(GobFileHandle) * gob->numHandles);
    if ( !gob->aHandles )
      return 0;
    _memset(gob->aHandles, 0, sizeof(GobFileHandle) * gob->numHandles);
    pGobHS->fileRead(gob->hGobFile, &header, sizeof(stdGobHeader));
    if ( _memcmp((const char *)&header, "GOB ", 4u) )
    {
      stdPrintf(std_g_pHS->errorPrint, ".\\Win95\\stdGob.c", 270, "Error: Bad signature in header of gob file.\n", 0, 0, 0, 0);
      return 0;
    }
    if ( header.version != 20 )
    {
      stdPrintf(std_g_pHS->errorPrint, ".\\Win95\\stdGob.c", 277, "Error: Bad version %d for gob file\n", header.version, 0, 0, 0);
      return 0;
    }
    pGobHS->fseek(gob->hGobFile, header.entryTable_offs, 0);
    pGobHS->fileRead(gob->hGobFile, &gob->numFiles, sizeof(uint32_t));
    gob->entries = (stdGobEntry *)STD_ALLOC(sizeof(stdGobEntry) * gob->numFiles);
    if ( !gob->entries )
      return 0;
    
    // Added
    _memset(gob->entries, 0, sizeof(stdGobEntry) * gob->numFiles);

    // We're not adding anything so like, keep it small?
#ifdef TARGET_RETRO_HOMEBREW
    gob->pDirHash = stdHashtbl_New(gob->numFiles);
#else
    gob->pDirHash = stdHashtbl_New(1024);
#endif
    for (int v4 = 0; v4 < gob->numFiles; v4++)
    {
#ifdef STDGOB_COMPACT_ENTRIES
        // Added: stage the fixed 136-byte disk entry; only offset/size stay
        // resident (the CRC-keyed pHashtbl doesn't retain the name pointer).
        stdGobDiskEntry diskEntry;
        pGobHS->fileRead(gob->hGobFile, &diskEntry, sizeof(stdGobDiskEntry));
        gob->entries[v4].fileOffset = diskEntry.fileOffset;
        gob->entries[v4].fileSize = diskEntry.fileSize;
        stdHashtbl_Add(gob->pDirHash, diskEntry.fname, &gob->entries[v4]);
#else
        pGobHS->fileRead(gob->hGobFile, &gob->entries[v4], sizeof(stdGobEntry));
        stdHashtbl_Add(gob->pDirHash, gob->entries[v4].fname, &gob->entries[v4]);
#endif
    }

    stdPlatform_Printf("OpenJKDF2: Gob loaded GOB file `%s`...\n", fname);
    
    return 1;
}

void stdGob_Free(Gob *gob)
{
    if (!gob )
        return;

    stdGob_FreeEntry(gob);
    STD_FREE(gob);
}

void stdGob_FreeEntry(Gob *gob)
{
    if ( gob->bFileMap )
    {
        jk_UnmapViewOfFile(gob->pBase);
        jk_CloseHandle(gob->hMapFile);
        jk_CloseHandle(gob->hFile);
    }
    else
    {
        // Added: Fix file handle leak
        if (gob->hGobFile) {
            pGobHS->fileClose(gob->hGobFile);
            gob->hGobFile = 0;
        }
        // Added: Fix memleak
        if (gob->aHandles) {
            STD_FREE(gob->aHandles);
            gob->aHandles = NULL;
        }
        if ( gob->entries )
        {
            STD_FREE(gob->entries);
            gob->entries = 0;
        }
        if ( gob->pDirHash )
        {
            stdHashtbl_Free(gob->pDirHash);
            gob->pDirHash = 0;
        }
    }
}

GobFileHandle* stdGob_FileOpen(Gob *gob, const char *filepath)
{
    stdGobEntry *entry = NULL;
    GobFileHandle *result = NULL;
    int v5;

    // Embedded resources
#if defined(QOL_IMPROVEMENTS)
    size_t sz = 0;
    void* data = stdEmbeddedRes_LoadOnlyInternal(filepath, &sz);
    if (data) {
        result = gob->aHandles;
        v5 = 0;
        if ( !gob->numHandles )
            return 0;

        while ( result->bUsed )
        {
            ++result;
            if ( ++v5 >= gob->numHandles )
                return 0;
        }
        result->bIsMemoryMapped = 1;
        result->pMemory = (intptr_t)data;
        result->memorySz = sz;

        result->bUsed = 1;
        result->parent = gob;
        result->entry = entry;
        result->offset = 0;
        // Added: Opening another file in this GOB makes the shared handle's position
        // ambiguous: invalidate the seek-skip cache so the next read re-seeks.
        gob->pCurHandle = 0;
        return result;
    }
#endif

    // Added: clean up paths
    if (filepath[0] == '.' && (filepath[1] == '/' || filepath[1] == '\\')) {
        filepath += 2;
    }
    stdString_SafeStrCopy(stdGob_fpath, filepath, 128);
    stdString_CStrToLower(stdGob_fpath);

#ifdef PLATFORM_POSIX
    for (int i = 0; i < 128; i++)
    {
        if (stdGob_fpath[i] == '/')
            stdGob_fpath[i] = '\\';
    }
#endif
    entry = (stdGobEntry*)stdHashtbl_Find(gob->pDirHash, stdGob_fpath);
    if (!entry)
        return 0;

    result = gob->aHandles;
    v5 = 0;
    if ( !gob->numHandles )
        return 0;

    while ( result->bUsed )
    {
        ++result;
        if ( ++v5 >= gob->numHandles )
            return 0;
    }
#ifdef QOL_IMPROVEMENTS
    result->bIsMemoryMapped = 0;
    result->pMemory = (intptr_t)NULL;
    result->memorySz = 0;
#endif
    result->bUsed = 1;
    result->parent = gob;
    result->entry = entry;
    result->offset = 0;
    // Added: Opening another file in this GOB makes the shared handle's position
    // ambiguous: invalidate the seek-skip cache so the next read re-seeks.
    gob->pCurHandle = 0;
    return result;
}

void stdGob_FileClose(GobFileHandle *f)
{
#ifdef QOL_IMPROVEMENTS
    if (f->pMemory) {
        free((void*)f->pMemory);
        f->pMemory = (intptr_t)NULL;
    }
    f->bIsMemoryMapped = 0;
#endif

    Gob* gob = f->parent;
    f->bUsed = 0;

    if (f == gob->pCurHandle) {
        gob->pCurHandle = 0;
    }
}

int stdGob_FileSeek(GobFileHandle *f, int pos, int whence)
{
    int seekOffsAbsolute;
    Gob *gob;

    seekOffsAbsolute = 0;
    switch (whence)
    {
        case SEEK_SET:
            seekOffsAbsolute = pos;
            break;
        case SEEK_CUR:
            seekOffsAbsolute = pos + f->offset;
            break;
        case SEEK_END:
            seekOffsAbsolute = pos + f->entry->fileSize;
            break;
        default:
            return 0;
    }

    gob = f->parent;
    f->offset = seekOffsAbsolute;

    if (f == gob->pCurHandle)
        gob->pCurHandle = 0;

    return 1;
}

int32_t stdGob_FileTell(GobFileHandle *f)
{
    return f->offset;
}

bool stdGob_FileEOF(GobFileHandle *f)
{
    int ret = 0;
    ret = f->offset >= f->entry->fileSize - 1;
    return ret;
}

size_t stdGob_FileRead(GobFileHandle *f, void *out, uint32_t len)
{
    Gob *gob;
    size_t result;

    //printf("\x1b[0;0Hreading %s %p %x\n", f->entry->fname, out, len);

#ifdef QOL_IMPROVEMENTS
    if (f->bIsMemoryMapped) {
        size_t to_read = len;
        if (f->offset >= f->memorySz) {
            f->offset = f->memorySz;
            return 0;
        }

        if (f->offset + to_read > f->memorySz) {
            to_read = f->memorySz - f->offset;
        }
        memcpy(out, (void*)(f->pMemory + f->offset), to_read);
        f->offset += to_read;

        return to_read;
    }
#endif

    gob = f->parent;
    if (gob->pCurHandle != f)
    {
        pGobHS->fseek(gob->hGobFile, f->offset + f->entry->fileOffset, 0);
        gob = f->parent;
        gob->pCurHandle = f;
    }

    if ( f->entry->fileSize - f->offset < len )
        len = f->entry->fileSize - f->offset;

    result = pGobHS->fileRead(gob->hGobFile, out, len);
    f->offset += result;
    return result;
}

const char* stdGob_FileGets(GobFileHandle *f, char *out, unsigned int len)
{
    stdGobEntry *entry;
    int offset;
    const char *result;
    Gob *gob;

#ifdef QOL_IMPROVEMENTS
    if (f->bIsMemoryMapped) {
        size_t to_read = len;
        if (f->offset >= f->memorySz) {
            f->offset = f->memorySz;
            return NULL;
        }

        if (f->offset + to_read > f->memorySz) {
            to_read = f->memorySz - f->offset;
        }
        if (!to_read) {
            return NULL;
        }
        strncpy(out, (char*)(f->pMemory + f->offset), to_read);
        char* cutoff = strchr(out, '\n');
        if (cutoff) {
            *(++cutoff) = 0;
        }

        size_t actual_read = strlen(out);
        f->offset += actual_read;

        if (!actual_read) return NULL;

        return out;
    }
#endif

    entry = f->entry;
    offset = f->offset;
    if ( offset >= entry->fileSize - 1 )
        return 0;
    gob = f->parent;
    if ( gob->pCurHandle != f )
    {
        pGobHS->fseek(gob->hGobFile, offset + entry->fileOffset, 0);
        gob = f->parent;
        gob->pCurHandle = f;
    }

    if ( f->entry->fileSize - f->offset + 1 < len )
        len = f->entry->fileSize - f->offset + 1;

    result = pGobHS->fileGets(gob->hGobFile, out, len);
    if ( result )
        f->offset += _strlen(result);

    return result;
}

const wchar_t* stdGob_FileGetws(GobFileHandle *f, wchar_t *out, unsigned int len)
{
    stdGobEntry *entry; // ecx
    int offset; // edx
    Gob *gob; // eax
    unsigned int seekOffs_; // edi
    unsigned int len_wide; // ecx
    const wchar_t *ret; // eax
    const wchar_t *ret_; // edi

#ifdef QOL_IMPROVEMENTS
    if (f->bIsMemoryMapped) {
        size_t to_read = len * sizeof(wchar_t);
        if (f->offset >= f->memorySz) {
            f->offset = f->memorySz;
            return 0;
        }

        if (f->offset + to_read > f->memorySz) {
            to_read = f->memorySz - f->offset;
        }
        if (!to_read) {
            return NULL;
        }
        __wcsncpy(out, (wchar_t*)(f->pMemory + f->offset), to_read / sizeof(wchar_t));
        wchar_t* cutoff = __wcschr(out, '\n');
        if (cutoff) {
            *(++cutoff) = 0;
        }

        size_t actual_read = (_wcslen(out))*sizeof(wchar_t);
        f->offset += actual_read;

        if (!actual_read) return NULL;

        return out;
    }
#endif

    entry = f->entry;
    offset = f->offset;
    if ( offset >= entry->fileSize - 1 )
        return 0;
    gob = f->parent;
    if ( gob->pCurHandle != f )
    {
        pGobHS->fseek(gob->hGobFile, offset + entry->fileOffset, 0);
        gob = f->parent;
        gob->pCurHandle = f;
    }
    seekOffs_ = f->offset;
    len_wide = len;
    if ( ((f->entry->fileSize - seekOffs_) >> 1) + 1 < len )
        len_wide = ((f->entry->fileSize - seekOffs_) >> 1) + 1;
    ret = pGobHS->fileGetws(gob->hGobFile, out, len_wide);
    if (ret)
        f->offset += _wcslen(ret);
    return ret;
}

// ADDED
size_t stdGob_FileSize(GobFileHandle *f)
{
    if (!f) return 0;
    if (!f->entry) return 0;
#ifdef QOL_IMPROVEMENTS
    if (f->bIsMemoryMapped) {
        return f->memorySz;
    }
#endif

    return f->entry->fileSize;
}
