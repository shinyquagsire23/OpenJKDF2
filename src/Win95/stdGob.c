#include "stdGob.h"

#include <stdio.h>

#include "jk.h"
#include "stdPlatform.h"

#include "General/stdHashTable.h"
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

stdGob* stdGob_Load(char *fpath, int a2, int a3)
{
    stdGob* gob = (stdGob*)std_pHS->alloc(sizeof(stdGob));
    if (gob)
    {
        _memset(gob, 0, sizeof(stdGob)); // TODO why was this needed
        stdGob_LoadEntry(gob, fpath, a2, a3); // TODO verify this? it does weird stuff
        return gob;
    }
    return NULL;
}

int stdGob_LoadEntry(stdGob *gob, char *fname, int a3, int a4)
{
    unsigned int v4; // ebx
    int v8; // edx
    stdGobFile *v9; // eax
    stdGobEntry *ent; // edi
    stdGobHeader header; // [esp+10h] [ebp-Ch]


    v4 = 0;
    _strncpy(gob->fpath, fname, 0x7Fu);
    gob->fpath[127] = 0;
    gob->numFilesOpen = a3;
    gob->lastReadFile = 0;

    //TODO fix this? WINE/df2_reimpl.dll keeps corrupting the gobs? Might be something else idk.
#if 0
    if ( a4 )
    {
        HANDLE v6 = jk_CreateFileA(gob->fpath, 0x80000000, 1u, 0, 3u, 0x10000000u, 0);
        gob->viewHandle2 = v6;
        HANDLE v7 = jk_CreateFileMappingA(v6, 0, 2u, 0, 0, 0);
        gob->viewHandle = v7;
        if ( v7 )
        {
            v8 = gob->numFilesOpen;
            gob->viewMapped = 1;
            v9 = (stdGobFile *)jk_LocalAlloc(0x40u, 16 * v8);
            gob->openedFile = v9;
            if ( v9 )
            {
                gob->viewAddr = jk_MapViewOfFile(gob->viewHandle, 4u, 0, 0, 0);
                return 1;
            }
            else
            {
                jk_UnmapViewOfFile(gob->viewAddr);
                jk_CloseHandle(gob->viewHandle);
            }
        }
        else
        {
            jk_CloseHandle(gob->viewHandle2);
        }
    }
#endif

    gob->viewMapped = 0;
    gob->fhand = pGobHS->fileOpen(gob->fpath, "r+b");
    if ( !gob->fhand )
      return 0;
    gob->openedFile = (stdGobFile *)std_pHS->alloc(sizeof(stdGobFile) * gob->numFilesOpen);
    if ( !gob->openedFile )
      return 0;
    _memset(gob->openedFile, 0, sizeof(stdGobFile) * gob->numFilesOpen);
    pGobHS->fileRead(gob->fhand, &header, sizeof(stdGobHeader));
    if ( _memcmp((const char *)&header, "GOB ", 4u) )
    {
      stdPrintf(std_pHS->errorPrint, ".\\Win95\\stdGob.c", 270, "Error: Bad signature in header of gob file.\n", 0, 0, 0, 0);
      return 0;
    }
    if ( header.version != 20 )
    {
      stdPrintf(std_pHS->errorPrint, ".\\Win95\\stdGob.c", 277, "Error: Bad version %d for gob file\n", header.version, 0, 0, 0);
      return 0;
    }
    pGobHS->fseek(gob->fhand, header.entryTable_offs, 0);
    pGobHS->fileRead(gob->fhand, &gob->numFiles, sizeof(uint32_t));
    gob->entries = (stdGobEntry *)std_pHS->alloc(sizeof(stdGobEntry) * gob->numFiles);
    if ( !gob->entries )
      return 0;
    
    // Added
    _memset(gob->entries, 0, sizeof(stdGobEntry) * gob->numFiles);

    ent = gob->entries;
    gob->entriesHashtable = stdHashTable_New(1024);
    if ( gob->numFiles > 0u )
    {
        do
        {
            pGobHS->fileRead(gob->fhand, ent, sizeof(stdGobEntry));
            stdHashTable_SetKeyVal(gob->entriesHashtable, ent->fname, ent);
            ++ent;
            ++v4;
        }
        while ( v4 < gob->numFiles );
    }

    jk_printf("Loaded GOB file `%s`...\n", fname);
    
    return 1;
}

void stdGob_Free(stdGob *gob)
{
    if (!gob )
        return;

    stdGob_FreeEntry(gob);
    std_pHS->free(gob);
}

void stdGob_FreeEntry(stdGob *gob)
{
    if ( gob->viewMapped )
    {
        jk_UnmapViewOfFile(gob->viewAddr);
        jk_CloseHandle(gob->viewHandle);
        jk_CloseHandle(gob->viewHandle2);
    }
    else
    {
        // Added: Fix file handle leak
        if (gob->fhand) {
            pGobHS->fileClose(gob->fhand);
            gob->fhand = 0;
        }
        // Added: Fix memleak
        if (gob->openedFile) {
            std_pHS->free(gob->openedFile);
            gob->openedFile = NULL;
        }
        if ( gob->entries )
        {
            std_pHS->free(gob->entries);
            gob->entries = 0;
        }
        if ( gob->entriesHashtable )
        {
            stdHashTable_Free(gob->entriesHashtable);
            gob->entriesHashtable = 0;
        }
    }
}

stdGobFile* stdGob_FileOpen(stdGob *gob, const char *filepath)
{
    stdGobEntry *entry = NULL;
    stdGobFile *result = NULL;
    int v5;

    // Embedded resources
#ifdef QOL_IMPROVEMENTS
    size_t sz = 0;
    void* data = stdEmbeddedRes_LoadOnlyInternal(filepath, &sz);
    if (data) {
        result = gob->openedFile;
        v5 = 0;
        if ( !gob->numFilesOpen )
            return 0;

        while ( result->isOpen )
        {
            ++result;
            if ( ++v5 >= gob->numFilesOpen )
                return 0;
        }
        result->bIsMemoryMapped = 1;
        result->pMemory = (intptr_t)data;
        result->memorySz = sz;

        result->isOpen = 1;
        result->parent = gob;
        result->entry = entry;
        result->seekOffs = 0;
        return result;
    }
#endif

    stdString_SafeStrCopy(stdGob_fpath, filepath, 128);
    stdString_CStrToLower(stdGob_fpath);

#ifdef PLATFORM_POSIX
    for (int i = 0; i < 128; i++)
    {
        if (stdGob_fpath[i] == '/')
            stdGob_fpath[i] = '\\';
    }
#endif
    entry = (stdGobEntry*)stdHashTable_GetKeyVal(gob->entriesHashtable, stdGob_fpath);
    if (!entry)
        return 0;

    result = gob->openedFile;
    v5 = 0;
    if ( !gob->numFilesOpen )
        return 0;

    while ( result->isOpen )
    {
        ++result;
        if ( ++v5 >= gob->numFilesOpen )
            return 0;
    }
#ifdef QOL_IMPROVEMENTS
    result->bIsMemoryMapped = 0;
    result->pMemory = (intptr_t)NULL;
    result->memorySz = 0;
#endif
    result->isOpen = 1;
    result->parent = gob;
    result->entry = entry;
    result->seekOffs = 0;
    return result;
}

void stdGob_FileClose(stdGobFile *f)
{
#ifdef QOL_IMPROVEMENTS
    if (f->pMemory) {
        free((void*)f->pMemory);
        f->pMemory = (intptr_t)NULL;
    }
    f->bIsMemoryMapped = 0;
#endif

    stdGob* gob = f->parent;
    f->isOpen = 0;

    if (f == gob->lastReadFile) {
        gob->lastReadFile = 0;
    }
}

int stdGob_FSeek(stdGobFile *f, int pos, int whence)
{
    int seekOffsAbsolute;
    stdGob *gob;

    seekOffsAbsolute = 0;
    switch (whence)
    {
        case SEEK_SET:
            seekOffsAbsolute = pos;
            break;
        case SEEK_CUR:
            seekOffsAbsolute = pos + f->seekOffs;
            break;
        case SEEK_END:
            seekOffsAbsolute = pos + f->entry->fileSize;
            break;
        default:
            return 0;
    }

    gob = f->parent;
    f->seekOffs = seekOffsAbsolute;

    if (f == gob->lastReadFile)
        gob->lastReadFile = 0;

    return 1;
}

int32_t stdGob_FTell(stdGobFile *f)
{
    return f->seekOffs;
}

bool stdGob_FEof(stdGobFile *f)
{
    int ret = 0;
    ret = f->seekOffs >= f->entry->fileSize - 1;
    return ret;
}

size_t stdGob_FileRead(stdGobFile *f, void *out, uint32_t len)
{
    stdGob *gob;
    size_t result;

#ifdef QOL_IMPROVEMENTS
    if (f->bIsMemoryMapped) {
        size_t to_read = len;
        if (f->seekOffs >= f->memorySz) {
            f->seekOffs = f->memorySz;
            return 0;
        }

        if (f->seekOffs + to_read > f->memorySz) {
            to_read = f->memorySz - f->seekOffs;
        }
        memcpy(out, (void*)(f->pMemory + f->seekOffs), to_read);
        f->seekOffs += to_read;

        return to_read;
    }
#endif

    gob = f->parent;
    if (gob->lastReadFile != f)
    {
        pGobHS->fseek(gob->fhand, f->seekOffs + f->entry->fileOffset, 0);
        gob = f->parent;
        gob->lastReadFile = f;
    }

    if ( f->entry->fileSize - f->seekOffs < len )
        len = f->entry->fileSize - f->seekOffs;

    result = pGobHS->fileRead(gob->fhand, out, len);
    f->seekOffs += result;
    return result;
}

const char* stdGob_FileGets(stdGobFile *f, char *out, unsigned int len)
{
    stdGobEntry *entry;
    int seekOffs;
    const char *result;
    stdGob *gob;

#ifdef QOL_IMPROVEMENTS
    if (f->bIsMemoryMapped) {
        size_t to_read = len;
        if (f->seekOffs >= f->memorySz) {
            f->seekOffs = f->memorySz;
            return NULL;
        }

        if (f->seekOffs + to_read > f->memorySz) {
            to_read = f->memorySz - f->seekOffs;
        }
        if (!to_read) {
            return NULL;
        }
        strncpy(out, (char*)(f->pMemory + f->seekOffs), to_read);
        char* cutoff = strchr(out, '\n');
        if (cutoff) {
            *(++cutoff) = 0;
        }

        size_t actual_read = strlen(out);
        f->seekOffs += actual_read;

        if (!actual_read) return NULL;

        return out;
    }
#endif

    entry = f->entry;
    seekOffs = f->seekOffs;
    if ( seekOffs >= entry->fileSize - 1 )
        return 0;
    gob = f->parent;
    if ( gob->lastReadFile != f )
    {
        pGobHS->fseek(gob->fhand, seekOffs + entry->fileOffset, 0);
        gob = f->parent;
        gob->lastReadFile = f;
    }

    if ( f->entry->fileSize - f->seekOffs + 1 < len )
        len = f->entry->fileSize - f->seekOffs + 1;

    result = pGobHS->fileGets(gob->fhand, out, len);
    if ( result )
        f->seekOffs += _strlen(result);

    return result;
}

const wchar_t* stdGob_FileGetws(stdGobFile *f, wchar_t *out, unsigned int len)
{
    stdGobEntry *entry; // ecx
    int seekOffs; // edx
    stdGob *gob; // eax
    unsigned int seekOffs_; // edi
    unsigned int len_wide; // ecx
    const wchar_t *ret; // eax
    const wchar_t *ret_; // edi

#ifdef QOL_IMPROVEMENTS
    if (f->bIsMemoryMapped) {
        size_t to_read = len * sizeof(wchar_t);
        if (f->seekOffs >= f->memorySz) {
            f->seekOffs = f->memorySz;
            return 0;
        }

        if (f->seekOffs + to_read > f->memorySz) {
            to_read = f->memorySz - f->seekOffs;
        }
        if (!to_read) {
            return NULL;
        }
        __wcsncpy(out, (char*)(f->pMemory + f->seekOffs), to_read / sizeof(wchar_t));
        wchar_t* cutoff = __wcschr(out, '\n');
        if (cutoff) {
            *(++cutoff) = 0;
        }

        size_t actual_read = (_wcslen(out))*sizeof(wchar_t);
        f->seekOffs += actual_read;

        if (!actual_read) return NULL;

        return out;
    }
#endif

    entry = f->entry;
    seekOffs = f->seekOffs;
    if ( seekOffs >= entry->fileSize - 1 )
        return 0;
    gob = f->parent;
    if ( gob->lastReadFile != f )
    {
        pGobHS->fseek(gob->fhand, seekOffs + entry->fileOffset, 0);
        gob = f->parent;
        gob->lastReadFile = f;
    }
    seekOffs_ = f->seekOffs;
    len_wide = len;
    if ( ((f->entry->fileSize - seekOffs_) >> 1) + 1 < len )
        len_wide = ((f->entry->fileSize - seekOffs_) >> 1) + 1;
    ret = pGobHS->fileGetws(gob->fhand, out, len_wide);
    if (ret)
        f->seekOffs += _wcslen(ret);
    return ret;
}

// ADDED
size_t stdGob_FileSize(stdGobFile *f)
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
