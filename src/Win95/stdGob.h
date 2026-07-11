#ifndef _STDGOB_H
#define _STDGOB_H

#include <stdint.h>
#include <stdbool.h>

#include "jk.h"

#define stdGob_Startup_ADDR (0x00436190)
#define stdGob_Shutdown_ADDR (0x004361C0)
#define stdGob_Load_ADDR (0x004361D0)
#define stdGob_LoadEntry_ADDR (0x00436210)
#define stdGob_Free_ADDR (0x004364D0)
#define stdGob_FreeEntry_ADDR (0x00436560)
#define stdGob_FileOpen_ADDR (0x004365D0)
#define stdGob_FileClose_ADDR (0x00436660)
#define stdGob_FileSeek_ADDR (0x00436680)
#define stdGob_FileTell_ADDR (0x004366E0)
#define stdGob_FileEOF_ADDR (0x004366F0)
#define stdGob_FileRead_ADDR (0x00436710)
#define stdGob_FileGets_ADDR (0x00436790)
#define stdGob_FileGetws_ADDR (0x00436830)

//#define stdGob_fpath ((char*)0x5635F8)
//#define gobHS (*(HostServices*)0x563678)
//#define pGobHS (*(HostServices**)0x5636E8)
//#define stdGob_bInit (*(int*)0x5636EC)

#define GOB_VERSION_LATEST (20)

typedef struct Gob Gob;
typedef struct tHashTable tHashTable;

typedef struct stdGobHeader
{
    uint32_t magic;
    uint32_t version;
    uint32_t entryTable_offs;
} stdGobHeader;

typedef struct stdGobEntry
{
    uint32_t fileOffset;
    int32_t fileSize;
#ifndef STDGOB_COMPACT_ENTRIES
    char fname[128]; // in-memory copy of the on-disk name (see STDGOB_COMPACT_ENTRIES)
#endif
} stdGobEntry;

// The on-disk directory entry layout (always 136 bytes), used as a staging
// buffer when STDGOB_COMPACT_ENTRIES strips names from the resident entries.
typedef struct stdGobDiskEntry
{
    uint32_t fileOffset;
    int32_t fileSize;
    char fname[128];
} stdGobDiskEntry;

typedef struct GobFileHandle
{
    uint32_t bUsed;
    Gob* parent;
    stdGobEntry* entry;
    int32_t offset;
#ifdef QOL_IMPROVEMENTS
    uint32_t bIsMemoryMapped;
    intptr_t pMemory;
    size_t memorySz;
#endif
} GobFileHandle;

typedef struct Gob
{
    char fpath[128];
    stdFile_t hGobFile;
    uint32_t numFiles;
    stdGobEntry* entries;
    tHashTable* pDirHash;
    uint32_t numHandles;
    GobFileHandle *aHandles;
    GobFileHandle *pCurHandle;
    uint32_t bFileMap;
    void* pBase;
    uint32_t hFile;
    uint32_t hMapFile;
} Gob;

int stdGob_Startup(HostServices *pHS);
void stdGob_Shutdown();
Gob* stdGob_Load(char *pFilename, int numFileHandles, int bMMapFile);
int stdGob_LoadEntry(Gob *pGob, char *pFilename, int numFileHandles, int bMMapFile);
void stdGob_Free(Gob *pGob);
void stdGob_FreeEntry(Gob *pGob);
GobFileHandle* stdGob_FileOpen(Gob *pGob, const char *aName);
void stdGob_FileClose(GobFileHandle *pHandle);
int stdGob_FileSeek(GobFileHandle *pHandle, int offset, int origin);
int32_t stdGob_FileTell(GobFileHandle *pHandle);
bool stdGob_FileEOF(GobFileHandle *pHandle);
size_t stdGob_FileRead(GobFileHandle *pHandle, void *data, uint32_t size);
const char* stdGob_FileGets(GobFileHandle *pGobFileHandle, char *pStr, unsigned int size);
const char16_t* stdGob_FileGetws(GobFileHandle *f, char16_t *out, unsigned int len);

// ADDED
size_t stdGob_FileSize(GobFileHandle *f);

#endif // _STDGOB_H
