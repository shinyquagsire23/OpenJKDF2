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
    uint32_t isOpen;
    Gob* parent;
    stdGobEntry* entry;
    int32_t seekOffs;
#ifdef QOL_IMPROVEMENTS
    uint32_t bIsMemoryMapped;
    intptr_t pMemory;
    size_t memorySz;
#endif
} GobFileHandle;

typedef struct Gob
{
    char fpath[128];
    stdFile_t fhand;
    uint32_t numFiles;
    stdGobEntry* entries;
    tHashTable* entriesHashtable;
    uint32_t numFilesOpen;
    GobFileHandle *openedFile;
    GobFileHandle *lastReadFile;
    uint32_t viewMapped;
    void* viewAddr;
    uint32_t viewHandle2;
    uint32_t viewHandle;
} Gob;

int stdGob_Startup(HostServices *pHS_in);
void stdGob_Shutdown();
Gob* stdGob_Load(char *fpath, int a2, int a3);
int stdGob_LoadEntry(Gob *gob, char *fname, int a3, int a4);
void stdGob_Free(Gob *gob);
void stdGob_FreeEntry(Gob *gob);
GobFileHandle* stdGob_FileOpen(Gob *gob, const char *filepath);
void stdGob_FileClose(GobFileHandle *f);
int stdGob_FileSeek(GobFileHandle *f, int pos, int whence);
int32_t stdGob_FileTell(GobFileHandle *f);
bool stdGob_FileEOF(GobFileHandle *f);
size_t stdGob_FileRead(GobFileHandle *f, void *out, uint32_t len);
const char* stdGob_FileGets(GobFileHandle *f, char *out, unsigned int len);
const wchar_t* stdGob_FileGetws(GobFileHandle *f, wchar_t *out, unsigned int len);

// ADDED
size_t stdGob_FileSize(GobFileHandle *f);

#endif // _STDGOB_H
