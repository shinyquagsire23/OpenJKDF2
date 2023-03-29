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
#define stdGob_FSeek_ADDR (0x00436680)
#define stdGob_FTell_ADDR (0x004366E0)
#define stdGob_FEof_ADDR (0x004366F0)
#define stdGob_FileRead_ADDR (0x00436710)
#define stdGob_FileGets_ADDR (0x00436790)
#define stdGob_FileGetws_ADDR (0x00436830)

//#define stdGob_fpath ((char*)0x5635F8)
//#define gobHS (*(HostServices*)0x563678)
//#define pGobHS (*(HostServices**)0x5636E8)
//#define stdGob_bInit (*(int*)0x5636EC)

#define GOB_VERSION_LATEST (20)

typedef struct stdGob stdGob;
typedef struct stdHashTable stdHashTable;

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
    char fname[128];
} stdGobEntry;

typedef struct stdGobFile
{
    uint32_t isOpen;
    stdGob* parent;
    stdGobEntry* entry;
    int32_t seekOffs;
#ifdef QOL_IMPROVEMENTS
    uint32_t bIsMemoryMapped;
    intptr_t pMemory;
    size_t memorySz;
#endif
} stdGobFile;

typedef struct stdGob
{
    char fpath[128];
    stdFile_t fhand;
    uint32_t numFiles;
    stdGobEntry* entries;
    stdHashTable* entriesHashtable;
    uint32_t numFilesOpen;
    stdGobFile *openedFile;
    stdGobFile *lastReadFile;
    uint32_t viewMapped;
    void* viewAddr;
    uint32_t viewHandle2;
    uint32_t viewHandle;
} stdGob;

int stdGob_Startup(HostServices *pHS_in);
void stdGob_Shutdown();
stdGob* stdGob_Load(char *fpath, int a2, int a3);
int stdGob_LoadEntry(stdGob *gob, char *fname, int a3, int a4);
void stdGob_Free(stdGob *gob);
void stdGob_FreeEntry(stdGob *gob);
stdGobFile* stdGob_FileOpen(stdGob *gob, const char *filepath);
void stdGob_FileClose(stdGobFile *f);
int stdGob_FSeek(stdGobFile *f, int pos, int whence);
int32_t stdGob_FTell(stdGobFile *f);
bool stdGob_FEof(stdGobFile *f);
size_t stdGob_FileRead(stdGobFile *f, void *out, unsigned int len);
const char* stdGob_FileGets(stdGobFile *f, char *out, unsigned int len);
const wchar_t* stdGob_FileGetws(stdGobFile *f, wchar_t *out, unsigned int len);

// ADDED
size_t stdGob_FileSize(stdGobFile *f);

#endif // _STDGOB_H
