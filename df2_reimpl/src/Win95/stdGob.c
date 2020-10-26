#include "stdGob.h"

#include <stdio.h>

#include "jk.h"
#include "stdPlatform.h"

#include "General/stdHashTable.h"
#include "General/stdString.h"

int stdGob_Startup(common_functions *pHS_in)
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
    signed int v5; // edi
    HANDLE v6; // eax
    HANDLE v7; // eax
    int v8; // edx
    stdGobFile *v9; // eax
    common_functions *v10; // ecx
    int fhand_; // eax
    stdGobFile *v13; // edi
    char v14; // dl
    unsigned int v15; // ecx
    int *v16; // edi
    common_functions *v17; // edx
    stdGobEntry *v18; // eax
    int *v19; // eax
    stdGobEntry *ent; // edi
    const char *ent_fname; // ebp
    stdGobHeader header; // [esp+10h] [ebp-Ch]

    v4 = 0;
    v5 = 0;
    _strncpy(gob->fpath, fname, 0x7Fu);
    gob->fpath[127] = 0;
    gob->numFilesOpen = a3;
    gob->lastReadFile = 0;
    if ( a4 )
    {
        v6 = jk_CreateFileA(gob->fpath, 0x80000000, 1u, 0, 3u, 0x10000000u, 0);
        gob->viewHandle2 = v6;
        v7 = jk_CreateFileMappingA(v6, 0, 2u, 0, 0, 0);
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
            CloseHandle(gob->viewHandle2);
        }
    }

    v10 = pGobHS;
    gob->viewMapped = 0;
    fhand_ = v10->fileOpen(gob->fpath, "r+b");
    gob->fhand = fhand_;
    if ( !fhand_ )
      return 0;
    v13 = (stdGobFile *)std_pHS->alloc(16 * gob->numFilesOpen);
    gob->openedFile = v13;
    if ( !v13 )
      return 0;
    v14 = 16 * (gob->numFilesOpen & 0xFF);
    v15 = (unsigned int)(16 * gob->numFilesOpen) >> 2;
    _memset(v13, 0, 4 * v15);
    v16 = &v13->isOpen + v15;
    v15 = (v15 & 0xFFFFFF00) | (v14 & 0xFF);
    v17 = pGobHS;
    _memset(v16, 0, v15 & 3);
    v17->fileRead(gob->fhand, &header, 12);
    if ( _memcmp((const char *)&header, "GOB ", 4u) )
    {
      stdPrintf((int)std_pHS->errorPrint, ".\\Win95\\stdGob.c", 270, "Error: Bad signature in header of gob file.\n", 0, 0, 0, 0);
      return 0;
    }
    if ( header.version != 20 )
    {
      stdPrintf((int)std_pHS->errorPrint, ".\\Win95\\stdGob.c", 277, "Error: Bad version %d for gob file\n", header.version, 0, 0, 0);
      return 0;
    }
    pGobHS->fseek(gob->fhand, header.entryTable_offs, 0);
    pGobHS->fileRead(gob->fhand, &gob->numFiles, 4);
    v18 = (stdGobEntry *)std_pHS->alloc(136 * gob->numFiles);
    gob->entries = v18;
    if ( !v18 )
      return 0;
    v19 = stdHashTable_New(1024);
    ent = gob->entries;
    gob->entriesHashtable = v19;
    if ( gob->numFiles > 0u )
    {
      ent_fname = ent->fname;
      do
      {
        pGobHS->fileRead(gob->fhand, ent, 0x88);
        stdHashTable_SetKeyVal(gob->entriesHashtable, ent_fname, ent);
        ++ent;
        ent_fname += sizeof(stdGobEntry);
        ++v4;
      }
      while ( v4 < gob->numFiles );
    }
  return 1;
}

stdGobFile* stdGob_FileOpen(stdGob *gob, char *filepath)
{
    stdGobEntry *entry;
    stdGobFile *result;
    int v5;

    _strncpy(stdGob_fpath, filepath, 127);
    stdGob_fpath[127] = 0;
    stdString_CStrToLower(stdGob_fpath);
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
    result->isOpen = 1;
    result->parent = gob;
    result->entry = entry;
    result->seekOffs = 0;
    return result;
}

void stdGob_FileClose(stdGobFile *f)
{
  stdGob* gob = f->parent;
  f->isOpen = 0;

  if (f == gob->lastReadFile)
    gob->lastReadFile = 0;
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

size_t stdGob_FileRead(stdGobFile *f, void *out, unsigned int len)
{
    stdGob *gob;
    unsigned int readLen;
    size_t result;

    gob = f->parent;
    if (gob->lastReadFile != f)
    {
        pGobHS->fseek(gob->fhand, f->seekOffs + f->entry->fileOffset, 0);
        gob = f->parent;
        gob->lastReadFile = f;
    }

    readLen = len;
    if ( f->entry->fileSize - f->seekOffs < len )
        readLen = f->entry->fileSize - f->seekOffs;

    result = pGobHS->fileRead(gob->fhand, out, readLen);
    f->seekOffs += result;
    return result;
}

char* stdGob_FileGets(stdGobFile *f, char *out, unsigned int len)
{
    stdGobEntry *entry;
    int seekOffs;
    const char *result;
    stdGob *gob;
    int readLen;

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
    readLen = len;
    if ( f->entry->fileSize - f->seekOffs + 1 < len )
        readLen = f->entry->fileSize - f->seekOffs + 1;

    result = pGobHS->fileGets(gob->fhand, out, readLen);
    if ( result )
        f->seekOffs += _strlen(result);

    return result;
}

wchar_t* stdGob_FileGetws(stdGobFile *f, wchar_t *out, unsigned int len)
{
  stdGobEntry *entry; // ecx
  int seekOffs; // edx
  stdGob *gob; // eax
  unsigned int seekOffs_; // edi
  unsigned int len_wide; // ecx
  const wchar_t *ret; // eax
  const wchar_t *ret_; // edi

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
    f->seekOffs += wcslen(ret);
  return ret;
}
