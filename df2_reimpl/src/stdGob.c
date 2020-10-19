#include "stdGob.h"

#include <stdio.h>

#include "jk.h"
#include "stdPlatform.h"

#include "stdHashTable.h"

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
        memset(gob, 0, sizeof(stdGob)); // TODO why was this needed
        stdGob_LoadEntry(gob, fpath, a2, a3); // TODO verify this? it does weird stuff
        return gob;
    }
    return NULL;
}

stdGobFile* stdGob_FileOpen(stdGob *gob, char *filepath)
{
    stdGobEntry *entry;
    stdGobFile *result;
    int v5;

    _strncpy(stdGob_fpath, filepath, 127);
    stdGob_fpath[127] = 0;
    strtolower(stdGob_fpath);
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
