#include "stdPlatform.h"

#include "Win95/std.h"
#include "General/stdMemory.h"

#ifdef LINUX
#include <stdlib.h>
#include <stdio.h>
#endif

#ifdef LINUX
static int Linux_stdFileRead(void* fhand, void* dst, size_t len)
{
    return fread(dst, len, 1, fhand);
}

static int Linux_stdFileWrite(void* fhand, void* dst, size_t len)
{
    return fwrite(dst, len, 1, fhand);
}
#endif

void stdPlatform_InitServices(common_functions *handlers)
{
    handlers->statusPrint = stdPlatform_Printf;
    handlers->messagePrint = stdPlatform_Printf;
    handlers->warningPrint = stdPlatform_Printf;
    handlers->errorPrint = stdPlatform_Printf;
    handlers->some_float = 1000.0;
    handlers->debugPrint = 0;
    handlers->assert = stdPlatform_Assert;
    handlers->unk_0 = 0;
    handlers->alloc = daAlloc;
    handlers->free = daFree;
    handlers->realloc =  daRealloc;
    handlers->getTimerTick = stdPlatform_GetTimeMsec;
    handlers->fileOpen = stdFileOpen;
    handlers->fileClose = stdFileClose;
    handlers->fileRead = stdFileRead;
    handlers->fileGets = stdFileGets;
    handlers->fileWrite = stdFileWrite;
    handlers->feof = stdFeof;
    handlers->ftell = stdFtell;
    handlers->fseek = stdFseek;
    handlers->fileSize = stdFileSize;
    handlers->filePrintf = stdFilePrintf;
    handlers->fileGetws = stdFileGetws;
    handlers->allocHandle = stdPlatform_AllocHandle;
    handlers->freeHandle = stdPlatform_FreeHandle;
    handlers->reallocHandle = stdPlatform_ReallocHandle;
    handlers->lockHandle = stdPlatform_LockHandle;
    handlers->unlockHandle = stdPlatform_UnlockHandle;
    
#ifdef LINUX
    handlers->alloc = malloc;
    handlers->free = free;
    handlers->realloc = realloc;
    handlers->fileOpen = fopen;
    handlers->fileRead = Linux_stdFileRead;
    handlers->fileGets = fgets;
    handlers->fileWrite = Linux_stdFileWrite;
    handlers->fseek = fseek;
    handlers->ftell = ftell;
#endif
}

int stdPlatform_Startup()
{
    return 1;
}
