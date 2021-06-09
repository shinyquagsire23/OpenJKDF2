#include "stdPlatform.h"

#include "Win95/std.h"
#include "General/stdMemory.h"

#ifdef LINUX
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string.h>
#endif

#ifdef LINUX
uint32_t Linux_TimeMs()
{
    struct timespec _t;

    clock_gettime(CLOCK_REALTIME, &_t);

    return _t.tv_sec*1000 + lround(_t.tv_nsec/1.0e6);
}

static int Linux_stdFileOpen(char* fpath, char* mode)
{
    char tmp[512];
    size_t len = strlen(fpath);

    if (len > 512) {
        len = 512;
    }
    strncpy(tmp, fpath, sizeof(tmp));

    for (int i = 0; i < len; i++)
    {
        if (tmp[i] == '\\') {
            tmp[i] = '/';
        }
    }

    //printf("File open `%s`->`%s` mode `%s`\n", fpath, tmp, mode);
    
    return fopen(tmp, mode);
}

static int Linux_stdFileClose(void* fhand)
{
    return close(fhand);
}


static int Linux_stdFileRead(void* fhand, void* dst, size_t len)
{
    size_t val =  fread(dst, 1, len, fhand);

    return val;
}

static int Linux_stdFileWrite(void* fhand, void* dst, size_t len)
{
    return fwrite(dst, len, 1, fhand);
}

static int Linux_stdFileGets(void* fhand, char* dst, size_t len)
{
    return fgets(dst, len, fhand);
}

static void* Linux_alloc(size_t len)
{
    //TODO figure out where we're having alloc issues?
    return malloc(len + 0x100);
}

static void Linux_free(void* ptr)
{
    return free(ptr);
}

static void* Linux_realloc(void* ptr, size_t len)
{
    //printf("%p %zx\n", ptr, len);
    return realloc(ptr, len);
}

uint32_t stdPlatform_GetTimeMsec()
{
    return Linux_TimeMs();
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
    handlers->alloc = Linux_alloc;
    handlers->free = Linux_free;
    handlers->realloc = Linux_realloc;
    handlers->fileOpen = Linux_stdFileOpen;
    handlers->fileClose = Linux_stdFileClose;
    handlers->fileRead = Linux_stdFileRead;
    handlers->fileGets = Linux_stdFileGets;
    handlers->fileWrite = Linux_stdFileWrite;
    handlers->fseek = fseek;
    handlers->ftell = ftell;
    handlers->getTimerTick = Linux_TimeMs;
#endif
}

int stdPlatform_Startup()
{
    return 1;
}

#ifdef LINUX
int stdPrintf(intptr_t a1, char *a2, int line, char *fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    printf("(%x %s:%d) ", a1, a2, line);
    int ret = vprintf(fmt, args);
    va_end (args);
    return ret;
}

int stdPlatform_Printf(char *fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    int ret = vprintf(fmt, args);
    va_end (args);
    return ret;
}
#endif
