#include "stdPlatform.h"

#include "Win95/std.h"
#include "General/stdMemory.h"
#include "Main/jkQuakeConsole.h"

#ifdef PLATFORM_POSIX
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string.h>

#include "external/fcaseopen/fcaseopen.h"
#endif

#include "SDL2_helper.h"

#ifdef TARGET_TWL
#include <nds.h>
#endif

#ifdef PLATFORM_POSIX
uint32_t Linux_TimeMs()
{
    // TWL has hardware timers we can use for accurate ms timing
#ifdef TARGET_TWL
    return (uint32_t)(((TIMER1_DATA*(1<<16))+TIMER0_DATA)/32.7285);
#endif

    struct timespec _t;

#if defined(_MSC_VER) && !defined(WIN64_MINGW)
    timespec_get(&_t, TIME_UTC);
#else
    clock_gettime(CLOCK_MONOTONIC, &_t);
#endif

    return _t.tv_sec*1000 + lround(_t.tv_nsec/1.0e6);
}

uint64_t Linux_TimeUs()
{
#ifdef TARGET_TWL
    return (uint64_t)(((TIMER1_DATA*(1<<16))+TIMER0_DATA)/32728.5);
#endif
    struct timespec _t;

#if defined(_MSC_VER) && !defined(WIN64_MINGW)
    timespec_get(&_t, TIME_UTC);
#else
    clock_gettime(CLOCK_MONOTONIC, &_t);
#endif

    return _t.tv_sec*1000000 + lround(_t.tv_nsec/1.0e3);
}

static stdFile_t Linux_stdFileOpen(const char* fpath, const char* mode)
{
    char tmp[512];
    size_t len = strlen(fpath);

    if (len > 512) {
        len = 512;
    }
    _strncpy(tmp, fpath, sizeof(tmp));

#ifndef WIN64_STANDALONE
    for (int i = 0; i < len; i++)
    {
        if (tmp[i] == '\\') {
            tmp[i] = '/';
        }
    }
#endif

#ifdef WIN32
for (int i = 0; i < len; i++)
{
    if (tmp[i] == '/') {
        tmp[i] = '\\';
    }
}
#endif

    stdFile_t ret = (stdFile_t)fcaseopen(tmp, mode);
    //printf("File open `%s`->`%s` mode `%s`, ret %x\n", fpath, tmp, mode, ret);
    
    return ret;
}

static int Linux_stdFileClose(stdFile_t fhand)
{
    int ret = fclose((FILE*)fhand);

#ifdef ARCH_WASM
    EM_ASM(
        FS.syncfs(false, function (err) {
            // Error
        });
    );
#endif // ARCH_WASM

    return ret;
}


static size_t Linux_stdFileRead(stdFile_t fhand, void* dst, size_t len)
{
    size_t val =  fread(dst, 1, len, (FILE*)fhand);

    return val;
}

static size_t Linux_stdFileWrite(stdFile_t fhand, void* dst, size_t len)
{
    return fwrite(dst, 1, len, (FILE*)fhand);
}

static const char* Linux_stdFileGets(stdFile_t fhand, char* dst, size_t len)
{
    return fgets(dst, len, (FILE*)fhand);
}

static int Linux_stdFseek(stdFile_t fhand, int a, int b)
{
    //printf("fseek? %x %x\n", a, b);
    int ret = fseek((FILE*)fhand, a, b);
    //printf("fseek %x\n", ret);
    return ret;
}

static int Linux_stdFtell(stdFile_t fhand)
{
    return ftell((FILE*)fhand);
}

static void* Linux_alloc(uint32_t len)
{
#ifdef TARGET_TWL
    intptr_t highwater = (intptr_t)getHeapLimit() - (intptr_t)getHeapEnd();
    intptr_t future_highwater = (intptr_t)getHeapLimit() - (intptr_t)getHeapEnd() - len;
    static int highwater_once = 0;
    static volatile void* dummy = NULL;

    //printf("alloc %x\n", len);
    //printf("heap 0x%x 0x%x\n", (intptr_t)getHeapLimit() - (intptr_t)getHeapEnd(), (intptr_t)getHeapEnd() - (intptr_t)getHeapStart());
    // HACK: libnds is dumb or something idk, touchscreen stops working when we cross this point
    void* ret = malloc(len);
    while (!openjkdf2_bIsExtraLowMemoryPlatform && (intptr_t)ret >= (intptr_t)(0x0D000000-0x10000) && (intptr_t)ret <= (intptr_t)(0x0D000000+0x80000)) {
        dummy = malloc(0x100000);
        ret = malloc(len);
        //printf("%p\n", ret);
    }
    if (!ret) {
        printf("Failed to allocate %x bytes...\n", len);
        //while (1) {}
        return NULL;
    }
    return ret;
#endif
    //TODO figure out where we're having alloc issues?
    return malloc(len);
}

static void Linux_free(void* ptr)
{
    return free(ptr);
}

static void* Linux_realloc(void* ptr, uint32_t len)
{
    //printf("%p %zx\n", ptr, len);
    return realloc(ptr, len);
}

static int Linux_stdFeof(stdFile_t fhand)
{
    return feof((FILE*)fhand);
}

uint32_t stdPlatform_GetTimeMsec()
{
    return Linux_TimeMs();
}
#endif

void stdPlatform_InitServices(HostServices *handlers)
{
    handlers->statusPrint = stdPlatform_Printf;
    handlers->messagePrint = stdPlatform_Printf;
    handlers->warningPrint = stdPlatform_Printf;
    handlers->errorPrint = stdPlatform_Printf;
    handlers->some_float = 1000.0;
    handlers->debugPrint = 0;
#ifndef PLATFORM_POSIX
    handlers->assert = stdPlatform_Assert;
#endif
    handlers->unk_0 = 0;
#ifndef PLATFORM_POSIX
    handlers->alloc = daAlloc;
    handlers->free = daFree;
    handlers->realloc =  daRealloc;
    handlers->getTimerTick = stdPlatform_GetTimeMsec;
    handlers->fileOpen = stdFileOpen;
    handlers->fileClose = stdFileClose;
    handlers->fileRead = stdFileRead;
    handlers->fileGets = stdFileGets;
    handlers->fileWrite = stdFileWrite;
    handlers->fileEof = stdFeof;
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
#endif

#ifdef PLATFORM_POSIX
    handlers->alloc = Linux_alloc;
    handlers->free = Linux_free;
    handlers->realloc = Linux_realloc;
    handlers->fileOpen = Linux_stdFileOpen;
    handlers->fileClose = Linux_stdFileClose;
    handlers->fileRead = Linux_stdFileRead;
    handlers->fileGets = Linux_stdFileGets;
    handlers->fileWrite = Linux_stdFileWrite;
    handlers->fseek = Linux_stdFseek;
    handlers->ftell = Linux_stdFtell;
    handlers->getTimerTick = Linux_TimeMs;
    handlers->fileEof = Linux_stdFeof;
#endif
}

int stdPlatform_Startup()
{
    return 1;
}

#ifdef PLATFORM_POSIX
int stdPrintf(int (*a1)(const char *, ...), const char *a2, int line, const char *fmt, ...)
{
    va_list args;
    va_start (args, fmt);
    printf("(%p %s:%d) ", a1, a2, line);
    int ret = vprintf(fmt, args);
    va_end (args);
    return ret;
}

#ifdef SDL2_RENDER
static SDL_mutex* stdPlatform_mtxPrintf = NULL;
#endif

int stdPlatform_Printf(const char *fmt, ...)
{
    char tmp[256];
    va_list args;

#ifdef SDL2_RENDER
    if (!stdPlatform_mtxPrintf)
        stdPlatform_mtxPrintf = SDL_CreateMutex();

    SDL_LockMutex(stdPlatform_mtxPrintf);
#endif
    
    va_start (args, fmt);
    int ret = vprintf(fmt, args);
    va_end (args);

    va_start (args, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, args);
    jkQuakeConsole_PrintLine(tmp);

#ifdef TARGET_ANDROID
    LOGI("%s", tmp);
#endif

    va_end (args);
#ifdef SDL2_RENDER
    SDL_UnlockMutex(stdPlatform_mtxPrintf);
#endif
    return ret;
}
#endif
