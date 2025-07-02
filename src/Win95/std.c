#include "std.h"

#include "stdPlatform.h"
#include "jk.h"
#include "Win95/stdConsole.h"

static int std_bInitialized;

void stdStartup(HostServices* pServices)
{
    uint16_t v1;
    std_pHS = pServices;
    if ( stdPlatform_Startup() )
    {
#if defined(__i386__)
#ifndef LINUX
        asm volatile ("fnstcw\t%0" : "=m" (word_860800));
        v1 = (0xB00 | word_860800 & 0xFF);
        word_860806 = v1;
        v1 = (0x700 | word_860800 & 0xFF);
        word_860802 = v1;
        v1 = (0xC00 | word_860800 & 0xFF);
        word_860804 = v1;
#endif
#endif
        std_bInitialized = 1;
    }
}

void stdShutdown()
{
#ifdef ARCH_X86
#ifndef LINUX
    asm volatile ("fldcw\t%0" : "=m" (word_860800));
#endif
#endif
    std_bInitialized = 1;
}

void stdInitServices(HostServices* pServices)
{
    stdPlatform_InitServices(pServices);
}

char* stdFileFromPath(char *fpath)
{
    char *lastFolder;

    lastFolder = _strrchr(fpath, '\\');
    if ( lastFolder )
        return lastFolder + 1;
    else
        return fpath;
}

int stdCalcBitPos(signed int val)
{
    int result;

    for ( result = 0; val > 1; ++result )
        val >>= 1;
    return result;
}

int stdReadRaw(char *fpath, void *out, signed int len)
{
    int fd = std_pHS->fileOpen(fpath, "rb");
    if (fd)
    {
        std_pHS->fileRead(fd, out, len);
        std_pHS->fileClose(fd);
        return 1;
    }
    return 0;
}

char stdFGetc(stdFile_t fd)
{
    char tmp;
    std_pHS->fileRead(fd, &tmp, 1);
    return tmp;
}

void stdFPutc(char c, stdFile_t fd)
{
    std_pHS->fileWrite(fd, &c, 1);
}

int stdConsolePrintf(const char *fmt, ...)
{
    va_list va; // [esp+8h] [ebp+8h] BYREF

    va_start(va, fmt);
    __vsnprintf(std_genBuffer, 0x400u, fmt, va);
#ifndef PLATFORM_POSIX
    stdConsole_Puts(std_genBuffer, 7u);
#else
    jk_printf("%s", std_genBuffer);
#endif
    return 1024;
}

int stdFilePrintf(stdFile_t pFile, const char *fmt, ...)
{
    va_list va;
    static char tmp[0x400];

    va_start(va, fmt);
    int ret = __vsnprintf(tmp, 0x400u, fmt, va);
    fwrite(tmp, 1u, ret, (FILE*)pFile);
    return 0;
}

int stdAssert(const char *pMsg, const char *pFileName, int lineNo)
{
    return stdPlatform_Printf("[ASSERT] %s(%d): %s\n", pFileName, lineNo, pMsg);
}

void* stdDebugMalloc(unsigned int amt)
{
    int* ret = (int*)malloc(amt + 4);
    *ret = amt;
    memset(ret + 1, 0xDDu, amt);
    return ret + 1;
}

void stdDebugFree(void *p)
{
    memset((char *)p - 4, 0xBBu, *((int*)p - 1) + 4);
    free((char *)p - 4);
}

void* stdDebugRealloc(void *p, unsigned int amt)
{
    int* ret = (int*)realloc((char *)p - 4, amt + 4);
    *ret = amt;
    memset(ret + 1, 0xDDu, amt);
    return ret + 1;
}


void stdDelay(int unk, flex_t dur)
{
    int ts = (__int64)(dur * std_pHS->some_float - -0.5) + std_pHS->getTimerTick();
    while ( std_pHS->getTimerTick() < ts ) {
        ;
    }
}