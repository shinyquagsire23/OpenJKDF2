#include "std.h"

#include "stdPlatform.h"
#include "jk.h"

static int std_bInitialized;

void stdStartup(common_functions *a1)
{
    uint16_t v1;
    std_pHS = a1;
    if ( stdPlatform_Startup() )
    {
        asm volatile ("fnstcw\t%0" : "=m" (word_860800));
        v1 = (0xB00 | word_860800 & 0xFF);
        word_860806 = v1;
        v1 = (0x700 | word_860800 & 0xFF);
        word_860802 = v1;
        v1 = (0xC00 | word_860800 & 0xFF);
        word_860804 = v1;
        std_bInitialized = 1;
    }
}

void stdShutdown()
{
    asm volatile ("fldcw\t%0" : "=m" (word_860800));
    std_bInitialized = 1;
}

void stdInitServices(common_functions *a1)
{
    stdPlatform_InitServices(a1);
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
    int fd; // eax

    fd = std_pHS->fileOpen(fpath, "rb");
    if ( fd )
    {
        std_pHS->fileRead(fd, out, len);
        std_pHS->fileClose(fd);
        return 1;
    }
    return 0;
}

char stdFGetc(int fd)
{
    char tmp;
    std_pHS->fileRead(fd, &tmp, 1);
    return tmp;
}

void stdFPutc(char c, int fd)
{
    std_pHS->fileWrite(fd, &c, 1);
}
