#include "std.h"

#include "stdPlatform.h"
#include "jk.h"

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
