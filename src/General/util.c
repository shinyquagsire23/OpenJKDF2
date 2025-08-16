#include "util.h"

#include "stdPlatform.h"

int util_FileExists(const char *fpath)
{
    intptr_t f = std_pHS->fileOpen(fpath, "r");
    if ( f )
    {
        std_pHS->fileClose(f);
        return 1;
    }

#ifdef TARGET_TWL
    return util_FileExistsLowLevel(fpath);
#else
    return 0;
#endif
}

int util_FileExistsLowLevel(const char *fpath)
{
    intptr_t f = pLowLevelHS->fileOpen(fpath, "r");
    if ( f )
    {
        pLowLevelHS->fileClose(f);
        return 1;
    }
    return 0;
}

uint32_t util_Weirdchecksum(uint8_t *data, int len, uint32_t last_hash)
{
    uint32_t result;

    for ( result = last_hash; len; --len )
        result = *data++ ^ ((result >> 31) + 2 * result);
    return result;
}
