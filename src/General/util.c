#include "util.h"

#include "stdPlatform.h"

int util_FileExists(const char *fpath)
{
    if (!fpath || !*fpath) return 0;
    intptr_t f = std_pHS->fileOpen(fpath, "r");
    if ( f )
    {
        std_pHS->fileClose(f);
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
