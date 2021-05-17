#include "util.h"

#include "stdPlatform.h"

int util_FileExists(char *fpath)
{
    intptr_t f = std_pHS->fileOpen(fpath, "r");
    if ( f )
    {
        std_pHS->fileClose(f);
        return 1;
    }
    return 0;
}
