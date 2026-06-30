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

#ifdef TARGET_RETRO_HOMEBREW
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

int util_RectsOverlap(const rdRect *a, const rdRect *b)
{
    if ( a->x + a->width < b->x )
        return 0;
    if ( b->x + b->width < a->x )
        return 0;
    if ( a->y + a->height < b->y )
        return 0;
    return a->y <= b->y + b->height;
}

int util_RectsOverlapExclusive(const rdRect *a, const rdRect *b)
{
    if ( a->x + a->width <= b->x )
        return 0;
    if ( b->x + b->width <= a->x )
        return 0;
    if ( a->y + a->height <= b->y )
        return 0;
    return a->y < b->y + b->height;
}

void util_RectUnion(rdRect *out, const rdRect *b)
{
    if ( b->x < out->x )
    {
        out->width += out->x - b->x;
        out->x = b->x;
    }
    if ( b->y < out->y )
    {
        out->height += out->y - b->y;
        out->y = b->y;
    }
    if ( out->x + out->width < b->x + b->width )
        out->width = (b->x + b->width) - out->x;
    if ( out->y + out->height < b->y + b->height )
        out->height = (b->y + b->height) - out->y;
}

uint32_t util_Weirdchecksum(uint8_t *data, int len, uint32_t last_hash)
{
    uint32_t result;

    for ( result = last_hash; len; --len )
        result = *data++ ^ ((result >> 31) + 2 * result);
    return result;
}
