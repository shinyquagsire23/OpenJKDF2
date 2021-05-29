#include "sithSurface.h"

#include "General/stdHashTable.h"
#include "World/sithWorld.h"
#include "jk.h"

int sithSurface_Startup()
{
    _memset(sithSurface_aSurfaces, 0, sizeof(rdSurface) * 256); // sizeof(sithSurface_aSurfaces)

    for (int i = 0; i < 256; i++)
    {
        sithSurface_aAvail[i] = 255 - i;
    }

    sithSurface_numAvail = 256;
    sithSurface_numSurfaces = 0;
    return 1;
}

int sithSurface_Open()
{
    sithSurface_bOpened = 1;
    return 1;
}

int sithSurface_Verify(sithWorld *world)
{
    for (int i = 0; i < world->numSurfaces; i++)
    {
        if (world->surfaces[i].parent_sector == 8 || !world->surfaces[i].parent_sector)
            return 0;
    }
    
    return 1;
}
