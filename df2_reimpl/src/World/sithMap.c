#include "sithMap.h"

#include "World/sithThing.h"
#include "jk.h"

int sithMap_Initialize(sithMap *map)
{
    if ( sithMap_bInitted )
        return 0;

    _memcpy(&sithMap_ctx, map, sizeof(sithMap_ctx));
    sithMap_bInitted = 1;
    return 1;
}

int sithMap_Shutdown()
{
    if ( sithMap_bInitted )
    {
        sithMap_bInitted = 0;
        return 1;
    }

    return 0;
}
