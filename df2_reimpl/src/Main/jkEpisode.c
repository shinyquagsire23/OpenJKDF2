#include "jkEpisode.h"

#include "World/sithThing.h"

#define jkEpisode_UpdateExtra ((void*)jkEpisode_UpdateExtra_ADDR)

int jkEpisode_Startup()
{
    sithThing_SetHandler(jkEpisode_UpdateExtra);
    return 1;
}
