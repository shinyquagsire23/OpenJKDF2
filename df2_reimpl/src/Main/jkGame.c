#include "jkGame.h"

#include "World/sithWorld.h"

#define jkGame_ParseSection ((void*)jkGame_ParseSection_ADDR)

int jkGame_Initialize()
{
    sithWorld_SetSectionParser("jk", jkGame_ParseSection);
    jkGame_bInitted = 1;
    return 1;
}
