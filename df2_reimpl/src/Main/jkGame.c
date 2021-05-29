#include "jkGame.h"

#include "World/sithWorld.h"

int jkGame_Initialize()
{
    sithWorld_SetSectionParser("jk", jkGame_ParseSection);
    jkGame_bInitted = 1;
    return 1;
}

int jkGame_ParseSection(int a1, int a2)
{
    return a2 == 0;
}
