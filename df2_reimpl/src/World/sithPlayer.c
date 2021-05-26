#include "sithPlayer.h"

#include "World/jkPlayer.h"
#include "Engine/sithNet.h"
#include "jk.h"

float sithPlayer_GetBinAmt(int idx)
{
    //if (idx)
    //    jk_printf("Get %u: %f\n", idx, jkPlayer_playerInfos[playerThingIdx].iteminfo[idx].ammoAmt);

    return jkPlayer_playerInfos[playerThingIdx].iteminfo[idx].ammoAmt;
}

void sithPlayer_SetBinAmt(int idx, float amt)
{
    jkPlayer_playerInfos[playerThingIdx].iteminfo[idx].ammoAmt = amt;
}

int sithPlayer_GetNum(sithThing *player)
{
    int i;

    if ( !player || player->thingType != THINGTYPE_PLAYER )
        return -1;
    if ( !net_isMulti )
        return 0;

    if ( jkPlayer_maxPlayers <= 0 )
        return -1;
    
    i = 0;
    while (i < jkPlayer_maxPlayers)
    {
        if ((jkPlayer_playerInfos[i].flags & 1) && jkPlayer_playerInfos[i].playerThing == player)
            return i;

        i++;
    }
    return -1;
}
