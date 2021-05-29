#include "sithPlayer.h"

#include "World/jkPlayer.h"
#include "Engine/sithNet.h"
#include "World/sithWorld.h"
#include "jk.h"

void sithPlayer_NewEntry(sithWorld *world)
{
    sithThing *v1; // eax
    int v2; // ecx
    int v3; // ebx
    int v5; // ebp
    int v7; // edi
    void *v8; // eax

    v1 = world->things;
    v2 = world->numThings;
    v3 = 0;
    if ( v2 >= 0 )
    {
        sithPlayerInfo* playerInfo = &jkPlayer_playerInfos[0];
        v5 = v2 + 1;
        do
        {
            if ( v1->thingType == THINGTYPE_PLAYER && (unsigned int)v3 < 0x20 )
            {
                playerInfo->playerThing = v1;
                v1->thingflags |= SITH_TF_INVULN;
                v1->actorParams.playerinfo = playerInfo;
                playerInfo->flags |= 2;
                rdMatrix_Copy34(&playerInfo->field_135C, &v1->lookOrientation);
                rdVector_Copy3(&playerInfo->field_135C.scale, &v1->position);
                playerInfo->field_138C = v1->sector;
                playerInfo++;
                ++v3;
            }
            ++v1;
            --v5;
        }
        while ( v5 );
    }
    jkPlayer_maxPlayers = v3;
    for (int i = jkPlayer_maxPlayers; i < 32; i++)
    {
        jkPlayer_playerInfos[i].playerThing = 0;
        jkPlayer_playerInfos[i].field_138C = 0;
    }
}

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
