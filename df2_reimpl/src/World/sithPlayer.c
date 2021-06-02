#include "sithPlayer.h"

#include "World/jkPlayer.h"
#include "Engine/sithNet.h"
#include "Engine/sithMulti.h"
#include "World/sithWorld.h"
#include "General/stdPalEffects.h"
#include "jk.h"

void sithPlayer_NewEntry(sithWorld *world)
{
    sithThing *v1; // eax
    int v2; // ecx
    uint32_t v3; // ebx
    int v5; // ebp
    int v7; // edi
    void *v8; // eax

    v1 = world->things;
    v2 = world->numThings;
    v3 = 0;
    if ( v2 >= 0 )
    {
        sithPlayerInfo* playerInfo = &jkPlayer_playerInfos[0];
        for (v5 = v2 + 1; v5 >= 0; v5--)
        {
            if ( v1->thingType == THINGTYPE_PLAYER && v3 < 0x20 )
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
        }
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

void sithPlayer_idk(int idx)
{
    unsigned int v6; // eax

    playerThingIdx = idx;
    g_selfPlayerInfo = &jkPlayer_playerInfos[idx];
    g_localPlayerThing = jkPlayer_playerInfos[idx].playerThing;

    sithWorld_pCurWorld->playerThing = g_localPlayerThing;
    sithWorld_pCurWorld->cameraFocus = g_localPlayerThing;

    g_localPlayerThing->thingflags &= ~0x100u;

    _wcsncpy(g_selfPlayerInfo->player_name, jkPlayer_playerShortName, 0x1Fu);
    g_selfPlayerInfo->player_name[31] = 0;

    _wcsncpy(g_selfPlayerInfo->multi_name, sithMulti_name, 0x1Fu);
    g_selfPlayerInfo->multi_name[31] = 0;

    for (v6 = 0; v6 < jkPlayer_maxPlayers; v6++)
    {
        if (jkPlayer_playerInfos[v6].playerThing)
        {
            if ( v6 != idx )
                jkPlayer_playerInfos[v6].playerThing->thingflags |= 0x100u;
        }
    }
}

void sithPlayer_ResetPalEffects()
{
    stdPalEffects_FlushAllEffects();
    g_selfPlayerInfo->palEffectsIdx1 = stdPalEffects_NewRequest(1);
    g_selfPlayerInfo->palEffectsIdx2 = stdPalEffects_NewRequest(2);
}
