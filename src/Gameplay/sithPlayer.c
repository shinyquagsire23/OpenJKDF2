#include "sithPlayer.h"

#include "World/jkPlayer.h"
#include "World/sithWorld.h"
#include "World/sithSector.h"
#include "World/sithWeapon.h"
#include "World/sithActor.h"
#include "Dss/sithMulti.h"
#include "Engine/sithCamera.h"
#include "Dss/sithGamesave.h"
#include "Devices/sithSoundMixer.h"
#include "World/sithSoundClass.h"
#include "Dss/sithMulti.h"
#include "Gameplay/sithTime.h"
#include "Devices/sithControl.h"
#include "Engine/sithPhysics.h"
#include "Engine/sithPuppet.h"
#include "Main/jkGame.h"
#include "General/stdPalEffects.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/stdMath.h"
#include "Dss/sithDSSThing.h"
#include "jk.h"

// Added: noclip
int sithPlayer_bNoClippingRend = 0;

void sithPlayer_Startup(int idx)
{
    SithPlayer *v1; // esi
    SithThing *v2; // eax

    v1 = &jkPlayer_playerInfos[idx];
    v1->flags = jkPlayer_playerInfos[idx].flags & ~1u;
    v1->playerNetId = 0;
    v2 = jkPlayer_playerInfos[idx].pLocalPlayer;
    if ( v2 )
    {
        if ( sithWorld_g_pCurrentWorld )
        {
            sithThing_SetThingModel(v2, v2->pTemplate->renderData.model3);
            jkPlayer_playerInfos[idx].pLocalPlayer->flags |= SITH_TF_DISABLED;
        }
    }
}

void sithPlayer_Open()
{
}

void sithPlayer_Close()
{
    if ( sithPlayer_g_pLocalPlayer )
    {
        stdPalEffects_FreeRequest(sithPlayer_g_pLocalPlayer->palEffectsIdx1);
        stdPalEffects_FreeRequest(sithPlayer_g_pLocalPlayer->palEffectsIdx2);
    }
    sithPlayer_g_pLocalPlayerThing = 0;
    sithPlayer_g_pLocalPlayer = 0;
}

void sithPlayer_PlacePlayers(SithWorld *pWorld)
{
    SithThing *v1; // eax
    int v2; // ecx
    uint32_t v3; // ebx
    int v5; // ebp
    int v7; // edi
    void *v8; // eax

    v1 = pWorld->aThings;
    v2 = pWorld->numThings;
    v3 = 0;
    if ( v2 >= 0 )
    {
        SithPlayer* playerInfo = &jkPlayer_playerInfos[0];
        for (v5 = v2 + 1; v5 >= 0; v5--)
        {
            if ( v1->type == SITH_THING_PLAYER && v3 < JKPLAYER_NUM_INFOS )
            {
                playerInfo->pLocalPlayer = v1;
                v1->flags |= SITH_TF_INVULN;
                v1->actorParams.pPlayer = playerInfo;
                playerInfo->flags |= 2;
                rdMatrix_Copy34(&playerInfo->orient, &v1->orient);
                rdVector_Copy3(&playerInfo->orient.scale, &v1->position);
                playerInfo->pInSector = v1->sector;
                playerInfo++;
                ++v3;


            }
            ++v1;
        }
    }
    jkPlayer_maxPlayers = v3;
    for (int i = jkPlayer_maxPlayers; i < JKPLAYER_NUM_INFOS; i++)
    {
        jkPlayer_playerInfos[i].pLocalPlayer = 0;
        jkPlayer_playerInfos[i].pInSector = 0;
    }
}

int sithPlayer_GetBinItemActive(int binIdx)
{
    return (jkPlayer_playerInfos[playerThingIdx].aItems[binIdx].state & 4) >> 2;
}

int sithPlayer_IsInvItemAvailable(int binIndex)
{
    return (jkPlayer_playerInfos[playerThingIdx].aItems[binIndex].state & 8) >> 3;
}

void sithPlayer_SetBinItemActive(int binIdx, int bEnabled)
{
    if ( bEnabled )
        jkPlayer_playerInfos[playerThingIdx].aItems[binIdx].state |= 4;
    else
        jkPlayer_playerInfos[playerThingIdx].aItems[binIdx].state &= ~4;
}

flex_t sithPlayer_GetInvItemAmount(int binIndex)
{
    //if (idx)
    //    jk_printf("Get %u: %f\n", idx, jkPlayer_playerInfos[playerThingIdx].aItems[idx].amount);

    return jkPlayer_playerInfos[playerThingIdx].aItems[binIndex].amount;
}

void sithPlayer_SetInvItemAmount(int binIndex, flex_t amount)
{
    jkPlayer_playerInfos[playerThingIdx].aItems[binIndex].amount = amount;
}

int sithPlayer_GetThingPlayerNum(SithThing *pThing)
{
    int i;

    if ( !pThing || pThing->type != SITH_THING_PLAYER )
        return -1;
    if ( !sithNet_isMulti )
        return 0;

    if ( jkPlayer_maxPlayers <= 0 )
        return -1;
    
    i = 0;
    while (i < jkPlayer_maxPlayers)
    {
        if ((jkPlayer_playerInfos[i].flags & 1) && jkPlayer_playerInfos[i].pLocalPlayer == pThing)
            return i;

        i++;
    }
    return -1;
}

void sithPlayer_SetLocalPlayer(int playerNum)
{
    unsigned int v6; // eax

    playerThingIdx = playerNum;
    sithPlayer_g_pLocalPlayer = &jkPlayer_playerInfos[playerNum];
    sithPlayer_g_pLocalPlayerThing = jkPlayer_playerInfos[playerNum].pLocalPlayer;

    sithWorld_g_pCurrentWorld->pLocalPlayer = sithPlayer_g_pLocalPlayerThing;
    sithWorld_g_pCurrentWorld->pCameraFocusThing = sithPlayer_g_pLocalPlayerThing;

    sithPlayer_g_pLocalPlayerThing->flags &= ~SITH_TF_INVULN;

    // Added: idk why this is needed?
    //sithPlayer_g_pLocalPlayerThing->controlType = SITH_CT_10;

    _wcsncpy(sithPlayer_g_pLocalPlayer->player_name, jkPlayer_playerShortName, 0x1Fu);
    sithPlayer_g_pLocalPlayer->player_name[31] = 0;

    _wcsncpy(sithPlayer_g_pLocalPlayer->multi_name, sithMulti_name, 0x1Fu);
    sithPlayer_g_pLocalPlayer->multi_name[31] = 0;

    for (v6 = 0; v6 < jkPlayer_maxPlayers; v6++)
    {
        if (jkPlayer_playerInfos[v6].pLocalPlayer)
        {
            if ( v6 != playerNum )
                jkPlayer_playerInfos[v6].pLocalPlayer->flags |= SITH_TF_INVULN;
        }
    }
}

void sithPlayer_ResetPalEffects()
{
    stdPalEffects_FlushAllEffects();
    sithPlayer_g_pLocalPlayer->palEffectsIdx1 = stdPalEffects_NewRequest(1);
    sithPlayer_g_pLocalPlayer->palEffectsIdx2 = stdPalEffects_NewRequest(2);
}

void sithPlayer_Update(SithPlayer *pPlayer, flex_t secDeltaTime)
{
    int v2; // edi
    SithThing *v3; // esi
    stdPalEffect *pPalEffect; // ebx
    flex_d_t v5; // st7
    int v14; // ecx
    flex_t v20; // [esp+0h] [ebp-4h]

    v20 = secDeltaTime * 0.4;
    v2 = (__int64)(secDeltaTime * 256.0 - -0.5);
    if ( pPlayer == sithPlayer_g_pLocalPlayer )
    {
        v3 = pPlayer->pLocalPlayer;
        pPalEffect = stdPalEffects_GetEffectPointer(pPlayer->palEffectsIdx1);
        if ( pPalEffect->tint.x != 0.0 )
        {
            pPalEffect->tint.x = stdMath_Clamp(pPalEffect->tint.x - v20, 0.0, 1.0);
        }
        if ( pPalEffect->tint.y != 0.0 )
        {
            pPalEffect->tint.y = stdMath_Clamp(pPalEffect->tint.y - v20, 0.0, 1.0);
        }
        if ( pPalEffect->tint.z != 0.0 )
        {
            pPalEffect->tint.z = stdMath_Clamp(pPalEffect->tint.z - v20, 0.0, 1.0);
        }
        if ( pPalEffect->add.x )
        {
            pPalEffect->add.x = stdMath_ClampInt(pPalEffect->add.x - v2, 0, 255);
        }
        if ( pPalEffect->add.y )
        {
            pPalEffect->add.y = stdMath_ClampInt(pPalEffect->add.y - v2, 0, 255);
        }
        if ( pPalEffect->add.z )
        {
            pPalEffect->add.z = stdMath_ClampInt(pPalEffect->add.z - v2, 0, 255);
        }
        sithWeapon_UpdateActorWeaponState(v3);
        sithInventory_SendFire(v3);
        if ( !v3->attach_flags )
        {
            v14 = v3->actorParams.flags;
            if ( (v14 & SITH_AF_FALLKILLED) == 0 && v3->moveType == SITH_MT_PHYSICS && v3->physicsParams.vel.z < -3.0 )
            {
                if ( v3->sector )
                {
                    if ( (v3->sector->flags & SITH_SECTOR_FALLDEATH) != 0 && !(g_debugmodeFlags & DEBUGFLAG_NOCLIP)) // Added: noclip
                    {
                        v3->flags |= SITH_TF_DEAD;
                        v3->actorParams.flags |= SITH_AF_FALLKILLED;
                        sithCamera_SetCameraFocus(&sithCamera_g_aCameras[1], v3, 0);
                        sithCamera_SetCurrentCamera(&sithCamera_g_aCameras[1]);
                    }
                }
            }
        }
        if ( (v3->actorParams.flags & SITH_AF_FALLKILLED) != 0 )
        {
            pPalEffect->fade -= secDeltaTime * 0.7;
            if (pPalEffect->fade <= 0.0)
                sithPlayer_KillPlayer(v3);
        }
    }
}

void sithPlayer_debug_loadauto(SithThing *player)
{
    char v1[128]; // [esp+4h] [ebp-80h] BYREF

    if ( (g_submodeFlags & 1) != 0 || (g_debugmodeFlags & DEBUGFLAG_IN_EDITOR) != 0 )
    {
        sithPlayer_NewPlayer(player);
    }
    else if ( !sithGamesave_Restore(sithGamesave_autosave_fname, 0, 0) )
    {
        stdString_snprintf(v1, 128, "%s%s", "_JKAUTO_", sithGamesave_AutosaveMapName()); // Added: single-slot on DC
        stdFnames_ChangeExt(v1, "jks");
        sithGamesave_Restore(v1, 0, 0);
    }
    sithSoundMixer_ResumeMusic(1);
    player->type = SITH_THING_PLAYER;
    player->msecLifeLeft = 0;
}

void sithPlayer_SetScreenTint(flex_t tintR, flex_t tintG, flex_t tintB)
{
    SithThing *focusThing; // eax
    stdPalEffect *pPalEffects; // ecx
    flex_d_t v8; // st7

    focusThing = sithWorld_g_pCurrentWorld->pCameraFocusThing;
    if ( (focusThing->type & 0xA) != 0 ) // ???
    {
        pPalEffects = stdPalEffects_GetEffectPointer(focusThing->actorParams.pPlayer->palEffectsIdx2);

        pPalEffects->tint.x = stdMath_Clamp(tintR, 0.0, 1.0);
        pPalEffects->tint.y = stdMath_Clamp(tintG, 0.0, 1.0);
        pPalEffects->tint.z = stdMath_Clamp(tintB, 0.0, 1.0);
    }
}

void sithPlayer_AddDynamicTint(flex_t fR, flex_t fG, flex_t fB)
{
    stdPalEffect *pPalEffects; // ecx

    pPalEffects = stdPalEffects_GetEffectPointer(sithPlayer_g_pLocalPlayer->palEffectsIdx1);
    pPalEffects->tint.x = stdMath_Clamp(fR + pPalEffects->tint.x, 0.0, 1.0);
    pPalEffects->tint.y = stdMath_Clamp(fG + pPalEffects->tint.y, 0.0, 1.0);
    pPalEffects->tint.z = stdMath_Clamp(fB + pPalEffects->tint.z, 0.0, 1.0);
}

void sithPlayer_AddDyamicAdd(int r, int g, int b)
{
    stdPalEffect* pPalEffects = stdPalEffects_GetEffectPointer(sithPlayer_g_pLocalPlayer->palEffectsIdx1);
    
    pPalEffects->add.x = r + pPalEffects->add.x;
    if ( pPalEffects->add.x > 0xFF )
        pPalEffects->add.x = 255;

    pPalEffects->add.y = g + pPalEffects->add.y;
    if ( pPalEffects->add.y > 0xFF )
        pPalEffects->add.y = 255;

    pPalEffects->add.z = b + pPalEffects->add.z;
    if ( pPalEffects->add.z > 0xFF )
        pPalEffects->add.z = 255;
}
int sithPlayer_sub_4C9060(SithThing *thing1, SithThing *thing2)
{
    SithPlayer *v2; // ecx
    SithPlayer *v3; // eax
    int v4; // ecx
    int v5; // eax

    if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 && thing1 != thing2 && thing1->type == SITH_THING_PLAYER && thing2->type == SITH_THING_PLAYER )
    {
        // Yes, these are assigns not ==
        if ( v2 = thing1->actorParams.pPlayer )
        {
            if ( v3 = thing2->actorParams.pPlayer )
            {
                if ( v4 = v2->teamNum )
                {
                    if ( v5 = v3->teamNum )
                    {
                        if ( v4 == v5 )
                            return 1;
                    }
                }
            }
        }
    }
    return 0;
}

void sithPlayer_KillPlayer(SithThing *pPlayerThing)
{
    SithPlayer *v1; // edi
    char v4[128]; // [esp+8h] [ebp-80h] BYREF

    v1 = pPlayerThing->actorParams.pPlayer;

    if ( pPlayerThing == sithPlayer_g_pLocalPlayerThing)
        sithDSSThing_Death(pPlayerThing, pPlayerThing, 1, -1, 255);

    if ( (pPlayerThing->flags & SITH_TF_CAPTURED) == 0
      || (sithCog_ThingSendMessage(pPlayerThing, pPlayerThing, SITH_MESSAGE_KILLED), (pPlayerThing->flags & SITH_TF_DESTROYED) == 0) )
    {
        sithSoundClass_StopSound(pPlayerThing, 0);
        sithThing_DetachAttachedThings(pPlayerThing);
        sithActor_SetHeadPYR(pPlayerThing, &rdroid_zeroVector3);
        pPlayerThing->physicsParams.flags &= ~(SITH_PF_CROUCHING|SITH_PF_800|SITH_PF_100);
        pPlayerThing->physicsParams.flags |= (SITH_PF_ALIGNSURFACE|SITH_PF_USEGRAVITY);
        pPlayerThing->actorParams.flags &= ~SITH_AF_BLEEDS;
        sithPhysics_ResetThingMovement(pPlayerThing);
        sithWeapon_SyncPuppet(pPlayerThing);
        if ( sithNet_isMulti )
            sithMulti_ProcessKilledPlayer(v1, pPlayerThing, pPlayerThing);
        if ( pPlayerThing == sithPlayer_g_pLocalPlayerThing )
        {
            sithPlayer_debug_loadauto(pPlayerThing);
        }
    }
}

void sithPlayer_PlayerKilledAction(SithThing *pPlayerThing, SithThing *pSrcThing)
{
    SithPlayer *v5; // edi

    v5 = pPlayerThing->actorParams.pPlayer;
    pPlayerThing->physicsParams.flags &= ~(SITH_PF_800|SITH_PF_100);
    pPlayerThing->physicsParams.flags |= SITH_PF_ALIGNSURFACE|SITH_PF_USEGRAVITY;
    pPlayerThing->flags |= SITH_TF_DEAD;
    pPlayerThing->actorParams.flags &= ~SITH_AF_BLEEDS;
    sithPhysics_ResetThingMovement(pPlayerThing);
    sithWeapon_SyncPuppet(pPlayerThing);
    sithInventory_BroadcastKilledMessage(pPlayerThing, pSrcThing);
    if ( sithNet_isMulti )
        sithMulti_ProcessKilledPlayer(v5, pPlayerThing, pSrcThing);
    if ( pPlayerThing == sithPlayer_g_pLocalPlayerThing )
        sithControl_death_msgtimer = sithTime_g_msecGameTime + 3000;
}

int sithPlayer_GetThingPlayerNumByIndex(int thingIdx)
{
    int result; // eax
    SithPlayer* i;

    if ( !sithNet_isMulti )
        return 0;
    result = 0;
    if ( jkPlayer_maxPlayers <= 0 )
        return -1;
    for ( i = &jkPlayer_playerInfos[0]; (i->flags & 1) == 0 || i->pLocalPlayer->idx != thingIdx; i++ )
    {
        if ( ++result >= jkPlayer_maxPlayers )
            return -1;
    }
    return result;
}

void sithPlayer_SetInvItemAvailable(int binIndex, int bAvailable)
{
    SithInventoryItem *v2; // eax
    int v3; // ecx

    v2 = &jkPlayer_playerInfos[playerThingIdx].aItems[binIndex];
    v3 = v2->state;
    if ( bAvailable )
        v2->state = v3 | 8;
    else
        v2->state = v3 & ~8u;
}

void sithPlayer_Reset(unsigned int playerNum)
{
    SithPlayer *pPlayerInfo;

    pPlayerInfo = &jkPlayer_playerInfos[playerNum];
    if ( playerNum < 0x20 )
    {
        pPlayerInfo->numKills = 0;
        pPlayerInfo->numKilled = 0;
        pPlayerInfo->teamNum = 0;
        pPlayerInfo->numSuicides = 0;
        pPlayerInfo->score = 0;
        pPlayerInfo->respawnMask = 0;
        pPlayerInfo->playerNetId = 0;
        pPlayerInfo->player_name[0] = 0;
        pPlayerInfo->multi_name[0] = 0;
        if ( pPlayerInfo->pLocalPlayer && sithWorld_g_pCurrentWorld )
            sithInventory_InitInventory(pPlayerInfo->pLocalPlayer);
        if ( pPlayerInfo == sithPlayer_g_pLocalPlayer )
        {
            stdPalEffects_FlushAllEffects();
            sithPlayer_g_pLocalPlayer->palEffectsIdx1 = stdPalEffects_NewRequest(1);
            sithPlayer_g_pLocalPlayer->palEffectsIdx2 = stdPalEffects_NewRequest(2);
        }
        pPlayerInfo->flags &= ~0x5;
    }
}

int sithPlayer_ShowPlayer(int playerNum, int id)
{
    if ( !jkPlayer_playerInfos[playerNum].pLocalPlayer )
        return 0;
    jkPlayer_playerInfos[playerNum].flags |= 5;
    jkPlayer_playerInfos[playerNum].playerNetId = id;
    jkPlayer_playerInfos[playerNum].pLocalPlayer->flags &= ~SITH_TF_DISABLED;

    //jkPlayer_playerInfos[idx].pLocalPlayer->controlType = SITH_CT_10; // TODO: WHY IS THIS NEEDED?

    return 1;
}

// MOTS altered
void sithPlayer_NewPlayer(SithThing *pPlayer)
{
    rdPuppet *v1; // ecx
    int v3; // eax
    SithThing *v4; // eax
    stdPalEffect *v6; // eax
    int v9; // edi

    v1 = pPlayer->renderData.puppet;
    if ( v1 )
    {
        if ( pPlayer->puppet )
        {
            v3 = pPlayer->puppet->field_18;
            if ( v3 >= 0 )
                sithPuppet_StopKey(v1, v3, 0.0);
        }
    }
    if ( !sithNet_isMulti || (pPlayer->flags & SITH_TF_INVULN) == 0 )
    {
        v4 = pPlayer->pTemplate;
        pPlayer->actorParams.endurance = 0; // MOTS added
        pPlayer->actorParams.health = v4->actorParams.health;
        if ( (v4->physicsParams.flags & SITH_PF_800) != 0 )
        {
            pPlayer->physicsParams.flags &= ~(SITH_PF_100|SITH_PF_ALIGNSURFACE);
            pPlayer->physicsParams.flags |= SITH_PF_800;
        }
        sithActor_SetHeadPYR(pPlayer, &rdroid_zeroVector3);
        if ( pPlayer == sithPlayer_g_pLocalPlayerThing )
        {
            sithCamera_SetCameraFocus(sithCamera_g_aCameras, pPlayer, 0);
            sithCamera_SetCameraFocus(&sithCamera_g_aCameras[1], pPlayer, 0);
            sithCamera_SetCurrentToCycleCamera();
            v6 = stdPalEffects_GetEffectPointer(sithPlayer_g_pLocalPlayer->palEffectsIdx1);
            stdPalEffects_ResetEffect(v6);
        }

        pPlayer->flags &= ~(SITH_TF_DEAD|SITH_TF_DESTROYED);
        pPlayer->actorParams.flags &= ~SITH_AF_FALLKILLED;
        pPlayer->msecLifeLeft = 0;
        if ( !sithNet_isMulti || pPlayer == sithPlayer_g_pLocalPlayerThing )
        {
            v9 = sithMulti_GetSpawnIdx(pPlayer);
            sithThing_ExitSector(pPlayer);
            sithThing_SetPositionAndOrient(
                pPlayer,
                &jkPlayer_playerInfos[v9].orient.scale,
                &jkPlayer_playerInfos[v9].orient);
            sithThing_EnterSector(pPlayer, jkPlayer_playerInfos[v9].pInSector, 1, 0);
            sithCamera_Update(sithCamera_g_pCurCamera);
            sithPhysics_ResetThingMovement(pPlayer);
            sithWeapon_SyncPuppet(pPlayer);
            sithCog_BroadcastMessage(SITH_MESSAGE_NEWPLAYER, SENDERTYPE_THING, pPlayer->idx, SENDERTYPE_THING, pPlayer->idx);
            if ( sithMessage_g_outputstream )
                sithDSSThing_UpdateState(pPlayer, -1, 255);
        }
    }
}

uint32_t sithPlayer_GetPlayerNum(int playerId)
{
    if ( !playerId )
        return -1;

    if ( !jkPlayer_maxPlayers )
        return -1;
    for ( uint32_t i = 0; i < jkPlayer_maxPlayers; ++i )
    {
        if (jkPlayer_playerInfos[i].playerNetId == playerId)
            return i;
    }
    return -1;
}

int sithPlayer_GetPlayerNumByName(wchar_t *pwName)
{
    int v1; // edi
    SithPlayer *i; // esi

    if ( !pwName )
        return -1;
    v1 = 0;
    if ( !jkPlayer_maxPlayers )
        return -1;
    for ( i = jkPlayer_playerInfos; (i->flags & 1) == 0 || __wcsicmp(i->player_name, pwName); ++i )
    {
        if ( ++v1 >= (unsigned int)jkPlayer_maxPlayers )
            return -1;
    }
    return v1;
}