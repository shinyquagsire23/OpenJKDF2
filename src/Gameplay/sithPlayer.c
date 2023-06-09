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
    sithPlayerInfo *v1; // esi
    sithThing *v2; // eax

    v1 = &jkPlayer_playerInfos[idx];
    v1->flags = jkPlayer_playerInfos[idx].flags & ~1u;
    v1->net_id = 0;
    v2 = jkPlayer_playerInfos[idx].playerThing;
    if ( v2 )
    {
        if ( sithWorld_pCurrentWorld )
        {
            sithThing_SetNewModel(v2, v2->templateBase->rdthing.model3);
            jkPlayer_playerInfos[idx].playerThing->thingflags |= SITH_TF_DISABLED;
        }
    }
}

void sithPlayer_Close()
{
    if ( sithPlayer_pLocalPlayer )
    {
        stdPalEffects_FreeRequest(sithPlayer_pLocalPlayer->palEffectsIdx1);
        stdPalEffects_FreeRequest(sithPlayer_pLocalPlayer->palEffectsIdx2);
    }
    sithPlayer_pLocalPlayerThing = 0;
    sithPlayer_pLocalPlayer = 0;
}

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
            if ( v1->type == SITH_THING_PLAYER && v3 < 32 )
            {
                playerInfo->playerThing = v1;
                v1->thingflags |= SITH_TF_INVULN;
                v1->actorParams.playerinfo = playerInfo;
                playerInfo->flags |= 2;
                rdMatrix_Copy34(&playerInfo->spawnPosOrient, &v1->lookOrientation);
                rdVector_Copy3(&playerInfo->spawnPosOrient.scale, &v1->position);
                playerInfo->pSpawnSector = v1->sector;
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
        jkPlayer_playerInfos[i].pSpawnSector = 0;
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

    if ( !player || player->type != SITH_THING_PLAYER )
        return -1;
    if ( !sithNet_isMulti )
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
    sithPlayer_pLocalPlayer = &jkPlayer_playerInfos[idx];
    sithPlayer_pLocalPlayerThing = jkPlayer_playerInfos[idx].playerThing;

    sithWorld_pCurrentWorld->playerThing = sithPlayer_pLocalPlayerThing;
    sithWorld_pCurrentWorld->cameraFocus = sithPlayer_pLocalPlayerThing;

    sithPlayer_pLocalPlayerThing->thingflags &= ~SITH_TF_INVULN;

    // Added: idk why this is needed?
    sithPlayer_pLocalPlayerThing->thingtype = SITH_THING_PLAYER;

    _wcsncpy(sithPlayer_pLocalPlayer->player_name, jkPlayer_playerShortName, 0x1Fu);
    sithPlayer_pLocalPlayer->player_name[31] = 0;

    _wcsncpy(sithPlayer_pLocalPlayer->multi_name, sithMulti_name, 0x1Fu);
    sithPlayer_pLocalPlayer->multi_name[31] = 0;

    for (v6 = 0; v6 < jkPlayer_maxPlayers; v6++)
    {
        if (jkPlayer_playerInfos[v6].playerThing)
        {
            if ( v6 != idx )
                jkPlayer_playerInfos[v6].playerThing->thingflags |= SITH_TF_INVULN;
        }
    }
}

void sithPlayer_ResetPalEffects()
{
    stdPalEffects_FlushAllEffects();
    sithPlayer_pLocalPlayer->palEffectsIdx1 = stdPalEffects_NewRequest(1);
    sithPlayer_pLocalPlayer->palEffectsIdx2 = stdPalEffects_NewRequest(2);
}

void sithPlayer_Tick(sithPlayerInfo *playerInfo, float a2)
{
    int v2; // edi
    sithThing *v3; // esi
    stdPalEffect *pPalEffect; // ebx
    double v5; // st7
    int v14; // ecx
    float v20; // [esp+0h] [ebp-4h]

    v20 = a2 * 0.4;
    v2 = (__int64)(a2 * 256.0 - -0.5);
    if ( playerInfo == sithPlayer_pLocalPlayer )
    {
        v3 = playerInfo->playerThing;
        pPalEffect = stdPalEffects_GetEffectPointer(playerInfo->palEffectsIdx1);
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
        sithWeapon_handle_inv_msgs(v3);
        sithInventory_SendFire(v3);
        if ( !v3->attach_flags )
        {
            v14 = v3->actorParams.typeflags;
            if ( (v14 & SITH_AF_FALLING_TO_DEATH) == 0 && v3->moveType == SITH_MT_PHYSICS && v3->physicsParams.vel.z < -3.0 )
            {
                if ( v3->sector )
                {
                    if ( (v3->sector->flags & SITH_SECTOR_FALLDEATH) != 0 && !(g_debugmodeFlags & DEBUGFLAG_NOCLIP)) // Added: noclip
                    {
                        v3->thingflags |= SITH_TF_DEAD;
                        v3->actorParams.typeflags |= SITH_AF_FALLING_TO_DEATH;
                        sithCamera_SetCameraFocus(&sithCamera_cameras[1], v3, 0);
                        sithCamera_SetCurrentCamera(&sithCamera_cameras[1]);
                    }
                }
            }
        }
        if ( (v3->actorParams.typeflags & SITH_AF_FALLING_TO_DEATH) != 0 )
        {
            pPalEffect->fade -= a2 * 0.7;
            if (pPalEffect->fade <= 0.0)
                sithPlayer_HandleSentDeathPkt(v3);
        }
    }
}

void sithPlayer_debug_loadauto(sithThing *player)
{
    char v1[128]; // [esp+4h] [ebp-80h] BYREF

    if ( (g_submodeFlags & 1) != 0 || (g_debugmodeFlags & 0x100) != 0 )
    {
        sithPlayer_debug_ToNextCheckpoint(player);
    }
    else if ( !sithGamesave_Load(sithGamesave_autosave_fname, 0, 0) )
    {
        stdString_snprintf(v1, 128, "%s%s", "_JKAUTO_", sithWorld_pCurrentWorld->map_jkl_fname);
        stdFnames_ChangeExt(v1, "jks");
        sithGamesave_Load(v1, 0, 0);
    }
    sithSoundMixer_ResumeMusic(1);
    player->type = SITH_THING_PLAYER;
    player->lifeLeftMs = 0;
}

void sithPlayer_SetScreenTint(float tintR, float tintG, float tintB)
{
    sithThing *focusThing; // eax
    stdPalEffect *pPalEffects; // ecx
    double v8; // st7

    focusThing = sithWorld_pCurrentWorld->cameraFocus;
    if ( (focusThing->type & 0xA) != 0 ) // ???
    {
        pPalEffects = stdPalEffects_GetEffectPointer(focusThing->actorParams.playerinfo->palEffectsIdx2);

        pPalEffects->tint.x = stdMath_Clamp(tintR, 0.0, 1.0);
        pPalEffects->tint.y = stdMath_Clamp(tintG, 0.0, 1.0);
        pPalEffects->tint.z = stdMath_Clamp(tintB, 0.0, 1.0);
    }
}

void sithPlayer_AddDynamicTint(float fR, float fG, float fB)
{
    stdPalEffect *pPalEffects; // ecx

    pPalEffects = stdPalEffects_GetEffectPointer(sithPlayer_pLocalPlayer->palEffectsIdx1);
    pPalEffects->tint.x = stdMath_Clamp(fR + pPalEffects->tint.x, 0.0, 1.0);
    pPalEffects->tint.y = stdMath_Clamp(fG + pPalEffects->tint.y, 0.0, 1.0);
    pPalEffects->tint.z = stdMath_Clamp(fB + pPalEffects->tint.z, 0.0, 1.0);
}

void sithPlayer_AddDyamicAdd(int r, int g, int b)
{
    stdPalEffect* pPalEffects = stdPalEffects_GetEffectPointer(sithPlayer_pLocalPlayer->palEffectsIdx1);
    
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
int sithPlayer_sub_4C9060(sithThing *thing1, sithThing *thing2)
{
    sithPlayerInfo *v2; // ecx
    sithPlayerInfo *v3; // eax
    int v4; // ecx
    int v5; // eax

    if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 && thing1 != thing2 && thing1->type == SITH_THING_PLAYER && thing2->type == SITH_THING_PLAYER )
    {
        // Yes, these are assigns not ==
        if ( v2 = thing1->actorParams.playerinfo )
        {
            if ( v3 = thing2->actorParams.playerinfo )
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

void sithPlayer_HandleSentDeathPkt(sithThing *thing)
{
    sithPlayerInfo *v1; // edi
    char v4[128]; // [esp+8h] [ebp-80h] BYREF

    v1 = thing->actorParams.playerinfo;

    if ( thing == sithPlayer_pLocalPlayerThing)
        sithDSSThing_SendDeath(thing, thing, 1, -1, 255);

    if ( (thing->thingflags & SITH_TF_CAPTURED) == 0
      || (sithCog_SendMessageFromThing(thing, thing, SITH_MESSAGE_KILLED), (thing->thingflags & SITH_TF_WILLBEREMOVED) == 0) )
    {
        sithSoundClass_StopSound(thing, 0);
        sithThing_detachallchildren(thing);
        sithActor_MoveJointsForEyePYR(thing, &rdroid_zeroVector3);
        thing->physicsParams.physflags &= ~(SITH_PF_CROUCHING|SITH_PF_800|SITH_PF_100);
        thing->physicsParams.physflags |= (SITH_PF_SURFACEALIGN|SITH_PF_USEGRAVITY);
        thing->actorParams.typeflags &= ~SITH_AF_BLEEDS;
        sithPhysics_ThingStop(thing);
        sithWeapon_SyncPuppet(thing);
        if ( sithNet_isMulti )
            sithMulti_HandleDeath(v1, thing, thing);
        if ( thing == sithPlayer_pLocalPlayerThing )
        {
            sithPlayer_debug_loadauto(thing);
        }
    }
}

void sithPlayer_sub_4C9150(sithThing *player, sithThing *killedBy)
{
    sithPlayerInfo *v5; // edi

    v5 = player->actorParams.playerinfo;
    player->physicsParams.physflags &= ~(SITH_PF_800|SITH_PF_100);
    player->physicsParams.physflags |= SITH_PF_SURFACEALIGN|SITH_PF_USEGRAVITY;
    player->thingflags |= SITH_TF_DEAD;
    player->actorParams.typeflags &= ~SITH_AF_BLEEDS;
    sithPhysics_ThingStop(player);
    sithWeapon_SyncPuppet(player);
    sithInventory_SendKilledMessageToAll(player, killedBy);
    if ( sithNet_isMulti )
        sithMulti_HandleDeath(v5, player, killedBy);
    if ( player == sithPlayer_pLocalPlayerThing )
        sithControl_death_msgtimer = sithTime_curMs + 3000;
}

int sithPlayer_GetNumidk(int a1)
{
    int result; // eax
    sithPlayerInfo* i;

    if ( !sithNet_isMulti )
        return 0;
    result = 0;
    if ( jkPlayer_maxPlayers <= 0 )
        return -1;
    for ( i = &jkPlayer_playerInfos[0]; (i->flags & 1) == 0 || i->playerThing->thingIdx != a1; i++ )
    {
        if ( ++result >= jkPlayer_maxPlayers )
            return -1;
    }
    return result;
}

void sithPlayer_SetBinCarries(int binIdx, int bCarries)
{
    sithItemInfo *v2; // eax
    int v3; // ecx

    v2 = &jkPlayer_playerInfos[playerThingIdx].iteminfo[binIdx];
    v3 = v2->state;
    if ( bCarries )
        v2->state = v3 | 8;
    else
        v2->state = v3 & ~8u;
}

void sithPlayer_sub_4C8910(unsigned int idx)
{
    sithPlayerInfo *pPlayerInfo;

    pPlayerInfo = &jkPlayer_playerInfos[idx];
    if ( idx < 0x20 )
    {
        pPlayerInfo->numKills = 0;
        pPlayerInfo->numKilled = 0;
        pPlayerInfo->teamNum = 0;
        pPlayerInfo->numSuicides = 0;
        pPlayerInfo->score = 0;
        pPlayerInfo->respawnMask = 0;
        pPlayerInfo->net_id = 0;
        pPlayerInfo->player_name[0] = 0;
        pPlayerInfo->multi_name[0] = 0;
        if ( pPlayerInfo->playerThing && sithWorld_pCurrentWorld )
            sithInventory_ClearInventory(pPlayerInfo->playerThing);
        if ( pPlayerInfo == sithPlayer_pLocalPlayer )
        {
            stdPalEffects_FlushAllEffects();
            sithPlayer_pLocalPlayer->palEffectsIdx1 = stdPalEffects_NewRequest(1);
            sithPlayer_pLocalPlayer->palEffectsIdx2 = stdPalEffects_NewRequest(2);
        }
        pPlayerInfo->flags &= ~0x5;
    }
}

int sithPlayer_sub_4C87C0(int idx, int netId)
{
    if ( !jkPlayer_playerInfos[idx].playerThing )
        return 0;
    jkPlayer_playerInfos[idx].flags |= 5;
    jkPlayer_playerInfos[idx].net_id = netId;
    jkPlayer_playerInfos[idx].playerThing->thingflags &= ~SITH_TF_DISABLED;

    jkPlayer_playerInfos[idx].playerThing->thingtype = SITH_THING_PLAYER; // TODO: WHY IS THIS NEEDED?

    return 1;
}

// MOTS altered
void sithPlayer_debug_ToNextCheckpoint(sithThing *player)
{
    rdPuppet *v1; // ecx
    int v3; // eax
    sithThing *v4; // eax
    stdPalEffect *v6; // eax
    int v9; // edi

    v1 = player->rdthing.puppet;
    if ( v1 )
    {
        if ( player->puppet )
        {
            v3 = player->puppet->field_18;
            if ( v3 >= 0 )
                sithPuppet_StopKey(v1, v3, 0.0);
        }
    }
    if ( !sithNet_isMulti || (player->thingflags & SITH_TF_INVULN) == 0 )
    {
        v4 = player->templateBase;
        player->actorParams.msUnderwater = 0; // MOTS added
        player->actorParams.health = v4->actorParams.health;
        if ( (v4->physicsParams.physflags & SITH_PF_800) != 0 )
        {
            player->physicsParams.physflags &= ~(SITH_PF_100|SITH_PF_SURFACEALIGN);
            player->physicsParams.physflags |= SITH_PF_800;
        }
        sithActor_MoveJointsForEyePYR(player, &rdroid_zeroVector3);
        if ( player == sithPlayer_pLocalPlayerThing )
        {
            sithCamera_SetCameraFocus(sithCamera_cameras, player, 0);
            sithCamera_SetCameraFocus(&sithCamera_cameras[1], player, 0);
            sithCamera_DoIdleAnimation();
            v6 = stdPalEffects_GetEffectPointer(sithPlayer_pLocalPlayer->palEffectsIdx1);
            stdPalEffects_ResetEffect(v6);
        }

        player->thingflags &= ~(SITH_TF_DEAD|SITH_TF_WILLBEREMOVED);
        player->actorParams.typeflags &= ~SITH_AF_FALLING_TO_DEATH;
        player->lifeLeftMs = 0;
        if ( !sithNet_isMulti || player == sithPlayer_pLocalPlayerThing )
        {
            v9 = sithMulti_GetSpawnIdx(player);
            sithThing_LeaveSector(player);
            sithThing_SetPosAndRot(
                player,
                &jkPlayer_playerInfos[v9].spawnPosOrient.scale,
                &jkPlayer_playerInfos[v9].spawnPosOrient);
            sithThing_EnterSector(player, jkPlayer_playerInfos[v9].pSpawnSector, 1, 0);
            sithCamera_FollowFocus(sithCamera_currentCamera);
            sithPhysics_ThingStop(player);
            sithWeapon_SyncPuppet(player);
            sithCog_SendSimpleMessageToAll(SITH_MESSAGE_NEWPLAYER, SENDERTYPE_THING, player->thingIdx, SENDERTYPE_THING, player->thingIdx);
            if ( sithComm_multiplayerFlags )
                sithDSSThing_SendSyncThing(player, -1, 255);
        }
    }
}

uint32_t sithPlayer_ThingIdxToPlayerIdx(int thingIdx)
{
    if ( !thingIdx )
        return -1;

    if ( !jkPlayer_maxPlayers )
        return -1;
    for ( uint32_t i = 0; i < jkPlayer_maxPlayers; ++i )
    {
        if (jkPlayer_playerInfos[i].net_id == thingIdx)
            return i;
    }
    return -1;
}

int sithPlayer_FindPlayerByName(wchar_t *pwStr)
{
    int v1; // edi
    sithPlayerInfo *i; // esi

    if ( !pwStr )
        return -1;
    v1 = 0;
    if ( !jkPlayer_maxPlayers )
        return -1;
    for ( i = jkPlayer_playerInfos; (i->flags & 1) == 0 || __wcsicmp(i->player_name, pwStr); ++i )
    {
        if ( ++v1 >= (unsigned int)jkPlayer_maxPlayers )
            return -1;
    }
    return v1;
}