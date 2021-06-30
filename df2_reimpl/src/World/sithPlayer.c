#include "sithPlayer.h"

#include "World/jkPlayer.h"
#include "World/sithWorld.h"
#include "World/sithSector.h"
#include "World/sithWeapon.h"
#include "World/sithUnk4.h"
#include "Engine/sithNet.h"
#include "Engine/sithMulti.h"
#include "Engine/sithCamera.h"
#include "Engine/sithSave.h"
#include "Engine/sithSoundSys.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithMulti.h"
#include "Engine/sithTime.h"
#include "Engine/sithControl.h"
#include "Main/jkGame.h"
#include "General/stdPalEffects.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "jk.h"

void sithPlayer_Initialize(int idx)
{
    sithPlayerInfo *v1; // esi
    sithThing *v2; // eax

    v1 = &jkPlayer_playerInfos[idx];
    v1->flags = jkPlayer_playerInfos[idx].flags & ~1u;
    v1->net_id = 0;
    v2 = jkPlayer_playerInfos[idx].playerThing;
    if ( v2 )
    {
        if ( sithWorld_pCurWorld )
        {
            sithThing_SetNewModel(v2, v2->templateBase->rdthing.model3);
            jkPlayer_playerInfos[idx].playerThing->thingflags |= SITH_TF_DISABLED;
        }
    }
}

void sithPlayer_Close()
{
    if ( g_selfPlayerInfo )
    {
        stdPalEffects_FreeRequest(g_selfPlayerInfo->palEffectsIdx1);
        stdPalEffects_FreeRequest(g_selfPlayerInfo->palEffectsIdx2);
    }
    g_localPlayerThing = 0;
    g_selfPlayerInfo = 0;
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

void sithPlayer_Tick(sithPlayerInfo *playerInfo, float a2)
{
    int v2; // edi
    sithThing *v3; // esi
    stdPalEffect *v4; // ebx
    double v5; // st7
    double v6; // st7
    double v7; // st7
    int v8; // eax
    int v9; // eax
    int v10; // eax
    int v11; // eax
    int v12; // eax
    int v13; // eax
    int v14; // ecx
    sithSector *v15; // eax
    float v20; // [esp+0h] [ebp-4h]

    v20 = a2 * 0.40000001;
    v2 = (__int64)(a2 * 256.0 - -0.5);
    if ( playerInfo == g_selfPlayerInfo )
    {
        v3 = playerInfo->playerThing;
        v4 = stdPalEffects_GetEffectPointer(playerInfo->palEffectsIdx1);
        if ( v4->tint.x != 0.0 )
        {
            v5 = v4->tint.x - v20;
            if ( v5 < 0.0 )
            {
                v5 = 0.0;
            }
            else if ( v5 > 1.0 )
            {
                v5 = 1.0;
            }
            v4->tint.x = v5;
        }
        if ( v4->tint.y != 0.0 )
        {
            v6 = v4->tint.y - v20;
            if ( v6 < 0.0 )
            {
                v6 = 0.0;
            }
            else if ( v6 > 1.0 )
            {
                v6 = 1.0;
            }
            v4->tint.y = v6;
        }
        if ( v4->tint.z != 0.0 )
        {
            v7 = v4->tint.z - v20;
            if ( v7 < 0.0 )
            {
                v7 = 0.0;
            }
            else if ( v7 > 1.0 )
            {
                v7 = 1.0;
            }
            v4->tint.z = v7;
        }
        v8 = v4->add.x;
        if ( v8 )
        {
            v9 = v8 - v2;
            if ( v9 < 0 )
            {
                v9 = 0;
            }
            else if ( v9 > 255 )
            {
                v9 = 255;
            }
            v4->add.x = v9;
        }
        v10 = v4->add.y;
        if ( v10 )
        {
            v11 = v10 - v2;
            if ( v11 < 0 )
            {
                v11 = 0;
            }
            else if ( v11 > 255 )
            {
                v11 = 255;
            }
            v4->add.y = v11;
        }
        v12 = v4->add.z;
        if ( v12 )
        {
            v13 = v12 - v2;
            if ( v13 < 0 )
            {
                v13 = 0;
            }
            else if ( v13 > 255 )
            {
                v13 = 255;
            }
            v4->add.z = v13;
        }
        sithWeapon_handle_inv_msgs(v3);
        sithInventory_SendFire(v3);
        if ( !v3->attach_flags )
        {
            v14 = v3->actorParams.typeflags;
            if ( (v14 & THING_TYPEFLAGS_400000) == 0 && v3->move_type == MOVETYPE_PHYSICS && v3->physicsParams.vel.z < -3.0 )
            {
                v15 = v3->sector;
                if ( v15 )
                {
                    if ( (v15->flags & 0x40) != 0 )
                    {
                        v3->thingflags |= 0x200;
                        v3->actorParams.typeflags |= THING_TYPEFLAGS_400000;
                        sithCamera_SetCameraFocus(&sithCamera_cameras[1], v3, 0);
                        sithCamera_SetCurrentCamera(&sithCamera_cameras[1]);
                    }
                }
            }
        }
        if ( (v3->actorParams.typeflags & THING_TYPEFLAGS_400000) != 0 )
        {
            v4->fade -= a2 * 0.69999999;
            if (v4->fade <= 0.0)
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
    else if ( !sithSave_Load(sithSave_autosave_fname, 0, 0) )
    {
        stdString_snprintf(v1, 128, "%s%s", "_JKAUTO_", sithWorld_pCurWorld->map_jkl_fname);
        stdFnames_ChangeExt(v1, "jks");
        sithSave_Load(v1, 0, 0);
    }
    sithSoundSys_ResumeMusic(1);
    player->thingType = THINGTYPE_PLAYER;
    player->lifeLeftMs = 0;
}

void sithPlayer_SetScreenTint(float tintR, float tintG, float tintB)
{
    sithThing *focusThing; // eax
    stdPalEffect *paleffect; // ecx
    double v5; // st7
    double v8; // st7

    focusThing = sithWorld_pCurWorld->cameraFocus;
    if ( (focusThing->thingType & THINGTYPE_PLAYER) != 0 ) // ???
    {
        paleffect = stdPalEffects_GetEffectPointer(focusThing->actorParams.playerinfo->palEffectsIdx2);
        if ( tintR < 0.0 )
        {
            v5 = 0.0;
        }
        else if ( tintR > 1.0 )
        {
            v5 = 1.0;
        }
        else
        {
            v5 = tintR;
        }
        paleffect->tint.x = v5;
        if ( tintG < 0.0 )
        {
            v8 = 0.0;
        }
        else if ( tintG > 1.0 )
        {
            v8 = 1.0;
        }
        else
        {
            v8 = tintG;
        }
        paleffect->tint.y = v8;
        if ( tintB < 0.0 )
        {
            paleffect->tint.z = 0.0;
        }
        else if ( tintB > 1.0 )
        {
            paleffect->tint.z = 1.0;
        }
        else
        {
            paleffect->tint.z = tintB;
        }
    }
}

void sithPlayer_AddDynamicTint(float fR, float fG, float fB)
{
    stdPalEffect *v3; // ecx
    double v4; // st7
    double v5; // st6
    double v6; // st7
    double v7; // st6
    double v8; // st7

    v3 = stdPalEffects_GetEffectPointer(g_selfPlayerInfo->palEffectsIdx1);
    v4 = fR + v3->tint.x;
    if ( v4 < 0.0 )
    {
        v4 = 0.0;
    }
    else if ( v4 > 1.0 )
    {
        v4 = 1.0;
    }
    v5 = v4;
    v6 = fG + v3->tint.y;
    v3->tint.x = v5;
    if ( v6 < 0.0 )
    {
        v6 = 0.0;
    }
    else if ( v6 > 1.0 )
    {
        v6 = 1.0;
    }
    v7 = v6;
    v8 = fB + v3->tint.z;
    v3->tint.y = v7;
    if ( v8 < 0.0 )
    {
        v8 = 0.0;
    }
    else if ( v8 > 0.5 )
    {
        v3->tint.z = 0.5;
        return;
    }
    v3->tint.z = v8;
}

void sithPlayer_AddDyamicAdd(int r, int g, int b)
{
    stdPalEffect *v3; // eax
    unsigned int v4; // ecx
    unsigned int v5; // ecx
    unsigned int v6; // ecx

    v3 = stdPalEffects_GetEffectPointer(g_selfPlayerInfo->palEffectsIdx1);
    v4 = r + v3->add.x;
    if ( v4 > 0xFF )
        v4 = 255;
    v3->add.x = v4;
    v5 = g + v3->add.y;
    if ( v5 > 0xFF )
        v5 = 255;
    v3->add.y = v5;
    v6 = b + v3->add.z;
    if ( v6 > 0xFF )
        v6 = 255;
    v3->add.z = v6;
}

int sithPlayer_sub_4C9060(sithThing *thing1, sithThing *thing2)
{
    sithPlayerInfo *v2; // ecx
    sithPlayerInfo *v3; // eax
    int v4; // ecx
    int v5; // eax

    if ( (net_MultiModeFlags & 1) != 0 && thing1 != thing2 && thing1->thingType == THINGTYPE_PLAYER && thing2->thingType == THINGTYPE_PLAYER )
    {
        v2 = thing1->actorParams.playerinfo;
        if ( v2 )
        {
            v3 = thing2->actorParams.playerinfo;
            if ( v3 )
            {
                v4 = v2->teamNum;
                if ( v4 )
                {
                    v5 = v3->teamNum;
                    if ( v5 )
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

#ifndef LINUX_TMP
    if ( thing == g_localPlayerThing)
        sithSector_cogMsg_SendDeath(thing, thing, 1, -1, 255);
#endif

    if ( (thing->thingflags & SITH_TF_CAPTURED) == 0
      || (sithCog_SendMessageFromThing(thing, thing, SITH_MESSAGE_KILLED), (thing->thingflags & SITH_TF_WILLBEREMOVED) == 0) )
    {
        sithSoundClass_StopSound(thing, 0);
        sithThing_detachallchildren(thing);
        sithUnk4_MoveJointsForEyePYR(thing, &rdroid_zeroVector3);
        thing->physicsParams.physflags &= ~(PHYSFLAGS_CROUCHING|PHYSFLAGS_800|PHYSFLAGS_100);
        thing->physicsParams.physflags |= (PHYSFLAGS_SURFACEALIGN|PHYSFLAGS_GRAVITY);
        thing->actorParams.typeflags &= ~0x2000;
        sithSector_StopPhysicsThing(thing);
        sithWeapon_SyncPuppet(thing);
        if ( net_isMulti )
            sithMulti_HandleDeath(v1, thing, thing);
        if ( thing == g_localPlayerThing )
        {
            if ( (g_submodeFlags & 1) != 0 || (g_debugmodeFlags & 0x100) != 0 )
            {
                sithPlayer_debug_ToNextCheckpoint(thing);
            }
            else if ( !sithSave_Load(sithSave_autosave_fname, 0, 0) )
            {
                stdString_snprintf(v4, 128, "%s%s", "_JKAUTO_", sithWorld_pCurWorld->map_jkl_fname);
                stdFnames_ChangeExt(v4, "jks");
                sithSave_Load(v4, 0, 0);
            }
            sithSoundSys_ResumeMusic(1);
            thing->thingType = THINGTYPE_PLAYER;
            thing->lifeLeftMs = 0;
        }
    }
}

void sithPlayer_sub_4C9150(sithThing *player, sithThing *killedBy)
{
    sithPlayerInfo *v5; // edi

    v5 = player->actorParams.playerinfo;
    player->physicsParams.physflags &= ~(PHYSFLAGS_800|PHYSFLAGS_100);
    player->physicsParams.physflags |= PHYSFLAGS_SURFACEALIGN|PHYSFLAGS_GRAVITY;
    player->thingflags |= SITH_TF_DEAD;
    player->actorParams.typeflags &= ~THING_TYPEFLAGS_ISBLOCKING;
    sithSector_StopPhysicsThing(player);
    sithWeapon_SyncPuppet(player);
    sithInventory_SendKilledMessageToAll(player, killedBy);
    if ( net_isMulti )
        sithMulti_HandleDeath(v5, player, killedBy);
    if ( player == g_localPlayerThing )
        sithControl_death_msgtimer = sithTime_curMs + 3000;
}

int sithPlayer_GetNumidk(int a1)
{
    int result; // eax
    sithPlayerInfo* i;

    if ( !net_isMulti )
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
