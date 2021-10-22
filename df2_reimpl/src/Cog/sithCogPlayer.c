#include "sithCogPlayer.h"

#include "World/jkPlayer.h"
#include "World/sithPlayer.h"
#include "Engine/sithMulti.h"
#include "Engine/sithNet.h"
#include "World/sithWeapon.h"

void sithCogPlayer_SetInvActivate(sithCog *ctx)
{
    int bActivate = sithCogVm_PopInt(ctx);
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player && player->thingType == THINGTYPE_PLAYER && player->actorParams.playerinfo && binIdx < 200 )
    {
        if ( bActivate )
            sithInventory_SetActivate(player, binIdx, 1);
        else
            sithInventory_SetActivate(player, binIdx, 0);
    }
}

void sithCogPlayer_SetInvAvailable(sithCog *ctx)
{
    int bAvailable = sithCogVm_PopInt(ctx);
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player && player->thingType == THINGTYPE_PLAYER && player->actorParams.playerinfo && binIdx < 200 )
    {
        if ( bAvailable )
            sithInventory_SetAvailable(player, binIdx, 1);
        else
            sithInventory_SetAvailable(player, binIdx, 0);
    }
}

void sithCogPlayer_IsInvActivated(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player && player->thingType == THINGTYPE_PLAYER && player->actorParams.playerinfo && binIdx < 200 )
    {
        if ( sithInventory_GetActivate(player, binIdx) )
            sithCogVm_PushInt(ctx, 1);
        else
            sithCogVm_PushInt(ctx, 0);
    }
}

void sithCogPlayer_IsInvAvailable(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player && player->thingType == THINGTYPE_PLAYER && player->actorParams.playerinfo && binIdx < 200 )
    {
        if ( sithInventory_GetAvailable(player, binIdx) )
            sithCogVm_PushInt(ctx, 1);
        else
            sithCogVm_PushInt(ctx, 0);
    }
}

void sithCogPlayer_SetGoalFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    int binIdx = sithCogVm_PopInt(ctx) + SITHBIN_GOAL00;
    sithThing* player = sithCogVm_PopThing(ctx);
    if ( player && player->thingType == THINGTYPE_PLAYER && player->actorParams.playerinfo && binIdx < 200 )
    {
        float amt = (float)((int)sithInventory_GetBinAmount(player, binIdx) | flags);
        sithInventory_SetBinAmount(player, binIdx, amt);
    }
}

void sithCogPlayer_ClearGoalFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    int binIdx = sithCogVm_PopInt(ctx) + SITHBIN_GOAL00;
    sithThing* player = sithCogVm_PopThing(ctx);
    if ( player && player->thingType == THINGTYPE_PLAYER && player->actorParams.playerinfo && binIdx < 200 )
    {
        float amt = (float)((int)sithInventory_GetBinAmount(player, binIdx) & ~flags);
        sithInventory_SetBinAmount(player, binIdx, amt);
    }
}

void sithCogPlayer_GetNumPlayers(sithCog *ctx)
{
    int numPlayers = 0;

    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        if (jkPlayer_playerInfos[i].flags & 1)
            ++numPlayers;
    }

    sithCogVm_PushInt(ctx, numPlayers);
}

void sithCogPlayer_GetMaxPlayers(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, jkPlayer_maxPlayers);
}

void sithCogPlayer_GetAbsoluteMaxPlayers(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, 32);
}

void sithCogPlayer_GetLocalPlayerThing(sithCog *ctx)
{
    if ( g_localPlayerThing )
        sithCogVm_PushInt(ctx, g_localPlayerThing->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogPlayer_GetPlayerThing(sithCog *ctx)
{
    uint32_t idx = sithCogVm_PopInt(ctx);
    if ( idx < jkPlayer_maxPlayers )
        sithCogVm_PushInt(ctx, jkPlayer_playerInfos[idx].playerThing->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogPlayer_GetPlayerNum(sithCog *ctx)
{
    int playerIdx;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->thingType == THINGTYPE_PLAYER 
        && (playerIdx = sithPlayer_GetNum(player), playerIdx != -1))
        sithCogVm_PushInt(ctx, playerIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogPlayer_GetPlayerTeam(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->thingType == THINGTYPE_PLAYER 
        && (playerInfo = player->actorParams.playerinfo) != 0 )
        sithCogVm_PushInt(ctx, playerInfo->teamNum);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogPlayer_SetPlayerTeam(sithCog *ctx)
{
    int teamNum = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->thingType == THINGTYPE_PLAYER)
    {
        sithPlayerInfo* playerInfo = player->actorParams.playerinfo;
        if ( playerInfo )
        {
            playerInfo->teamNum = teamNum;
            if ( sithNet_isMulti )
                sithMulti_SyncScores();
        }
    }
}

void sithCogPlayer_GetPlayerScore(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->thingType == THINGTYPE_PLAYER 
        && (playerInfo = player->actorParams.playerinfo) != 0 )
        sithCogVm_PushInt(ctx, playerInfo->score);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogPlayer_SetPlayerScore(sithCog *ctx)
{
    int score = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->thingType == THINGTYPE_PLAYER)
    {
        sithPlayerInfo* playerInfo = player->actorParams.playerinfo;
        if ( playerInfo )
        {
            playerInfo->score = score;
            if ( sithNet_isMulti )
                sithMulti_SyncScores();
        }
    }
}

void sithCogPlayer_GetPlayerKills(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->thingType == THINGTYPE_PLAYER 
        && (playerInfo = player->actorParams.playerinfo) != 0 )
        sithCogVm_PushInt(ctx, playerInfo->numKills);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogPlayer_SetPlayerKills(sithCog *ctx)
{
    int numKills = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->thingType == THINGTYPE_PLAYER)
    {
        sithPlayerInfo* playerInfo = player->actorParams.playerinfo;
        if ( playerInfo )
        {
            playerInfo->numKills = numKills;
            if ( sithNet_isMulti )
                sithMulti_SyncScores();
        }
    }
}

void sithCogPlayer_GetPlayerKilled(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->thingType == THINGTYPE_PLAYER 
        && (playerInfo = player->actorParams.playerinfo) != 0 )
        sithCogVm_PushInt(ctx, playerInfo->numKilled);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogPlayer_SetPlayerKilled(sithCog *ctx)
{
    int numKilled = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->thingType == THINGTYPE_PLAYER)
    {
        sithPlayerInfo* playerInfo = player->actorParams.playerinfo;
        if ( playerInfo )
        {
            playerInfo->numKilled = numKilled;
            if ( sithNet_isMulti )
                sithMulti_SyncScores();
        }
    }
}

void sithCogPlayer_GetPlayerSuicides(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->thingType == THINGTYPE_PLAYER 
        && (playerInfo = player->actorParams.playerinfo) != 0 )
        sithCogVm_PushInt(ctx, playerInfo->numSuicides);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogPlayer_SetPlayerSuicides(sithCog *ctx)
{
    int numSuicides = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->thingType == THINGTYPE_PLAYER)
    {
        sithPlayerInfo* playerInfo = player->actorParams.playerinfo;
        if ( playerInfo )
        {
            playerInfo->numSuicides = numSuicides;
            if ( sithNet_isMulti )
                sithMulti_SyncScores();
        }
    }
}

void sithCogPlayer_PickupBackpack(sithCog *ctx)
{
    sithThing* backpack = sithCogVm_PopThing(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player
      && player->thingType == THINGTYPE_PLAYER
      && player->actorParams.playerinfo
      && backpack
      && backpack->thingType == THINGTYPE_ITEM
      && (backpack->actorParams.typeflags & 4) != 0 )
    {
        sithInventory_PickupBackpack(player, backpack);
    }
}

void sithCogPlayer_NthBackpackBin(sithCog *ctx)
{
    int ret;

    int n = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing
        && thing->thingType == THINGTYPE_ITEM
        && (thing->actorParams.typeflags & SITH_TF_4))
    {
        ret = sithInventory_NthBackpackBin(thing, n);
        sithCogVm_PushInt(ctx, ret);
    }
}

void sithCogPlayer_NthBackpackValue(sithCog *ctx)
{
    int ret;

    int n = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing
        && thing->thingType == THINGTYPE_ITEM
        && (thing->actorParams.typeflags & SITH_TF_4))
    {
        ret = sithInventory_NthBackpackValue(thing, n);
        sithCogVm_PushInt(ctx, ret);
    }
}

void sithCogPlayer_NumBackpackItems(sithCog *ctx)
{
    int ret;

    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing
        && thing->thingType == THINGTYPE_ITEM
        && (thing->actorParams.typeflags & SITH_TF_4))
    {
        ret = sithInventory_NumBackpackItems(thing);
        sithCogVm_PushInt(ctx, ret);
    }
}

void sithCogPlayer_CreateBackpack(sithCog *ctx)
{
    sithThing* player = sithCogVm_PopThing(ctx);

    if (player
        && player->thingType == THINGTYPE_PLAYER
        && player->actorParams.playerinfo)
    {
        sithThing* backpack = sithInventory_CreateBackpack(player);
        if ( backpack )
            sithCogVm_PushInt(ctx, backpack->thingIdx);
        else
            sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogPlayer_GetAutoSwitch(sithCog *ctx)
{
    if ( sithNet_isMulti )
        sithCogVm_PushInt(ctx, sithWeapon_bMultiplayerAutoSwitch);
    else
        sithCogVm_PushInt(ctx, sithWeapon_bAutoSwitch);
}

void sithCogPlayer_SetAutoSwitch(sithCog *ctx)
{
    int bVal = sithCogVm_PopInt(ctx);
    if ( sithNet_isMulti )
        sithWeapon_bMultiplayerAutoSwitch = bVal;
    else
        sithWeapon_bAutoSwitch = bVal;
}

void sithCogPlayer_GetAutoPickup(sithCog *ctx)
{
    if ( sithNet_isMulti )
        sithCogVm_PushInt(ctx, sithWeapon_bMultiAutoPickup);
    else
        sithCogVm_PushInt(ctx, sithWeapon_bAutoPickup);
}

void sithCogPlayer_SetAutoPickup(sithCog *ctx)
{
    int bVal = sithCogVm_PopInt(ctx);
    if ( sithNet_isMulti )
        sithWeapon_bMultiplayerAutoSwitch = bVal;
    else
        sithWeapon_bAutoSwitch = bVal;
}

void sithCogPlayer_GetAutoReload(sithCog *ctx)
{
    if ( sithNet_isMulti )
        sithCogVm_PushInt(ctx, sithWeapon_bMultiAutoReload);
    else
        sithCogVm_PushInt(ctx, sithWeapon_bAutoReload);
}

void sithCogPlayer_SetAutoReload(sithCog *ctx)
{
    int bVal = sithCogVm_PopInt(ctx);
    if ( sithNet_isMulti )
        sithWeapon_bMultiAutoPickup = bVal;
    else
        sithWeapon_bAutoPickup = bVal;
}

void sithCogPlayer_GetRespawnMask(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player
        && player->thingType == THINGTYPE_PLAYER
        && (playerInfo = player->actorParams.playerinfo))
        sithCogVm_PushInt(ctx, playerInfo->respawnMask);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogPlayer_SetRespawnMask(sithCog *ctx)
{
    int mask = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if (player
        && player->thingType == THINGTYPE_PLAYER)
    {
        sithPlayerInfo* playerInfo = player->actorParams.playerinfo;
        if (playerInfo)
            playerInfo->respawnMask = mask;
    }
}

void sithCogPlayer_ActivateBin(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    float delay = sithCogVm_PopFlex(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if (player
        && player->thingType == THINGTYPE_PLAYER
        && delay >= 0.0 )
    {
        if (player->actorParams.playerinfo)
            sithInventory_ActivateBin(player, ctx, delay, binIdx);
    }
}

void sithCogPlayer_DeactivateBin(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if (player
        && player->thingType == THINGTYPE_PLAYER
        && player->actorParams.playerinfo)
    {
        float ret = sithInventory_DeactivateBin(player, ctx, binIdx);
        sithCogVm_PushFlex(ctx, ret);
    }
    else
    {
        sithCogVm_PushFlex(ctx, -1.0);
    }
}

void sithCogPlayer_GetNumPlayersInTeam(sithCog *ctx)
{
    int numPlayers = 0;
    int teamNum = sithCogVm_PopInt(ctx);
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        if ((jkPlayer_playerInfos[i].flags & 1) && jkPlayer_playerInfos[i].teamNum == teamNum )
            ++numPlayers;
    }
    sithCogVm_PushInt(ctx, numPlayers);
}

void sithCogPlayer_AddScoreToTeamMembers(sithCog *ctx)
{
    int scoreAdd = sithCogVm_PopInt(ctx);
    int teamNum = sithCogVm_PopInt(ctx);
    
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        if ((jkPlayer_playerInfos[i].flags & 1) && jkPlayer_playerInfos[i].teamNum == teamNum )
            jkPlayer_playerInfos[i].score += scoreAdd;
    }
}

void sithCogPlayer_SetBinWait(sithCog *ctx)
{
    float wait = sithCogVm_PopFlex(ctx);
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if (player
        && player->thingType == THINGTYPE_PLAYER
        && wait >= -1.0)
        sithInventory_SetBinWait(player, binIdx, wait);
}

void sithCogPlayer_SyncScores(sithCog *ctx)
{
    if (sithNet_isMulti)
        sithMulti_SyncScores();
}

void sithCogPlayer_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetInvActivate, "setinvactivated");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetInvAvailable, "setinvavailable");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_IsInvActivated, "isinvactivated");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_IsInvAvailable, "isinvavailable");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetGoalFlags, "setgoalflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_ClearGoalFlags, "cleargoalflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetNumPlayers, "getnumplayers");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetMaxPlayers, "getmaxplayers");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetAbsoluteMaxPlayers, "getabsolutemaxplayers");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetLocalPlayerThing, "getlocalplayerthing");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetPlayerThing, "getplayerthing");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetPlayerNum, "getplayernum");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetPlayerTeam, "getplayerteam");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetPlayerTeam, "setplayerteam");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetPlayerScore, "getplayerscore");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetPlayerScore, "setplayerscore");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetPlayerKills, "getplayerkills");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetPlayerKills, "setplayerkills");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetPlayerKilled, "getplayerkilled");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetPlayerKilled, "setplayerkilled");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetPlayerSuicides, "getplayersuicides");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetPlayerSuicides, "setplayersuicides");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_PickupBackpack, "pickupbackpack");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_CreateBackpack, "createbackpack");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_NthBackpackBin, "nthbackpackbin");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_NthBackpackValue, "nthbackpackvalue");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_NumBackpackItems, "numbackpackitems");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetAutoSwitch, "getautoswitch");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetAutoSwitch, "setautoswitch");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetAutoPickup, "getautopickup");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetAutoPickup, "setautopickup");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetAutoReload, "getautoreload");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetAutoReload, "setautoreload");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetRespawnMask, "getrespawnmask");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetRespawnMask, "setrespawnmask");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_ActivateBin, "activatebin");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_DeactivateBin, "deactivatebin");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SetBinWait, "setbinwait");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_GetNumPlayersInTeam, "getnumplayersinteam");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_AddScoreToTeamMembers, "addscoretoteammembers");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogPlayer_SyncScores, "syncscores");

}
