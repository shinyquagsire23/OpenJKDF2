#include "sithCogFunctionPlayer.h"

#include "World/jkPlayer.h"
#include "World/sithPlayer.h"
#include "Engine/sithMulti.h"
#include "Engine/sithNet.h"
#include "World/sithWeapon.h"

void sithCogFunctionPlayer_SetInvActivate(sithCog *ctx)
{
    int bActivate = sithCogVm_PopInt(ctx);
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo && binIdx < SITHBIN_NUMBINS )
    {
        if ( bActivate )
            sithInventory_SetActivate(player, binIdx, 1);
        else
            sithInventory_SetActivate(player, binIdx, 0);
    }
}

void sithCogFunctionPlayer_SetInvAvailable(sithCog *ctx)
{
    int bAvailable = sithCogVm_PopInt(ctx);
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo && binIdx < SITHBIN_NUMBINS )
    {
        if ( bAvailable )
            sithInventory_SetAvailable(player, binIdx, 1);
        else
            sithInventory_SetAvailable(player, binIdx, 0);
    }
}

void sithCogFunctionPlayer_IsInvActivated(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo && binIdx < SITHBIN_NUMBINS )
    {
        if ( sithInventory_GetActivate(player, binIdx) )
            sithCogVm_PushInt(ctx, 1);
        else
            sithCogVm_PushInt(ctx, 0);
    }
}

void sithCogFunctionPlayer_IsInvAvailable(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo && binIdx < SITHBIN_NUMBINS )
    {
        if ( sithInventory_GetAvailable(player, binIdx) )
            sithCogVm_PushInt(ctx, 1);
        else
            sithCogVm_PushInt(ctx, 0);
    }
}

void sithCogFunctionPlayer_SetGoalFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    int binIdx = sithCogVm_PopInt(ctx) + SITHBIN_GOAL00;
    sithThing* player = sithCogVm_PopThing(ctx);
    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo && binIdx < SITHBIN_NUMBINS )
    {
        float amt = (float)((int)sithInventory_GetBinAmount(player, binIdx) | flags);
        sithInventory_SetBinAmount(player, binIdx, amt);
    }
}

void sithCogFunctionPlayer_ClearGoalFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    int binIdx = sithCogVm_PopInt(ctx) + SITHBIN_GOAL00;
    sithThing* player = sithCogVm_PopThing(ctx);
    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo && binIdx < SITHBIN_NUMBINS )
    {
        float amt = (float)((int)sithInventory_GetBinAmount(player, binIdx) & ~flags);
        sithInventory_SetBinAmount(player, binIdx, amt);
    }
}

void sithCogFunctionPlayer_GetNumPlayers(sithCog *ctx)
{
    int numPlayers = 0;

    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        if (jkPlayer_playerInfos[i].flags & 1)
            ++numPlayers;
    }

    sithCogVm_PushInt(ctx, numPlayers);
}

void sithCogFunctionPlayer_GetMaxPlayers(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, jkPlayer_maxPlayers);
}

void sithCogFunctionPlayer_GetAbsoluteMaxPlayers(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, 32);
}

void sithCogFunctionPlayer_GetLocalPlayerThing(sithCog *ctx)
{
    if ( g_localPlayerThing )
        sithCogVm_PushInt(ctx, g_localPlayerThing->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_GetPlayerThing(sithCog *ctx)
{
    uint32_t idx = sithCogVm_PopInt(ctx);
    if ( idx < jkPlayer_maxPlayers )
        sithCogVm_PushInt(ctx, jkPlayer_playerInfos[idx].playerThing->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_GetPlayerNum(sithCog *ctx)
{
    int playerIdx;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerIdx = sithPlayer_GetNum(player), playerIdx != -1))
        sithCogVm_PushInt(ctx, playerIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_GetPlayerTeam(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.playerinfo) != 0 )
        sithCogVm_PushInt(ctx, playerInfo->teamNum);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_SetPlayerTeam(sithCog *ctx)
{
    int teamNum = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->type == SITH_THING_PLAYER)
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

void sithCogFunctionPlayer_GetPlayerScore(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.playerinfo) != 0 )
        sithCogVm_PushInt(ctx, playerInfo->score);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_SetPlayerScore(sithCog *ctx)
{
    int score = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->type == SITH_THING_PLAYER)
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

void sithCogFunctionPlayer_GetPlayerKills(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.playerinfo) != 0 )
        sithCogVm_PushInt(ctx, playerInfo->numKills);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_SetPlayerKills(sithCog *ctx)
{
    int numKills = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->type == SITH_THING_PLAYER)
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

void sithCogFunctionPlayer_GetPlayerKilled(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.playerinfo) != 0 )
        sithCogVm_PushInt(ctx, playerInfo->numKilled);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_SetPlayerKilled(sithCog *ctx)
{
    int numKilled = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->type == SITH_THING_PLAYER)
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

void sithCogFunctionPlayer_GetPlayerSuicides(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.playerinfo) != 0 )
        sithCogVm_PushInt(ctx, playerInfo->numSuicides);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_SetPlayerSuicides(sithCog *ctx)
{
    int numSuicides = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->type == SITH_THING_PLAYER)
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

void sithCogFunctionPlayer_PickupBackpack(sithCog *ctx)
{
    sithThing* backpack = sithCogVm_PopThing(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player
      && player->type == SITH_THING_PLAYER
      && player->actorParams.playerinfo
      && backpack
      && backpack->type == SITH_THING_ITEM
      && (backpack->actorParams.typeflags & 4) != 0 )
    {
        sithInventory_PickupBackpack(player, backpack);
    }
}

void sithCogFunctionPlayer_NthBackpackBin(sithCog *ctx)
{
    int ret;

    int n = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing
        && thing->type == SITH_THING_ITEM
        && (thing->actorParams.typeflags & SITH_TF_4))
    {
        ret = sithInventory_NthBackpackBin(thing, n);
        sithCogVm_PushInt(ctx, ret);
    }
}

void sithCogFunctionPlayer_NthBackpackValue(sithCog *ctx)
{
    int ret;

    int n = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing
        && thing->type == SITH_THING_ITEM
        && (thing->actorParams.typeflags & SITH_TF_4))
    {
        ret = sithInventory_NthBackpackValue(thing, n);
        sithCogVm_PushInt(ctx, ret);
    }
}

void sithCogFunctionPlayer_NumBackpackItems(sithCog *ctx)
{
    int ret;

    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing
        && thing->type == SITH_THING_ITEM
        && (thing->actorParams.typeflags & SITH_TF_4))
    {
        ret = sithInventory_NumBackpackItems(thing);
        sithCogVm_PushInt(ctx, ret);
    }
}

void sithCogFunctionPlayer_CreateBackpack(sithCog *ctx)
{
    sithThing* player = sithCogVm_PopThing(ctx);

    if (player
        && player->type == SITH_THING_PLAYER
        && player->actorParams.playerinfo)
    {
        sithThing* backpack = sithInventory_CreateBackpack(player);
        if ( backpack )
            sithCogVm_PushInt(ctx, backpack->thingIdx);
        else
            sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionPlayer_GetAutoSwitch(sithCog *ctx)
{
    if ( sithNet_isMulti )
        sithCogVm_PushInt(ctx, sithWeapon_bMultiplayerAutoSwitch);
    else
        sithCogVm_PushInt(ctx, sithWeapon_bAutoSwitch);
}

void sithCogFunctionPlayer_SetAutoSwitch(sithCog *ctx)
{
    int bVal = sithCogVm_PopInt(ctx);
    if ( sithNet_isMulti )
        sithWeapon_bMultiplayerAutoSwitch = bVal;
    else
        sithWeapon_bAutoSwitch = bVal;
}

void sithCogFunctionPlayer_GetAutoPickup(sithCog *ctx)
{
    if ( sithNet_isMulti )
        sithCogVm_PushInt(ctx, sithWeapon_bMultiAutoPickup);
    else
        sithCogVm_PushInt(ctx, sithWeapon_bAutoPickup);
}

void sithCogFunctionPlayer_SetAutoPickup(sithCog *ctx)
{
    int bVal = sithCogVm_PopInt(ctx);
    if ( sithNet_isMulti )
        sithWeapon_bMultiplayerAutoSwitch = bVal;
    else
        sithWeapon_bAutoSwitch = bVal;
}

void sithCogFunctionPlayer_GetAutoReload(sithCog *ctx)
{
    if ( sithNet_isMulti )
        sithCogVm_PushInt(ctx, sithWeapon_bMultiAutoReload);
    else
        sithCogVm_PushInt(ctx, sithWeapon_bAutoReload);
}

void sithCogFunctionPlayer_SetAutoReload(sithCog *ctx)
{
    int bVal = sithCogVm_PopInt(ctx);
    if ( sithNet_isMulti )
        sithWeapon_bMultiAutoPickup = bVal;
    else
        sithWeapon_bAutoPickup = bVal;
}

void sithCogFunctionPlayer_GetRespawnMask(sithCog *ctx)
{
    sithPlayerInfo *playerInfo;

    sithThing* player = sithCogVm_PopThing(ctx);
    if (player
        && player->type == SITH_THING_PLAYER
        && (playerInfo = player->actorParams.playerinfo))
        sithCogVm_PushInt(ctx, playerInfo->respawnMask);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_SetRespawnMask(sithCog *ctx)
{
    int mask = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if (player
        && player->type == SITH_THING_PLAYER)
    {
        sithPlayerInfo* playerInfo = player->actorParams.playerinfo;
        if (playerInfo)
            playerInfo->respawnMask = mask;
    }
}

void sithCogFunctionPlayer_ActivateBin(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    float delay = sithCogVm_PopFlex(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if (player
        && player->type == SITH_THING_PLAYER
        && delay >= 0.0 )
    {
        if (player->actorParams.playerinfo)
            sithInventory_ActivateBin(player, ctx, delay, binIdx);
    }
}

void sithCogFunctionPlayer_DeactivateBin(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if (player
        && player->type == SITH_THING_PLAYER
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

void sithCogFunctionPlayer_GetNumPlayersInTeam(sithCog *ctx)
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

void sithCogFunctionPlayer_AddScoreToTeamMembers(sithCog *ctx)
{
    int scoreAdd = sithCogVm_PopInt(ctx);
    int teamNum = sithCogVm_PopInt(ctx);
    
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        if ((jkPlayer_playerInfos[i].flags & 1) && jkPlayer_playerInfos[i].teamNum == teamNum )
            jkPlayer_playerInfos[i].score += scoreAdd;
    }
}

void sithCogFunctionPlayer_SetBinWait(sithCog *ctx)
{
    float wait = sithCogVm_PopFlex(ctx);
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if (player
        && player->type == SITH_THING_PLAYER
        && wait >= -1.0)
        sithInventory_SetBinWait(player, binIdx, wait);
}

void sithCogFunctionPlayer_SyncScores(sithCog *ctx)
{
    if (sithNet_isMulti)
        sithMulti_SyncScores();
}

void sithCogFunctionPlayer_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetInvActivate, "setinvactivated");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetInvAvailable, "setinvavailable");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_IsInvActivated, "isinvactivated");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_IsInvAvailable, "isinvavailable");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetGoalFlags, "setgoalflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_ClearGoalFlags, "cleargoalflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetNumPlayers, "getnumplayers");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetMaxPlayers, "getmaxplayers");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetAbsoluteMaxPlayers, "getabsolutemaxplayers");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetLocalPlayerThing, "getlocalplayerthing");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetPlayerThing, "getplayerthing");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetPlayerNum, "getplayernum");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetPlayerTeam, "getplayerteam");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetPlayerTeam, "setplayerteam");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetPlayerScore, "getplayerscore");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetPlayerScore, "setplayerscore");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetPlayerKills, "getplayerkills");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetPlayerKills, "setplayerkills");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetPlayerKilled, "getplayerkilled");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetPlayerKilled, "setplayerkilled");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetPlayerSuicides, "getplayersuicides");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetPlayerSuicides, "setplayersuicides");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_PickupBackpack, "pickupbackpack");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_CreateBackpack, "createbackpack");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_NthBackpackBin, "nthbackpackbin");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_NthBackpackValue, "nthbackpackvalue");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_NumBackpackItems, "numbackpackitems");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetAutoSwitch, "getautoswitch");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetAutoSwitch, "setautoswitch");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetAutoPickup, "getautopickup");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetAutoPickup, "setautopickup");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetAutoReload, "getautoreload");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetAutoReload, "setautoreload");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetRespawnMask, "getrespawnmask");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetRespawnMask, "setrespawnmask");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_ActivateBin, "activatebin");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_DeactivateBin, "deactivatebin");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SetBinWait, "setbinwait");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_GetNumPlayersInTeam, "getnumplayersinteam");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_AddScoreToTeamMembers, "addscoretoteammembers");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_SyncScores, "syncscores");

}
