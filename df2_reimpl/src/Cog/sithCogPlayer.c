#include "sithCogPlayer.h"

#include "World/jkPlayer.h"
#include "World/sithPlayer.h"
#include "Engine/sithMulti.h"
#include "Engine/sithNet.h"

static void (*sithCogPlayer_SetPlayerKills)(sithCog* ctx) = (void*)0x004E1010;
static void (*sithCogPlayer_GetPlayerKilled)(sithCog* ctx) = (void*)0x004E1070;
static void (*sithCogPlayer_SetPlayerKilled)(sithCog* ctx) = (void*)0x004E10C0;
static void (*sithCogPlayer_GetPlayerSuicides)(sithCog* ctx) = (void*)0x004E1120;
static void (*sithCogPlayer_SetPlayerSuicides)(sithCog* ctx) = (void*)0x004E1170;
static void (*sithCogPlayer_PickupBackpack)(sithCog* ctx) = (void*)0x004E11C0;
static void (*sithCogPlayer_NthBackpackBin)(sithCog* ctx) = (void*)0x004E1210;
static void (*sithCogPlayer_NthBackpackValue)(sithCog* ctx) = (void*)0x004E1260;
static void (*sithCogPlayer_NumBackpackItems)(sithCog* ctx) = (void*)0x004E12B0;
static void (*sithCogPlayer_CreateBackpack)(sithCog* ctx) = (void*)0x004E12F0;
static void (*sithCogPlayer_GetAutoSwitch)(sithCog* ctx) = (void*)0x004E1340;
static void (*sithCogPlayer_SetAutoSwitch)(sithCog* ctx) = (void*)0x004E1380;
static void (*sithCogPlayer_GetAutoPickup)(sithCog* ctx) = (void*)0x004E13B0;
static void (*sithCogPlayer_SetAutoPickup)(sithCog* ctx) = (void*)0x004E13F0;
static void (*sithCogPlayer_GetAutoReload)(sithCog* ctx) = (void*)0x004E1420;
static void (*sithCogPlayer_SetAutoReload)(sithCog* ctx) = (void*)0x004E1460;
static void (*sithCogPlayer_GetRespawnMask)(sithCog* ctx) = (void*)0x004E1490;
static void (*sithCogPlayer_SetRespawnMask)(sithCog* ctx) = (void*)0x004E14E0;
static void (*sithCogPlayer_ActivateBin)(sithCog* ctx) = (void*)0x004E1520;
static void (*sithCogPlayer_DeactivateBin)(sithCog* ctx) = (void*)0x004E1590;
static void (*sithCogPlayer_GetNumPlayersInTeam)(sithCog* ctx) = (void*)0x004E15F0;
static void (*sithCogPlayer_AddScoreToTeamMembers)(sithCog* ctx) = (void*)0x004E1640;
static void (*sithCogPlayer_SetBinWait)(sithCog* ctx) = (void*)0x004E1690;
static void (*sithCogPlayer_SyncScores)(sithCog* ctx) = (void*)0x004E16F0;

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
    if ((!net_isMulti || net_isServer)
        && player
        && player->thingType == THINGTYPE_PLAYER)
    {
        sithPlayerInfo* playerInfo = player->actorParams.playerinfo;
        if ( playerInfo )
        {
            playerInfo->teamNum = teamNum;
            if ( net_isMulti )
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
    if ((!net_isMulti || net_isServer)
        && player
        && player->thingType == THINGTYPE_PLAYER)
    {
        sithPlayerInfo* playerInfo = player->actorParams.playerinfo;
        if ( playerInfo )
        {
            playerInfo->score = score;
            if ( net_isMulti )
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
