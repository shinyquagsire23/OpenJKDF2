#include "sithCogFunctionPlayer.h"

#include "World/jkPlayer.h"
#include "Gameplay/sithPlayer.h"
#include "Dss/sithMulti.h"
#include "World/sithWeapon.h"
#include "World/sithActor.h"
#include "Gameplay/sithInventory.h"

void sithCogFunctionPlayer_SetInvActivated(sithCog *ctx)
{
    int bActivate = sithCogExec_PopInt(ctx);
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        if (bActivate)
            sithInventory_SetInventoryActivated(player, binIdx, 1);
        else
            sithInventory_SetInventoryActivated(player, binIdx, 0);
    }
}

void sithCogFunctionPlayer_SetInvAvailable(sithCog *ctx)
{
    int bAvailable = sithCogExec_PopInt(ctx);
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        if (bAvailable)
            sithInventory_SetInventoryAvailable(player, binIdx, 1);
        else
            sithInventory_SetInventoryAvailable(player, binIdx, 0);
    }
}

void sithCogFunctionPlayer_IsInvActivated(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        if (sithInventory_IsInventoryActivated(player, binIdx)) {
            sithCogExec_PushInt(ctx, 1);
        }
        else {
            sithCogExec_PushInt(ctx, 0);
        }
        return;
    }

    // Added: We need to push *something*??
    sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionPlayer_IsInvAvailable(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        if ( sithInventory_IsInventoryAvailable(player, binIdx) )
            sithCogExec_PushInt(ctx, 1);
        else
            sithCogExec_PushInt(ctx, 0);
        return;
    }

    // Added: We need to push *something*??
    sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionPlayer_SetGoalFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    int binIdx = sithCogExec_PopInt(ctx) + SITHBIN_GOAL00;
    SithThing* player = sithCogExec_PopThing(ctx);
    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        cog_flex_t amt = (cog_flex_t)((int)sithInventory_GetInventory(player, binIdx) | flags); // FLEXTODO
        sithInventory_SetInventory(player, binIdx, amt);
    }
}

void sithCogFunctionPlayer_ClearGoalFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    int binIdx = sithCogExec_PopInt(ctx) + SITHBIN_GOAL00;
    SithThing* player = sithCogExec_PopThing(ctx);
    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        cog_flex_t amt = (cog_flex_t)((int)sithInventory_GetInventory(player, binIdx) & ~flags); // FLEXTODO
        sithInventory_SetInventory(player, binIdx, amt);
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

    sithCogExec_PushInt(ctx, numPlayers);
}

void sithCogFunctionPlayer_GetMaxPlayers(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, jkPlayer_maxPlayers);
}

void sithCogFunctionPlayer_GetAbsoluteMaxPlayers(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, 32);
}

void sithCogFunctionPlayer_GetLocalPlayerThing(sithCog *ctx)
{
    if (sithPlayer_g_pLocalPlayerThing)
        sithCogExec_PushInt(ctx, sithPlayer_g_pLocalPlayerThing->idx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_GetPlayerThing(sithCog *ctx)
{
    uint32_t idx = sithCogExec_PopInt(ctx);
    if (idx < jkPlayer_maxPlayers)
        sithCogExec_PushInt(ctx, jkPlayer_playerInfos[idx].pLocalPlayer->idx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_GetPlayerNum(sithCog *ctx)
{
    int playerIdx;

    SithThing* player = sithCogExec_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerIdx = sithPlayer_GetThingPlayerNum(player), playerIdx != -1))
        sithCogExec_PushInt(ctx, playerIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionPlayer_GetPlayerTeam(sithCog *ctx)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.pPlayer) != 0 ) {
        sithCogExec_PushInt(ctx, playerInfo->teamNum);
    }
    else {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionPlayer_SetPlayerTeam(sithCog *ctx)
{
    int teamNum = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->type == SITH_THING_PLAYER)
    {
        SithPlayer* playerInfo = player->actorParams.pPlayer;
        if (playerInfo)
        {
            playerInfo->teamNum = teamNum;
            if ( sithNet_isMulti )
                sithMulti_SyncScores();
        }
    }
}

void sithCogFunctionPlayer_GetPlayerScore(sithCog *ctx)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.pPlayer) != 0 ) {
        sithCogExec_PushInt(ctx, playerInfo->score);
    }
    else {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionPlayer_SetPlayerScore(sithCog *ctx)
{
    int score = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->type == SITH_THING_PLAYER)
    {
        SithPlayer* playerInfo = player->actorParams.pPlayer;
        if (playerInfo)
        {
            playerInfo->score = score;
            if (sithNet_isMulti) {
                sithMulti_SyncScores();
            }
        }
    }
}

void sithCogFunctionPlayer_GetPlayerKills(sithCog *ctx)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.pPlayer) != 0 ) {
        sithCogExec_PushInt(ctx, playerInfo->numKills);
    }
    else {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionPlayer_SetPlayerKills(sithCog *ctx)
{
    int numKills = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->type == SITH_THING_PLAYER)
    {
        SithPlayer* playerInfo = player->actorParams.pPlayer;
        if ( playerInfo )
        {
            playerInfo->numKills = numKills;
            if (sithNet_isMulti) {
                sithMulti_SyncScores();
            }
        }
    }
}

void sithCogFunctionPlayer_GetPlayerKilled(sithCog *ctx)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.pPlayer) != 0) {
        sithCogExec_PushInt(ctx, playerInfo->numKilled);
    }
    else {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionPlayer_SetPlayerKilled(sithCog *ctx)
{
    int numKilled = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->type == SITH_THING_PLAYER)
    {
        SithPlayer* playerInfo = player->actorParams.pPlayer;
        if (playerInfo)
        {
            playerInfo->numKilled = numKilled;
            if (sithNet_isMulti) {
                sithMulti_SyncScores();
            }
        }
    }
}

void sithCogFunctionPlayer_GetPlayerSuicides(sithCog *ctx)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(ctx);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.pPlayer) != 0) {
        sithCogExec_PushInt(ctx, playerInfo->numSuicides);
    }
    else {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionPlayer_SetPlayerSuicides(sithCog *ctx)
{
    int numSuicides = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);
    if ((!sithNet_isMulti || sithNet_isServer)
        && player
        && player->type == SITH_THING_PLAYER)
    {
        SithPlayer* playerInfo = player->actorParams.pPlayer;
        if (playerInfo)
        {
            playerInfo->numSuicides = numSuicides;
            if (sithNet_isMulti) {
                sithMulti_SyncScores();
            }
        }
    }
}

void sithCogFunctionPlayer_PickupBackpack(sithCog *ctx)
{
    SithThing* pBackpack = sithCogExec_PopThing(ctx);
    SithThing* pPlayer = sithCogExec_PopThing(ctx);

    if ( pPlayer
      && pPlayer->type == SITH_THING_PLAYER
      && pPlayer->actorParams.pPlayer
      && pBackpack
      && pBackpack->type == SITH_THING_ITEM
      && pBackpack->itemParams.flags & SITH_ITEM_BACKPACK)
    {
        sithInventory_PickupBackpack(pPlayer, pBackpack);
    }
}

void sithCogFunctionPlayer_NthBackpackBin(sithCog *ctx)
{
    int ret;

    int n = sithCogExec_PopInt(ctx);
    SithThing* thing = sithCogExec_PopThing(ctx);
    if (thing
        && thing->type == SITH_THING_ITEM
        && (thing->itemParams.flags & SITH_ITEM_BACKPACK))
    {
        ret = sithInventory_GetBackpackItemID(thing, n);
        sithCogExec_PushInt(ctx, ret);
    }
}

void sithCogFunctionPlayer_NthBackpackValue(sithCog *ctx)
{
    int ret;

    int n = sithCogExec_PopInt(ctx);
    SithThing* thing = sithCogExec_PopThing(ctx);
    if (thing
        && thing->type == SITH_THING_ITEM
        && (thing->itemParams.flags & SITH_ITEM_BACKPACK))
    {
        ret = sithInventory_GetBackpackItemValue(thing, n);
        sithCogExec_PushInt(ctx, ret);
    }
}

void sithCogFunctionPlayer_GetNumBackbackItems(sithCog *ctx)
{
    int ret;

    SithThing* thing = sithCogExec_PopThing(ctx);
    if (thing
        && thing->type == SITH_THING_ITEM
        && (thing->itemParams.flags & SITH_ITEM_BACKPACK))
    {
        ret = sithInventory_GetNumBackpackItems(thing);
        sithCogExec_PushInt(ctx, ret);
    }
}

void sithCogFunctionPlayer_CreateBackpack(sithCog *ctx)
{
    SithThing* player = sithCogExec_PopThing(ctx);

    if (player
        && player->type == SITH_THING_PLAYER
        && player->actorParams.pPlayer)
    {
        SithThing* backpack = sithInventory_CreateBackpack(player);
        if ( backpack )
            sithCogExec_PushInt(ctx, backpack->idx);
        else
            sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionPlayer_GetAutoSwitch(sithCog *ctx)
{
    if (sithNet_isMulti) {
        sithCogExec_PushInt(ctx, sithWeapon_bMultiplayerAutoSwitch);
    }
    else {
        sithCogExec_PushInt(ctx, sithWeapon_bAutoSwitch);
    }
}

void sithCogFunctionPlayer_SetAutoSwitch(sithCog *ctx)
{
    int bVal = sithCogExec_PopInt(ctx);
    if (sithNet_isMulti) {
        sithWeapon_bMultiplayerAutoSwitch = bVal;
    }
    else {
        sithWeapon_bAutoSwitch = bVal;
    }
}

void sithCogFunctionPlayer_GetAutoPickup(sithCog *ctx)
{
    if (sithNet_isMulti) {
        sithCogExec_PushInt(ctx, sithWeapon_bMultiAutoPickup);
    }
    else {
        sithCogExec_PushInt(ctx, sithWeapon_bAutoPickup);
    }
}

void sithCogFunctionPlayer_SetAutoPickup(sithCog *ctx)
{
    int bVal = sithCogExec_PopInt(ctx);
    if (sithNet_isMulti) {
        sithWeapon_bMultiplayerAutoSwitch = bVal;
    }
    else {
        sithWeapon_bAutoSwitch = bVal;
    }
}

void sithCogFunctionPlayer_GetAutoReload(sithCog *ctx)
{
    if (sithNet_isMulti) {
        sithCogExec_PushInt(ctx, sithWeapon_bMultiAutoReload);
    }
    else {
        sithCogExec_PushInt(ctx, sithWeapon_bAutoReload);
    }
}

void sithCogFunctionPlayer_SetAutoReload(sithCog *ctx)
{
    int bVal = sithCogExec_PopInt(ctx);
    if (sithNet_isMulti) {
        sithWeapon_bMultiAutoPickup = bVal;
    }
    else {
        sithWeapon_bAutoPickup = bVal;
    }
}

void sithCogFunctionPlayer_GetRespawnMask(sithCog *ctx)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(ctx);
    if (player
        && player->type == SITH_THING_PLAYER
        && (playerInfo = player->actorParams.pPlayer)) {
        sithCogExec_PushInt(ctx, playerInfo->respawnMask);
    }
    else {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionPlayer_SetRespawnMask(sithCog *ctx)
{
    int mask = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (player
        && player->type == SITH_THING_PLAYER)
    {
        SithPlayer* playerInfo = player->actorParams.pPlayer;
        if (playerInfo) {
            playerInfo->respawnMask = mask;
        }
    }
}

void sithCogFunctionPlayer_ActivateBin(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    cog_flex_t delay = sithCogExec_PopFlex(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (player
        && player->type == SITH_THING_PLAYER
        && delay >= 0.0 )
    {
        if (player->actorParams.pPlayer) {
            sithInventory_ActivateBin(player, ctx, delay, binIdx);
        }
    }
}

void sithCogFunctionPlayer_DeactivateBin(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (player
        && player->type == SITH_THING_PLAYER
        && player->actorParams.pPlayer)
    {
        cog_flex_t ret = sithInventory_DeactivateBin(player, ctx, binIdx);
        sithCogExec_PushFlex(ctx, ret);
    }
    else
    {
        sithCogExec_PushFlex(ctx, -1.0);
    }
}

void sithCogFunctionPlayer_GetNumPlayersInTeam(sithCog *ctx)
{
    int numPlayers = 0;
    int teamNum = sithCogExec_PopInt(ctx);
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        if ((jkPlayer_playerInfos[i].flags & 1) && jkPlayer_playerInfos[i].teamNum == teamNum )
            ++numPlayers;
    }
    sithCogExec_PushInt(ctx, numPlayers);
}

void sithCogFunctionPlayer_AddScoreToTeamMembers(sithCog *ctx)
{
    int scoreAdd = sithCogExec_PopInt(ctx);
    int teamNum = sithCogExec_PopInt(ctx);
    
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        if ((jkPlayer_playerInfos[i].flags & 1) && jkPlayer_playerInfos[i].teamNum == teamNum )
            jkPlayer_playerInfos[i].score += scoreAdd;
    }
}

void sithCogFunctionPlayer_SetBinWait(sithCog *ctx)
{
    cog_flex_t wait = sithCogExec_PopFlex(ctx);
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (player
        && player->type == SITH_THING_PLAYER
        && wait >= -1.0) {
        sithInventory_SetBinWait(player, binIdx, wait);
    }
}

void sithCogFunctionPlayer_SyncScores(sithCog *ctx)
{
    if (sithNet_isMulti) {
        sithMulti_SyncScores();
    }
}

// MOTS added
void sithCogFunctionPlayer_KillPlayerQuietly(sithCog *ctx)
{
    sithActor_KillActor(sithPlayer_g_pLocalPlayerThing, NULL, 12345678); // Magic number special case
    return;
}



void sithCogFunctionPlayer_Startup(SithCogSymbolTable* ctx)
{
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetInvActivated, "setinvactivated");

    // DW added: g_debugModeFlags & DEBUGFLAG_100 check
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetInvAvailable, "setinvavailable");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_IsInvActivated, "isinvactivated");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_IsInvAvailable, "isinvavailable");

    // Start DW removed
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetGoalFlags, "setgoalflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_ClearGoalFlags, "cleargoalflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetNumPlayers, "getnumplayers");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetMaxPlayers, "getmaxplayers");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetAbsoluteMaxPlayers, "getabsolutemaxplayers");
    // End DW removed

    // Start DW removed
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetLocalPlayerThing, "getlocalplayerthing");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetPlayerThing, "getplayerthing");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetPlayerNum, "getplayernum");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetPlayerTeam, "getplayerteam");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetPlayerTeam, "setplayerteam");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetPlayerScore, "getplayerscore");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetPlayerScore, "setplayerscore");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetPlayerKills, "getplayerkills");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetPlayerKills, "setplayerkills");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetPlayerKilled, "getplayerkilled");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetPlayerKilled, "setplayerkilled");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetPlayerSuicides, "getplayersuicides");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetPlayerSuicides, "setplayersuicides");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_PickupBackpack, "pickupbackpack");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_CreateBackpack, "createbackpack");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_NthBackpackBin, "nthbackpackbin");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_NthBackpackValue, "nthbackpackvalue");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetNumBackbackItems, "numbackpackitems");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetAutoSwitch, "getautoswitch");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetAutoSwitch, "setautoswitch");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetAutoPickup, "getautopickup");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetAutoPickup, "setautopickup");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetAutoReload, "getautoreload");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetAutoReload, "setautoreload");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetRespawnMask, "getrespawnmask");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetRespawnMask, "setrespawnmask");
    // End DW removed

    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_ActivateBin, "activatebin");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_DeactivateBin, "deactivatebin");

    // Start DW removed
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SetBinWait, "setbinwait");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_GetNumPlayersInTeam, "getnumplayersinteam");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_AddScoreToTeamMembers, "addscoretoteammembers");
    sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_SyncScores, "syncscores");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_KillPlayerQuietly, "killplayerquietly");
    }
    // End DW removed
}
