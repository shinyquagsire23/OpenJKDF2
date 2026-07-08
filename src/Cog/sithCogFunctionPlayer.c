#include "sithCogFunctionPlayer.h"

#include "World/jkPlayer.h"
#include "Gameplay/sithPlayer.h"
#include "Dss/sithMulti.h"
#include "World/sithWeapon.h"
#include "World/sithActor.h"
#include "Gameplay/sithInventory.h"

void sithCogFunctionPlayer_SetInvActivated(sithCog *pCog)
{
    int bActivate = sithCogExec_PopInt(pCog);
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        if (bActivate)
            sithInventory_SetInventoryActivated(player, binIdx, 1);
        else
            sithInventory_SetInventoryActivated(player, binIdx, 0);
    }
}

void sithCogFunctionPlayer_SetInvAvailable(sithCog *pCog)
{
    int bAvailable = sithCogExec_PopInt(pCog);
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        if (bAvailable)
            sithInventory_SetInventoryAvailable(player, binIdx, 1);
        else
            sithInventory_SetInventoryAvailable(player, binIdx, 0);
    }
}

void sithCogFunctionPlayer_IsInvActivated(sithCog *pCog)
{
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        if (sithInventory_IsInventoryActivated(player, binIdx)) {
            sithCogExec_PushInt(pCog, 1);
        }
        else {
            sithCogExec_PushInt(pCog, 0);
        }
        return;
    }

    // Added: We need to push *something*??
    sithCogExec_PushInt(pCog, 0);
}

void sithCogFunctionPlayer_IsInvAvailable(sithCog *pCog)
{
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        if ( sithInventory_IsInventoryAvailable(player, binIdx) )
            sithCogExec_PushInt(pCog, 1);
        else
            sithCogExec_PushInt(pCog, 0);
        return;
    }

    // Added: We need to push *something*??
    sithCogExec_PushInt(pCog, 0);
}

void sithCogFunctionPlayer_SetGoalFlags(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    int binIdx = sithCogExec_PopInt(pCog) + SITHBIN_GOAL00;
    SithThing* player = sithCogExec_PopThing(pCog);
    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        cog_flex_t amt = (cog_flex_t)((int)sithInventory_GetInventory(player, binIdx) | flags); // FLEXTODO
        sithInventory_SetInventory(player, binIdx, amt);
    }
}

void sithCogFunctionPlayer_ClearGoalFlags(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    int binIdx = sithCogExec_PopInt(pCog) + SITHBIN_GOAL00;
    SithThing* player = sithCogExec_PopThing(pCog);
    if (player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS)
    {
        cog_flex_t amt = (cog_flex_t)((int)sithInventory_GetInventory(player, binIdx) & ~flags); // FLEXTODO
        sithInventory_SetInventory(player, binIdx, amt);
    }
}

void sithCogFunctionPlayer_GetNumPlayers(sithCog *pCog)
{
    int numPlayers = 0;

    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        if (jkPlayer_playerInfos[i].flags & 1)
            ++numPlayers;
    }

    sithCogExec_PushInt(pCog, numPlayers);
}

void sithCogFunctionPlayer_GetMaxPlayers(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, jkPlayer_maxPlayers);
}

void sithCogFunctionPlayer_GetAbsoluteMaxPlayers(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, 32);
}

void sithCogFunctionPlayer_GetLocalPlayerThing(sithCog *pCog)
{
    if (sithPlayer_g_pLocalPlayerThing)
        sithCogExec_PushInt(pCog, sithPlayer_g_pLocalPlayerThing->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionPlayer_GetPlayerThing(sithCog *pCog)
{
    uint32_t idx = sithCogExec_PopInt(pCog);
    if (idx < jkPlayer_maxPlayers)
        sithCogExec_PushInt(pCog, jkPlayer_playerInfos[idx].pLocalPlayer->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionPlayer_GetPlayerNum(sithCog *pCog)
{
    int playerIdx;

    SithThing* player = sithCogExec_PopThing(pCog);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerIdx = sithPlayer_GetThingPlayerNum(player), playerIdx != -1))
        sithCogExec_PushInt(pCog, playerIdx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionPlayer_GetPlayerTeam(sithCog *pCog)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(pCog);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.pPlayer) != 0 ) {
        sithCogExec_PushInt(pCog, playerInfo->teamNum);
    }
    else {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionPlayer_SetPlayerTeam(sithCog *pCog)
{
    int teamNum = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);
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

void sithCogFunctionPlayer_GetPlayerScore(sithCog *pCog)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(pCog);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.pPlayer) != 0 ) {
        sithCogExec_PushInt(pCog, playerInfo->score);
    }
    else {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionPlayer_SetPlayerScore(sithCog *pCog)
{
    int score = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);
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

void sithCogFunctionPlayer_GetPlayerKills(sithCog *pCog)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(pCog);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.pPlayer) != 0 ) {
        sithCogExec_PushInt(pCog, playerInfo->numKills);
    }
    else {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionPlayer_SetPlayerKills(sithCog *pCog)
{
    int numKills = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);
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

void sithCogFunctionPlayer_GetPlayerKilled(sithCog *pCog)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(pCog);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.pPlayer) != 0) {
        sithCogExec_PushInt(pCog, playerInfo->numKilled);
    }
    else {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionPlayer_SetPlayerKilled(sithCog *pCog)
{
    int numKilled = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);
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

void sithCogFunctionPlayer_GetPlayerSuicides(sithCog *pCog)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(pCog);
    if (player 
        && player->type == SITH_THING_PLAYER 
        && (playerInfo = player->actorParams.pPlayer) != 0) {
        sithCogExec_PushInt(pCog, playerInfo->numSuicides);
    }
    else {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionPlayer_SetPlayerSuicides(sithCog *pCog)
{
    int numSuicides = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);
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

void sithCogFunctionPlayer_PickupBackpack(sithCog *pCog)
{
    SithThing* pBackpack = sithCogExec_PopThing(pCog);
    SithThing* pPlayer = sithCogExec_PopThing(pCog);

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

void sithCogFunctionPlayer_NthBackpackBin(sithCog *pCog)
{
    int ret;

    int n = sithCogExec_PopInt(pCog);
    SithThing* thing = sithCogExec_PopThing(pCog);
    if (thing
        && thing->type == SITH_THING_ITEM
        && (thing->itemParams.flags & SITH_ITEM_BACKPACK))
    {
        ret = sithInventory_GetBackpackItemID(thing, n);
        sithCogExec_PushInt(pCog, ret);
    }
}

void sithCogFunctionPlayer_NthBackpackValue(sithCog *pCog)
{
    int ret;

    int n = sithCogExec_PopInt(pCog);
    SithThing* thing = sithCogExec_PopThing(pCog);
    if (thing
        && thing->type == SITH_THING_ITEM
        && (thing->itemParams.flags & SITH_ITEM_BACKPACK))
    {
        ret = sithInventory_GetBackpackItemValue(thing, n);
        sithCogExec_PushInt(pCog, ret);
    }
}

void sithCogFunctionPlayer_GetNumBackbackItems(sithCog *pCog)
{
    int ret;

    SithThing* thing = sithCogExec_PopThing(pCog);
    if (thing
        && thing->type == SITH_THING_ITEM
        && (thing->itemParams.flags & SITH_ITEM_BACKPACK))
    {
        ret = sithInventory_GetNumBackpackItems(thing);
        sithCogExec_PushInt(pCog, ret);
    }
}

void sithCogFunctionPlayer_CreateBackpack(sithCog *pCog)
{
    SithThing* player = sithCogExec_PopThing(pCog);

    if (player
        && player->type == SITH_THING_PLAYER
        && player->actorParams.pPlayer)
    {
        SithThing* backpack = sithInventory_CreateBackpack(player);
        if ( backpack )
            sithCogExec_PushInt(pCog, backpack->idx);
        else
            sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionPlayer_GetAutoSwitch(sithCog *pCog)
{
    if (sithNet_isMulti) {
        sithCogExec_PushInt(pCog, sithWeapon_bMultiplayerAutoSwitch);
    }
    else {
        sithCogExec_PushInt(pCog, sithWeapon_bAutoSwitch);
    }
}

void sithCogFunctionPlayer_SetAutoSwitch(sithCog *pCog)
{
    int bVal = sithCogExec_PopInt(pCog);
    if (sithNet_isMulti) {
        sithWeapon_bMultiplayerAutoSwitch = bVal;
    }
    else {
        sithWeapon_bAutoSwitch = bVal;
    }
}

void sithCogFunctionPlayer_GetAutoPickup(sithCog *pCog)
{
    if (sithNet_isMulti) {
        sithCogExec_PushInt(pCog, sithWeapon_bMultiAutoPickup);
    }
    else {
        sithCogExec_PushInt(pCog, sithWeapon_bAutoPickup);
    }
}

void sithCogFunctionPlayer_SetAutoPickup(sithCog *pCog)
{
    int bVal = sithCogExec_PopInt(pCog);
    if (sithNet_isMulti) {
        sithWeapon_bMultiplayerAutoSwitch = bVal;
    }
    else {
        sithWeapon_bAutoSwitch = bVal;
    }
}

void sithCogFunctionPlayer_GetAutoReload(sithCog *pCog)
{
    if (sithNet_isMulti) {
        sithCogExec_PushInt(pCog, sithWeapon_bMultiAutoReload);
    }
    else {
        sithCogExec_PushInt(pCog, sithWeapon_bAutoReload);
    }
}

void sithCogFunctionPlayer_SetAutoReload(sithCog *pCog)
{
    int bVal = sithCogExec_PopInt(pCog);
    if (sithNet_isMulti) {
        sithWeapon_bMultiAutoPickup = bVal;
    }
    else {
        sithWeapon_bAutoPickup = bVal;
    }
}

void sithCogFunctionPlayer_GetRespawnMask(sithCog *pCog)
{
    SithPlayer *playerInfo;

    SithThing* player = sithCogExec_PopThing(pCog);
    if (player
        && player->type == SITH_THING_PLAYER
        && (playerInfo = player->actorParams.pPlayer)) {
        sithCogExec_PushInt(pCog, playerInfo->respawnMask);
    }
    else {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionPlayer_SetRespawnMask(sithCog *pCog)
{
    int mask = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (player
        && player->type == SITH_THING_PLAYER)
    {
        SithPlayer* playerInfo = player->actorParams.pPlayer;
        if (playerInfo) {
            playerInfo->respawnMask = mask;
        }
    }
}

void sithCogFunctionPlayer_ActivateBin(sithCog *pCog)
{
    int binIdx = sithCogExec_PopInt(pCog);
    cog_flex_t delay = sithCogExec_PopFlex(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (player
        && player->type == SITH_THING_PLAYER
        && delay >= 0.0 )
    {
        if (player->actorParams.pPlayer) {
            sithInventory_ActivateBin(player, pCog, delay, binIdx);
        }
    }
}

void sithCogFunctionPlayer_DeactivateBin(sithCog *pCog)
{
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (player
        && player->type == SITH_THING_PLAYER
        && player->actorParams.pPlayer)
    {
        cog_flex_t ret = sithInventory_DeactivateBin(player, pCog, binIdx);
        sithCogExec_PushFlex(pCog, ret);
    }
    else
    {
        sithCogExec_PushFlex(pCog, -1.0);
    }
}

void sithCogFunctionPlayer_GetNumPlayersInTeam(sithCog *pCog)
{
    int numPlayers = 0;
    int teamNum = sithCogExec_PopInt(pCog);
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        if ((jkPlayer_playerInfos[i].flags & 1) && jkPlayer_playerInfos[i].teamNum == teamNum )
            ++numPlayers;
    }
    sithCogExec_PushInt(pCog, numPlayers);
}

void sithCogFunctionPlayer_AddScoreToTeamMembers(sithCog *pCog)
{
    int scoreAdd = sithCogExec_PopInt(pCog);
    int teamNum = sithCogExec_PopInt(pCog);
    
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        if ((jkPlayer_playerInfos[i].flags & 1) && jkPlayer_playerInfos[i].teamNum == teamNum )
            jkPlayer_playerInfos[i].score += scoreAdd;
    }
}

void sithCogFunctionPlayer_SetBinWait(sithCog *pCog)
{
    cog_flex_t wait = sithCogExec_PopFlex(pCog);
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (player
        && player->type == SITH_THING_PLAYER
        && wait >= -1.0) {
        sithInventory_SetBinWait(player, binIdx, wait);
    }
}

void sithCogFunctionPlayer_SyncScores(sithCog *pCog)
{
    if (sithNet_isMulti) {
        sithMulti_SyncScores();
    }
}

// MOTS added
void sithCogFunctionPlayer_KillPlayerQuietly(sithCog *pCog)
{
    sithActor_KillActor(sithPlayer_g_pLocalPlayerThing, NULL, 12345678); // Magic number special case
    return;
}



void sithCogFunctionPlayer_Startup(SithCogSymbolTable* pCog)
{
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetInvActivated, "setinvactivated");

    // DW added: g_debugModeFlags & DEBUGFLAG_100 check
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetInvAvailable, "setinvavailable");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_IsInvActivated, "isinvactivated");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_IsInvAvailable, "isinvavailable");

    // Start DW removed
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetGoalFlags, "setgoalflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_ClearGoalFlags, "cleargoalflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetNumPlayers, "getnumplayers");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetMaxPlayers, "getmaxplayers");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetAbsoluteMaxPlayers, "getabsolutemaxplayers");
    // End DW removed

    // Start DW removed
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetLocalPlayerThing, "getlocalplayerthing");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetPlayerThing, "getplayerthing");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetPlayerNum, "getplayernum");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetPlayerTeam, "getplayerteam");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetPlayerTeam, "setplayerteam");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetPlayerScore, "getplayerscore");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetPlayerScore, "setplayerscore");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetPlayerKills, "getplayerkills");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetPlayerKills, "setplayerkills");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetPlayerKilled, "getplayerkilled");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetPlayerKilled, "setplayerkilled");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetPlayerSuicides, "getplayersuicides");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetPlayerSuicides, "setplayersuicides");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_PickupBackpack, "pickupbackpack");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_CreateBackpack, "createbackpack");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_NthBackpackBin, "nthbackpackbin");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_NthBackpackValue, "nthbackpackvalue");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetNumBackbackItems, "numbackpackitems");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetAutoSwitch, "getautoswitch");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetAutoSwitch, "setautoswitch");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetAutoPickup, "getautopickup");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetAutoPickup, "setautopickup");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetAutoReload, "getautoreload");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetAutoReload, "setautoreload");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetRespawnMask, "getrespawnmask");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetRespawnMask, "setrespawnmask");
    // End DW removed

    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_ActivateBin, "activatebin");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_DeactivateBin, "deactivatebin");

    // Start DW removed
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SetBinWait, "setbinwait");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_GetNumPlayersInTeam, "getnumplayersinteam");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_AddScoreToTeamMembers, "addscoretoteammembers");
    sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_SyncScores, "syncscores");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionPlayer_KillPlayerQuietly, "killplayerquietly");
    }
    // End DW removed
}
