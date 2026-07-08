#include "sithInventory.h"

#include "jk.h"
#include "Cog/sithCog.h"
#include "Gameplay/sithTime.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "World/sithSector.h"
#include "World/sithTemplate.h"
#include "Devices/sithControl.h"
#include "World/jkPlayer.h"
#include "Dss/sithDSSThing.h"
#include "Main/Main.h"
#include "General/stdString.h"
#include "Main/jkDev.h"

// MOTS added
static int sithInventory_008d60f8;
static int sithInventory_008d60fc;
static const int sithInventory_aMotsForcePowerBins[18] = {0, SITHBIN_F_JUMP, SITHBIN_F_SPEED, SITHBIN_F_SEEING, SITHBIN_F_PROJECT, SITHBIN_F_PUSH, SITHBIN_F_PULL, SITHBIN_F_GRIP, SITHBIN_F_FARSIGHT, SITHBIN_F_SABERTHROW, SITHBIN_F_HEALING, SITHBIN_F_PERSUASION, SITHBIN_F_BLINDING, SITHBIN_F_CHAINLIGHT, SITHBIN_F_ABSORB, SITHBIN_F_PROTECTION, SITHBIN_F_DESTRUCTION, SITHBIN_F_DEADLYSIGHT};

void sithInventory_RegisterType(int binIdx, sithCog *cog, char *name, flex_t min, flex_t max, int flags)
{
    SithInventoryType* desc = &sithInventory_g_aTypes[binIdx];
    
    stdString_SafeStrCopy(desc->fpath, name, sizeof(desc->fpath));

    desc->cog = cog;
    desc->min = min;
    desc->max = max;
    desc->flags = flags | 1;
}

int sithInventory_FindNextTypeID(SithThing *pThing, int startSearchId, int flags)
{
    if (flags == 8 && Main_bMotsCompat)
    {
        SithPlayer *puVar1;
        SithPlayer *puVar2;
        SithPlayer *puVar3;
        SithPlayer *puVar4;
        SithPlayer *psVar3;
        int iVar4;
        int iVar2 = 0;
        const int* piVar1 = sithInventory_aMotsForcePowerBins + 1;
        do 
        {
            iVar4 = iVar2;
            if (*piVar1 == startSearchId) break;
            piVar1 = piVar1 + 1;
            iVar2 = iVar2 + 1;
            iVar4 = startSearchId;
        } 
        while (piVar1 < &sithInventory_aMotsForcePowerBins[18]);

        if (iVar2 == 0x11) {
            iVar4 = 0;
        }
        uint32_t uVar5 = iVar4 + 1;
        if (uVar5 < 0x11)
        {
            puVar1 = pThing->actorParams.pPlayer;
            piVar1 = sithInventory_aMotsForcePowerBins + iVar4 + 2;
            do 
            {
                if (((puVar1 != (SithPlayer *)0xffffff78) &&
                    ((sithInventory_g_aTypes[*piVar1].flags & 1) != 0)) &&
                    ((puVar1->aItems[*piVar1].state & 4) != 0)) {
                    return sithInventory_aMotsForcePowerBins[uVar5 + 1];
                }
                piVar1 = piVar1 + 1;
                uVar5 = uVar5 + 1;
            }
            while (piVar1 < &sithInventory_aMotsForcePowerBins[18]);
        }

        uVar5 = 0;
        if (0 < iVar4)
        {
            puVar2 = pThing->actorParams.pPlayer;
            piVar1 = sithInventory_aMotsForcePowerBins;
            do
            {
                piVar1 = piVar1 + 1;
                if (((puVar2 != (SithPlayer *)0xffffff78) &&
                    ((sithInventory_g_aTypes[*piVar1].flags & 1) != 0)) &&
                    ((puVar2->aItems[*piVar1].state & 4) != 0)) {
                    return sithInventory_aMotsForcePowerBins[uVar5 + 1];
                }
                uVar5 = uVar5 + 1;
            } while ((int)uVar5 < iVar4);
        }
        return -1;
    }
    else {
        if ( startSearchId + 1 < SITHBIN_NUMBINS )
        {
            for (int i = startSearchId + 1; i < SITHBIN_NUMBINS; i++)
            {
                SithInventoryType* desc =  &sithInventory_g_aTypes[i];

                if ((flags & desc->flags) && pThing->actorParams.pPlayer != (SithPlayer *)-136 && (desc->flags & SITHINVENTORY_TYPE_REGISTERED) && (pThing->actorParams.pPlayer->aItems[i].state & SITHINVENTORY_ITEM_AVAILABLE))
                    return i;
            }
        }
       
        if ( startSearchId <= 0 )
            return -1;

        for (int i = 0; i < startSearchId; i++)
        {
            SithInventoryType* desc =  &sithInventory_g_aTypes[i];

            if ((flags & desc->flags) && pThing->actorParams.pPlayer != (SithPlayer *)-136 && (desc->flags & SITHINVENTORY_TYPE_REGISTERED) && (pThing->actorParams.pPlayer->aItems[i].state & SITHINVENTORY_ITEM_AVAILABLE))
                return i;
        }

        return -1;
    }
}

int sithInventory_FindPreviousTypeID(SithThing *pThing, int startSearchId, int flags)
{
    if (flags == 8 && Main_bMotsCompat)
    {
        int iVar8 = 0;
        SithPlayer *puVar1;
        SithPlayer *puVar2;
        SithPlayer *puVar3;
        SithPlayer *puVar7;

        int iVar6 = 0;
        const int* piVar5 = sithInventory_aMotsForcePowerBins + 1;
        do 
        {
            iVar8 = iVar6;
            if (*piVar5 == startSearchId) break;
            piVar5 = piVar5 + 1;
            iVar6 = iVar6 + 1;
            iVar8 = startSearchId;
        } 
        while (piVar5 < &sithInventory_aMotsForcePowerBins[18]);

        if (iVar6 == 0x11) {
          iVar8 = 0;
        }

        iVar6 = iVar8 + -1;
        if (-1 < iVar6)
        {
            puVar1 = pThing->actorParams.pPlayer;
            piVar5 = sithInventory_aMotsForcePowerBins + iVar8;
            do 
            {
                if (((puVar1 != (SithPlayer *)0xffffff78) &&
                    ((sithInventory_g_aTypes[*piVar5].flags & 1) != 0)) &&
                    ((puVar1->aItems[*piVar5].state & 4) != 0)) {
                    return sithInventory_aMotsForcePowerBins[iVar6 + 1];
                }
                iVar6 = iVar6 + -1;
                piVar5 = piVar5 + -1;
            }
            while (-1 < iVar6);
        }

        iVar6 = 0x10;
        if (iVar8 < 0x10)
        {
            puVar2 = pThing->actorParams.pPlayer;
            piVar5 = sithInventory_aMotsForcePowerBins + 0x11;
            do 
            {
                if (((puVar2 != (SithPlayer *)0xffffff78) &&
                    ((sithInventory_g_aTypes[*piVar5].flags & 1) != 0)) &&
                    ((puVar2->aItems[*piVar5].state & 4) != 0)) {
                    return sithInventory_aMotsForcePowerBins[iVar6 + 1];
                }
                iVar6 = iVar6 + -1;
                piVar5 = piVar5 + -1;
            }
            while (iVar8 < iVar6);
        }
        return -1;
    }
    else {
        if ( startSearchId - 1 >= 0 )
        {
            for (int i = startSearchId - 1; i >= 0; --i)
            {
                SithInventoryType* desc = &sithInventory_g_aTypes[i];
                if (!(!(flags & desc->flags) || pThing->actorParams.pPlayer == (SithPlayer *)-136 || !(desc->flags & SITHINVENTORY_TYPE_REGISTERED) || !(pThing->actorParams.pPlayer->aItems[i].state & SITHINVENTORY_ITEM_AVAILABLE)))
                    return i;
            }
        }
        
        if ( startSearchId >= 199 )
            return -1;

        for (int i = 199; i > startSearchId; --i)
        {
            SithInventoryType* desc = &sithInventory_g_aTypes[i];
            if (!(!(flags & desc->flags) || pThing->actorParams.pPlayer == (SithPlayer *)-136 || !(desc->flags & SITHINVENTORY_TYPE_REGISTERED) || !(pThing->actorParams.pPlayer->aItems[i].state & SITHINVENTORY_ITEM_AVAILABLE)))
                return i;
        }

        return -1;
    }
}

int sithInventory_FindNextItemID(SithThing *pThing, signed int itemId)
{
    return sithInventory_FindNextTypeID(pThing, itemId, ITEMINFO_ITEM);
}

int sithInventory_FindPreviousItemID(SithThing *pThing, signed int itemId)
{
    return sithInventory_FindPreviousTypeID(pThing, itemId, ITEMINFO_ITEM);
}

void sithInventory_SelectItem(SithThing *pThing, int typeId)
{
    if ( typeId < 0 )
        return;

    if ( pThing->actorParams.pPlayer == (SithPlayer *)-136 || !(sithInventory_g_aTypes[typeId].flags & SITHINVENTORY_TYPE_REGISTERED) || !(pThing->actorParams.pPlayer->aItems[typeId].state & SITHINVENTORY_ITEM_AVAILABLE) )
        return;
        
    sithCog* curItemCog = sithInventory_g_aTypes[pThing->actorParams.pPlayer->curItemID].cog;
    if ( curItemCog )
    {
        sithCog_SendMessage(curItemCog, SITH_MESSAGE_DESELECTED, SENDERTYPE_SYSTEM, pThing->actorParams.pPlayer->curItemID, SENDERTYPE_THING, pThing->idx, 0);
        if ( sithInventory_g_bSendDeactivateMessage == 1 )
        {
            sithCog_SendMessage(
                sithInventory_g_aTypes[pThing->actorParams.pPlayer->curItemID].cog,
                SITH_MESSAGE_DEACTIVATED,
                SENDERTYPE_SYSTEM,
                pThing->actorParams.pPlayer->curItemID,
                SENDERTYPE_THING,
                pThing->idx,
                0);
            sithInventory_g_bSendDeactivateMessage = 0;
        }
    }

    sithCog* itemCog = sithInventory_g_aTypes[typeId].cog;
    if ( itemCog )
    {
        sithCog_SendMessage(itemCog, SITH_MESSAGE_SELECTED, SENDERTYPE_SYSTEM, typeId, SENDERTYPE_THING, pThing->idx, 0);
    }

    pThing->actorParams.pPlayer->curItemID = typeId;

    // For some reason items don't print out like force powers, ugh
#ifdef TARGET_RETRO_HOMEBREW
    jkDev_DebugLog(sithInventory_g_aTypes[typeId].fpath);
#endif
}

void sithInventory_SelectNextItem(SithThing *pThing)
{
    sithInventory_SelectItem(pThing, sithInventory_FindNextItemID(pThing, pThing->actorParams.pPlayer->curItemID));
}

void sithInventory_SelectPreviousItem(SithThing *pThing)
{
    sithInventory_SelectItem(pThing, sithInventory_FindPreviousItemID(pThing, pThing->actorParams.pPlayer->curItemID));
}

// MOTS added
int sithInventory_SelectWeaponPrior(int param_1)
{
    int iVar1;
    SithInventoryType *psVar2;
    
    if (((param_1 < SITHBIN_NUMBINS) && (-1 < param_1)) && ((sithInventory_g_aTypes[param_1].flags & ITEMINFO_WEAPON) != 0)) {
        iVar1 = 0;
        if (0 < param_1) {
            psVar2 = sithInventory_g_aTypes;
            do {
                if ((psVar2->flags & ITEMINFO_WEAPON) != 0) {
                    iVar1 = iVar1 + 1;
                }
                psVar2 = psVar2 + 1;
                param_1 = param_1 + -1;
            } while (param_1 != 0);
            return iVar1;
        }
    }
    else {
        iVar1 = -1;
    }
    return iVar1;
}

int sithInventory_SelectWeaponFollowing(int idx)
{
    int count = 0;
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        if ( sithInventory_g_aTypes[i].flags & ITEMINFO_WEAPON )
        {
            if ( count == idx ) {
                return i;
            }
            ++count;
        }
    }

    return -1;
}

SithInventoryType* sithInventory_GetType(int typeId)
{
    // Added: bounds
    if (typeId < 0)
        return &sithInventory_g_aTypes[0];
    if (typeId >= SITHBIN_NUMBINS)
        return &sithInventory_g_aTypes[0];

    return &sithInventory_g_aTypes[typeId];
}

int sithInventory_GetCurrentWeapon(SithThing *pThing)
{
    if (!pThing || !pThing->actorParams.pPlayer) return 0; // Added: Prevent nullptr deref

    return pThing->actorParams.pPlayer->curWeaponID;
}

void sithInventory_SetCurrentWeapon(SithThing *pThing, int weaponID)
{
    if (!pThing || !pThing->actorParams.pPlayer) return; // Added: Prevent nullptr deref

    pThing->actorParams.pPlayer->curWeaponID = weaponID;
}

int sithInventory_GetCurrentItem(SithThing *pThing)
{
    if (!pThing || !pThing->actorParams.pPlayer) return 0; // Added: Prevent nullptr deref

    return pThing->actorParams.pPlayer->curItemID;
}

void sithInventory_SetCurrentItem(SithThing *pThing, int typeId)
{
    if (!pThing || !pThing->actorParams.pPlayer) return; // Added: Prevent nullptr deref

    pThing->actorParams.pPlayer->curItemID = typeId;
}

int sithInventory_GetCurPower(SithThing *player)
{
    if (!player || !player->actorParams.pPlayer) return 0; // Added: Prevent nullptr deref

    return player->actorParams.pPlayer->curPower;
}

void sithInventory_SetCurPower(SithThing *player, int idx)
{
    if (!player || !player->actorParams.pPlayer) return; // Added: Prevent nullptr deref

    player->actorParams.pPlayer->curPower = idx;
}

int sithInventory_GetWeaponPrior(SithThing *thing, int binNum)
{
    return sithInventory_FindNextTypeID(thing, binNum, ITEMINFO_WEAPON);
}

int sithInventory_GetWeaponFollowing(SithThing *thing, int binNum)
{
    return sithInventory_FindPreviousTypeID(thing, binNum, ITEMINFO_WEAPON);
}

int sithInventory_GetPowerPrior(SithThing *thing, int binNum)
{
    return sithInventory_FindNextTypeID(thing, binNum, SITHINVENTORY_TYPE_AUTOAIM);
}

int sithInventory_GetPowerFollowing(SithThing *thing, int binNum)
{
    return sithInventory_FindPreviousTypeID(thing, binNum, SITHINVENTORY_TYPE_AUTOAIM);
}

void sithInventory_SelectPower(SithThing *player, int binNum)
{
    if ( binNum < 0 )
        return;

    if ( player->actorParams.pPlayer == (SithPlayer *)-136 || !(sithInventory_g_aTypes[binNum].flags & SITHINVENTORY_TYPE_REGISTERED) || !(player->actorParams.pPlayer->aItems[binNum].state & SITHINVENTORY_ITEM_AVAILABLE) )
        return;

    int curPower = player->actorParams.pPlayer->curPower;
    if ( curPower >= 0 )
    {
        if ( sithInventory_g_aTypes[curPower].cog )
        {
            sithCog_SendMessage(sithInventory_g_aTypes[curPower].cog, SITH_MESSAGE_DESELECTED, SENDERTYPE_SYSTEM, curPower, SENDERTYPE_THING, player->idx, 0);
            if ( sithInventory_bUnkPower == 1 )
            {
                sithCog_SendMessage(sithInventory_g_aTypes[curPower].cog, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_SYSTEM, curPower, SENDERTYPE_THING, player->idx, 0);
                sithInventory_bUnkPower = 0;
            }
        }
    }
    
    if ( sithInventory_g_aTypes[binNum].cog )
        sithCog_SendMessage(sithInventory_g_aTypes[binNum].cog, SITH_MESSAGE_SELECTED, SENDERTYPE_SYSTEM, binNum, SENDERTYPE_THING, player->idx, 0);
    player->actorParams.pPlayer->curPower = binNum;
}

void sithInventory_SelectPowerPrior(SithThing *player)
{
    int binNum = sithInventory_GetPowerPrior(player, player->actorParams.pPlayer->curPower);
    sithInventory_SelectPower(player, binNum);
}

void sithInventory_SelectPowerFollowing(SithThing *player)
{
    int binNum = sithInventory_GetPowerFollowing(player, player->actorParams.pPlayer->curPower);
    sithInventory_SelectPower(player, binNum);
}

int sithInventory_ActivateBin(SithThing *player, sithCog *cog, flex_t delay, int binNum)
{
    SithInventoryItem *info;

    if ( player->actorParams.pPlayer == (SithPlayer *)-136 || !(sithInventory_g_aTypes[binNum].flags & SITHINVENTORY_TYPE_REGISTERED) )
        return 0;

    info = &player->actorParams.pPlayer->aItems[binNum];
    info->activationDelaySecs = delay;
    info->activatedTimeSecs = sithTime_g_secGameTime;
    if ( delay <= 0.0 )
        info->binWait = -1.0;
    if (info->binWait != -1.0 && sithTime_g_secGameTime >= (flex_d_t)info->binWait )
    {
        sithCog_SendMessageEx(cog, SITH_MESSAGE_FIRE, SENDERTYPE_SYSTEM, binNum, SENDERTYPE_THING, player->idx, 0, 0.0, 0.0, 0.0, 0.0);
        info->binWait = sithTime_g_secGameTime + info->activationDelaySecs;
    }
    return 1;
}

flex_t sithInventory_DeactivateBin(SithThing *player, sithCog *unused, int binNum)
{
    SithInventoryItem *info;
    flex_t result;

    if ( player->actorParams.pPlayer == (SithPlayer *)-136 || !(sithInventory_g_aTypes[binNum].flags & SITHINVENTORY_TYPE_REGISTERED) )
        return 0.0;

    info = &player->actorParams.pPlayer->aItems[binNum];
    if ( info->activatedTimeSecs == -1.0 )
        result = 0.0;
    else
        result = sithTime_g_secGameTime - info->activatedTimeSecs;

    info->activationDelaySecs = -1.0;
    info->binWait = -1.0;
    info->activatedTimeSecs = -1.0;
    return result;
}

int sithInventory_BinSendActivate(SithThing *player, int binIdx)
{
    if ( sithTime_g_secGameTime < player->actorParams.pPlayer->aItems[binIdx].binWait )
        return 0;

    if ( binIdx < 0 )
        return 0;

    if ( player->actorParams.pPlayer == (SithPlayer *)-136 )
        return 0;

    if ( !(sithInventory_g_aTypes[binIdx].flags & SITHINVENTORY_TYPE_REGISTERED) )
        return 0;

    if ( !(player->actorParams.pPlayer->aItems[binIdx].state & SITHINVENTORY_ITEM_AVAILABLE) )
        return 0;

    if ( !sithInventory_g_aTypes[binIdx].cog )
        return 0;

    sithCog_SendMessage(sithInventory_g_aTypes[binIdx].cog, SITH_MESSAGE_ACTIVATE, SENDERTYPE_SYSTEM, binIdx, SENDERTYPE_THING, player->idx, 0);
    return 1;
}

void sithInventory_BinSendDeactivate(SithThing *player, int senderIndex)
{
    if ( senderIndex >= 0
      && player->actorParams.pPlayer != (SithPlayer *)-136
      && sithInventory_g_aTypes[senderIndex].flags & SITHINVENTORY_TYPE_REGISTERED
      && player->actorParams.pPlayer->aItems[senderIndex].state & SITHINVENTORY_ITEM_AVAILABLE )
    {
        if ( sithInventory_g_aTypes[senderIndex].cog )
            sithCog_SendMessage(sithInventory_g_aTypes[senderIndex].cog, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_0, senderIndex, SENDERTYPE_THING, player->idx, 0);
    }
}

flex_t sithInventory_ChangeInventory(SithThing *pThing, int typeId, flex_t amount)
{
    SithInventoryItem *info;

    if ( pThing->actorParams.pPlayer == (SithPlayer *)-136 || !(sithInventory_g_aTypes[typeId].flags & SITHINVENTORY_TYPE_REGISTERED) )
        return 0.0;

    info = &pThing->actorParams.pPlayer->aItems[typeId];
    return sithInventory_SetInventory(pThing, typeId, info->amount + amount);
}

flex_t sithInventory_GetInventory(SithThing *pThing, int typeId)
{
    if ( pThing->actorParams.pPlayer != (SithPlayer *)-136 && sithInventory_g_aTypes[typeId].flags & SITHINVENTORY_TYPE_REGISTERED )
        return pThing->actorParams.pPlayer->aItems[typeId].amount;
    else
        return 0.0;
}

flex_t sithInventory_SetInventory(SithThing *pThing, int typeId, flex_t amount)
{
    SithInventoryItem *info;

    if ( pThing->actorParams.pPlayer == (SithPlayer *)-136 || !(sithInventory_g_aTypes[typeId].flags & SITHINVENTORY_TYPE_REGISTERED) )
        return 0.0;

    info = &pThing->actorParams.pPlayer->aItems[typeId];
    
    flex_t origAmt = info->amount;
    info->amount = amount;
    if ( info->amount < sithInventory_g_aTypes[typeId].min )
    {
        info->amount = sithInventory_g_aTypes[typeId].min;
    }
    else if ( info->amount > sithInventory_g_aTypes[typeId].max )
    {
        info->amount = sithInventory_g_aTypes[typeId].max;
    }

    if ( info->amount != origAmt )
    {
        if ( sithInventory_g_aTypes[typeId].cog )
            sithCog_SendMessage(sithInventory_g_aTypes[typeId].cog, SITH_MESSAGE_CHANGED, SENDERTYPE_0, 0, SENDERTYPE_THING, pThing->idx, typeId);
        info->state |= SITHINVENTORY_ITEM_CHANGED;
    }
    return info->amount;
}

void sithInventory_SetInventoryActivated(SithThing *pThing, int typeId, int bActivated)
{
    if ( pThing->actorParams.pPlayer != (SithPlayer *)-136 && sithInventory_g_aTypes[typeId].flags & SITHINVENTORY_TYPE_REGISTERED)
    {
        if ( bActivated )
            pThing->actorParams.pPlayer->aItems[typeId].state |= SITHINVENTORY_ITEM_ACTIVATED;
        else
            pThing->actorParams.pPlayer->aItems[typeId].state &= ~SITHINVENTORY_ITEM_ACTIVATED;
    }
}

int sithInventory_IsInventoryActivated(SithThing *pThing, int typeId)
{
    if ( pThing->actorParams.pPlayer != (SithPlayer *)-136 && sithInventory_g_aTypes[typeId].flags & SITHINVENTORY_TYPE_REGISTERED)
    {
        return !!(pThing->actorParams.pPlayer->aItems[typeId].state & SITHINVENTORY_ITEM_ACTIVATED);
    }
    return 0;
}

void sithInventory_SetInventoryAvailable(SithThing *pThing, int typeId, int bAvailable)
{
    if ( pThing->actorParams.pPlayer != (SithPlayer *)-136 && sithInventory_g_aTypes[typeId].flags & SITHINVENTORY_TYPE_REGISTERED)
    {
        if ( bAvailable )
            pThing->actorParams.pPlayer->aItems[typeId].state |= SITHINVENTORY_ITEM_AVAILABLE;
        else
            pThing->actorParams.pPlayer->aItems[typeId].state &= ~SITHINVENTORY_ITEM_AVAILABLE;
    }
}

int sithInventory_IsInventoryAvailable(SithThing *pThing, int typeId)
{
    if ( pThing->actorParams.pPlayer != (SithPlayer *)-136 && sithInventory_g_aTypes[typeId].flags & SITHINVENTORY_TYPE_REGISTERED)
    {
        return !!(pThing->actorParams.pPlayer->aItems[typeId].state & SITHINVENTORY_ITEM_AVAILABLE);
    }
    return 0;
}

void sithInventory_SetCarries(SithThing *player, int binIdx, int bCarries)
{
    if ( player->actorParams.pPlayer != (SithPlayer *)-136 && sithInventory_g_aTypes[binIdx].flags & SITHINVENTORY_TYPE_REGISTERED)
    {
        if ( bCarries )
            player->actorParams.pPlayer->aItems[binIdx].state |= SITHINVENTORY_ITEM_FOUND;
        else
            player->actorParams.pPlayer->aItems[binIdx].state &= ~SITHINVENTORY_ITEM_FOUND;
    }
}

int sithInventory_GetCarries(SithThing *player, int binIdx)
{
    if ( player->actorParams.pPlayer != (SithPlayer *)-136 && sithInventory_g_aTypes[binIdx].flags & SITHINVENTORY_TYPE_REGISTERED)
    {
        return !!(player->actorParams.pPlayer->aItems[binIdx].state & SITHINVENTORY_ITEM_FOUND);
    }
    return 0;
}

int sithInventory_IsBackpackItem(SithThing *pThing, int typeId)
{
    return sithInventory_g_aTypes[typeId].flags & (SITHINVENTORY_TYPE_REGISTERED | SITHINVENTORY_TYPE_BACKPACKITEM) == (SITHINVENTORY_TYPE_REGISTERED | SITHINVENTORY_TYPE_BACKPACKITEM);
}

void sithInventory_SerializedWrite(SithThing *thing)
{
    for (int i= 0; i < SITHBIN_NUMBINS; i++)
    {
        SithInventoryItem* aItems = &thing->actorParams.pPlayer->aItems[i];
        if ( sithInventory_g_aTypes[i].flags & 1 )
        {
            *(flex32_t *)&std_g_genBuffer[0] = aItems->amount; // FLEXTODO
            *(int*)&std_g_genBuffer[4] = aItems->field_4;
            *(flex32_t *)&std_g_genBuffer[8] = aItems->state; // FLEXTODO
            stdConffile_Write(std_g_genBuffer, 12);
        }
    }
}

flex_t sithInventory_GetInventoryMinimum(SithThing *pThing, int id)
{
    return sithInventory_g_aTypes[id].min;
}

flex_t sithInventory_GetInventoryMaximum(SithThing *pThing, int id)
{
    return sithInventory_g_aTypes[id].max;
}

void sithInventory_SetInventoryFlags(SithThing *pThing, int id, int flags)
{
    sithInventory_g_aTypes[id].flags |= flags;
}

int sithInventory_GetInventoryFlags(SithThing *pThing, int id)
{
    return sithInventory_g_aTypes[id].flags;
}

void sithInventory_ClearInventoryFlags(SithThing *pThing, int id, int flags)
{
    sithInventory_g_aTypes[id].flags &= ~flags;
}

flex_t sithInventory_BroadcastInventoryMessage(SithThing *pThing, int srcType, int srcIdx, int msg, int status, flex_t param0, flex_t param1, flex_t param2, flex_t param3)
{
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        SithInventoryType* desc = &sithInventory_g_aTypes[i];

        if ( status & pThing->actorParams.pPlayer->aItems[i].state // is this order a bug?
          && pThing->actorParams.pPlayer != (SithPlayer *)-136
          && desc->flags & SITHINVENTORY_TYPE_REGISTERED
          && pThing->actorParams.pPlayer->aItems[i].state & SITHINVENTORY_ITEM_AVAILABLE )
        {
            if ( desc->cog )
            {
                param0 = sithCog_SendMessageEx(
                             desc->cog,
                             msg,
                             SENDERTYPE_THING,
                             pThing->idx,
                             srcType,
                             srcIdx,
                             -1,
                             param0,
                             param1,
                             param2,
                             param3);
            }
        }
    }
    return param0;
}

flex_t sithInventory_BroadcastMessage(SithThing *pThing, int srcType, int srcIdx, int messageType, int flags, flex_t param0, flex_t param1, flex_t param2, flex_t param3)
{
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        SithInventoryType* desc = &sithInventory_g_aTypes[i];

        if ( pThing->actorParams.pPlayer != (SithPlayer *)-136
          && desc->flags & SITHINVENTORY_TYPE_REGISTERED
          && pThing->actorParams.pPlayer // added
          && pThing->actorParams.pPlayer->aItems[i].state & SITHINVENTORY_ITEM_AVAILABLE
          && desc->flags & flags )
        {
            if ( desc->cog )
            {
                param0 = sithCog_SendMessageEx(
                             desc->cog,
                             messageType,
                             SENDERTYPE_THING,
                             pThing->idx,
                             srcType,
                             srcIdx,
                             -1,
                             param0,
                             param1,
                             param2,
                             param3);
            }
        }
    }
    
    return param0;
}

void sithInventory_ResetInventory(SithThing *pThing)
{
    SithInventoryItem *v2; // ecx
    int v4; // edi
    SithInventoryType *v5; // esi
    SithPlayer *v6; // eax
    SithInventoryItem *v7; // eax
    int v8; // ecx
    int v9; // edi
    SithInventoryType *v10; // esi
    SithInventoryItem *v11; // ebp
    SithPlayer *v12; // eax
    SithInventoryItem *v13; // eax
    SithInventoryItem *v14; // [esp+10h] [ebp-4h]
    int binIdxIter; // [esp+18h] [ebp+4h]

    v2 = pThing->actorParams.pPlayer->aItems;
    v14 = v2;
    if ( !sithInventory_g_bInitInventory || sithNet_isMulti )
        goto LABEL_16;
    v4 = 0;
    
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        v5 = &sithInventory_g_aTypes[i];
        sithInventory_SetInventory(pThing, i, 0.0);
        v6 = pThing->actorParams.pPlayer;
        if ( (v5->flags & ITEMINFO_DEFAULT) != 0 )
        {
            v7 = v6->aItems;
            if ( !v7 )
                goto LABEL_14;
            if ( (v5->flags & SITHINVENTORY_TYPE_REGISTERED) == 0 )
                goto LABEL_12;
            v8 = v7[v4].state | 4;
            goto LABEL_11;
        }
        v7 = v6->aItems;
        if ( !v7 )
            goto LABEL_14;
        if ( (v5->flags & SITHINVENTORY_TYPE_REGISTERED) != 0 )
        {
            v8 = v7[v4].state & ~4u;
LABEL_11:
            v7[v4].state = v8;
        }
LABEL_12:
        if ( (v5->flags & SITHINVENTORY_TYPE_REGISTERED) != 0 )
            v7[v4].state &= ~2u;
LABEL_14:
        sithInventory_SetCarries(pThing, i, 0);
        ++v4;
    }

    v2 = v14;
    sithInventory_g_bInitInventory = 0;
LABEL_16:
    binIdxIter = 0;
    v10 = sithInventory_g_aTypes;
    v11 = v2;
    
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        if ( (v10->flags & SITHINVENTORY_TYPE_NOT_CARRIED_BETWEEN_LEVELS) != 0 )
        {
            if ( pThing->actorParams.pPlayer != (SithPlayer *)-136 && (v10->flags & SITHINVENTORY_TYPE_REGISTERED) != 0 )
                pThing->actorParams.pPlayer->aItems[i].state &= ~4u;
            sithInventory_SetInventory(pThing, binIdxIter, 0.0);
            v2 = v14;
        }
        if ( v2 )
        {
            if ( (v10->flags & SITHINVENTORY_TYPE_REGISTERED) != 0 )
            {
                v12 = pThing->actorParams.pPlayer;
                v11->binWait = -1.0;
                v13 = v12->aItems;
                if ( v13 )
                {
                    if ( (v10->flags & SITHINVENTORY_TYPE_REGISTERED) != 0 )
                        v13[i].state &= ~2u;
                }
            }
        }
        ++v10;
        v11++;
        ++binIdxIter;
    }

#ifdef DEBUG_QOL_CHEATS
    if (!sithNet_isMulti) {
        sithInventory_SetInventory(pThing, SITHBIN_JEDI_RANK, 7.0);
        jkPlayer_SetRank(7);
        sithInventory_SetInventory(pThing, SITHBIN_FISTS, 1.0);
        sithInventory_SetInventory(pThing, SITHBIN_LIGHTSABER, 1.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_JUMP, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_SPEED, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_PULL, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_SEEING, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_HEALING, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_PERSUASION, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_BLINDING, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_ABSORB, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_GRIP, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_LIGHTNING, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_THROW, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_DESTRUCTION, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_DEADLYSIGHT, 4.0);
        sithInventory_SetInventory(pThing, SITHBIN_F_PROTECTION, 4.0);

        sithInventory_SetInventory(pThing, SITHBIN_FORCEMANA, 100.0);
        
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_JUMP, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_SPEED, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_PULL, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_SEEING, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_HEALING, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_PERSUASION, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_BLINDING, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_ABSORB, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_GRIP, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_LIGHTNING, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_THROW, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_DESTRUCTION, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_DEADLYSIGHT, 1);
        sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_PROTECTION, 1);

        if (Main_bMotsCompat) {
            sithInventory_SetInventory(pThing, SITHBIN_JEDI_RANK, 8.0);
            jkPlayer_SetRank(8);

            sithInventory_SetInventory(pThing, SITHBIN_F_FARSIGHT, 4.0);
            sithInventory_SetInventory(pThing, SITHBIN_F_PROJECT, 4.0);
            sithInventory_SetInventory(pThing, SITHBIN_F_SABERTHROW, 4.0);
            sithInventory_SetInventory(pThing, SITHBIN_F_PUSH, 4.0);
            sithInventory_SetInventory(pThing, SITHBIN_F_CHAINLIGHT, 4.0);

            sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_FARSIGHT, 1);
            sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_PROJECT, 1);
            sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_SABERTHROW, 1);
            sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_PUSH, 1);
            sithInventory_SetInventoryAvailable(pThing, SITHBIN_F_CHAINLIGHT, 1);
        }

        jkPlayer_SetAccessiblePowers(7);
        //jkSaber_InitializeSaberInfo(player, "sabergreen1.mat", "sabergreen0.mat", 0.003, 0.001, 0.100, );
    }
#endif

    pThing->actorParams.pPlayer->curItemID = 0;
    pThing->actorParams.pPlayer->curWeaponID = 0;
    pThing->actorParams.pPlayer->curPower = 0;
    sithInventory_g_bSendDeactivateMessage = 0;
    sithInventory_bUnkPower = 0;
    sithInventory_8339EC = 0;
    sithInventory_bRendIsHidden = 0;
    sithInventory_8339F4 = 0;
}

void sithInventory_ResetAllTypes(SithThing *pThing)
{
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        if (sithInventory_g_aTypes[i].flags & SITHINVENTORY_TYPE_NOT_CARRIED_BETWEEN_LEVELS)
            sithInventory_SetInventory(pThing, i, 0.0);
    }
}

// MOTS altered
SithThing* sithInventory_CreateBackpack(SithThing *pThing)
{
    SithThing *templateThing;
    SithThing *backpack;

    if ( !sithNet_isMulti )
        return 0;

    templateThing = sithTemplate_GetTemplate("+backpack");
    if ( !templateThing )
        return 0;

    backpack = sithThing_CreateThing(templateThing, pThing);
    if ( !backpack )
        return 0;

    backpack->itemParams.numBins = 0;
    backpack->itemParams.flags |= SITH_ITEM_BACKPACK; 
    
    if (!Main_bMotsCompat)
    {
        for (int i = 0; i < SITHBIN_NUMBINS; i++)
        {
            SithInventoryType* desc = &sithInventory_g_aTypes[i];
            if ( desc->flags & SITHINVENTORY_TYPE_REGISTERED && (desc->flags & SITHINVENTORY_TYPE_BACKPACKITEM))
            {
                flex_t amount = 0.0;
                if ( pThing->actorParams.pPlayer != (SithPlayer *)-136 && desc->flags & SITHINVENTORY_TYPE_REGISTERED )
                    amount = pThing->actorParams.pPlayer->aItems[i].amount;

                if ( backpack->itemParams.numBins < 16 && amount > 0.0 )
                {
                    backpack->itemParams.contents[backpack->itemParams.numBins].binIdx = i;
                    backpack->itemParams.contents[backpack->itemParams.numBins++].value = amount;
                }
            }
        }
    }
    else {
        // MOTS adds all of the guns into the backpack first, then items
        for (int i = SITHBIN_MOTS_NONE; i < SITHBIN_MOTS_CARBO_GUN+1; i++)
        {
            SithInventoryType* desc = &sithInventory_g_aTypes[i];
            if ( desc->flags & SITHINVENTORY_TYPE_REGISTERED && (desc->flags & SITHINVENTORY_TYPE_BACKPACKITEM))
            {
                flex_t amount = 0.0;
                if ( pThing->actorParams.pPlayer != (SithPlayer *)-136 && desc->flags & SITHINVENTORY_TYPE_REGISTERED )
                    amount = pThing->actorParams.pPlayer->aItems[i].amount;

                if ( backpack->itemParams.numBins < 16 && amount > 0.0 )
                {
                    backpack->itemParams.contents[backpack->itemParams.numBins].binIdx = i;
                    backpack->itemParams.contents[backpack->itemParams.numBins++].value = amount;
                }
            }
        }

        for (int i = SITHBIN_ENERGY; i < SITHBIN_NUMBINS; i++)
        {
            SithInventoryType* desc = &sithInventory_g_aTypes[i];
            if ( (i < SITHBIN_MOTS_NONE || i > SITHBIN_MOTS_CARBO_GUN) && desc->flags & SITHINVENTORY_TYPE_REGISTERED && (desc->flags & SITHINVENTORY_TYPE_BACKPACKITEM))
            {
                flex_t amount = 0.0;
                if ( pThing->actorParams.pPlayer != (SithPlayer *)-136 && desc->flags & SITHINVENTORY_TYPE_REGISTERED )
                    amount = pThing->actorParams.pPlayer->aItems[i].amount;

                if ( backpack->itemParams.numBins < 16 && amount > 0.0 )
                {
                    backpack->itemParams.contents[backpack->itemParams.numBins].binIdx = i;
                    backpack->itemParams.contents[backpack->itemParams.numBins++].value = amount;
                }
            }
        }
    }
    

    sithDSSThing_CreateThing(templateThing, backpack, pThing, 0, 0, 0, 255, 1);
    sithDSSThing_UpdateState(backpack, -1, 255);
    return backpack;
}

void sithInventory_PickupBackpack(SithThing *pPlayerThing, SithThing *pBackpackThing)
{
    for (int i = 0; i < pBackpackThing->itemParams.numBins; i++)
    {
        SithBackpackItem* item = &pBackpackThing->itemParams.contents[i];
        SithInventoryType* desc = &sithInventory_g_aTypes[i];

        if ((desc->flags & SITHINVENTORY_TYPE_REGISTERED) && (desc->flags & SITHINVENTORY_TYPE_BACKPACKITEM))
        {
            sithInventory_ChangeInventory(pPlayerThing, item->binIdx, item->value);
        }
    }
}

int sithInventory_GetBackpackItemID(SithThing *pBackpackThing, signed int itemNum)
{
    if ( itemNum >= pBackpackThing->itemParams.numBins )
        return -1;
    else
        return pBackpackThing->itemParams.contents[itemNum].binIdx;
}

flex_t sithInventory_GetBackpackItemValue(SithThing *pBackpackThing, signed int itemNum)
{
    if ( itemNum >= pBackpackThing->itemParams.numBins )
        return -1.0;
    else
        return pBackpackThing->itemParams.contents[itemNum].value;
}

int sithInventory_GetNumBackpackItems(SithThing *pBackpackThing)
{
    return pBackpackThing->itemParams.numBins;
}

// MOTS altered
int sithInventory_HandleInvSkillKeys(SithThing *player, flex_t deltaSecs)
{
    SithThing *v1; // edi
    SithControlBinding *v2; // esi
    int v3; // eax
    sithCog *v4; // ecx
    int v5; // esi
    sithCog *v6; // eax
    int v7; // esi
    sithCog *v8; // eax
    SithPlayer *v10; // eax
    int v11; // esi
    sithCog *v12; // eax
    int v13; // esi
    sithCog *v14; // eax
    SithPlayer *v15; // eax
    int v16; // esi
    sithCog *v17; // eax
    int v18; // esi
    sithCog *v19; // eax
    SithControlBinding *v20; // ebp
    int v22; // eax
    int v23; // esi
    int *v24; // eax
    int v25; // eax
    sithCog *v26; // eax
    int v27; // eax
    SithPlayer *v28; // ecx
    SithInventoryItem *v29; // edx
    SithInventoryType *v30;
    int v31; // ecx
    int v32; // esi
    sithCog *v33; // ecx
    int v34; // eax
    int v35; // ebx
    int v36; // esi
    SithInventoryType *v38; // ebp
    int v40; // [esp+10h] [ebp-4h]
    int keyRead;

    v1 = player;
    if ( player->type != SITH_THING_PLAYER ) {
        return 0;
    }

    if (player->flags & SITH_TF_DEAD) {
        return 0;
    }

    if ( (player->actorParams.flags & SITH_AF_CONTROLSDISABLED) != 0 )
    {
        v2 = &sithInventory_powerKeybinds[0];
        do
        {
            if ( v2->enabled == 1 )
                v3 = v2->binding;
            else
                v3 = -1;
            if ( v3 != -1 && v2->idk == 1 )
            {
                v2->idk = 0;
                sithThing_MotsTick(13,0,(flex_t)v3); // FLEXTODO
                if ( v3 >= 0
                  && v1->actorParams.pPlayer != (SithPlayer *)-136
                  && (sithInventory_g_aTypes[v3].flags & SITHINVENTORY_TYPE_REGISTERED) != 0
                  && (v1->actorParams.pPlayer->aItems[v3].state & 4) != 0 )
                {
                    v4 = sithInventory_g_aTypes[v3].cog;
                    if ( v4 )
                        sithCog_SendMessage(v4, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_0, v3, SENDERTYPE_THING, v1->idx, SENDERTYPE_0);
                }
            }
            v2++;
        }
        while ( (intptr_t)v2 < (intptr_t)&sithInventory_powerKeybinds[20] );
        if ( sithInventory_g_bSendDeactivateMessage == 1 )
        {
            sithInventory_g_bSendDeactivateMessage = 0;
            sithThing_MotsTick(12,0,(flex_t)player->actorParams.pPlayer->curItemID); // FLEXTODO
            v5 = player->actorParams.pPlayer->curItemID;
            if ( v5 >= 0 )
            {
                if ( sithInventory_IsInventoryAvailable(v1, player->actorParams.pPlayer->curItemID) )
                {
                    v6 = sithInventory_g_aTypes[v5].cog;
                    if ( v6 )
                        sithCog_SendMessage(v6, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_0, v5, SENDERTYPE_THING, v1->idx, SENDERTYPE_0);
                }
            }
        }
        if ( sithInventory_bUnkPower == 1 )
        {
            sithInventory_bUnkPower = 0;
            sithThing_MotsTick(13,0,(flex_t)player->actorParams.pPlayer->curPower); // FLEXTODO
            v7 = player->actorParams.pPlayer->curPower;
            if ( v7 >= 0 )
            {
                if ( sithInventory_IsInventoryAvailable(v1, player->actorParams.pPlayer->curPower) )
                {
                    v8 = sithInventory_g_aTypes[v7].cog;
                    if ( v8 )
                    {
                        sithCog_SendMessage(v8, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_0, v7, SENDERTYPE_THING, v1->idx, SENDERTYPE_0);
                        return 0;
                    }
                }
            }
        }
    }
    else
    {
        if ( sithControl_GetKey(INPUT_FUNC_USEINV, &keyRead) 
#ifdef QOL_IMPROVEMENTS
            || sithControl_GetKey(INPUT_FUNC_USELASTSELECTED, &keyRead) && sithControl_GetLastSelected() == LAST_SELECTED_ITEM
#endif // QOL_IMPROVEMENTS
            )
        {
            if ( !sithInventory_g_bSendDeactivateMessage )
            {
                // MOTS added
                sithInventory_008d60f8 = 1;
                if (sithThing_MotsTick(12,1,(flex_t)player->actorParams.pPlayer->curItemID)) // FLEXTODO
                {
                    v10 = v1->actorParams.pPlayer;
                    v11 = player->actorParams.pPlayer->curItemID;
                    sithInventory_g_bSendDeactivateMessage = 1;
                    if ( sithTime_g_secGameTime >= (flex_d_t)v10->aItems[v11].binWait && v11 >= SENDERTYPE_0 )
                    {
                        if ( sithInventory_IsInventoryAvailable(v1, v11) )
                        {
                            v12 = sithInventory_g_aTypes[v11].cog;
                            if ( v12 )
                                sithCog_SendMessage(v12, SITH_MESSAGE_ACTIVATE, SITH_MESSAGE_ACTIVATE, v11, SENDERTYPE_THING, v1->idx, SENDERTYPE_0);
                        }
                    }
                }
            }
        }
        else 
        {
            // MOTS added
            if (sithInventory_008d60f8) {
                sithThing_MotsTick(12,0,(flex_t)player->actorParams.pPlayer->curItemID); // FLEXTODO
                sithInventory_008d60f8 = 0;
            }

            if ( sithInventory_g_bSendDeactivateMessage == 1 )
            {
                sithInventory_g_bSendDeactivateMessage = 0;
                v13 = player->actorParams.pPlayer->curItemID;
                if ( v13 >= 0 )
                {
                    if ( sithInventory_IsInventoryAvailable(v1, player->actorParams.pPlayer->curItemID) )
                    {
                        v14 = sithInventory_g_aTypes[v13].cog;
                        if ( v14 )
                            sithCog_SendMessage(v14, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_0, v13, SENDERTYPE_THING, v1->idx, SENDERTYPE_0);
                    }
                }
            }
        }

        if ( sithControl_GetKey(INPUT_FUNC_USESKILL, &keyRead) 
#ifdef QOL_IMPROVEMENTS
            || sithControl_GetKey(INPUT_FUNC_USELASTSELECTED, &keyRead) && sithControl_GetLastSelected() == LAST_SELECTED_SKILL
#endif // QOL_IMPROVEMENTS
            )
        {
            if ( !sithInventory_bUnkPower )
            {
                // MOTS added
                sithInventory_008d60fc = 1;
                if (sithThing_MotsTick(13,1,(flex_t)player->actorParams.pPlayer->curItemID)) // FLEXTODO
                {
                    v15 = v1->actorParams.pPlayer;
                    v16 = player->actorParams.pPlayer->curPower;
                    sithInventory_bUnkPower = 1;
                    if ( sithTime_g_secGameTime >= (flex_d_t)v15->aItems[v16].binWait && v16 >= SENDERTYPE_0 )
                    {
                        if ( sithInventory_IsInventoryAvailable(v1, v16) )
                        {
                            v17 = sithInventory_g_aTypes[v16].cog;
                            if ( v17 )
                                sithCog_SendMessage(v17, SITH_MESSAGE_ACTIVATE, SITH_MESSAGE_ACTIVATE, v16, SENDERTYPE_THING, v1->idx, SENDERTYPE_0);
                        }
                    }
                }
            }
        }
        else
        {
            // MOTS added
            if (sithInventory_008d60fc) {
                sithThing_MotsTick(13,0,(flex_t)player->actorParams.pPlayer->curPower); // FLEXTODO
                sithInventory_008d60fc = 0;
            }

            if ( sithInventory_bUnkPower == 1 )
            {
                sithInventory_bUnkPower = 0;
                v18 = player->actorParams.pPlayer->curPower;
                if ( v18 >= SENDERTYPE_0 )
                {
                    if ( sithInventory_IsInventoryAvailable(v1, player->actorParams.pPlayer->curPower) )
                    {
                        v19 = sithInventory_g_aTypes[v18].cog;
                        if ( v19 )
                            sithCog_SendMessage(v19, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_0, v18, SENDERTYPE_THING, v1->idx, SENDERTYPE_0);
                    }
                }
            }
        }

        v40 = 0;
        v20 = &sithInventory_powerKeybinds[0];
        do
        {
            if ( v20->enabled == 1 )
            {
                int v21 = sithControl_GetKey(v40 + INPUT_FUNC_ACTIVATE0, &keyRead) == 0;
                v22 = v20->idk;
                if ( v21 )
                {
                    if ( v22 == 1 )
                    {
                        v20->idk = 0;
                        v27 = v20->enabled == 1 ? v20->binding : -1;
                        v28 = v1->actorParams.pPlayer;
                        v29 = v28->aItems;
                        if ( v28 == (SithPlayer *)-136 || (sithInventory_g_aTypes[v27].flags & SITHINVENTORY_TYPE_REGISTERED) == 0 )
                            v30 = 0;
                        else
                            v30 = &sithInventory_g_aTypes[v27];
                        v31 = v30->flags;
                        if ( (v31 & 0x100) != 0 )
                        {
                            // TODO MOTS added some stuff here?
                            v32 = 0;
                            if ( (v31 & 8) != 0 && v28->curPower == v27 && sithThing_MotsTick(13, 1, (flex_t)v27)) { // FLEXTODO
                                v32 = 1;
                            }
                            if ( (v31 & 2) != 0 && v28->curItemID == v27 && sithThing_MotsTick(12, 1, (flex_t)v27)) { // FLEXTODO
                                v32 = 1;
                            }
                            if ( v32 )
                            {
                                if ( v27 >= 0 )
                                {
                                    if ( v29 )
                                    {
                                        if ( (sithInventory_g_aTypes[v27].flags & SITHINVENTORY_TYPE_REGISTERED) != 0 && (v29[v27].state & 4) != 0 )
                                        {
                                            v33 = sithInventory_g_aTypes[v27].cog;
                                            if ( v33 )
                                                sithCog_SendMessage(v33, SITH_MESSAGE_DEACTIVATED, 0, v27, SENDERTYPE_THING, v1->idx, 0);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else if ( !v22 )
                {
                    v20->idk = 1;
                    v23 = v20->enabled == 1 ? v20->binding : -1;
                    v24 = (int *)(v1->actorParams.pPlayer == (SithPlayer *)-136 || (sithInventory_g_aTypes[v23].flags & SITHINVENTORY_TYPE_REGISTERED) == 0 ? 0 : &sithInventory_g_aTypes[v23]);
                    v25 = *v24;
                    if ( (v25 & 0x100) != 0 )
                    {
                        sithInventory_8339EC = 1;
                        if ( (v25 & 8) != 0 )
                        {
                            if (!sithThing_MotsTick(11, 0, (flex_t)v23)) goto skip_cog; // FLEXTODO
                            sithInventory_SelectPower(v1, v23);
                            if (!sithThing_MotsTick(13, 1, (flex_t)v23)) goto skip_cog; // FLEXTODO
                        }
                        else if ( (v25 & 2) != 0 )
                        {
                            if (!sithThing_MotsTick(10, 0, (flex_t)v23)) goto skip_cog; // FLEXTODO
                            sithInventory_SelectItem(v1, v23);
                            if (!sithThing_MotsTick(12, 1, (flex_t)v23)) goto skip_cog; // FLEXTODO
                        }

                        if ( sithTime_g_secGameTime >= (flex_d_t)v1->actorParams.pPlayer->aItems[v23].binWait && v23 >= 0 )
                        {
                            if ( sithInventory_IsInventoryAvailable(v1, v23) )
                            {
                                v26 = sithInventory_g_aTypes[v23].cog;
                                if ( v26 )
                                    sithCog_SendMessage(v26, SITH_MESSAGE_ACTIVATE, SENDERTYPE_SYSTEM, v23, SENDERTYPE_THING, v1->idx, 0);
                            }
                        }
                    }
                }
                else // MOTS added
                {
                    v23 = v20->enabled == 1 ? v20->binding : -1;
                    v24 = (int *)(v1->actorParams.pPlayer == (SithPlayer *)-136 || (sithInventory_g_aTypes[v23].flags & SITHINVENTORY_TYPE_REGISTERED) == 0 ? 0 : &sithInventory_g_aTypes[v23]);
                    v25 = *v24;
                    if (v25 & 0x100)
                    {
                        if (v25 & 8)
                        {
                            sithThing_MotsTick(13, 2, (flex_t)v23); // FLEXTODO
                        }
                        else if (v25 & 2)
                        {
                            sithThing_MotsTick(12, 2, (flex_t)v23); // FLEXTODO
                        }
                    }
                }
            }
skip_cog:
            v20++;
            ++v40;
        }
        while ( (intptr_t)v20 < (intptr_t)&sithInventory_powerKeybinds[20].idk );

        sithControl_GetKey(INPUT_FUNC_NEXTINV, &keyRead);
        while (keyRead--)
        {
#ifdef QOL_IMPROVEMENTS
            // Common button for both items and force power usage for controllers
            sithControl_SetLastSelected(LAST_SELECTED_ITEM);
#endif // QOL_IMPROVEMENTS

            if (sithThing_MotsTick(10,1,1.0))
            {
                v34 = sithInventory_FindNextTypeID(v1, v1->actorParams.pPlayer->curItemID, 2);
                sithInventory_SelectItem(v1, v34);
                sithInventory_bRendIsHidden = 1;
                sithInventory_8339F4 = 0;
                sithInventory_8339EC = 0;
            }
        }

        sithControl_GetKey(INPUT_FUNC_PREVINV, &keyRead);
        while (keyRead--)
        {
#ifdef QOL_IMPROVEMENTS
            // Common button for both items and force power usage for controllers
            sithControl_SetLastSelected(LAST_SELECTED_ITEM);
#endif // QOL_IMPROVEMENTS

            v35 = v1->actorParams.pPlayer->curItemID;
            v36 = v35 - 1;
            if ( v35 - 1 < 0 )
            {
LABEL_103:
                v36 = 199;
                if ( v35 >= 199 )
                {
LABEL_108:
                    v36 = -1;
                }
                else
                {
                    v38 = &sithInventory_g_aTypes[199];
                    while ( (v38->flags & 2) == 0 || !sithInventory_IsInventoryAvailable(v1, v36) )
                    {
                        --v36;
                        --v38;
                        if ( v36 <= v35 )
                            goto LABEL_108;
                    }
                }
            }
            else
            {
                while ( (sithInventory_g_aTypes[v36].flags & 2) == 0 || !sithInventory_IsInventoryAvailable(v1, v36) )
                {
                    --v36;
                    if ( v36 < 0 )
                        goto LABEL_103;
                }
            }
            sithInventory_SelectItem(v1, v36);
            sithInventory_8339F4 = 0;
            sithInventory_8339EC = 0;
            sithInventory_bRendIsHidden = 1;
        }

        sithControl_GetKey(INPUT_FUNC_NEXTSKILL, &keyRead);
        while (keyRead--)
        {
#ifdef QOL_IMPROVEMENTS
            // Common button for both items and force power usage for controllers
            sithControl_SetLastSelected(LAST_SELECTED_SKILL);
#endif // QOL_IMPROVEMENTS
            if (sithThing_MotsTick(11, 1, 1.0)) {
                sithInventory_SelectPowerPrior(v1);
                sithInventory_8339F4 = 1;
                sithInventory_bRendIsHidden = 0;
                sithInventory_8339EC = 0;
            }
        }

        sithControl_GetKey(INPUT_FUNC_PREVSKILL, &keyRead);
        while (keyRead--)
        {
#ifdef QOL_IMPROVEMENTS
            // Common button for both items and force power usage for controllers
            sithControl_SetLastSelected(LAST_SELECTED_SKILL);
#endif // QOL_IMPROVEMENTS
            if (sithThing_MotsTick(11, 1, -1.0)) {
                sithInventory_SelectPowerFollowing(v1);
                sithInventory_8339F4 = 1;
                sithInventory_bRendIsHidden = 0;
                sithInventory_8339EC = 0;
            }
        }
    }
    return 0;
}

void sithInventory_SendFire(SithThing *player)
{
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        SithInventoryItem* aItems = &player->actorParams.pPlayer->aItems[i];
        SithInventoryType* desc = &sithInventory_g_aTypes[i];
        
        if ( aItems->activationDelaySecs > 0.0 
             && sithTime_g_secGameTime >= aItems->binWait 
             && desc->flags & SITHINVENTORY_TYPE_AUTOAIM )
        {
            if ( desc->cog )
            {
                aItems->binWait = sithTime_g_secGameTime + aItems->activationDelaySecs;
                sithCog_SendMessageEx(desc->cog, SITH_MESSAGE_FIRE, SENDERTYPE_SYSTEM, i, SENDERTYPE_THING, player->idx, 0, 0.0, 0.0, 0.0, 0.0);
            }
        }
    }
}

SithInventoryItem* sithInventory_GetBin(SithThing *player, int binIdx)
{
    if ( player->actorParams.pPlayer != (SithPlayer *)-136 
         && sithInventory_g_aTypes[binIdx].flags & SITHINVENTORY_TYPE_REGISTERED )
        return &player->actorParams.pPlayer->aItems[binIdx];
    else
        return NULL;
}

SithInventoryType* sithInventory_GetInventoryType(SithThing *pThing, int typeId)
{
    if ( pThing->actorParams.pPlayer == (SithPlayer *)-136 
    || !(sithInventory_g_aTypes[typeId].flags & SITHINVENTORY_TYPE_REGISTERED) )
        return NULL;

    return &sithInventory_g_aTypes[typeId];
}

int sithInventory_KeybindInit()
{
    int v0; // ebx

    v0 = 0;
    for (int i = 0; i < 20; i++)
    {
        sithInventory_powerKeybinds[i].enabled = 0;
    }

    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        if ( (sithInventory_g_aTypes[i].flags & 0x100) != 0 )
        {
            sithControl_RegisterKeyFunction(v0 + 42);
            sithInventory_powerKeybinds[v0].enabled = 1;
            sithInventory_powerKeybinds[v0].binding = i;
            sithInventory_powerKeybinds[v0].idk = 0;
            ++v0;
            
            if (v0 >= 20)
            {
                break;
            }
        }
    }
    return v0;
}

void sithInventory_InitInventory(SithThing *pThing)
{
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        SithInventoryType* desc = &sithInventory_g_aTypes[i];
        SithPlayer* pPlayer = pThing->actorParams.pPlayer;

        sithInventory_SetInventory(pThing, i, 0.0);

        // Original game had this, idk why but it did.
        // Commented out to avoid compiler warnings.
#if 0
        if ( !pPlayer->aItems )
            continue;
#endif

        if ( desc->flags & ITEMINFO_DEFAULT && desc->flags & SITHINVENTORY_TYPE_REGISTERED)
        {
            pPlayer->aItems[i].state |= SITHINVENTORY_ITEM_AVAILABLE;
        }
        else if ( desc->flags & SITHINVENTORY_TYPE_REGISTERED )
        {
            pPlayer->aItems[i].state &= ~SITHINVENTORY_ITEM_AVAILABLE;
        }

        if ( desc->flags & SITHINVENTORY_TYPE_REGISTERED )
            pPlayer->aItems[i].state &= ~SITHINVENTORY_ITEM_ACTIVATED;

        if ( desc->flags & SITHINVENTORY_TYPE_REGISTERED )
            pPlayer->aItems[i].state &= ~SITHINVENTORY_ITEM_FOUND;
    }
}

void sithInventory_SetPowerKeybind(int idx, int binding)
{
    sithInventory_powerKeybinds[idx].enabled = 1;
    sithInventory_powerKeybinds[idx].binding = binding;
    sithInventory_powerKeybinds[idx].idk = 0;
}

int sithInventory_GetPowerKeybind(int idx)
{
    if ( sithInventory_powerKeybinds[idx].enabled == 1 )
        return sithInventory_powerKeybinds[idx].binding;
    else
        return -1;
}

void sithInventory_BroadcastKilledMessage(SithThing *pSender, SithThing *pKiller)
{
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        SithInventoryType* desc = &sithInventory_g_aTypes[i];
        
        if ( pSender->actorParams.pPlayer != (SithPlayer *)-136 
          && desc->flags & SITHINVENTORY_TYPE_REGISTERED 
          && pSender->actorParams.pPlayer // Added
          && pSender->actorParams.pPlayer->aItems[i].state & SITHINVENTORY_ITEM_AVAILABLE 
          && desc->cog )
        {
            sithCog_SendMessage(desc->cog, SITH_MESSAGE_KILLED, SENDERTYPE_THING, pSender->idx, SENDERTYPE_THING, pKiller ? pKiller->idx : -1, 0);
        }
    }
}

void sithInventory_SetBinWait(SithThing *player, int binIdx, flex_t wait)
{
    if ( player->actorParams.pPlayer != (SithPlayer *)-136 )
    {
        if ( sithInventory_g_aTypes[binIdx].flags & SITHINVENTORY_TYPE_REGISTERED )
            player->actorParams.pPlayer->aItems[binIdx].binWait = wait + sithTime_g_secGameTime;
    }
}
