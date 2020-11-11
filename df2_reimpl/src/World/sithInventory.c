#include "sithInventory.h"

#include "jk.h"
#include "Cog/sithCog.h"
#include "Engine/sithTime.h"

void sithInventory_NewEntry(int binIdx, sithCog *cog, char *name, float min, float max, int flags)
{
    sithItemDescriptor* desc = &sithInventory_aDescriptors[binIdx];
    
    _strncpy(desc->fpath, name, 0x7F);
    desc->fpath[127] = 0;

    desc->cog = cog;
    desc->ammoMin = min;
    desc->ammoMax = max;
    desc->flags = flags | 1;
}

int sithInventory_GetNumBinsWithFlag(sithThing *thing, int binNum, int flags)
{
    if ( binNum + 1 < 200 )
    {
        for (int i = binNum + 1; i < 200; i++)
        {
            sithItemDescriptor* desc =  &sithInventory_aDescriptors[i];

            if ((flags & desc->flags) && thing->actorParams.playerinfo != (sithPlayerInfo *)-136 && (desc->flags & ITEMINFO_VALID) && (thing->actorParams.playerinfo->iteminfo[i].state & ITEMSTATE_AVAILABLE))
                return i;
        }
    }
   
    if ( binNum <= 0 )
        return -1;

    for (int i = 0; i < 200; i++)
    {
        sithItemDescriptor* desc =  &sithInventory_aDescriptors[i];

        if ((flags & desc->flags) && thing->actorParams.playerinfo != (sithPlayerInfo *)-136 && (desc->flags & ITEMINFO_VALID) && (thing->actorParams.playerinfo->iteminfo[i].state & ITEMSTATE_AVAILABLE))
            return i;
    }

    return -1;
}

int sithInventory_GetNumBinsWithFlagRev(sithThing *thing, int binNumEnd, int flags)
{
    if ( binNumEnd - 1 >= 0 )
    {
        for (int i = binNumEnd - 1; i >= 0; --i)
        {
            sithItemDescriptor* desc = &sithInventory_aDescriptors[i];
            if (!(!(flags & desc->flags) || thing->actorParams.playerinfo == (sithPlayerInfo *)-136 || !(desc->flags & ITEMINFO_VALID) || !(thing->actorParams.playerinfo->iteminfo[i].state & ITEMSTATE_AVAILABLE)))
                return i;
        }
    }
    
    if ( binNumEnd >= 199 )
        return -1;

    for (int i = 199; i > binNumEnd - 1; --i)
    {
        sithItemDescriptor* desc = &sithInventory_aDescriptors[i];
        if (!(!(flags & desc->flags) || thing->actorParams.playerinfo == (sithPlayerInfo *)-136 || !(desc->flags & ITEMINFO_VALID) || !(thing->actorParams.playerinfo->iteminfo[i].state & ITEMSTATE_AVAILABLE)))
            return i;
    }

    return -1;
}

int sithInventory_GetNumItemsPriorToIdx(sithThing *thing, signed int binNumStart)
{
    return sithInventory_GetNumBinsWithFlag(thing, binNumStart, ITEMINFO_ITEM);
}

int sithInventory_GetNumItemsFollowingIdx(sithThing *thing, signed int binNumStart)
{
    return sithInventory_GetNumBinsWithFlagRev(thing, binNumStart, ITEMINFO_ITEM);
}

void sithInventory_SelectItem(sithThing *thing, int binIdx)
{
    if ( binIdx < 0 )
        return;
        
    if ( thing->actorParams.playerinfo == (sithPlayerInfo *)-136 || !(sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID) || !(thing->actorParams.playerinfo->iteminfo[binIdx].state & ITEMSTATE_AVAILABLE) )
        return;
        
    sithCog* curItemCog = sithInventory_aDescriptors[thing->actorParams.playerinfo->curItem].cog;
    if ( curItemCog )
    {
        sithCog_SendMessage(curItemCog, SITH_MESSAGE_DESELECTED, SENDERTYPE_SYSTEM, thing->actorParams.playerinfo->curItem, SENDERTYPE_THING, thing->thingIdx, 0);
        if ( sithInventory_bUnk == 1 )
        {
            sithCog_SendMessage(
                sithInventory_aDescriptors[thing->actorParams.playerinfo->curItem].cog,
                SITH_MESSAGE_DEACTIVATED,
                SENDERTYPE_SYSTEM,
                thing->actorParams.playerinfo->curItem,
                SENDERTYPE_THING,
                thing->thingIdx,
                0);
            sithInventory_bUnk = 0;
        }
    }

    sithCog* itemCog = sithInventory_aDescriptors[binIdx].cog;
    if ( itemCog )
    {
        sithCog_SendMessage(itemCog, SITH_MESSAGE_SELECTED, SENDERTYPE_SYSTEM, binIdx, SENDERTYPE_THING, thing->thingIdx, 0);
    }

    thing->actorParams.playerinfo->curItem = binIdx;
}

void sithInventory_SelectItemPrior(sithThing *thing)
{
    sithInventory_SelectItem(thing, sithInventory_GetNumItemsPriorToIdx(thing, thing->actorParams.playerinfo->curItem));
}

void sithInventory_SelectItemFollowing(sithThing *thing)
{
    sithInventory_SelectItem(thing, sithInventory_GetNumItemsFollowingIdx(thing, thing->actorParams.playerinfo->curItem));
}

int sithInventory_SelectWeaponFollowing(int idx)
{
    int count = 0;
    for (int i = 0; i < 200; i++)
    {
        if ( sithInventory_aDescriptors[i].flags & ITEMINFO_WEAPON )
        {
            if ( count == idx )
                return i;
            ++count;
        }
    }

    return -1;
}

sithItemDescriptor* sithInventory_GetBinByIdx(int idx)
{
    return &sithInventory_aDescriptors[idx];
}

int sithInventory_GetCurWeapon(sithThing *player)
{
    return player->actorParams.playerinfo->curWeapon;
}

void sithInventory_SetCurWeapon(sithThing *player, int idx)
{
    player->actorParams.playerinfo->curWeapon = idx;
}

int sithInventory_GetCurItem(sithThing *player)
{
    return player->actorParams.playerinfo->curItem;
}

void sithInventory_SetCurItem(sithThing *player, int idx)
{
    player->actorParams.playerinfo->curItem = idx;
}

int sithInventory_GetCurPower(sithThing *player)
{
    return player->actorParams.playerinfo->curPower;
}

void sithInventory_SetCurPower(sithThing *player, int idx)
{
    player->actorParams.playerinfo->curPower = idx;
}

int sithInventory_GetWeaponPrior(sithThing *thing, int binNum)
{
    return sithInventory_GetNumBinsWithFlag(thing, binNum, ITEMINFO_WEAPON);
}

int sithInventory_GetWeaponFollowing(sithThing *thing, int binNum)
{
    return sithInventory_GetNumBinsWithFlagRev(thing, binNum, ITEMINFO_WEAPON);
}

int sithInventory_GetPowerPrior(sithThing *thing, int binNum)
{
    return sithInventory_GetNumBinsWithFlag(thing, binNum, ITEMINFO_POWER);
}

int sithInventory_GetPowerFollowing(sithThing *thing, int binNum)
{
    return sithInventory_GetNumBinsWithFlagRev(thing, binNum, ITEMINFO_POWER);
}

void sithInventory_SelectPower(sithThing *player, int binNum)
{
    if ( binNum < 0 )
        return;

    if ( player->actorParams.playerinfo == (sithPlayerInfo *)-136 || !(sithInventory_aDescriptors[binNum].flags & ITEMINFO_VALID) || !(player->actorParams.playerinfo->iteminfo[binNum].state & ITEMSTATE_AVAILABLE) )
        return;

    int curPower = player->actorParams.playerinfo->curPower;
    if ( curPower >= 0 )
    {
        if ( sithInventory_aDescriptors[curPower].cog )
        {
            sithCog_SendMessage(sithInventory_aDescriptors[curPower].cog, SITH_MESSAGE_DESELECTED, SENDERTYPE_SYSTEM, curPower, SENDERTYPE_THING, player->thingIdx, 0);
            if ( sithInventory_bUnkPower == 1 )
            {
                sithCog_SendMessage(sithInventory_aDescriptors[curPower].cog, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_SYSTEM, curPower, SENDERTYPE_THING, player->thingIdx, 0);
                sithInventory_bUnkPower = 0;
            }
        }
    }
    
    if ( sithInventory_aDescriptors[binNum].cog )
        sithCog_SendMessage(sithInventory_aDescriptors[binNum].cog, SITH_MESSAGE_SELECTED, SENDERTYPE_SYSTEM, binNum, SENDERTYPE_THING, player->thingIdx, 0);
    player->actorParams.playerinfo->curPower = binNum;
}

void sithInventory_SelectPowerPrior(sithThing *player)
{
    int binNum = sithInventory_GetPowerPrior(player, player->actorParams.playerinfo->curPower);
    sithInventory_SelectPower(player, binNum);
}

void sithInventory_SelectPowerFollowing(sithThing *player)
{
    int binNum = sithInventory_GetPowerFollowing(player, player->actorParams.playerinfo->curPower);
    sithInventory_SelectPower(player, binNum);
}

int sithInventory_ActivateBin(sithThing *player, sithCog *cog, float delay, int binNum)
{
    sithItemInfo *info;

    if ( player->actorParams.playerinfo == (sithPlayerInfo *)-136 || !(sithInventory_aDescriptors[binNum].flags & ITEMINFO_VALID) )
        return 0;

    info = &player->actorParams.playerinfo->iteminfo[binNum];
    info->activationDelaySecs = delay;
    info->activatedTimeSecs = sithTime_curSeconds;
    if ( delay <= 0.0 )
        info->binWait = -1.0;
    if (info->binWait != -1.0 && sithTime_curSeconds >= (double)info->binWait )
    {
        sithCog_SendMessageEx(cog, SITH_MESSAGE_FIRE, SENDERTYPE_SYSTEM, binNum, SENDERTYPE_THING, player->thingIdx, 0, 0.0, 0.0, 0.0, 0.0);
        info->binWait = sithTime_curSeconds + info->activationDelaySecs;
    }
    return 1;
}

float sithInventory_DeactivateBin(sithThing *player, sithCog *unused, int binNum)
{
    sithItemInfo *info;
    float result;

    if ( player->actorParams.playerinfo == (sithPlayerInfo *)-136 || !(sithInventory_aDescriptors[binNum].flags & ITEMINFO_VALID) )
        return 0.0;

    info = &player->actorParams.playerinfo->iteminfo[binNum];
    if ( info->activatedTimeSecs == -1.0 )
        result = 0.0;
    else
        result = sithTime_curSeconds - info->activatedTimeSecs;

    info->activationDelaySecs = -1.0;
    info->binWait = -1.0;
    info->activatedTimeSecs = -1.0;
    return result;
}

int sithInventory_BinSendActivate(sithThing *player, int binIdx)
{
    if ( sithTime_curSeconds < player->actorParams.playerinfo->iteminfo[binIdx].binWait )
        return 0;

    if ( binIdx < 0 )
        return 0;

    if ( player->actorParams.playerinfo == (sithPlayerInfo *)-136 )
        return 0;

    if ( !(sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID) )
        return 0;

    if ( !(player->actorParams.playerinfo->iteminfo[binIdx].state & ITEMSTATE_AVAILABLE) )
        return 0;

    if ( !sithInventory_aDescriptors[binIdx].cog )
        return 0;

    sithCog_SendMessage(sithInventory_aDescriptors[binIdx].cog, SITH_MESSAGE_ACTIVATE, SENDERTYPE_SYSTEM, binIdx, SENDERTYPE_THING, player->thingIdx, 0);
    return 1;
}

void sithInventory_BinSendDeactivate(sithThing *player, int senderIndex)
{
    if ( senderIndex >= 0
      && player->actorParams.playerinfo != (sithPlayerInfo *)-136
      && sithInventory_aDescriptors[senderIndex].flags & ITEMINFO_VALID
      && player->actorParams.playerinfo->iteminfo[senderIndex].state & ITEMSTATE_AVAILABLE )
    {
        if ( sithInventory_aDescriptors[senderIndex].cog )
            sithCog_SendMessage(sithInventory_aDescriptors[senderIndex].cog, COGMSG_SYNCPUPPET, SENDERTYPE_0, senderIndex, SENDERTYPE_THING, player->thingIdx, 0);
    }
}

float sithInventory_ChangeInv(sithThing *player, int binIdx, float amt)
{
    sithItemInfo *info;

    if ( player->actorParams.playerinfo == (sithPlayerInfo *)-136 || !(sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID) )
        return 0.0;

    info = &player->actorParams.playerinfo->iteminfo[binIdx];
    return sithInventory_SetBinAmount(player, binIdx, info->ammoAmt + amt);
}

float sithInventory_GetBinAmount(sithThing *player, int binIdx)
{
    if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 && sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID )
        return player->actorParams.playerinfo->iteminfo[binIdx].ammoAmt;
    else
        return 0.0;
}

float sithInventory_SetBinAmount(sithThing *player, int binIdx, float amt)
{
    sithItemInfo *info;

    if ( player->actorParams.playerinfo == (sithPlayerInfo *)-136 || !(sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID) )
        return 0.0;

    info = &player->actorParams.playerinfo->iteminfo[binIdx];
    
    float origAmt = info->ammoAmt;
    info->ammoAmt = amt;
    if ( info->ammoAmt < sithInventory_aDescriptors[binIdx].ammoMin )
    {
        info->ammoAmt = sithInventory_aDescriptors[binIdx].ammoMin;
    }
    else if ( info->ammoAmt > sithInventory_aDescriptors[binIdx].ammoMax )
    {
        info->ammoAmt = sithInventory_aDescriptors[binIdx].ammoMax;
    }

    if ( info->ammoAmt != origAmt )
    {
        if ( sithInventory_aDescriptors[binIdx].cog )
            sithCog_SendMessage(sithInventory_aDescriptors[binIdx].cog, SITH_MESSAGE_CHANGED, SENDERTYPE_0, 0, SENDERTYPE_THING, player->thingIdx, binIdx);
        info->state |= ITEMSTATE_1;
    }
    return info->ammoAmt;
}

void sithInventory_SetActivate(sithThing *player, int binIdx, int bActivate)
{
    if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 && sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID)
    {
        if ( bActivate )
            player->actorParams.playerinfo->iteminfo[binIdx].state |= ITEMSTATE_ACTIVATE;
        else
            player->actorParams.playerinfo->iteminfo[binIdx].state &= ~ITEMSTATE_ACTIVATE;
    }
}

int sithInventory_GetActivate(sithThing *player, int binIdx)
{
    if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 && sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID)
    {
        return !!(player->actorParams.playerinfo->iteminfo[binIdx].state & ITEMSTATE_ACTIVATE);
    }
    return 0;
}

void sithInventory_SetAvailable(sithThing *player, int binIdx, int bAvailable)
{
    if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 && sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID)
    {
        if ( bAvailable )
            player->actorParams.playerinfo->iteminfo[binIdx].state |= ITEMSTATE_AVAILABLE;
        else
            player->actorParams.playerinfo->iteminfo[binIdx].state &= ~ITEMSTATE_AVAILABLE;
    }
}

int sithInventory_GetAvailable(sithThing *player, int binIdx)
{
    if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 && sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID)
    {
        return !!(player->actorParams.playerinfo->iteminfo[binIdx].state & ITEMSTATE_AVAILABLE);
    }
    return 0;
}

void sithInventory_SetCarries(sithThing *player, int binIdx, int bCarries)
{
    if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 && sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID)
    {
        if ( bCarries )
            player->actorParams.playerinfo->iteminfo[binIdx].state |= ITEMSTATE_CARRIES;
        else
            player->actorParams.playerinfo->iteminfo[binIdx].state &= ~ITEMSTATE_CARRIES;
    }
}

int sithInventory_GetCarries(sithThing *player, int binIdx)
{
    if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 && sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID)
    {
        return !!(player->actorParams.playerinfo->iteminfo[binIdx].state & ITEMSTATE_CARRIES);
    }
    return 0;
}

int sithInventory_IsBackpackable(sithThing *player, int binIdx)
{
    return sithInventory_aDescriptors[binIdx].flags & (ITEMINFO_VALID | ITEMINFO_MP_BACKPACK) == (ITEMINFO_VALID | ITEMINFO_MP_BACKPACK);
}

// serializedwrite

float sithInventory_GetMin(sithThing *player, int binIdx)
{
    return sithInventory_aDescriptors[binIdx].ammoMin;
}

float sithInventory_GetMax(sithThing *player, int binIdx)
{
    return sithInventory_aDescriptors[binIdx].ammoMax;
}

void sithInventory_SetFlags(sithThing *player, int binIdx, int flags)
{
    sithInventory_aDescriptors[binIdx].flags |= flags;
}

int sithInventory_GetFlags(sithThing *player, int binIdx)
{
    return sithInventory_aDescriptors[binIdx].flags;
}

void sithInventory_UnsetFlags(sithThing *player, int binIdx, int flags)
{
    sithInventory_aDescriptors[binIdx].flags &= ~flags;
}

float sithInventory_SendMessageToAllWithState(sithThing *player, int sourceType, int sourceIdx, int msgid, int stateFlags, float param0, float param1, float param2, float param3)
{
    for (int i = 0; i < 200; i++)
    {
        sithItemDescriptor* desc = &sithInventory_aDescriptors[i];

        if ( stateFlags & player->actorParams.playerinfo->iteminfo[i].state // is this order a bug?
          && player->actorParams.playerinfo != (sithPlayerInfo *)-136
          && desc->flags & ITEMINFO_VALID
          && player->actorParams.playerinfo->iteminfo[i].state & ITEMSTATE_AVAILABLE )
        {
            if ( desc->cog )
            {
                param0 = sithCog_SendMessageEx(
                             desc->cog,
                             msgid,
                             SENDERTYPE_THING,
                             player->thingIdx,
                             sourceType,
                             sourceIdx,
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

float sithInventory_SendMessageToAllWithFlag(sithThing *player, int sourceType, int sourceIdx, int msgid, int flags, float param0, float param1, float param2, float param3)
{
    for (int i = 0; i < 200; i++)
    {
        sithItemDescriptor* desc = &sithInventory_aDescriptors[i];

        if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136
          && desc->flags & ITEMINFO_VALID
          && player->actorParams.playerinfo->iteminfo[i].state & ITEMSTATE_AVAILABLE
          && desc->flags & flags )
        {
            if ( desc->cog )
            {
                param0 = sithCog_SendMessageEx(
                             desc->cog,
                             msgid,
                             SENDERTYPE_THING,
                             player->thingIdx,
                             sourceType,
                             sourceIdx,
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

void sithInventory_ClearUncarried(sithThing *player)
{
    for (int i = 0; i < 200; i++)
    {
        if (sithInventory_aDescriptors[i].flags & ITEMINFO_NOTCARRIED)
            sithInventory_SetBinAmount(player, i, 0.0);
    }
}

void sithInventory_ClearInventory(sithThing *player)
{
    for (int i = 0; i < 200; i++)
    {
        sithItemDescriptor* desc = &sithInventory_aDescriptors[i];
        sithPlayerInfo* playerinfo = player->actorParams.playerinfo;

        sithInventory_SetBinAmount(player, i, 0.0);
        
        if ( !playerinfo->iteminfo )
            continue;
                
        if ( desc->flags & ITEMINFO_DEFAULT && desc->flags & ITEMINFO_VALID)
        {
            playerinfo->iteminfo[i].state |= ITEMSTATE_AVAILABLE;
        }
        else if ( desc->flags & ITEMINFO_VALID )
        {
            playerinfo->iteminfo[i].state &= ~ITEMSTATE_AVAILABLE;
        }

        if ( desc->flags & ITEMINFO_VALID )
            playerinfo->iteminfo[i].state &= ~ITEMSTATE_ACTIVATE;

        if ( desc->flags & ITEMINFO_VALID )
            playerinfo->iteminfo[i].state &= ~ITEMSTATE_CARRIES;
    }
}

void sithInventory_SendKilledMessageToAll(sithThing *player, sithThing *sender)
{
    for (int i = 0; i < 200; i++)
    {
        sithItemDescriptor* desc = &sithInventory_aDescriptors[i];
        
        if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 
          && desc->flags & ITEMINFO_VALID 
          && player->actorParams.playerinfo->iteminfo[i].state & ITEMSTATE_AVAILABLE 
          && desc->cog )
        {
            sithCog_SendMessage(desc->cog, SITH_MESSAGE_KILLED, SENDERTYPE_THING, player->thingIdx, SENDERTYPE_THING, sender ? sender->thingIdx : -1, 0);
        }
    }
}

void sithInventory_SetBinWait(sithThing *player, int binIdx, float wait)
{
    if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 )
    {
        if ( sithInventory_aDescriptors[binIdx].flags & 1 )
            player->actorParams.playerinfo->iteminfo[binIdx].binWait = wait + sithTime_curSeconds;
    }
}
