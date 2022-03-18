#include "sithInventory.h"

#include "jk.h"
#include "Cog/sithCog.h"
#include "Engine/sithTime.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "Engine/sithNet.h"
#include "World/sithSector.h"
#include "Engine/sithTemplate.h"
#include "Engine/sithControl.h"
#include "World/jkPlayer.h"
#include "Dss/sithDSSThing.h"

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
    if ( binNum + 1 < SITHBIN_NUMBINS )
    {
        for (int i = binNum + 1; i < SITHBIN_NUMBINS; i++)
        {
            sithItemDescriptor* desc =  &sithInventory_aDescriptors[i];

            if ((flags & desc->flags) && thing->actorParams.playerinfo != (sithPlayerInfo *)-136 && (desc->flags & ITEMINFO_VALID) && (thing->actorParams.playerinfo->iteminfo[i].state & ITEMSTATE_AVAILABLE))
                return i;
        }
    }
   
    if ( binNum <= 0 )
        return -1;

    for (int i = 0; i < SITHBIN_NUMBINS; i++)
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
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
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

void sithInventory_SerializedWrite(sithThing *thing)
{
    for (int i= 0; i < SITHBIN_NUMBINS; i++)
    {
        sithItemInfo* iteminfo = &thing->actorParams.playerinfo->iteminfo[i];
        if ( sithInventory_aDescriptors[i].flags & 1 )
        {
            *(float *)&std_genBuffer[0] = iteminfo->ammoAmt;
            *(int*)&std_genBuffer[4] = iteminfo->field_4;
            *(float *)&std_genBuffer[8] = iteminfo->state;
            stdConffile_Write(std_genBuffer, 12);
        }
    }
}

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
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
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
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        sithItemDescriptor* desc = &sithInventory_aDescriptors[i];

        if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136
          && desc->flags & ITEMINFO_VALID
          && player->actorParams.playerinfo // added
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

void sithInventory_Reset(sithThing *player)
{
    sithItemInfo *v2; // ecx
    int v4; // edi
    sithItemDescriptor *v5; // esi
    sithPlayerInfo *v6; // eax
    sithItemInfo *v7; // eax
    int v8; // ecx
    int v9; // edi
    sithItemDescriptor *v10; // esi
    sithItemInfo *v11; // ebp
    sithPlayerInfo *v12; // eax
    sithItemInfo *v13; // eax
    sithItemInfo *v14; // [esp+10h] [ebp-4h]
    int binIdxIter; // [esp+18h] [ebp+4h]

    v2 = player->actorParams.playerinfo->iteminfo;
    v14 = v2;
    if ( !sithInventory_549FA0 || sithNet_isMulti )
        goto LABEL_16;
    v4 = 0;
    
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        v5 = &sithInventory_aDescriptors[i];
        sithInventory_SetBinAmount(player, i, 0.0);
        v6 = player->actorParams.playerinfo;
        if ( (v5->flags & ITEMINFO_DEFAULT) != 0 )
        {
            v7 = v6->iteminfo;
            if ( !v7 )
                goto LABEL_14;
            if ( (v5->flags & ITEMINFO_VALID) == 0 )
                goto LABEL_12;
            v8 = v7[v4].state | 4;
            goto LABEL_11;
        }
        v7 = v6->iteminfo;
        if ( !v7 )
            goto LABEL_14;
        if ( (v5->flags & ITEMINFO_VALID) != 0 )
        {
            v8 = v7[v4].state & ~4u;
LABEL_11:
            v7[v4].state = v8;
        }
LABEL_12:
        if ( (v5->flags & ITEMINFO_VALID) != 0 )
            v7[v4].state &= ~2u;
LABEL_14:
        sithInventory_SetCarries(player, i, 0);
        ++v4;
    }

    v2 = v14;
    sithInventory_549FA0 = 0;
LABEL_16:
    binIdxIter = 0;
    v10 = sithInventory_aDescriptors;
    v11 = v2;
    
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        if ( (v10->flags & ITEMINFO_NOTCARRIED) != 0 )
        {
            if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 && (v10->flags & ITEMINFO_VALID) != 0 )
                player->actorParams.playerinfo->iteminfo[i].state &= ~4u;
            sithInventory_SetBinAmount(player, binIdxIter, 0.0);
            v2 = v14;
        }
        if ( v2 )
        {
            if ( (v10->flags & ITEMINFO_VALID) != 0 )
            {
                v12 = player->actorParams.playerinfo;
                v11->binWait = -1.0;
                v13 = v12->iteminfo;
                if ( v13 )
                {
                    if ( (v10->flags & ITEMINFO_VALID) != 0 )
                        v13[i].state &= ~2u;
                }
            }
        }
        ++v10;
        v11++;
        ++binIdxIter;
    }

#ifdef DEBUG_QOL_CHEATS
    sithInventory_SetBinAmount(player, SITHBIN_JEDI_RANK, 7.0);
    jkPlayer_SetRank(7);
    sithInventory_SetBinAmount(player, SITHBIN_FISTS, 1.0);
    sithInventory_SetBinAmount(player, SITHBIN_LIGHTSABER, 1.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_JUMP, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_SPEED, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_PULL, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_SEEING, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_HEALING, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_PERSUASION, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_BLINDING, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_ABSORB, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_GRIP, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_LIGHTNING, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_THROW, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_DESTRUCTION, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_DEADLYSIGHT, 4.0);
    sithInventory_SetBinAmount(player, SITHBIN_F_PROTECTION, 4.0);

    sithInventory_SetBinAmount(player, SITHBIN_FORCEMANA, 100.0);
    
    sithInventory_SetAvailable(player, SITHBIN_F_JUMP, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_SPEED, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_PULL, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_SEEING, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_HEALING, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_PERSUASION, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_BLINDING, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_ABSORB, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_GRIP, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_LIGHTNING, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_THROW, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_DESTRUCTION, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_DEADLYSIGHT, 1);
    sithInventory_SetAvailable(player, SITHBIN_F_PROTECTION, 1);

    jkPlayer_SetAccessiblePowers(7);
    //jkSaber_InitializeSaberInfo(player, "sabergreen1.mat", "sabergreen0.mat", 0.003, 0.001, 0.100, );
#endif

    v2[200].ammoAmt = 0.0;
    v2[200].field_4 = 0;
    v2[200].state = 0;
    sithInventory_bUnk = 0;
    sithInventory_bUnkPower = 0;
    sithInventory_8339EC = 0;
    sithInventory_bRendIsHidden = 0;
    sithInventory_8339F4 = 0;
}

void sithInventory_ClearUncarried(sithThing *player)
{
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        if (sithInventory_aDescriptors[i].flags & ITEMINFO_NOTCARRIED)
            sithInventory_SetBinAmount(player, i, 0.0);
    }
}

sithThing* sithInventory_CreateBackpack(sithThing *player)
{
    sithThing *templateThing;
    sithThing *backpack;

    if ( !sithNet_isMulti )
        return 0;

    templateThing = sithTemplate_GetEntryByName("+backpack");
    if ( !templateThing )
        return 0;

    backpack = sithThing_SpawnTemplate(templateThing, player);
    if ( !backpack )
        return 0;

    backpack->itemParams.numBins = 0;
    backpack->itemParams.typeflags |= THING_TYPEFLAGS_DAMAGE; // ??
    
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        sithItemDescriptor* desc = &sithInventory_aDescriptors[i];
        if ( desc->flags & ITEMINFO_VALID && (desc->flags & ITEMINFO_MP_BACKPACK))
        {
            float ammoAmt = 0.0;
            if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 && desc->flags & ITEMINFO_VALID )
                ammoAmt = player->actorParams.playerinfo->iteminfo[i].ammoAmt;

            if ( backpack->itemParams.numBins < 16 && ammoAmt > 0.0 )
            {
                backpack->itemParams.contents[backpack->itemParams.numBins].binIdx = i;
                backpack->itemParams.contents[backpack->itemParams.numBins++].value = ammoAmt;
            }
        }
    }

    sithDSSThing_SendCreateThing(templateThing, backpack, player, 0, 0, 0, 255, 1);
    sithDSSThing_SendSyncThing(backpack, -1, 255);
    return backpack;
}

void sithInventory_PickupBackpack(sithThing *player, sithThing *backpack)
{
    for (int i = 0; i < backpack->itemParams.numBins; i++)
    {
        sithBackpackItem* item = &backpack->itemParams.contents[i];
        sithItemDescriptor* desc = &sithInventory_aDescriptors[i];

        if ((desc->flags & ITEMINFO_VALID) && (desc->flags & ITEMINFO_MP_BACKPACK))
        {
            sithInventory_ChangeInv(player, item->binIdx, item->value);
        }
    }
}

int sithInventory_NthBackpackBin(sithThing *item, signed int n)
{
    if ( n >= item->itemParams.numBins )
        return -1;
    else
        return item->itemParams.contents[n].binIdx;
}

float sithInventory_NthBackpackValue(sithThing *item, signed int n)
{
    if ( n >= item->itemParams.numBins )
        return -1.0;
    else
        return item->itemParams.contents[n].value;
}

int sithInventory_NumBackpackItems(sithThing *item)
{
    return item->itemParams.numBins;
}

int sithInventory_HandleInvSkillKeys(sithThing *player, float deltaSecs)
{
    sithThing *v1; // edi
    sithKeybind *v2; // esi
    int v3; // eax
    sithCog *v4; // ecx
    int v5; // esi
    sithCog *v6; // eax
    int v7; // esi
    sithCog *v8; // eax
    sithPlayerInfo *v10; // eax
    int v11; // esi
    sithCog *v12; // eax
    int v13; // esi
    sithCog *v14; // eax
    sithPlayerInfo *v15; // eax
    int v16; // esi
    sithCog *v17; // eax
    int v18; // esi
    sithCog *v19; // eax
    int *v20; // ebp
    int v22; // eax
    int v23; // esi
    int *v24; // eax
    int v25; // eax
    sithCog *v26; // eax
    int v27; // eax
    sithPlayerInfo *v28; // ecx
    sithItemInfo *v29; // edx
    sithItemDescriptor *v30;
    int v31; // ecx
    int v32; // esi
    sithCog *v33; // ecx
    int v34; // eax
    int v35; // ebx
    int v36; // esi
    sithItemDescriptor *v38; // ebp
    sithItemInfo *v39; // [esp+10h] [ebp-4h]
    int v40; // [esp+10h] [ebp-4h]
    int keyRead;

    v1 = player;
    if ( player->type == SITH_THING_PLAYER )
    {
        v39 = player->actorParams.playerinfo->iteminfo;
        if ( (player->thingflags & 0x200) == 0 )
        {
            if ( (player->actorParams.typeflags & THING_TYPEFLAGS_IMMOBILE) != 0 )
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
                        if ( v3 >= 0
                          && v1->actorParams.playerinfo != (sithPlayerInfo *)-136
                          && (sithInventory_aDescriptors[v3].flags & ITEMINFO_VALID) != 0
                          && (v1->actorParams.playerinfo->iteminfo[v3].state & 4) != 0 )
                        {
                            v4 = sithInventory_aDescriptors[v3].cog;
                            if ( v4 )
                                sithCog_SendMessage(v4, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_0, v3, SENDERTYPE_THING, v1->thingIdx, SENDERTYPE_0);
                        }
                    }
                    v2++;
                }
                while ( (intptr_t)v2 < (intptr_t)&sithInventory_powerKeybinds[20] );
                if ( sithInventory_bUnk == 1 )
                {
                    sithInventory_bUnk = 0;
                    v5 = *(int*)(&v39[200].ammoAmt);
                    if ( v5 >= 0 )
                    {
                        if ( sithInventory_GetAvailable(v1, *(int*)(&v39[200].ammoAmt)) )
                        {
                            v6 = sithInventory_aDescriptors[v5].cog;
                            if ( v6 )
                                sithCog_SendMessage(v6, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_0, v5, SENDERTYPE_THING, v1->thingIdx, SENDERTYPE_0);
                        }
                    }
                }
                if ( sithInventory_bUnkPower == 1 )
                {
                    sithInventory_bUnkPower = 0;
                    v7 = v39[200].state;
                    if ( v7 >= 0 )
                    {
                        if ( sithInventory_GetAvailable(v1, v39[200].state) )
                        {
                            v8 = sithInventory_aDescriptors[v7].cog;
                            if ( v8 )
                            {
                                sithCog_SendMessage(v8, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_0, v7, SENDERTYPE_THING, v1->thingIdx, SENDERTYPE_0);
                                return 0;
                            }
                        }
                    }
                }
            }
            else
            {
                if ( sithControl_ReadFunctionMap(INPUT_FUNC_USEINV, &keyRead) )
                {
                    if ( !sithInventory_bUnk )
                    {
                        v10 = v1->actorParams.playerinfo;
                        v11 = *(int*)(&v39[200].ammoAmt);
                        sithInventory_bUnk = SITH_MESSAGE_ACTIVATE;
                        if ( sithTime_curSeconds >= (double)v10->iteminfo[v11].binWait && v11 >= SENDERTYPE_0 )
                        {
                            if ( sithInventory_GetAvailable(v1, v11) )
                            {
                                v12 = sithInventory_aDescriptors[v11].cog;
                                if ( v12 )
                                    sithCog_SendMessage(v12, SITH_MESSAGE_ACTIVATE, SITH_MESSAGE_ACTIVATE, v11, SENDERTYPE_THING, v1->thingIdx, SENDERTYPE_0);
                            }
                        }
                    }
                }
                else if ( sithInventory_bUnk == SITH_MESSAGE_ACTIVATE )
                {
                    sithInventory_bUnk = SENDERTYPE_0;
                    v13 = *(int*)(&v39[200].ammoAmt);
                    if ( v13 >= SENDERTYPE_0 )
                    {
                        if ( sithInventory_GetAvailable(v1, *(int*)(&v39[200].ammoAmt)) )
                        {
                            v14 = sithInventory_aDescriptors[v13].cog;
                            if ( v14 )
                                sithCog_SendMessage(v14, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_0, v13, SENDERTYPE_THING, v1->thingIdx, SENDERTYPE_0);
                        }
                    }
                }
                if ( sithControl_ReadFunctionMap(INPUT_FUNC_USESKILL, &keyRead) )
                {
                    if ( !sithInventory_bUnkPower )
                    {
                        v15 = v1->actorParams.playerinfo;
                        v16 = v39[200].state;
                        sithInventory_bUnkPower = SITH_MESSAGE_ACTIVATE;
                        if ( sithTime_curSeconds >= (double)v15->iteminfo[v16].binWait && v16 >= SENDERTYPE_0 )
                        {
                            if ( sithInventory_GetAvailable(v1, v16) )
                            {
                                v17 = sithInventory_aDescriptors[v16].cog;
                                if ( v17 )
                                    sithCog_SendMessage(v17, SITH_MESSAGE_ACTIVATE, SITH_MESSAGE_ACTIVATE, v16, SENDERTYPE_THING, v1->thingIdx, SENDERTYPE_0);
                            }
                        }
                    }
                }
                else if ( sithInventory_bUnkPower == SITH_MESSAGE_ACTIVATE )
                {
                    sithInventory_bUnkPower = SENDERTYPE_0;
                    v18 = v39[200].state;
                    if ( v18 >= SENDERTYPE_0 )
                    {
                        if ( sithInventory_GetAvailable(v1, v39[200].state) )
                        {
                            v19 = sithInventory_aDescriptors[v18].cog;
                            if ( v19 )
                                sithCog_SendMessage(v19, SITH_MESSAGE_DEACTIVATED, SENDERTYPE_0, v18, SENDERTYPE_THING, v1->thingIdx, SENDERTYPE_0);
                        }
                    }
                }
                v40 = 0;
                v20 = &sithInventory_powerKeybinds[0].idk;
                do
                {
                    if ( *(v20 - 2) == 1 )
                    {
                        int v21 = sithControl_ReadFunctionMap(v40 + INPUT_FUNC_ACTIVATE0, &keyRead) == 0;
                        v22 = *v20;
                        if ( v21 )
                        {
                            if ( v22 == 1 )
                            {
                                *v20 = 0;
                                v27 = *(v20 - 2) == 1 ? *(v20 - 1) : -1;
                                v28 = v1->actorParams.playerinfo;
                                v29 = v28->iteminfo;
                                if ( v28 == (sithPlayerInfo *)-136 || (sithInventory_aDescriptors[v27].flags & ITEMINFO_VALID) == 0 )
                                    v30 = 0;
                                else
                                    v30 = &sithInventory_aDescriptors[v27];
                                v31 = v30->flags;
                                if ( (v31 & 0x100) != 0 )
                                {
                                    v32 = 0;
                                    if ( (v31 & 8) != 0 && v29[200].state == v27 )
                                        v32 = 1;
                                    if ( (v31 & 2) != 0 && *(int*)(&v29[200].ammoAmt) == v27 )
                                        v32 = 1;
                                    if ( v32 )
                                    {
                                        if ( v27 >= 0 )
                                        {
                                            if ( v29 )
                                            {
                                                if ( (sithInventory_aDescriptors[v27].flags & ITEMINFO_VALID) != 0 && (v29[v27].state & 4) != 0 )
                                                {
                                                    v33 = sithInventory_aDescriptors[v27].cog;
                                                    if ( v33 )
                                                        sithCog_SendMessage(v33, SITH_MESSAGE_DEACTIVATED, 0, v27, SENDERTYPE_THING, v1->thingIdx, 0);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else if ( !v22 )
                        {
                            *v20 = 1;
                            v23 = *(v20 - 2) == 1 ? *(v20 - 1) : -1;
                            v24 = (int *)(v1->actorParams.playerinfo == (sithPlayerInfo *)-136 || (sithInventory_aDescriptors[v23].flags & ITEMINFO_VALID) == 0 ? 0 : &sithInventory_aDescriptors[v23]);
                            v25 = *v24;
                            if ( (v25 & 0x100) != 0 )
                            {
                                sithInventory_8339EC = 1;
                                if ( (v25 & 8) != 0 )
                                {
                                    sithInventory_SelectPower(v1, v23);
                                }
                                else if ( (v25 & 2) != 0 )
                                {
                                    sithInventory_SelectItem(v1, v23);
                                }
                                if ( sithTime_curSeconds >= (double)v1->actorParams.playerinfo->iteminfo[v23].binWait && v23 >= 0 )
                                {
                                    if ( sithInventory_GetAvailable(v1, v23) )
                                    {
                                        v26 = sithInventory_aDescriptors[v23].cog;
                                        if ( v26 )
                                            sithCog_SendMessage(v26, SITH_MESSAGE_ACTIVATE, SENDERTYPE_SYSTEM, v23, SENDERTYPE_THING, v1->thingIdx, 0);
                                    }
                                }
                            }
                        }
                    }
                    v20 += 3;
                    ++v40;
                }
                while ( (int)v20 < (int)&sithInventory_powerKeybinds[20].idk );
                sithControl_ReadFunctionMap(INPUT_FUNC_NEXTINV, &keyRead);
                while (keyRead--)
                {
                    v34 = sithInventory_GetNumBinsWithFlag(v1, v1->actorParams.playerinfo->curItem, 2);
                    sithInventory_SelectItem(v1, v34);
                    sithInventory_bRendIsHidden = 1;
                    sithInventory_8339F4 = 0;
                    sithInventory_8339EC = 0;
                }
                sithControl_ReadFunctionMap(INPUT_FUNC_PREVINV, &keyRead);

                while (keyRead--)
                {
                    v35 = v1->actorParams.playerinfo->curItem;
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
                            v38 = &sithInventory_aDescriptors[199];
                            while ( (v38->flags & 2) == 0 || !sithInventory_GetAvailable(v1, v36) )
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
                        while ( (sithInventory_aDescriptors[v36].flags & 2) == 0 || !sithInventory_GetAvailable(v1, v36) )
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
                sithControl_ReadFunctionMap(INPUT_FUNC_NEXTSKILL, &keyRead);

                while (keyRead--)
                {
                    sithInventory_SelectPowerPrior(v1);
                    sithInventory_8339F4 = 1;
                    sithInventory_bRendIsHidden = 0;
                    sithInventory_8339EC = 0;
                }
                sithControl_ReadFunctionMap(INPUT_FUNC_PREVSKILL, &keyRead);

                while (keyRead--)
                {
                    sithInventory_SelectPowerFollowing(v1);
                    sithInventory_8339F4 = 1;
                    sithInventory_bRendIsHidden = 0;
                    sithInventory_8339EC = 0;
                }
            }
        }
    }
    return 0;
}

void sithInventory_SendFire(sithThing *player)
{
    for (int i = 0; i < SITHBIN_NUMBINS; i++) // TODO I think the actual game has an off by one here
    {
        sithItemInfo* iteminfo = &player->actorParams.playerinfo->iteminfo[i];
        sithItemDescriptor* desc = &sithInventory_aDescriptors[i];
        
        if ( iteminfo->activationDelaySecs > 0.0 
             && sithTime_curSeconds >= iteminfo->binWait 
             && desc->flags & ITEMINFO_POWER )
        {
            if ( desc->cog )
            {
                iteminfo->binWait = sithTime_curSeconds + iteminfo->activationDelaySecs;
                sithCog_SendMessageEx(desc->cog, SITH_MESSAGE_FIRE, SENDERTYPE_SYSTEM, i, SENDERTYPE_THING, player->thingIdx, 0, 0.0, 0.0, 0.0, 0.0);
            }
        }
    }
}

sithItemInfo* sithInventory_GetBin(sithThing *player, int binIdx)
{
    if ( player->actorParams.playerinfo != (sithPlayerInfo *)-136 
         && sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID )
        return &player->actorParams.playerinfo->iteminfo[binIdx];
    else
        return NULL;
}

sithItemDescriptor* sithInventory_GetItemDesc(sithThing *player, int idx)
{
    if ( player->actorParams.playerinfo == (sithPlayerInfo *)-136 
    || !(sithInventory_aDescriptors[idx].flags & ITEMINFO_VALID) )
        return NULL;

    return &sithInventory_aDescriptors[idx];
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
        if ( (sithInventory_aDescriptors[i].flags & 0x100) != 0 )
        {
            sithControl_sub_4D6930(v0 + 42);
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

void sithInventory_ClearInventory(sithThing *player)
{
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
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

void sithInventory_SendKilledMessageToAll(sithThing *player, sithThing *sender)
{
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
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
        if ( sithInventory_aDescriptors[binIdx].flags & ITEMINFO_VALID )
            player->actorParams.playerinfo->iteminfo[binIdx].binWait = wait + sithTime_curSeconds;
    }
}
