#ifndef _SITHINVENTORY_H
#define _SITHINVENTORY_H

#include "types.h"
#include "globals.h"

#define sithInventory_RegisterType_ADDR (0x004D1120)
#define sithInventory_FindNextTypeID_ADDR (0x004D1180)
#define sithInventory_FindPreviousTypeID_ADDR (0x004D1220)
#define sithInventory_FindNextItemID_ADDR (0x004D12C0)
#define sithInventory_FindPreviousItemID_ADDR (0x004D1380)
#define sithInventory_SelectItem_ADDR (0x004D1440)
#define sithInventory_SelectNextItem_ADDR (0x004D1540)
#define sithInventory_SelectPreviousItem_ADDR (0x004D15F0)
#define sithInventory_SelectWeaponFollowing_ADDR (0x004D16A0)
#define sithInventory_GetType_ADDR (0x004D16D0)
#define sithInventory_GetCurrentWeapon_ADDR (0x004D16F0)
#define sithInventory_SetCurrentWeapon_ADDR (0x004D1710)
#define sithInventory_GetCurrentItem_ADDR (0x004D1730)
#define sithInventory_SetCurrentItem_ADDR (0x004D1750)
#define sithInventory_GetCurPower_ADDR (0x004D1770)
#define sithInventory_SetCurPower_ADDR (0x004D1790)
#define sithInventory_GetWeaponPrior_ADDR (0x004D17B0)
#define sithInventory_GetWeaponFollowing_ADDR (0x004D1850)
#define sithInventory_GetPowerPrior_ADDR (0x004D18F0)
#define sithInventory_GetPowerFollowing_ADDR (0x004D1990)
#define sithInventory_SelectPowerPrior_ADDR (0x004D1A30)
#define sithInventory_SelectPowerFollowing_ADDR (0x004D1B90)
#define sithInventory_ActivateBin_ADDR (0x004D1CE0)
#define sithInventory_DeactivateBin_ADDR (0x004D1DA0)
#define sithInventory_BinSendActivate_ADDR (0x004D1E10)
#define sithInventory_BinSendDeactivate_ADDR (0x004D1E90)
#define sithInventory_ChangeInventory_ADDR (0x004D1EF0)
#define sithInventory_GetInventory_ADDR (0x004D1FC0)
#define sithInventory_SetInventory_ADDR (0x004D2000)
#define sithInventory_SetInventoryActivated_ADDR (0x004D20C0)
#define sithInventory_IsInventoryActivated_ADDR (0x004D2110)
#define sithInventory_SetInventoryAvailable_ADDR (0x004D2150)
#define sithInventory_IsInventoryAvailable_ADDR (0x004D21A0)
#define sithInventory_SetCarries_ADDR (0x004D21E0)
#define sithInventory_GetCarries_ADDR (0x004D2230)
#define sithInventory_IsBackpackItem_ADDR (0x004D2270)
#define sithInventory_SerializedWrite_ADDR (0x004D22A0)
#define sithInventory_GetInventoryMinimum_ADDR (0x004D2300)
#define sithInventory_GetInventoryMaximum_ADDR (0x004D2320)
#define sithInventory_SetInventoryFlags_ADDR (0x004D2340)
#define sithInventory_GetInventoryFlags_ADDR (0x004D2370)
#define sithInventory_ClearInventoryFlags_ADDR (0x004D2390)
#define sithInventory_BroadcastInventoryMessage_ADDR (0x004D23C0)
#define sithInventory_BroadcastMessage_ADDR (0x004D24A0)
#define sithInventory_ResetInventory_ADDR (0x004D2560)
#define sithInventory_ResetAllTypes_ADDR (0x004D2700)
#define sithInventory_CreateBackpack_ADDR (0x004D2740)
#define sithInventory_PickupBackpack_ADDR (0x004D2860)
#define sithInventory_GetBackpackItemID_ADDR (0x004D28C0)
#define sithInventory_GetBackpackItemValue_ADDR (0x004D28E0)
#define sithInventory_GetNumBackpackItems_ADDR (0x004D2910)
#define sithInventory_HandleInvSkillKeys_ADDR (0x004D2920)
#define sithInventory_SendFire_ADDR (0x004D3020)
#define sithInventory_GetBin_ADDR (0x004D30B0)
#define sithInventory_GetInventoryType_ADDR (0x004D30F0)
#define sithInventory_KeybindInit_ADDR (0x004D3120)
#define sithInventory_SetPowerKeybind_ADDR (0x004D3190)
#define sithInventory_GetPowerKeybind_ADDR (0x004D31C0)
#define sithInventory_InitInventory_ADDR (0x004D31E0)
#define sithInventory_BroadcastKilledMessage_ADDR (0x004D3280)
#define sithInventory_SetBinWait_ADDR (0x004D32F0)
#define sithInventory_SelectPower_ADDR (0x004D3330)

void sithInventory_RegisterType(int binIdx, sithCog *cog, char *name, flex_t min, flex_t max, int flags);
int sithInventory_FindNextTypeID(SithThing *pThing, int startSearchId, int flags);
int sithInventory_FindPreviousTypeID(SithThing *pThing, int binNum, int flags);
int sithInventory_FindNextItemID(SithThing *pThing, signed int itemId);
int sithInventory_FindPreviousItemID(SithThing *pThing, signed int itemId);
void sithInventory_SelectItem(SithThing *pThing, int typeId);
void sithInventory_SelectNextItem(SithThing *pThing);
void sithInventory_SelectPreviousItem(SithThing *pThing);
int sithInventory_SelectWeaponPrior(int param_1); // MOTS added
int sithInventory_SelectWeaponFollowing(int idx);
SithInventoryType* sithInventory_GetType(int typeId);
int sithInventory_GetCurrentWeapon(SithThing *pThing);
void sithInventory_SetCurrentWeapon(SithThing *pThing, int weaponID);
int sithInventory_GetCurrentItem(SithThing *pThing);
void sithInventory_SetCurrentItem(SithThing *pThing, int typeId);
int sithInventory_GetCurPower(SithThing *player);
void sithInventory_SetCurPower(SithThing *player, int idx);
int sithInventory_GetWeaponPrior(SithThing *thing, int binNum);
int sithInventory_GetWeaponFollowing(SithThing *thing, int binNum);
int sithInventory_GetPowerPrior(SithThing *thing, int binNum);
int sithInventory_GetPowerFollowing(SithThing *thing, int binNum);
void sithInventory_SelectPower(SithThing *player, int binNum);
void sithInventory_SelectPowerPrior(SithThing *player);
void sithInventory_SelectPowerFollowing(SithThing *player);
int sithInventory_ActivateBin(SithThing *player, sithCog *cog, flex_t delay, int binNum);
flex_t sithInventory_DeactivateBin(SithThing *player, sithCog *unused, int binNum);
int sithInventory_BinSendActivate(SithThing *player, int binIdx);
void sithInventory_BinSendDeactivate(SithThing *player, int senderIndex);
flex_t sithInventory_ChangeInventory(SithThing *pThing, int typeId, flex_t amount);
flex_t sithInventory_GetInventory(SithThing *pThing, int typeId);
flex_t sithInventory_SetInventory(SithThing *pThing, int typeId, flex_t amount);
void sithInventory_SetInventoryActivated(SithThing *pThing, int typeId, int bActivated);
int sithInventory_IsInventoryActivated(SithThing *pThing, int typeId);
void sithInventory_SetInventoryAvailable(SithThing *pThing, int typeId, int bAvailable);
int sithInventory_IsInventoryAvailable(SithThing *pThing, int typeId);
void sithInventory_SetCarries(SithThing *player, int binIdx, int bCarries);
int sithInventory_GetCarries(SithThing *player, int binIdx);
int sithInventory_IsBackpackItem(SithThing *pThing, int typeId);
void sithInventory_SerializedWrite(SithThing *thing);
flex_t sithInventory_GetInventoryMinimum(SithThing *pThing, int id);
flex_t sithInventory_GetInventoryMaximum(SithThing *pThing, int id);
void sithInventory_SetInventoryFlags(SithThing *pThing, int id, int flags);
int sithInventory_GetInventoryFlags(SithThing *pThing, int id);
void sithInventory_ClearInventoryFlags(SithThing *pThing, int id, int flags);
flex_t sithInventory_BroadcastInventoryMessage(SithThing *pThing, int srcType, int srcIdx, int msg, int status, flex_t param0, flex_t param1, flex_t param2, flex_t param3);
flex_t sithInventory_BroadcastMessage(SithThing *pThing, int srcType, int srcIdx, int messageType, int flags, flex_t param0, flex_t param1, flex_t param2, flex_t param3);
void sithInventory_ResetInventory(SithThing *pThing);
void sithInventory_ResetAllTypes(SithThing *pThing);
SithThing* sithInventory_CreateBackpack(SithThing *pThing);
void sithInventory_PickupBackpack(SithThing *pPlayerThing, SithThing *pBackpackThing);
int sithInventory_GetBackpackItemID(SithThing *player, signed int itemNum);
flex_t sithInventory_GetBackpackItemValue(SithThing *pBackpackThing, signed int itemNum);
int sithInventory_GetNumBackpackItems(SithThing *pBackpackThing);
int sithInventory_HandleInvSkillKeys(SithThing *player, flex_t deltaSecs);
//static int (*sithInventory_HandleInvSkillKeys)(SithThing *player, flex_t b) = (void*)sithInventory_HandleInvSkillKeys_ADDR;
void sithInventory_SendFire(SithThing *player);
SithInventoryItem* sithInventory_GetBin(SithThing *player, int binIdx);
SithInventoryType* sithInventory_GetInventoryType(SithThing *pThing, int typeId);
int sithInventory_KeybindInit();
//static void (*sithInventory_KeybindInit)() = (void*)sithInventory_KeybindInit_ADDR;
void sithInventory_SetPowerKeybind(int idx, int binding);
int sithInventory_GetPowerKeybind(int idx);
void sithInventory_InitInventory(SithThing *pThing);
void sithInventory_BroadcastKilledMessage(SithThing *pSender, SithThing *pKiller);
void sithInventory_SetBinWait(SithThing *player, int binIdx, flex_t wait);

#endif // _SITHINVENTORY_H
