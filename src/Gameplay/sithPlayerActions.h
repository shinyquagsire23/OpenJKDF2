#ifndef _SITHPLAYERACTIONS_H
#define _SITHPLAYERACTIONS_H

#include "types.h"

#define sithPlayerActions_Activate_ADDR (0x004FC0A0)
#define sithPlayerActions_JumpWithVel_ADDR (0x004FC270)
#define sithPlayerActions_MoveToPlayerPosition_ADDR (0x004FC450)

MATH_FUNC void sithPlayerActions_JumpWithVel(SithThing *thing, flex_t vel);
void sithPlayerActions_Activate(SithThing *thing);
void sithPlayerActions_MoveToPlayerPosition(SithThing *thing, int idx);

// Added
SithThing* sithPlayerActions_SpawnThingAtLookAt(SithThing *pPlayerThing, SithThing* pCreateThingTemplate);

//static void (*sithPlayerActions_Remove)(SithThing *thing) = (void*)sithPlayerActions_Remove_ADDR;
//static void (*sithPlayerActions_Activate)(SithThing*) = (void*)sithPlayerActions_Activate_ADDR;
//static void (*sithPlayerActions_MoveToPlayerPosition)(SithThing *a1, int a2) = (void*)sithPlayerActions_MoveToPlayerPosition_ADDR;

#endif // _SITHPLAYERACTIONS_H
