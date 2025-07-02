#ifndef _SITHPLAYERACTIONS_H
#define _SITHPLAYERACTIONS_H

#include "types.h"

#define sithPlayerActions_Activate_ADDR (0x004FC0A0)
#define sithPlayerActions_JumpWithVel_ADDR (0x004FC270)
#define sithPlayerActions_WarpToCheckpoint_ADDR (0x004FC450)

void sithPlayerActions_JumpWithVel(sithThing *thing, flex_t vel);
void sithPlayerActions_Activate(sithThing *thing);
void sithPlayerActions_WarpToCheckpoint(sithThing *thing, int idx);

// Added
sithThing* sithPlayerActions_SpawnThingAtLookAt(sithThing *pPlayerThing, sithThing* pTemplate);

//static void (*sithPlayerActions_Remove)(sithThing *thing) = (void*)sithPlayerActions_Remove_ADDR;
//static void (*sithPlayerActions_Activate)(sithThing*) = (void*)sithPlayerActions_Activate_ADDR;
//static void (*sithPlayerActions_WarpToCheckpoint)(sithThing *a1, int a2) = (void*)sithPlayerActions_WarpToCheckpoint_ADDR;

#endif // _SITHPLAYERACTIONS_H
