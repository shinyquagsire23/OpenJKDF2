#ifndef _SITHITEM_H
#define _SITHITEM_H

#include "types.h"

#define sithItem_PlayerCollisionHandler_ADDR (0x004FBE10)
#define sithItem_Initialize_ADDR (0x004FBE70)
#define sithItem_SetItemTaken_ADDR (0x004FBEA0)
#define sithItem_DestroyItem_ADDR (0x004FBF30)
#define sithItem_ParseArg_ADDR (0x004FC030)


int sithItem_PlayerCollisionHandler(sithThing *a1, sithThing *a2, sithCollisionSearchEntry *a4, int a5);
void sithItem_Initialize(sithThing *out);
MATH_FUNC void sithItem_SetItemTaken(sithThing *item, sithThing *actor, int a3);
void sithItem_DestroyItem(sithThing *item);
int sithItem_ParseArg(stdConffileArg *arg, sithThing *thing, int paramIdx);

#endif // _SITHITEM_H
