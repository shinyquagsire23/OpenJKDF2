#ifndef _SITHITEM_H
#define _SITHITEM_H

#include "types.h"

#define sithItem_Collide_ADDR (0x004FBE10)
#define sithItem_New_ADDR (0x004FBE70)
#define sithItem_Take_ADDR (0x004FBEA0)
#define sithItem_Remove_ADDR (0x004FBF30)
#define sithItem_LoadThingParams_ADDR (0x004FC030)


int sithItem_Collide(sithThing *a1, sithThing *a2, sithCollisionSearchEntry *a4, int a5);
void sithItem_New(sithThing *out);
MATH_FUNC void sithItem_Take(sithThing *item, sithThing *actor, int a3);
void sithItem_Remove(sithThing *item);
int sithItem_LoadThingParams(stdConffileArg *arg, sithThing *thing, int paramIdx);

#endif // _SITHITEM_H
