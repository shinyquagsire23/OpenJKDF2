#ifndef _SITHITEM_H
#define _SITHITEM_H

#define sithItem_Collide_ADDR (0x004FBE10)
#define sithItem_CreateThing_ADDR (0x004FBE70)
#define sithItem_Take_ADDR (0x004FBEA0)
#define sithItem_Remove_ADDR (0x004FBF30)
#define sithItem_LoadThingParams_ADDR (0x004FC030)

static int (*sithItem_Collide)(sithThing *a1, sithThing *a2) = (void*)sithItem_Collide_ADDR;

#endif // _SITHITEM_H
