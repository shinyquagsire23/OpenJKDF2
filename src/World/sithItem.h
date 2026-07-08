#ifndef _SITHITEM_H
#define _SITHITEM_H

#include "types.h"

#define sithItem_PlayerCollisionHandler_ADDR (0x004FBE10)
#define sithItem_Initialize_ADDR (0x004FBE70)
#define sithItem_SetItemTaken_ADDR (0x004FBEA0)
#define sithItem_DestroyItem_ADDR (0x004FBF30)
#define sithItem_ParseArg_ADDR (0x004FC030)


int sithItem_PlayerCollisionHandler(SithThing *pItem, SithThing *pPlayer, SithCollision *pCollision, int a5);
void sithItem_Initialize(SithThing *pThing);
MATH_FUNC void sithItem_SetItemTaken(SithThing *pItem, SithThing *pSrcThing, int bNoMultiSync);
void sithItem_DestroyItem(SithThing *pItem);
int sithItem_ParseArg(StdConffileArg *pArg, SithThing *pThing, int adjNum);

#endif // _SITHITEM_H
