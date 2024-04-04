#ifndef _AI_SITHAIAWARENESS_H
#define _AI_SITHAIAWARENESS_H

#include "types.h"
#include "globals.h"

#define sithAIAwareness_Startup_ADDR (0x004F29F0)
#define sithAIAwareness_Shutdown_ADDR (0x004F2A50)
#define sithAIAwareness_AddEntry_ADDR (0x004F2A90)
#define sithSector_sub_4F2B10_ADDR (0x004F2B10)
#define sithAIAwareness_Tick_ADDR (0x004F2B60)
#define sithAIAwareness_sub_4F2C30_ADDR (0x004F2C30)

int sithAIAwareness_Startup();
void sithAIAwareness_Shutdown();
int sithAIAwareness_AddEntry(sithSector *sector, rdVector3 *pos, int a3, float a4, sithThing *thing);
int sithAIAwareness_Tick(int a, sithEventInfo* b);
void sithAIAwareness_sub_4F2C30(sithSectorEntry *pSectorEntry, sithSector *pSector, rdVector3 *pPos1, rdVector3 *pPos2, float a5, float a6, sithThing *pThing);

#endif // _AI_SITHAIAWARENESS_H