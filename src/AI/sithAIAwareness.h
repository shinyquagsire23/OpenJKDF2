#ifndef _AI_SITHAIAWARENESS_H
#define _AI_SITHAIAWARENESS_H

#include "types.h"
#include "globals.h"

#define sithAIAwareness_Startup_ADDR (0x004F29F0)
#define sithAIAwareness_Close_ADDR (0x004F2A50)
#define sithAIAwareness_CreateTransmittingEvent_ADDR (0x004F2A90)
#define sithAIAwareness_sub_4F2B10_ADDR (0x004F2B10)
#define sithAIAwareness_Update_ADDR (0x004F2B60)
#define sithAIAwareness_ProcessEvent_ADDR (0x004F2C30)

int sithAIAwareness_Startup();
void sithAIAwareness_Close();
int sithAIAwareness_CreateTransmittingEvent(sithSector *sector, rdVector3 *pos, int32_t a3, flex_t a4, sithThing *thing);
void sithAIAwareness_ProcessEvents();
int sithAIAwareness_Update(int32_t a, sithEventInfo* b);
void sithAIAwareness_ProcessEvent(sithSectorEntry *pSectorEntry, sithSector *pSector, rdVector3 *pPos1, rdVector3 *pPos2, flex_t a5, flex_t a6, sithThing *pThing);

#endif // _AI_SITHAIAWARENESS_H