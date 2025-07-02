#ifndef _JKEPISODE_H
#define _JKEPISODE_H

#include "types.h"

#define jkEpisode_Startup_ADDR (0x0040D510)
#define jkEpisode_Shutdown_ADDR (0x0040D530)
#define jkEpisode_UpdateExtra_ADDR (0x0040D540)
#define jkEpisode_Load_ADDR (0x0040D560)
#define jkEpisode_GetCurrentEpisodeEntry_ADDR (0x0040DC50)
#define jkEpisode_GetNextEntryInDecisionPath_ADDR (0x0040DC60)
#define jkEpisode_EndLevel_ADDR (0x0040DCD0)
#define jkEpisode_idk4_ADDR (0x0040DD10)
#define jkEpisode_LoadVerify_ADDR (0x0040DD70)
#define jkEpisode_idk6_ADDR (0x0040E2B0)

int jkEpisode_Startup();
void jkEpisode_Shutdown();
int jkEpisode_LoadVerify();
int jkEpisode_Load(jkEpisodeLoad *a1);
jkEpisodeEntry* jkEpisode_GetCurrentEpisodeEntry(jkEpisodeLoad *a1);
jkEpisodeEntry* jkEpisode_GetNextEntryInDecisionPath(jkEpisodeLoad *pLoad, int bIsAPath);
int jkEpisode_EndLevel(jkEpisodeLoad *pEpisode, int levelNum);
int jkEpisode_UpdateExtra(sithThing *thing);
int jkEpisode_idk4(jkEpisodeLoad *pEpisodeLoad, char *pEpisodeName);
int jkEpisode_idk6(const char *pName);

void jkEpisode_CreateBubble(sithThing *pThing,flex_t radius,uint32_t type); // MOTS added
void jkEpisode_DestroyBubble(sithThing *pThing); // MOTS added
int jkEpisode_GetBubbleInfo(sithThing *pThing,uint32_t *pTypeOut,sithThing **pThingOut,flex_t *pOut); // MOTS added

//static int (*jkEpisode_Startup)() = (void*)jkEpisode_Startup_ADDR;
//static int (*jkEpisode_Load)(jkEpisodeLoad *a1) = (void*)jkEpisode_Load_ADDR;
//static unsigned int (*jkEpisode_LoadVerify)() = (void*)jkEpisode_LoadVerify_ADDR;

#endif // _JKEPISODE_H
