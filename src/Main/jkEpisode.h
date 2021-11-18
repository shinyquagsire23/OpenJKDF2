#ifndef _JKEPISODE_H
#define _JKEPISODE_H

#include "types.h"

#define jkEpisode_Startup_ADDR (0x0040D510)
#define jkEpisode_Shutdown_ADDR (0x0040D530)
#define jkEpisode_UpdateExtra_ADDR (0x0040D540)
#define jkEpisode_Load_ADDR (0x0040D560)
#define jkEpisode_idk1_ADDR (0x0040DC50)
#define jkEpisode_idk2_ADDR (0x0040DC60)
#define jkEpisode_EndLevel_ADDR (0x0040DCD0)
#define jkEpisode_idk4_ADDR (0x0040DD10)
#define jkEpisode_LoadVerify_ADDR (0x0040DD70)
#define jkEpisode_idk6_ADDR (0x0040E2B0)

int jkEpisode_Startup();
int jkEpisode_LoadVerify();
int jkEpisode_Load(jkEpisodeLoad *a1);
jkEpisodeEntry* jkEpisode_idk1(jkEpisodeLoad *a1);
jkEpisodeEntry* jkEpisode_idk2(jkEpisodeLoad *pLoad, int bIsAPath);
int jkEpisode_EndLevel(jkEpisodeLoad *pEpisode, int levelNum);
void jkEpisode_UpdateExtra(sithThing *thing);

//static int (*jkEpisode_Startup)() = (void*)jkEpisode_Startup_ADDR;
//static int (*jkEpisode_Load)(jkEpisodeLoad *a1) = (void*)jkEpisode_Load_ADDR;
//static unsigned int (*jkEpisode_LoadVerify)() = (void*)jkEpisode_LoadVerify_ADDR;

#endif // _JKEPISODE_H
