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

typedef struct jkEpisode
{
    char name[32];
    wchar_t unistr[32];
    int field_60;
    int field_64;
    int field_68;
    int field_6C;
    int field_70;
    int field_74;
    int field_78;
    int field_7C;
    int field_80;
    int field_84;
    int field_88;
    int field_8C;
    int field_90;
    int field_94;
    int field_98;
    int field_9C;
    int field_A0;
} jkEpisode;

typedef struct jkEpisodeEntry
{
    int lineNum;
    int cdNum;
    int level;
    int type;
    char fileName[32];
    int lightpow;
    int darkpow;
    int gotoA;
    int gotoB;
} jkEpisodeEntry;


typedef struct jkEpisodeLoad
{
    int field_0;
    int numSeq;
    int field_8;
    jkEpisodeEntry* paEntries;
} jkEpisodeLoad;
#define jkEpisode_aEpisodes ((jkEpisode*)0x8568E0)
#define jkEpisode_var4 ((char*)0x005540D8)
#define jkEpisode_var5 ((char*)0x00554158)
#define jkEpisode_var2 (*(uint32_t*)0x005541D8)
#define jkEpisode_mLoad (*(jkEpisodeLoad*)0x00552B68)

int jkEpisode_Startup();
int jkEpisode_LoadVerify();
int jkEpisode_Load(jkEpisodeLoad *a1);
jkEpisodeEntry* jkEpisode_idk1(jkEpisodeLoad *a1);
jkEpisodeEntry* jkEpisode_idk2(jkEpisodeLoad *pLoad, int bIsAPath);
void jkEpisode_UpdateExtra(sithThing *thing);

//static int (*jkEpisode_Startup)() = (void*)jkEpisode_Startup_ADDR;
//static int (*jkEpisode_Load)(jkEpisodeLoad *a1) = (void*)jkEpisode_Load_ADDR;
//static unsigned int (*jkEpisode_LoadVerify)() = (void*)jkEpisode_LoadVerify_ADDR;

#endif // _JKEPISODE_H
