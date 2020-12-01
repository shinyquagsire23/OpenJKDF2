#ifndef _JKEPISODE_H
#define _JKEPISODE_H

#define jkEpisode_LoadVerify_ADDR (0x0040DD70)
#define jkEpisode_Load_ADDR (0x0040D560)

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

typedef struct jkEpisodeLoad
{
    int field_0;
    int field_4;
    int field_8;
    int field_C;
} jkEpisodeLoad;

#define jkEpisode_aEpisodes ((jkEpisode*)0x8568E0)
#define jkEpisode_var4 ((char*)0x005540D8)
#define jkEpisode_var5 ((char*)0x00554158)
#define jkEpisode_var2 (*(int*)0x005541D8)

static int (*jkEpisode_Load)(jkEpisodeLoad *a1) = (void*)jkEpisode_Load_ADDR;
static unsigned int (*jkEpisode_LoadVerify)() = (void*)jkEpisode_LoadVerify_ADDR;

#endif // _JKEPISODE_H
