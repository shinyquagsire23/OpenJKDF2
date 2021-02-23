#ifndef _SITHSOUNDCLASS_H
#define _SITHSOUNDCLASS_H

#define sithSoundClass_sub_4DD080_ADDR (0x004DD080)
#define sithSoundClass_Startup_ADDR (0x004E63E0)
#define sithSoundClass_Shutdown_ADDR (0x004E6480)
#define sithSoundClass_Load_ADDR (0x004E64C0)
#define sithSoundClass_sub_4E66E0_ADDR (0x004E66E0)
#define sithSoundClass_LoadEntry_ADDR (0x004E67D0)
#define sithSoundClass_allocidk_ADDR (0x004E6980)
#define sithSoundClass_Free_ADDR (0x004E69E0)
#define sithSoundClass_Free2_ADDR (0x004E6A30)
#define sithSoundClass_PlayThingSoundclass_ADDR (0x004E6AF0)
#define sithSoundClass_ThingPlaySoundclass4_ADDR (0x004E6B30)
#define sithSoundClass_ThingPlaySoundclass_ADDR (0x004E6B70)
#define sithSoundClass_ThingPlaySoundclass5_ADDR (0x004E6C10)
#define sithSoundClass_ThingPauseSoundclass_ADDR (0x004E6CA0)
#define sithSoundClass_ThingPlaySoundclass2_ADDR (0x004E6CD0)
#define sithSoundClass_sub_4E6D70_ADDR (0x004E6D70)


enum SITH_SC
{
    SITH_SC_0        = 0,
    SITH_SC_CREATE   = 1,
    SITH_SC_ACTIVATE  = 2,
    SITH_SC_STARTMOVE  = 3,
    SITH_SC_STOPMOVE  = 4,
    SITH_SC_MOVING   = 5,
    SITH_SC_LWALKHARD  = 6,
    SITH_SC_RWALKHARD  = 7,
    SITH_SC_LRUNHARD  = 8,
    SITH_SC_RRUNHARD  = 9,
    SITH_SC_LWALKMETAL  = 10,
    SITH_SC_RWALKMETAL  = 11,
    SITH_SC_LRUNMETAL  = 12,
    SITH_SC_RRUNMETAL  = 13,
    SITH_SC_LWALKWATER  = 14,
    SITH_SC_RWALKWATER  = 15,
    SITH_SC_LRUNWATER  = 16,
    SITH_SC_RRUNWATER  = 17,
    SITH_SC_LWALKPUDDLE  = 18,
    SITH_SC_RWALKPUDDLE  = 19,
    SITH_SC_LRUNPUDDLE  = 20,
    SITH_SC_RRUNPUDDLE  = 21,
    SITH_SC_LWALKEARTH  = 22,
    SITH_SC_RWALKEARTH  = 23,
    SITH_SC_LRUNEARTH  = 24,
    SITH_SC_RRUNEARTH  = 25,
    SITH_SC_ENTERWATER  = 26,
    SITH_SC_ENTERWATERSLOW  = 27,
    SITH_SC_EXITWATER  = 28,
    SITH_SC_EXITWATERSLOW  = 29,
    SITH_SC_LSWIMSURFACE  = 30,
    SITH_SC_RSWIMSURFACE  = 31,
    SITH_SC_TREADSURFACE  = 32,
    SITH_SC_LSWIMUNDER  = 33,
    SITH_SC_RSWIMUNDER  = 34,
    SITH_SC_TREADUNDER  = 35,
    SITH_SC_JUMP     = 36,
    SITH_SC_JUMPMETAL  = 37,
    SITH_SC_JUMPWATER  = 38,
    SITH_SC_JUMPEARTH  = 39,
    SITH_SC_LANDHARD  = 40,
    SITH_SC_LANDMETAL  = 41,
    SITH_SC_LANDWATER  = 42,
    SITH_SC_LANDPUDDLE  = 43,
    SITH_SC_LANDEARTH  = 44,
    SITH_SC_LANDHURT  = 45,
    SITH_SC_HITHARD  = 46,
    SITH_SC_HITMETAL  = 47,
    SITH_SC_HITEARTH  = 48,
    SITH_SC_DEFLECTED  = 49,
    SITH_SC_SCRAPEHARD  = 50,
    SITH_SC_SCRAPEMETAL  = 51,
    SITH_SC_SCRAPEEARTH  = 52,
    SITH_SC_HITDAMAGED  = 53,
    SITH_SC_FALLING  = 54,
    SITH_SC_CORPSEHIT  = 55,
    SITH_SC_HURTIMPACT  = 56,
    SITH_SC_HURTENERGY  = 57,
    SITH_SC_HURTFIRE  = 58,
    SITH_SC_HURTMAGIC  = 59,
    SITH_SC_HURTSPECIAL  = 60,
    SITH_SC_DROWNING  = 61,
    SITH_SC_CHOKING  = 62,
    SITH_SC_DEATH1   = 63,
    SITH_SC_DEATH2   = 64,
    SITH_SC_DEATHUNDER  = 65,
    SITH_SC_DROWNED  = 66,
    SITH_SC_SPLATTERED  = 67,
    SITH_SC_PANT     = 68,
    SITH_SC_BREATH   = 69,
    SITH_SC_GASP     = 70,
    SITH_SC_FIRE1    = 71,
    SITH_SC_FIRE2    = 72,
    SITH_SC_FIRE3    = 73,
    SITH_SC_FIRE4    = 74,
    SITH_SC_CURIOUS  = 75,
    SITH_SC_ALERT    = 76,
    SITH_SC_IDLE     = 77,
    SITH_SC_GLOAT    = 78,
    SITH_SC_FEAR     = 79,
    SITH_SC_BOAST    = 80,
    SITH_SC_HAPPY    = 81,
    SITH_SC_VICTORY  = 82,
    SITH_SC_HELP     = 83,
    SITH_SC_FLEE     = 84,
    SITH_SC_SEARCH   = 85,
    SITH_SC_CALM     = 86,
    SITH_SC_SURPRISE  = 87,
    SITH_SC_RESERVED1  = 88,
    SITH_SC_RESERVED2  = 89,
    SITH_SC_RESERVED3  = 90,
    SITH_SC_RESERVED4  = 91,
    SITH_SC_RESERVED5  = 92,
    SITH_SC_RESERVED6  = 93,
    SITH_SC_RESERVED7  = 94,
    SITH_SC_RESERVED8  = 95
};

typedef struct sithSoundClass
{
    char snd_fname[32];
    int field_20;
    int field_24;
    int field_28;
    int field_2C;
    int field_30;
    int field_34;
    int field_38;
    int field_3C;
    int field_40;
    int field_44;
    int field_48;
    int field_4C;
    int field_50;
    int field_54;
    int field_58;
    int field_5C;
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
    int field_A4;
    int field_A8;
    int field_AC;
    int field_B0;
    int field_B4;
    int field_B8;
    int field_BC;
    int field_C0;
    int field_C4;
    int field_C8;
    int field_CC;
    int field_D0;
    int field_D4;
    int field_D8;
    int field_DC;
    int field_E0;
    int field_E4;
    int field_E8;
    int field_EC;
    int field_F0;
    int field_F4;
    int field_F8;
    int field_FC;
    int field_100;
    int field_104;
    int field_108;
    int field_10C;
    int field_110;
    int field_114;
    int field_118;
    int field_11C;
    int field_120;
    int field_124;
    int field_128;
    int field_12C;
    int field_130;
    int field_134;
    int field_138;
    int field_13C;
    int field_140;
    int field_144;
    int field_148;
    int field_14C;
    int field_150;
    int field_154;
    int field_158;
    int field_15C;
    int field_160;
    int field_164;
    int field_168;
    int field_16C;
    int field_170;
    int field_174;
    int field_178;
    int field_17C;
    int field_180;
    int field_184;
    int field_188;
    int field_18C;
    int field_190;
    int field_194;
    int field_198;
    int field_19C;
} sithSoundClass;

static int (*sithSoundClass_Load)(sithWorld* world, int a) = (void*)sithSoundClass_Load_ADDR;
static sithSoundClass* (*sithSoundClass_ThingPlaySoundclass)(sithThing *a1, unsigned int a2) = (void*)sithSoundClass_ThingPlaySoundclass_ADDR;
static void (*sithSoundClass_ThingPlaySoundclass4)(sithThing *a1, unsigned int a2) = (void*)sithSoundClass_ThingPlaySoundclass4_ADDR;
static void (*sithSoundClass_ThingPauseSoundclass)(sithThing *a1, unsigned int a2) = (void*)sithSoundClass_ThingPauseSoundclass_ADDR;

#endif // _SITHSOUNDCLASS_H
