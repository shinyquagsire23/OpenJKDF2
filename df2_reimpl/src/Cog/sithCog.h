#ifndef _SITHCOG_H
#define _SITHCOG_H

#include <stdint.h>

#define jkCog_RegisterVerbs_ADDR (0x40A110)
#define jkCog_Initialize_ADDR (0x40A0C0)
#define sithCog_Startup_ADDR    (0x4DE070)
#define sithCogUtil_Initialize_ADDR (0x00505400)
#define sithCogThing_Initialize_ADDR (0x005014E0)
#define sithCogAI_Initialize_ADDR (0x00500B00)
#define sithCogSound_Initialize_ADDR (0x004FF060)
#define sithCogPlayer_Initialize_ADDR (0x004E0780)
#define sithCogSector_Initialize_ADDR (0x004FE680)
#define sithCogSurface_Initialize_ADDR (0x004FFB50)

#define sithCogYACC_yyparse_ADDR (0x50BF50)

typedef int SITH_MESSAGE;

typedef struct sithCogCallstack
{
    uint32_t field_0;
    uint32_t* script_running;
    uint32_t field_8;
    uint32_t field_C;
} sithCogCallstack;

typedef struct sithCogStackvar
{
    uint32_t type;
    uint32_t data[3];
} sithCogStackvar;

typedef struct sithCog sithCog;

typedef struct sithCog
{
    void* cogscript; // sithCogScript*
    uint32_t flags;
    sithCog* selfCog;
    uint32_t script_running;
    uint32_t cogscript_pc;
    uint32_t wakeTimeMs;
    uint32_t field_18;
    uint32_t field_1C;
    uint32_t field_20;
    uint32_t senderId;
    uint32_t senderRef;
    uint32_t senderType;
    uint32_t sourceRef;
    uint32_t sourceType;
    uint32_t field_38;
    float params[4];
    float returnEx;
    sithCogCallstack callstack[4];
    uint32_t calldepth;
    void* variable_hashmap_maybe;
    sithCogStackvar variable_array[64];
    uint32_t stack_pos_idk;
    char cogscript_fpath[32];
    char field_4BC[4104];
} sithCog;

enum COGFLAGS
{
    COGFLAGS_TRACE = 1,
    COGFLAGS_PAUSED = 2,
};

enum COG_TYPE
{
    COG_TYPE_VERB    = 0,
    COG_TYPE_1       = 1,
    COG_TYPE_GLOBAL  = 2,
    COG_TYPE_MESSAGE  = 3
};

enum COGMSG_ID
{
    COGMSG_TELEPORTTHING  = 1,
    COGMSG_CHAT      = 2,
    COGMSG_SYNCSECTORALT  = 3,
    COGMSG_FIREPROJECTILE  = 4,
    COGMSG_DEATH     = 5,
    COGMSG_DAMAGE    = 6,
    COGMSG_SETTHINGMODEL  = 7,
    COGMSG_SENDTRIGGER  = 8,
    COGMSG_PLAYKEY   = 9,
    COGMSG_PLAYSOUNDPOS  = 10,
    COGMSG_SYNCTHING  = 11,
    COGMSG_SYNCTHINGFULL  = 12,
    COGMSG_SYNCCOG   = 13,
    COGMSG_SYNCSURFACE  = 14,
    COGMSG_SYNCAI    = 15,
    COGMSG_SYNCITEMDESC  = 16,
    COGMSG_STOPANIM  = 17,
    COGMSG_SYNCSECTOR  = 18,
    COGMSG_OPENDOOR  = 19,
    COGMSG_SYNCTHINGFRAME  = 20,
    COGMSG_SYNCPUPPET  = 21,
    COGMSG_SYNCTHINGATTACHMENT  = 22,
    COGMSG_SYNCTIMERS  = 23,
    COGMSG_SYNCCAMERAS  = 24,
    COGMSG_TAKEITEM1  = 25,
    COGMSG_TAKEITEM2  = 26,
    COGMSG_STOPKEY   = 27,
    COGMSG_STOPSOUND  = 28,
    COGMSG_CREATETHING  = 29,
    COGMSG_SYNCPALEFFECTS  = 30,
    COGMSG_ID_1F     = 31,
    COGMSG_LEAVEJOIN  = 32,
    COGMSG_JOINLEAVE  = 33,
    COGMSG_REQUESTCONNECT  = 34,
    COGMSG_DESTROYTHING  = 35,
    COGMSG_JOINING   = 36,
    COGMSG_SOUNDCLASSPLAY  = 37,
    COGMSG_PING      = 38,
    COGMSG_PINGREPLY  = 39,
    COGMSG_RESET     = 40,
    COGMSG_ENUMPLAYERS  = 41,
    COGMSG_KICK      = 42,
    COGMSG_ID_2B     = 43,
    COGMSG_ID_2C     = 44,
    COGMSG_ID_2D     = 45,
    COGMSG_ID_2E     = 46,
    COGMSG_ID_2F     = 47,
    COGMSG_JKENABLESABER  = 48,
    COGMSG_SABERINFO3  = 49,
    COGMSG_ID_32     = 50,
    COGMSG_ID_33     = 51,
    COGMSG_ID_34     = 52,
    COGMSG_HUDTARGET  = 53,
    COGMSG_ID_36     = 54,
    COGMSG_JKPRINTUNISTRING  = 55,
    COGMSG_ENDLEVEL  = 56,
    COGMSG_SABERINFO1  = 57,
    COGMSG_SABERINFO2  = 58,
    COGMSG_JKSETWEAPONMESH  = 59,
    COGMSG_SETTEAM   = 60,
    COGMSG_61        = 61
};

enum SENDERTYPE
{
    SENDERTYPE_0     = 0,
    SENDERTYPE_SYSTEM  = 1,
    SENDERTYPE_2     = 2,
    SENDERTYPE_THING  = 3,
    SENDERTYPE_4     = 4,
    SENDERTYPE_SECTOR  = 5,
    SENDERTYPE_SURFACE  = 6,
    SENDERTYPE_7     = 7,
    SENDERTYPE_8     = 8,
    SENDERTYPE_COG   = 9
};

static void (*sithCogScript_RegisterVerb)(void* a, intptr_t func, char* cmd) = (void*)0x4E0700;
static void (__cdecl *sithCog_SendMessage)(sithCog *a1, int msgid, int senderType, int senderIndex, int sourceType, int sourceIndex, int linkId) = (void*)0x4DEBE0;
static float (__cdecl *sithCog_SendMessageEx)(sithCog *a1, SITH_MESSAGE message, int senderType, int senderIndex, int sourceType, int sourceIndex, int linkId, float param0, float param1, float param2, float param3) = (void*)0x4DEDC0;


int sithCog_Startup();

void sithCogUtil_Initialize(void* a1);
void sithCogThing_Initialize(void* a1);
void sithCogAI_Initialize(void* a1);
void sithCogSound_Initialize(void* a1);
void sithCogPlayer_Initialize(void* a1);
void sithCogSector_Initialize(void* a1);
void sithCogSurface_Initialize(void* a1);

#endif // _SITHCOG_H
