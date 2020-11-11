#ifndef _SITHCOG_H
#define _SITHCOG_H

#include <stdint.h>
#include "sithCogVm.h"
#include "sithCogScript.h"

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

#define sithCog_SendMessageFromThing_ADDR (0x4DFAC0)
#define sithCog_SendMessageFromThingEx_ADDR (0x004DFAF0)
#define sithCog_SendMessageToAll_ADDR (0x4DEB00)

#define sithCogYACC_yyparse_ADDR (0x50BF50)

typedef int SITH_MESSAGE;

enum SITH_MESSAGE_E
{
    SITH_MESSAGE_0   = 0,
    SITH_MESSAGE_ACTIVATE  = 1,
    SITH_MESSAGE_REMOVED  = 2,
    SITH_MESSAGE_STARTUP  = 3,
    SITH_MESSAGE_TIMER  = 4,
    SITH_MESSAGE_BLOCKED  = 5,
    SITH_MESSAGE_ENTERED  = 6,
    SITH_MESSAGE_EXITED  = 7,
    SITH_MESSAGE_CROSSED  = 8,
    SITH_MESSAGE_SIGHTED  = 9,
    SITH_MESSAGE_DAMAGED  = 10,
    SITH_MESSAGE_ARRIVED  = 11,
    SITH_MESSAGE_KILLED  = 12,
    SITH_MESSAGE_PULSE  = 13,
    SITH_MESSAGE_TOUCHED  = 14,
    SITH_MESSAGE_CREATED  = 15,
    SITH_MESSAGE_LOADING  = 16,
    SITH_MESSAGE_SELECTED  = 17,
    SITH_MESSAGE_DESELECTED  = 18,
    SITH_MESSAGE_AUTOSELECT  = 19,
    SITH_MESSAGE_CHANGED  = 20,
    SITH_MESSAGE_DEACTIVATED  = 21,
    SITH_MESSAGE_SHUTDOWN  = 22,
    SITH_MESSAGE_RESPAWN  = 23,
    SITH_MESSAGE_AIEVENT  = 24,
    SITH_MESSAGE_SKILL  = 25,
    SITH_MESSAGE_TAKEN  = 26,
    SITH_MESSAGE_USER0  = 27,
    SITH_MESSAGE_USER1  = 28,
    SITH_MESSAGE_USER2  = 29,
    SITH_MESSAGE_USER3  = 30,
    SITH_MESSAGE_USER4  = 31,
    SITH_MESSAGE_USER5  = 32,
    SITH_MESSAGE_USER6  = 33,
    SITH_MESSAGE_USER7  = 34,
    SITH_MESSAGE_NEWPLAYER  = 35,
    SITH_MESSAGE_FIRE  = 36,
    SITH_MESSAGE_JOIN  = 37,
    SITH_MESSAGE_LEAVE  = 38,
    SITH_MESSAGE_SPLASH  = 39,
    SITH_MESSAGE_TRIGGER  = 40,
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

void sithCog_SendMessageFromThing(sithThing *a1, sithThing *a2, int msg);
static double (*sithCog_SendMessageFromThingEx)(sithThing *sender, sithThing *receiver, SITH_MESSAGE message, float param0, float param1, float param2, float param3) = (void*)sithCog_SendMessageFromThingEx_ADDR;
static void (*sithCog_SendMessageToAll)(int cmdid, int senderType, int senderIdx, int sourceType, int sourceIdx, float arg0, float arg1, float arg2, float arg3) = (void*)sithCog_SendMessageToAll_ADDR;

#define sithCog_masterCog (*(sithCog**)0x008B542C)

#endif // _SITHCOG_H
