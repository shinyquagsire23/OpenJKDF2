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

#define sithCogYACC_yyparse_ADDR (0x50BF50)

typedef int SITH_MESSAGE;

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
