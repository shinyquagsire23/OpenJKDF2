#ifndef _SITHCOGAI_H
#define _SITHCOGAI_H

#include "sithCog.h"
#include "types.h"

#define sithCogAI_apViewThings ((sithThing**)0x00855CE8) // 32
#define sithCogAI_unk1 (*(int*)0x00855D68)
#define sithCogAI_viewThingIdx (*(int*)0x00855D6C)

void sithCogAI_Initialize(void* ctx);

#endif // _SITHCOGAI_H
