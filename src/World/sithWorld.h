#ifndef _SITHWORLD_H
#define _SITHWORLD_H

#include "types.h"
#include "globals.h"

#include "Cog/sithCog.h"
#include "Cog/sithCogExec.h"
#include "Engine/rdKeyframe.h"
#include "World/sithThing.h"
#include "Engine/rdMaterial.h"
#include "World/sithSurface.h"

#define sithWorld_Startup_ADDR (0x004CF6F0)
#define sithWorld_Shutdown_ADDR (0x004CFAB0)
#define sithWorld_SetLoadProgressCallback_ADDR (0x004CFB00)
#define sithWorld_UpdateLoadProgress_ADDR (0x004CFB10)
#define sithWorld_Load_ADDR (0x004CFB30)
#define sithWorld_LoadPostProcess_ADDR (0x004CFD50)
#define sithWorld_Parse_ADDR (0x004CFF20)
#define sithWorld_Free_ADDR (0x004D0080)
#define sithWorld_NewEntry_ADDR (0x004D00B0)
#define sithWorld_FreeEntry_ADDR (0x004D00E0)
#define sithWorld_GetMemoryUsage_ADDR (0x004D0540)
#define sithWorld_RegisterTextSectionParser_ADDR (0x004D0820)
#define sithWorld_sub_4D08B0_ADDR (0x004D08B0)
#define sithWorld_sub_4D0930_ADDR (0x004D0930)
#define sithWorld_ResetRenderState_ADDR (0x004D0A20)
#define sithWorld_ResetGeoresource_ADDR (0x004D0AA0)
#define sithWorld_ValidateWorld_ADDR (0x004D0B00)
#define sithWorld_CalcWorldChecksum_ADDR (0x004D0C30)
#define sithWorld_InitPlayers_ADDR (0x004D0D10)
#define sithWorld_TimeSectionParse_ADDR (0x004D0D50)
#define sithWorld_GetTextSectionParserIndex_ADDR (0x004D0E20)
#define sithWorld_ReadGeoresourceText_ADDR (0x004D0E70)

int sithWorld_Startup();
void sithWorld_Shutdown();
void sithWorld_SetLoadProgressCallback(sithWorldProgressCallback_t pfProgressCallback);
void sithWorld_UpdateLoadProgress(flex_t progress);
int sithWorld_Load(SithWorld *pWorld, char *pFilename);
SithWorld* sithWorld_NewEntry();
int sithWorld_LoadPostProcess(SithWorld *pWorld);
void sithWorld_FreeEntry(SithWorld *pWorld);
int sithWorld_ReadHeaderText(SithWorld *pWorld, int bSkip);
int sithWorld_ReadCopyrightText(SithWorld *pWorld, int bSkip);
int sithWorld_RegisterTextSectionParser(char *aSectionName, sithWorldSectionParser_t parser);
int sithWorld_GetTextSectionParserIndex(char *aSectionName);
int sithWorld_ValidateWorld(SithWorld *pWorld);
uint32_t sithWorld_CalcWorldChecksum(SithWorld *pWorld, uint32_t seed);
int sithWorld_InitPlayers();
int sithWorld_ReadGeoresourceText(SithWorld *pWorld, int bSkip);
void sithWorld_ResetRenderState(SithWorld *pWorld);
void sithWorld_Free();
void sithWorld_ResetGeoresource(SithWorld *pWorld);
void sithWorld_GetMemoryUsage(SithWorld *pWorld, int *aMemUsed, int *aCount);
void sithWorld_SetChecksumExtraFunc(sithWorld_ChecksumHandler_t handler); // MOTS added


//static int (*sithWorld_LoadPostProcess)(SithWorld *pWorld) = (void*)sithWorld_LoadPostProcess_ADDR;
//static void (*sithWorld_ResetRenderState)(SithWorld *pWorld) = (void*)sithWorld_ResetRenderState_ADDR;
//static int (*sithWorld_Load)(SithWorld *pWorld, char *map_jkl_fname) = (void*)sithWorld_Load_ADDR;

//static void (*sithWorld_ResetGeoresource)(SithWorld *pWorld) = (void*)sithWorld_ResetGeoresource_ADDR;

#endif // _SITHWORLD_H
