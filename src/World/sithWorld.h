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
#define sithWorld_SetLoadPercentCallback_ADDR (0x004CFB00)
#define sithWorld_UpdateLoadPercent_ADDR (0x004CFB10)
#define sithWorld_Load_ADDR (0x004CFB30)
#define sithWorld_NewEntry_ADDR (0x004CFD50)
#define sithWorld_Parse_ADDR (0x004CFF20)
#define sithWorld_Free_ADDR (0x004D0080)
#define sithWorld_New_ADDR (0x004D00B0)
#define sithWorld_FreeEntry_ADDR (0x004D00E0)
#define sithWorld_GetMemorySize_ADDR (0x004D0540)
#define sithWorld_SetSectionParser_ADDR (0x004D0820)
#define sithWorld_sub_4D08B0_ADDR (0x004D08B0)
#define sithWorld_sub_4D0930_ADDR (0x004D0930)
#define sithWorld_sub_4D0A20_ADDR (0x004D0A20)
#define sithWorld_ResetSectorRuntimeAlteredVars_ADDR (0x004D0AA0)
#define sithWorld_Verify_ADDR (0x004D0B00)
#define sithWorld_CalcChecksum_ADDR (0x004D0C30)
#define sithWorld_Initialize_ADDR (0x004D0D10)
#define sithWorld_TimeSectionParse_ADDR (0x004D0D50)
#define sithWorld_FindSectionParser_ADDR (0x004D0E20)
#define sithWorld_LoadGeoresource_ADDR (0x004D0E70)

int sithWorld_Startup();
void sithWorld_Shutdown();
void sithWorld_SetLoadPercentCallback(sithWorldProgressCallback_t func);
void sithWorld_UpdateLoadPercent(float percent);
int sithWorld_Load(sithWorld *pWorld, char *map_jkl_fname);
sithWorld* sithWorld_New();
int sithWorld_NewEntry(sithWorld *pWorld);
void sithWorld_FreeEntry(sithWorld *pWorld);
int sithHeader_Load(sithWorld *pWorld, int junk);
int sithCopyright_Load(sithWorld *lvl, int junk);
int sithWorld_SetSectionParser(char *section_name, sithWorldSectionParser_t parser);
int sithWorld_FindSectionParser(char *a1);
int sithWorld_Verify(sithWorld *pWorld);
uint32_t sithWorld_CalcChecksum(sithWorld *pWorld, uint32_t seed);
int sithWorld_Initialize();
int sithWorld_LoadGeoresource(sithWorld *pWorld, int a2);
void sithWorld_sub_4D0A20(sithWorld *pWorld);
void sithWorld_Free();
void sithWorld_ResetSectorRuntimeAlteredVars(sithWorld *pWorld);

void sithWorld_SetChecksumExtraFunc(sithWorld_ChecksumHandler_t handler); // MOTS added

//TODO list
// sithWorld_GetMemorySize


//static int (*sithWorld_NewEntry)(sithWorld *pWorld) = (void*)sithWorld_NewEntry_ADDR;
//static void (*sithWorld_sub_4D0A20)(sithWorld *pWorld) = (void*)sithWorld_sub_4D0A20_ADDR;
//static int (*sithWorld_Load)(sithWorld *pWorld, char *map_jkl_fname) = (void*)sithWorld_Load_ADDR;

//static void (*sithWorld_ResetSectorRuntimeAlteredVars)(sithWorld *pWorld) = (void*)sithWorld_ResetSectorRuntimeAlteredVars_ADDR;

#endif // _SITHWORLD_H
