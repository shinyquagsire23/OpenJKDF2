#ifndef _SITHMATERIAL_H
#define _SITHMATERIAL_H

#include "types.h"
#include "globals.h"

#define sithMaterial_Startup_ADDR (0x004F0CC0)
#define sithMaterial_Shutdown_ADDR (0x004F0CE0)
#define sithMaterial_FreeWorldMaterials_ADDR (0x004F0D00)
#define sithMaterial_ReadMaterialsListText_ADDR (0x004F0D90)
#define sithMaterial_Load_ADDR (0x004F0F70)
#define sithMaterial_GetMaterialByIndex_ADDR (0x004F10A0)
#define sithMaterial_GetMemorySize_ADDR (0x004F10E0)
#define sithMaterial_AllocWorldMaterials_ADDR (0x004F1140)
#define sithMaterial_UnloadAll_ADDR (0x004F11C0)

int sithMaterial_Startup();
void sithMaterial_Shutdown();
void sithMaterial_FreeWorldMaterials(SithWorld *pWorld);
MATH_FUNC int sithMaterial_ReadMaterialsListText(SithWorld *pWorld, int bSkip);
rdMaterial* sithMaterial_Load(const char *pName, int create_ddraw_surface, int gpu_mem);
rdMaterial* sithMaterial_GetMaterialByIndex(int index);
int sithMaterial_GetMemorySize(rdMaterial *mat);
rdVector2* sithMaterial_AllocWorldMaterials(SithWorld *pWorld, int numMaterials);
void sithMaterial_UnloadAll();

#endif // _SITHMATERIAL_H
