#ifndef _SITHMATERIAL_H
#define _SITHMATERIAL_H

#include "types.h"
#include "globals.h"

#define sithMaterial_Startup_ADDR (0x004F0CC0)
#define sithMaterial_Shutdown_ADDR (0x004F0CE0)
#define sithMaterial_Free_ADDR (0x004F0D00)
#define sithMaterial_Load_ADDR (0x004F0D90)
#define sithMaterial_LoadEntry_ADDR (0x004F0F70)
#define sithMaterial_GetByIdx_ADDR (0x004F10A0)
#define sithMaterial_GetMemorySize_ADDR (0x004F10E0)
#define sithMaterial_New_ADDR (0x004F1140)
#define sithMaterial_UnloadAll_ADDR (0x004F11C0)

int sithMaterial_Startup();
void sithMaterial_Shutdown();
void sithMaterial_Free(sithWorld *world);
MATH_FUNC int sithMaterial_Load(sithWorld *world, int a2);
rdMaterial* sithMaterial_LoadEntry(const char *a1, int create_ddraw_surface, int gpu_mem);
rdMaterial* sithMaterial_GetByIdx(int idx);
int sithMaterial_GetMemorySize(rdMaterial *mat);
rdVector2* sithMaterial_New(sithWorld *world, int num);
void sithMaterial_UnloadAll();

#endif // _SITHMATERIAL_H
