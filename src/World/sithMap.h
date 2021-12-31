#ifndef _SITH_MAP_H
#define _SITH_MAP_H

#include "types.h"
#include "globals.h"

#define sithMap_Initialize_ADDR (0x004EC330)
#define sithMap_Shutdown_ADDR (0x004EC360)
#define sithMap_DrawCircle_ADDR (0x004EC380)
#define sithMap_sub_4EC4D0_ADDR (0x004EC4D0)
#define sithMap_Draw_ADDR (0x004EC550)
#define sithMap_IsSurfaceDrawable_ADDR (0x004EC9C0)

int sithMap_Initialize(sithMap* map);
int sithMap_Shutdown();
void sithMap_DrawCircle(rdCamera *camera, rdMatrix34 *viewMat);
void sithMap_sub_4EC4D0(sithSector *sector);
int sithMap_Draw(sithSector *sector);
int sithMap_IsSurfaceDrawable(sithSurface *pSurface, int idx, int idx2);

//static int (*sithMap_Draw)(sithSector *sector) = (void*)sithMap_Draw_ADDR;

#endif // _SITH_MAP_H
