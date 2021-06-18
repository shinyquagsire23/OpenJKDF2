#ifndef _SITH_MAP_H
#define _SITH_MAP_H

#include "types.h"

#define sithMap_Initialize_ADDR (0x004EC330)
#define sithMap_Shutdown_ADDR (0x004EC360)
#define sithMap_DrawCircle_ADDR (0x004EC380)
#define sithMap_sub_4EC4D0_ADDR (0x004EC4D0)
#define sithMap_Draw_ADDR (0x004EC550)
#define sithMap_IsSurfaceDrawable_ADDR (0x004EC9C0)

#define sithMap_bInitted (*(int*)0x0084DF1C)
#define sithMap_ctx (*(sithMap*)0x0084DEB0)

typedef struct sithMap
{
  int numArr;
  float* unkArr;
  int* anonymous_1;
  int playerColor;
  int actorColor;
  int itemColor;
  int weaponColor;
  int otherColor;
  int teamColors[5];
} sithMap;

int sithMap_Initialize(sithMap* map);
int sithMap_Shutdown();

#endif // _SITH_MAP_H
