#ifndef _SITHSPRITE_H
#define _SITHSPRITE_H

#include "types.h"
#include "globals.h"

#define sithSprite_Startup_ADDR (0x004F2130)
#define sithSprite_Shutdown_ADDR (0x004F2170)
#define sithSprite_ReadStaticSpritesListText_ADDR (0x004F2190)
#define sithSprite_FreeWorldSprites_ADDR (0x004F2330)
#define sithSprite_Load_ADDR (0x004F23B0)
#define sithSprite_AllocWorldSprites_ADDR (0x004F25F0)

int sithSprite_Startup();
void sithSprite_Shutdown();
int sithSprite_ReadStaticSpritesListText(sithWorld *world, int a2);
void sithSprite_FreeWorldSprites(sithWorld *world);
rdSprite* sithSprite_Load(char *fpath);
int sithSprite_AllocWorldSprites(sithWorld *world, int num);

#endif // _SITHSPRITE_H
