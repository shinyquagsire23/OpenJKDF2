#ifndef _SITHSPRITE_H
#define _SITHSPRITE_H

#define sithSprite_Startup_ADDR (0x004F2130)
#define sithSprite_Shutdown_ADDR (0x004F2170)
#define sithSprite_Load_ADDR (0x004F2190)
#define sithSprite_FreeEntry_ADDR (0x004F2330)
#define sithSprite_LoadEntry_ADDR (0x004F23B0)
#define sithSprite_New_ADDR (0x004F25F0)

#define sithSprite_hashmap (*(stdHashTable**)0x00852F90)

typedef struct rdSprite rdSprite;
typedef struct sithWorld sithWorld;

int sithSprite_Startup();
void sithSprite_Shutdown();
int sithSprite_Load(sithWorld *world, int a2);
void sithSprite_FreeEntry(sithWorld *world);
rdSprite* sithSprite_LoadEntry(char *fpath);
int sithSprite_New(sithWorld *world, int num);

#endif // _SITHSPRITE_H
