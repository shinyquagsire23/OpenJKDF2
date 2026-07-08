#ifndef _SITHSECTOR_H
#define _SITHSECTOR_H

#include "types.h"
#include "globals.h"

#define sithSector_ReadSectorsListText_ADDR (0x004F8720)
#define sithSector_GetIdxFromPtr_ADDR (0x004F8BB0)
#define sithSector_AllocWorldSectors_ADDR (0x004F8BF0)
#define sithSector_NewEntry_ADDR (0x004F8C70)
#define sithSector_FreeWorldSectors_ADDR (0x004F8CA0)
#define sithSector_FindSectorAtPos_ADDR (0x004F8D00)
#define sithSector_HideSectorAdjoins_ADDR (0x004F8DE0)
#define sithSector_ShowSectorAdjoins_ADDR (0x004F8E10)
#define sithSector_GetSectorThingCount_ADDR (0x004F8E40)
#define sithSector_GetSectorPlayerCount_ADDR (0x004F8E60)
#define sithSector_SyncSector_ADDR (0x004F8E80)
#define sithSector_SyncSectors_ADDR (0x004F8EF0)
#define sithSector_GetPtrFromIdx_ADDR (0x004F8F50)

int sithSector_ReadSectorsListText(SithWorld *world, int tmp);

int sithSector_GetIdxFromPtr(SithSector *sector);
void sithSector_ShowSectorAdjoins(SithSector *sector);
void sithSector_HideSectorAdjoins(SithSector *sector);
int sithSector_GetSectorThingCount(SithSector *sector);
int sithSector_AllocWorldSectors(SithWorld *world, int num);
void sithSector_NewEntry(SithSector *sector, int idx);
void sithSector_FreeWorldSectors(SithWorld *world);
int sithSector_GetSectorPlayerCount(SithSector *sector);
SithSector* sithSector_GetPtrFromIdx(int idx);
void sithSector_SyncSector(SithSector *pSector, int a2);
void sithSector_SyncSectors();
SithSector* sithSector_FindSectorAtPos(SithWorld *pWorld, rdVector3 *pos);

//static int (*sithSector_LoadThingPhysicsParams)(stdConffileArg *arg, SithThing *thing, int param) = (void*)sithSector_LoadThingPhysicsParams_ADDR;
//static void (*sithSector_ThingPhysGeneral)(SithThing *thing, flex_t deltaSeconds) = (void*)sithSector_ThingPhysGeneral_ADDR;
//static void (*sithSector_ThingPhysPlayer)(SithThing *player, flex_t deltaSeconds) = (void*)sithSector_ThingPhysPlayer_ADDR;
//static void (*sithSector_ThingPhysUnderwater)(SithThing *a1, flex_t a2) = (void*)sithSector_ThingPhysUnderwater_ADDR;

//static void (*sithSector_ThingSetLook)(SithThing *a1, const rdVector3 *a2, flex_t a3) = (void*)sithSector_ThingSetLook_ADDR;
//static void (*sithSector_FreeWorldSectors)(SithWorld* world) = (void*)sithSector_FreeWorldSectors_ADDR;

//static signed int (*sithSector_AddEntry)(SithSector *sector, rdVector3 *a2, int a3, flex_t a4, SithThing *a5) = (void*)sithSector_AddEntry_ADDR;
//static int (*sithSector_SetSkyParams)(flex_t horizontalPixelsPerRev, flex_t horizontalDist, flex_t ceilingSky) = (void*)sithSector_SetSkyParams_ADDR;
//static void (*sithSector_UpdateSky)() = (void*)sithSector_UpdateSky_ADDR;
//static void (*sithSector_sub_4F2E30)(rdProcEntry *a1, sithSurfaceInfo* a2, int num_vertices) = (void*)sithSector_sub_4F2E30_ADDR;
//static void (*sithSector_sub_4F2F60)(rdProcEntry *a1, sithSurfaceInfo *a2, rdVector3 *a3, unsigned int a4) = (void*)sithSector_sub_4F2F60_ADDR;
//static int (*sithSector_TimerTick)() = (void*)sithSector_TimerTick_ADDR;
//static int (*sithSector_SyncSector)(SithSector *sector, int a2) = (void*)sithSector_SyncSector_ADDR;
//static void (*sithSector_sub_4F2C30)(sithSectorEntry *sectorEntry, SithSector *sector, rdVector3 *pos1, rdVector3 *pos2, flex_t a5, flex_t a6, SithThing *thing) = (void*)sithSector_sub_4F2C30_ADDR;

#endif // _SITHSECTOR_H
