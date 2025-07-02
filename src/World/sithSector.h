#ifndef _SITHSECTOR_H
#define _SITHSECTOR_H

#include "types.h"
#include "globals.h"

#define sithSector_Load_ADDR (0x004F8720)
#define sithSector_GetIdxFromPtr_ADDR (0x004F8BB0)
#define sithSector_New_ADDR (0x004F8BF0)
#define sithSector_NewEntry_ADDR (0x004F8C70)
#define sithSector_Free_ADDR (0x004F8CA0)
#define sithSector_sub_4F8D00_ADDR (0x004F8D00)
#define sithSector_UnsetAdjoins_ADDR (0x004F8DE0)
#define sithSector_SetAdjoins_ADDR (0x004F8E10)
#define sithSector_GetThingsCount_ADDR (0x004F8E40)
#define sithSector_GetNumPlayers_ADDR (0x004F8E60)
#define sithSector_SyncSector_ADDR (0x004F8E80)
#define sithSector_Sync_ADDR (0x004F8EF0)
#define sithSector_GetPtrFromIdx_ADDR (0x004F8F50)

int sithSector_Load(sithWorld *world, int tmp);

int sithSector_GetIdxFromPtr(sithSector *sector);
void sithSector_SetAdjoins(sithSector *sector);
void sithSector_UnsetAdjoins(sithSector *sector);
int sithSector_GetThingsCount(sithSector *sector);
void sithSector_Free(sithWorld *world);
int sithSector_GetNumPlayers(sithSector *sector);
sithSector* sithSector_GetPtrFromIdx(int idx);
void sithSector_SyncSector(sithSector *pSector, int a2);
void sithSector_Sync();
sithSector* sithSector_sub_4F8D00(sithWorld *pWorld, rdVector3 *pos);

//static int (*sithSector_LoadThingPhysicsParams)(stdConffileArg *arg, sithThing *thing, int param) = (void*)sithSector_LoadThingPhysicsParams_ADDR;
//static void (*sithSector_ThingPhysGeneral)(sithThing *thing, flex_t deltaSeconds) = (void*)sithSector_ThingPhysGeneral_ADDR;
//static void (*sithSector_ThingPhysPlayer)(sithThing *player, flex_t deltaSeconds) = (void*)sithSector_ThingPhysPlayer_ADDR;
//static void (*sithSector_ThingPhysUnderwater)(sithThing *a1, flex_t a2) = (void*)sithSector_ThingPhysUnderwater_ADDR;

//static void (*sithSector_ThingSetLook)(sithThing *a1, const rdVector3 *a2, flex_t a3) = (void*)sithSector_ThingSetLook_ADDR;
//static void (*sithSector_Free)(sithWorld* world) = (void*)sithSector_Free_ADDR;

//static signed int (*sithSector_AddEntry)(sithSector *sector, rdVector3 *a2, int a3, flex_t a4, sithThing *a5) = (void*)sithSector_AddEntry_ADDR;
//static int (*sithSector_SetSkyParams)(flex_t horizontalPixelsPerRev, flex_t horizontalDist, flex_t ceilingSky) = (void*)sithSector_SetSkyParams_ADDR;
//static void (*sithSector_UpdateSky)() = (void*)sithSector_UpdateSky_ADDR;
//static void (*sithSector_sub_4F2E30)(rdProcEntry *a1, sithSurfaceInfo* a2, int num_vertices) = (void*)sithSector_sub_4F2E30_ADDR;
//static void (*sithSector_sub_4F2F60)(rdProcEntry *a1, sithSurfaceInfo *a2, rdVector3 *a3, unsigned int a4) = (void*)sithSector_sub_4F2F60_ADDR;
//static int (*sithSector_TimerTick)() = (void*)sithSector_TimerTick_ADDR;
//static int (*sithSector_SyncSector)(sithSector *sector, int a2) = (void*)sithSector_SyncSector_ADDR;
//static void (*sithSector_sub_4F2C30)(sithSectorEntry *sectorEntry, sithSector *sector, rdVector3 *pos1, rdVector3 *pos2, flex_t a5, flex_t a6, sithThing *thing) = (void*)sithSector_sub_4F2C30_ADDR;

#endif // _SITHSECTOR_H
