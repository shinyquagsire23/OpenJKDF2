#ifndef _SITHSECTOR_H
#define _SITHSECTOR_H

#include "types.h"
#include "globals.h"

// sithRenderSky

// sithPhysics

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

typedef enum ATTACHFLAGS
{
  SITH_ATTACH_WORLDSURFACE = 0x1,
  SITH_ATTACH_THINGSURFACE = 0x2,
  SITH_ATTACH_THING = 0x4,
  SITH_ATTACH_NO_MOVE = 0x8,
} ATTACHFLAGS;

typedef enum SITH_SECTOR_FLAG
{
  SITH_SECTOR_NOGRAVITY = 0x1,
  SITH_SECTOR_UNDERWATER = 0x2,
  SITH_SECTOR_COGLINKED = 0x4,
  SITH_SECTOR_HASTHRUST = 0x8,
  SITH_SECTOR_AUTOMAPHIDE = 0x10,
  SITH_SECTOR_NOACTORS = 0x20,
  SITH_SECTOR_FALLDEATH = 0x40,
  SITH_SECTOR_ADJOINS_SET = 0x80,
  SITH_SECTOR_100 = 0x100,
  SITH_SECTOR_200 = 0x200,
  SITH_SECTOR_400 = 0x400,
  SITH_SECTOR_800 = 0x800,
  SITH_SECTOR_HAS_COLLIDE_BOX = 0x1000,
  SITH_SECTOR_2000 = 0x2000,
  SITH_SECTOR_AUTOMAPVISIBLE = 0x4000,
  SITH_SECTOR_SYNC = 0x8000,
} SITH_SECTOR_FLAG;

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

//static int (*sithSector_LoadThingPhysicsParams)(stdConffileArg *arg, sithThing *thing, int param) = (void*)sithSector_LoadThingPhysicsParams_ADDR;
//static void (*sithSector_ThingPhysGeneral)(sithThing *thing, float deltaSeconds) = (void*)sithSector_ThingPhysGeneral_ADDR;
//static void (*sithSector_ThingPhysPlayer)(sithThing *player, float deltaSeconds) = (void*)sithSector_ThingPhysPlayer_ADDR;
//static void (*sithSector_ThingPhysUnderwater)(sithThing *a1, float a2) = (void*)sithSector_ThingPhysUnderwater_ADDR;

//static void (*sithSector_ThingSetLook)(sithThing *a1, const rdVector3 *a2, float a3) = (void*)sithSector_ThingSetLook_ADDR;
//static void (*sithSector_Free)(sithWorld* world) = (void*)sithSector_Free_ADDR;

//static signed int (*sithSector_AddEntry)(sithSector *sector, rdVector3 *a2, int a3, float a4, sithThing *a5) = (void*)sithSector_AddEntry_ADDR;
//static int (*sithSector_SetSkyParams)(float horizontalPixelsPerRev, float horizontalDist, float ceilingSky) = (void*)sithSector_SetSkyParams_ADDR;
//static void (*sithSector_UpdateSky)() = (void*)sithSector_UpdateSky_ADDR;
//static void (*sithSector_sub_4F2E30)(rdProcEntry *a1, sithSurfaceInfo* a2, int num_vertices) = (void*)sithSector_sub_4F2E30_ADDR;
//static void (*sithSector_sub_4F2F60)(rdProcEntry *a1, sithSurfaceInfo *a2, rdVector3 *a3, unsigned int a4) = (void*)sithSector_sub_4F2F60_ADDR;
//static int (*sithSector_TimerTick)() = (void*)sithSector_TimerTick_ADDR;
//static int (*sithSector_SyncSector)(sithSector *sector, int a2) = (void*)sithSector_SyncSector_ADDR;
//static void (*sithSector_sub_4F2C30)(sithSectorEntry *sectorEntry, sithSector *sector, rdVector3 *pos1, rdVector3 *pos2, float a5, float a6, sithThing *thing) = (void*)sithSector_sub_4F2C30_ADDR;

#endif // _SITHSECTOR_H
