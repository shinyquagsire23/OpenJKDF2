#ifndef _SITHSURFACE_H
#define _SITHSURFACE_H

#include "types.h"
#include "globals.h"
#include "Raster/rdFace.h"

#define sithSurface_UnsetAdjoins_ADDR (0x004E5A10)
#define sithSurface_SetAdjoins_ADDR (0x004E5A30)
#define sithSurface_New_ADDR (0x004E5A50)
#define sithSurface_sub_4E5AD0_ADDR (0x004E5AD0)
#define sithSurface_Free_ADDR (0x004E5B40)
#define sithSurface_Load_ADDR (0x004E5C00)
#define sithSurface_GetIdxFromPtr_ADDR (0x004E6190)
#define sithSurface_Verify_ADDR (0x004E61B0)
#define sithSurface_SendDamageToThing_ADDR (0x004E61F0)
#define sithSurface_GetCenter_ADDR (0x004E6250)
#define sithSurface_SyncSurface_ADDR (0x004E6330)
#define sithSurface_Sync_ADDR (0x004E6360)
#define sithSurface_sub_4E63B0_ADDR (0x004E63B0)
#define sithSurface_Startup_ADDR (0x004EF900)
#define sithSurface_Shutdown_ADDR (0x004EF950)
#define sithSurface_Open_ADDR (0x004EF960)
#define sithSurface_Startup2_ADDR (0x004EF970)
#define sithSurface_Startup3_ADDR (0x004EF9C0)
#define sithSurface_StopAnim_ADDR (0x004EFA10)
#define sithSurface_GetSurfaceAnim_ADDR (0x004EFAC0)
#define sithSurface_SlideWall_ADDR (0x004EFB20)
#define sithSurface_SlideHorizonSky_ADDR (0x004EFFF0)
#define sithSurface_sub_4F00A0_ADDR (0x004F00A0)
#define sithSurface_SurfaceAnim_ADDR (0x004F0180)
#define sithSurface_MaterialAnim_ADDR (0x004F02C0)
#define sithSurface_SurfaceLightAnim_ADDR (0x004F03F0)
#define sithSurface_SetSectorLight_ADDR (0x004F04A0)
#define sithSurface_SetThingLight_ADDR (0x004F0560)
#define sithSurface_Tick_ADDR (0x004F0630)
#define sithSurface_GetRdSurface_ADDR (0x004F09F0)
#define sithSurface_DetachThing_ADDR (0x004F0A30)
#define sithSurface_GetByIdx_ADDR (0x004F0AA0)
#define sithSurface_Alloc_ADDR (0x004F0AF0)
#define sithSurface_SyncFull_ADDR (0x004F0B50)
#define sithSurface_ScrollSky_ADDR (0x004F0BC0)

#define SITH_SURFACE_HORIZONSKY (0x200)
#define SITH_SURFACE_CEILINGSKY (0x400)

enum SithSurfaceFlag
{
    SITH_SURFACE_FLOOR = 0x1,
    SITH_SURFACE_COG_LINKED = 0x2,
    SITH_SURFACE_HAS_COLLISION = 0x4,
    SITH_SURFACE_AI_CAN_WALK_ON_FLOOR = 0x8, // from jkdf2 docs
    SITH_SURFACE_DOUBLE_TEXTURE_SCALE = 0x10,
    SITH_SURFACE_HALF_TEXTURE_SCALE = 0x20,
    SITH_SURFACE_EIGHT_TEXTURE_SCALE = 0x40,
    SITH_SURFACE_80 = 0x80, // Jones specific: AETHERIUM
    SITH_SURFACE_HORIZON_SKY = 0x200,
    SITH_SURFACE_CEILING_SKY = 0x400,
    SITH_SURFACE_SCROLLING = 0x800,
    SITH_SURFACE_ICY = 0x1000, // Jones specific: KILL_FLOOR
    SITH_SURFACE_VERYICY = 0x2000, // Jones specific: CLIMBABLE
    SITH_SURFACE_MAGSEALED = 0x4000, // Jones specific: TRACK
    SITH_SURFACE_CHANGED = 0x8000,
    SITH_SURFACE_METAL = 0x10000,
    SITH_SURFACE_WATER = 0x20000,
    SITH_SURFACE_PUDDLE = 0x40000,
    SITH_SURFACE_EARTH = 0x80000,
    SITH_SURFACE_VERYDEEPWATER = 0x100000,
    SITH_SURFACE_200000 = 0x200000,
    SITH_SURFACE_400000 = 0x400000,
    SITH_SURFACE_800000 = 0x800000, // animating?
    SITH_SURFACE_1000000 = 0x1000000,

#ifdef RENDER_DROID2
	SITH_SURFACE_EMISSIVE = 0x40000000,
#endif

    /*SITH_SURFACE_EARTH = 0x80000, // Jones specific
    SITH_SURFACE_WEB = 0x100000, // Jones specific
    SITH_SURFACE_LAVA = 0x200000, // Jones specific
    SITH_SURFACE_SNOW = 0x400000, // Jones specific
    SITH_SURFACE_WOOD = 0x800000, // Jones specific
    SITH_SURFACE_LEDGE = 0x1000000, // Jones specific
    SITH_SURFACE_WATER_CLIMBOUT_LEDGE = 0x2000000, // Jones specific
    SITH_SURFACE_QUARTER_SURFACE_SCALE = 0x4000000, // Jones specific
    SITH_SURFACE_QUADRUPLE_SURFACE_SCALE = 0x8000000, // Jones specific
    SITH_SURFACE_WHIP_AIM = 0x10000000, // Jones specific
    SITH_SURFACE_ECHO = 0x20000000, // Jones specific
    SITH_SURFACE_WOOD_ECHO = 0x40000000, // Jones specific
    SITH_SURFACE_EARTH_ECHO = 0x80000000, // Jones specific
    */
};

enum SithSurfaceAdjoinFlag
{
    SITHSURF_ADJOIN_VISIBLE = 0x1,
    SITHSURF_ADJOIN_ALLOW_MOVEMENT = 0x2, // ADJOIN_MOVE
    SITHSURF_ADJOIN_ALLOW_SOUND = 0x4,
    SITHSURF_ADJOIN_ALLOW_PLAYER_ONLY = 0x8, // aka SITHSURF_ADJOIN_AI_IMPASSABLE
    SITHSURF_ADJOIN_ALLOW_AI_ONLY = 0x10, // aka SITHSURF_ADJOIN_PLAYER_IMPASSABLE
    SITHSURF_ADJOIN_SET_BY_SECTOR = 0x20,
    SITHSURF_ADJOIN_40 = 0x40,
    SITHSURF_ADJOIN_80 = 0x80,
};

int sithSurface_Startup();
void sithSurface_Shutdown();
int sithSurface_Open();
int sithSurface_Verify(sithWorld *world);
int sithSurface_Load(sithWorld *world);
int sithSurface_GetIdxFromPtr(sithSurface *surface);
void sithSurface_UnsetAdjoins(sithAdjoin *adjoin);
void sithSurface_SetAdjoins(sithAdjoin *adjoin);
rdSurface* sithSurface_SurfaceAnim(sithSurface *parent, float a2, uint16_t flags);
int sithSurface_Startup2();
int sithSurface_Startup3();
void sithSurface_SetSectorLight(sithSector *sector, float extraLight, float a3, int a4);
void sithSurface_Free(sithWorld *world);
void sithSurface_Tick(float deltaSecs);
void sithSurface_ScrollSky(rdSurface *surface, int flags, float deltaSecs, uint8_t a4);
int sithSurface_StopAnim(rdSurface *surface);
uint32_t sithSurface_GetSurfaceAnim(sithSurface *surface);
rdSurface* sithSurface_SurfaceLightAnim(sithSurface *surface, float a2, float a3);
rdSurface* sithSurface_SlideWall(sithSurface *surface, rdVector3 *a2);
rdSurface* sithSurface_MaterialAnim(rdMaterial *material, float a2, int a3);
void sithSurface_DetachThing(sithSurface *a1, rdVector3 *out);
int sithSurface_GetCenter(sithSurface *surface, rdVector3 *out);
rdSurface* sithSurface_SlideHorizonSky(int flags, rdVector2 *a2);
rdSurface* sithSurface_sub_4F00A0(sithThing *thing, float a2, uint32_t a3);
rdSurface* sithSurface_SetThingLight(sithThing *thing, float a2, float a3, int a4);
void sithSurface_SendDamageToThing(sithSurface *sender, sithThing *receiver, float damage, int damageType);
rdSurface* sithSurface_GetRdSurface(sithSurface *surface);
rdSurface* sithSurface_GetByIdx(int idx);
void sithSurface_SyncFull(int mpFlags);
rdSurface* sithSurface_Alloc();
sithSurface* sithSurface_sub_4E63B0(int idx);
void sithSurface_SyncSurface(sithSurface *pSurface);
void sithSurface_Sync();

//static void (*sithSurface_Shutdown)() = (void*)sithSurface_Shutdown_ADDR;
//static int (*sithSurface_Startup)() = (void*)sithSurface_Startup_ADDR;
static int (*_sithSurface_Load)(sithWorld*) = (void*)sithSurface_Load_ADDR;
//static void (__cdecl *sithSurface_SendDamageToThing)(sithSurface *sender, sithThing *receiver, float damage, int damageType) = (void*)sithSurface_SendDamageToThing_ADDR;
static int* (*_sithSurface_SurfaceAnim)(void*, float, int) = (void*)sithSurface_SurfaceAnim_ADDR;
//static int* (*sithSurface_MaterialAnim)(void*, float, int) = (void*)sithSurface_MaterialAnim_ADDR;
//static rdSurface* (*sithSurface_GetByIdx)(int) = (void*)sithSurface_GetByIdx_ADDR;
//static int (*sithSurface_StopAnim)(rdSurface *a1) = (void*)sithSurface_StopAnim_ADDR;
//static rdSurface* (__cdecl *sithSurface_GetRdSurface)(sithSurface *a1) = (void*)sithSurface_GetRdSurface_ADDR;
//static int (*sithSurface_GetSurfaceAnim)(sithSurface *a1) = (void*)sithSurface_GetSurfaceAnim_ADDR;
//static rdSurface* (*sithSurface_SetThingLight)(sithThing *a1, float a2, float a3, int a4) = (void*)sithSurface_SetThingLight_ADDR;
//static rdSurface* (*sithSurface_sub_4F00A0)(sithThing *a1, float a2, int a3) = (void*)sithSurface_sub_4F00A0_ADDR;
//static void (*sithSurface_Free)(sithWorld* world) = (void*)sithSurface_Free_ADDR;
static void (*_sithSurface_Tick)(float time) = (void*)sithSurface_Tick_ADDR;
//static rdSurface* (*sithSurface_SlideHorizonSky)(int a1, rdVector2 *a2) = (void*)sithSurface_SlideHorizonSky_ADDR;
//static rdSurface* (*sithSurface_SurfaceLightAnim)(sithSurface *surface, float a2, float a3) = (void*)sithSurface_SurfaceLightAnim_ADDR;
//static rdSurface* (*sithSurface_SlideWall)(sithSurface *surface, rdVector3 *a2) = (void*)sithSurface_SlideWall_ADDR;
//static uint32_t (*sithSurface_SyncSurface)(sithSurface *a1) = (void*)sithSurface_SyncSurface_ADDR;
//static void (*sithSurface_DetachThing)(sithSurface *a1, rdVector3 *out) = (void*)sithSurface_DetachThing_ADDR;
//static void (*sithSurface_ScrollSky)(rdSurface *surface, int a2, float a3, int a4) = (void*)sithSurface_ScrollSky_ADDR;
//static int (*sithSurface_GetCenter)(sithSurface *a1, rdVector3 *a2) = (void*)sithSurface_GetCenter_ADDR;

//static void (*sithSurface_SyncFull)(int mpFlags) = (void*)sithSurface_SyncFull_ADDR;

#endif // _SITHSURFACE_H
