#ifndef _SITHSURFACE_H
#define _SITHSURFACE_H

#include "types.h"
#include "Primitives/rdFace.h"

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
#define sithSurface_PushSurface_ADDR (0x004E6330)
#define sithSurface_Syncidk_ADDR (0x004E6360)
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
#define sithSurface_Sync_ADDR (0x004F0B50)
#define sithSurface_ScrollSky_ADDR (0x004F0BC0)

#define sithSurface_numAvail (*(int*)0x0084DF48)
#define sithSurface_aAvail ((int*)0x0084DF4C) // 256
#define sithSurface_numSurfaces (*(int*)0x0084E350)
#define sithSurface_aSurfaces ((rdSurface*)0x0084E358) // 256
#define sithSurface_bOpened (*(int*)0x00852F58)
#define sithSurface_byte_8EE668 (*(uint8_t*)0x008EE668)
#define sithSurface_numSurfaces_0 (*(int*)0x00847F18)

typedef struct sithSurfaceInfo
{
    rdFace face;
    float* field_40;
    uint32_t lastTouchedMs;
} sithSurfaceInfo;

struct rdSurface
{
  uint32_t index; // -14
  uint32_t flags; // -13
  sithThing *parent_thing; // -12
  uint32_t signature; // -11
  rdMaterial* material; // -10
  sithSurface *sithSurfaceParent; // -9
  sithSector* sector; // -8
  rdVector2 field_1C;
  rdVector3 field_24;
  uint32_t field_30;
  uint32_t field_34;
  uint32_t wallCel;
  float field_3C;
  float field_40;
  float field_44;
  float field_48;
};

typedef struct sithSurface
{
    uint32_t field_0;
    uint32_t field_4;
    sithSector* parent_sector;
    sithAdjoin* adjoin;
    uint32_t surfaceFlags;
    sithSurfaceInfo surfaceInfo;
} sithSurface;

typedef enum SURFACEFLAGS
{
    SURFACEFLAGS_1 = 0x1,
    SURFACEFLAGS_2 = 0x2,
    SURFACEFLAGS_4 = 0x4,
    SURFACEFLAGS_8 = 0x8,
    SURFACEFLAGS_10 = 0x10,
    SURFACEFLAGS_20 = 0x20,
    SURFACEFLAGS_40 = 0x40,
    SURFACEFLAGS_80 = 0x80,
    SURFACEFLAGS_100 = 0x100,
    SURFACEFLAGS_200 = 0x200,
    SURFACEFLAGS_400 = 0x400,
    SURFACEFLAGS_800 = 0x800,
    SURFACEFLAGS_1000 = 0x1000,
    SURFACEFLAGS_2000 = 0x2000,
    SURFACEFLAGS_4000 = 0x4000,
    SURFACEFLAGS_8000 = 0x8000,
    SURFACEFLAGS_METAL = 0x10000,
    SURFACEFLAGS_WATER = 0x20000,
    SURFACEFLAGS_PUDDLE = 0x40000,
    SURFACEFLAGS_EARTH = 0x80000,
    SURFACEFLAGS_100000 = 0x100000,
    SURFACEFLAGS_200000 = 0x200000,
    SURFACEFLAGS_400000 = 0x400000,
    SURFACEFLAGS_800000 = 0x800000,
    SURFACEFLAGS_1000000 = 0x1000000,
    SURFACEFLAGS_2000000 = 0x2000000,
    SURFACEFLAGS_4000000 = 0x4000000,
    SURFACEFLAGS_8000000 = 0x8000000,
} SURFACEFLAGS;

int sithSurface_Startup();
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

static void (*sithSurface_Shutdown)() = (void*)sithSurface_Shutdown_ADDR;
//static int (*sithSurface_Startup)() = (void*)sithSurface_Startup_ADDR;
static int (*_sithSurface_Load)(sithWorld*) = (void*)sithSurface_Load_ADDR;
static void (__cdecl *sithSurface_SendDamageToThing)(sithSurface *sender, sithThing *receiver, float damage, int damageType) = (void*)sithSurface_SendDamageToThing_ADDR;
static int* (*_sithSurface_SurfaceAnim)(void*, float, int) = (void*)sithSurface_SurfaceAnim_ADDR;
static int* (*sithSurface_MaterialAnim)(void*, float, int) = (void*)sithSurface_MaterialAnim_ADDR;
static rdSurface* (*sithSurface_GetByIdx)(int) = (void*)sithSurface_GetByIdx_ADDR;
static int (*sithSurface_StopAnim)(rdSurface *a1) = (void*)sithSurface_StopAnim_ADDR;
static rdSurface* (__cdecl *sithSurface_GetRdSurface)(sithSurface *a1) = (void*)sithSurface_GetRdSurface_ADDR;
static int (*sithSurface_GetSurfaceAnim)(sithSurface *a1) = (void*)sithSurface_GetSurfaceAnim_ADDR;
static rdSurface* (*sithSurface_SetThingLight)(sithThing *a1, float a2, float a3, int a4) = (void*)sithSurface_SetThingLight_ADDR;
static rdSurface* (*sithSurface_sub_4F00A0)(sithThing *a1, float a2, int a3) = (void*)sithSurface_sub_4F00A0_ADDR;
//static void (*sithSurface_Free)(sithWorld* world) = (void*)sithSurface_Free_ADDR;
static void (*_sithSurface_Tick)(float time) = (void*)sithSurface_Tick_ADDR;
static rdSurface* (*sithSurface_SlideHorizonSky)(int a1, rdVector2 *a2) = (void*)sithSurface_SlideHorizonSky_ADDR;
static rdSurface* (*sithSurface_SurfaceLightAnim)(sithSurface *surface, float a2, float a3) = (void*)sithSurface_SurfaceLightAnim_ADDR;
static rdSurface* (*sithSurface_SlideWall)(sithSurface *surface, rdVector3 *a2) = (void*)sithSurface_SlideWall_ADDR;
static uint32_t (*sithSurface_PushSurface)(sithSurface *a1) = (void*)sithSurface_PushSurface_ADDR;
static void (*sithSurface_DetachThing)(sithSurface *a1, rdVector3 *out) = (void*)sithSurface_DetachThing_ADDR;
//static void (*sithSurface_ScrollSky)(rdSurface *surface, int a2, float a3, int a4) = (void*)sithSurface_ScrollSky_ADDR;

#endif // _SITHSURFACE_H
