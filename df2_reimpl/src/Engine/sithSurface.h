#ifndef _SITHSURFACE_H
#define _SITHSURFACE_H

#include "types.h"

#define sithSurface_sub_4E5A10_ADDR (0x004E5A10)
#define sithSurface_sub_4E5A30_ADDR (0x004E5A30)
#define sithSurface_New_ADDR (0x004E5A50)
#define sithSurface_sub_4E5AD0_ADDR (0x004E5AD0)
#define sithSurface_Free_ADDR (0x004E5B40)
#define sithSurface_Load_ADDR (0x004E5C00)
#define sithSurface_sub_4E6190_ADDR (0x004E6190)
#define sithSurface_Verify_ADDR (0x004E61B0)
#define sithSurface_SendDamageToThing_ADDR (0x004E61F0)
#define sithSurface_GetCenter_ADDR (0x004E6250)
#define sithSurface_Sync_0_ADDR (0x004E6330)
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
#define sithSurface_tick_ADDR (0x004F0630)
#define sithSurface_GetRdSurface_ADDR (0x004F09F0)
#define sithSurface_detachthing_ADDR (0x004F0A30)
#define sithSurface_GetByIdx_ADDR (0x004F0AA0)
#define sithSurface_Alloc_ADDR (0x004F0AF0)
#define sithSurface_Sync_ADDR (0x004F0B50)
#define sithSurface_ScrollSky_ADDR (0x004F0BC0)

#define sithSurface_numAvail (*(int*)0x0084DF48)
#define sithSurface_aAvail ((int*)0x0084DF4C) // 256
#define sithSurface_numSurfaces (*(int*)0x0084E350)
#define sithSurface_aSurfaces ((rdSurface*)0x0084E358) // 256
#define sithSurface_bOpened (*(int*)0x00852F58)

typedef struct sithSurfaceInfo
{
    uint32_t field_0;
    uint32_t faceType;
    uint32_t geoMode;
    uint32_t lightMode;
    uint32_t texMode;
    uint32_t numVertices;
    int* vertexIdxs;
    int* vertexUVIdxs;
    rdMaterial* material;
    uint32_t wallCel;
    rdVector2 clipIdk;
    float extraLight;
    rdVector3 surfaceNormal;
    int* field_40;
    uint32_t lastTouchedMs;
} sithSurfaceInfo;

struct rdSurface
{
  int field_0;
  int field_4;
  sithSector *parent_sector;
  sithAdjoin *adjoin;
  int surfaceFlags;
  sithSurface *sithSurfaceParent;
  int faceType;
  int geoMode;
  int lightMode;
  int texMode;
  uint32_t numVertices;
  int *vertexIdxs;
  int field_30;
  rdMaterial *material;
  int wallCel;
  int field_3C;
  int field_40;
  int field_44;
  int field_48;
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

//static int (*sithSurface_Startup)() = (void*)sithSurface_Startup_ADDR;
static void (__cdecl *sithSurface_SendDamageToThing)(sithSurface *sender, sithThing *receiver, float damage, int damageType) = (void*)sithSurface_SendDamageToThing_ADDR;
static int* (*sithSurface_SurfaceAnim)(void*, float, int) = (void*)sithSurface_SurfaceAnim_ADDR;
static int* (*sithSurface_MaterialAnim)(void*, float, int) = (void*)sithSurface_MaterialAnim_ADDR;
static rdSurface* (*sithSurface_GetByIdx)(int) = (void*)sithSurface_GetByIdx_ADDR;
static int (*sithSurface_StopAnim)(rdSurface *a1) = (void*)sithSurface_StopAnim_ADDR;
static rdSurface* (__cdecl *sithSurface_GetRdSurface)(sithSurface *a1) = (void*)sithSurface_GetRdSurface_ADDR;
static int (*sithSurface_GetSurfaceAnim)(sithSurface *a1) = (void*)sithSurface_GetSurfaceAnim_ADDR;
static rdSurface* (*sithSurface_SetThingLight)(sithThing *a1, float a2, float a3, int a4) = (void*)sithSurface_SetThingLight_ADDR;
static rdSurface* (*sithSurface_sub_4F00A0)(sithThing *a1, float a2, int a3) = (void*)sithSurface_sub_4F00A0_ADDR;
static void (*sithSurface_Free)(sithWorld* world) = (void*)sithSurface_Free_ADDR;

#endif // _SITHSURFACE_H
