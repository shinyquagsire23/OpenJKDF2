#ifndef _SITHSURFACE_H
#define _SITHSURFACE_H

#include "Primitives/rdVector.h"

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
#define sithSurface_StopSurfaceAnim_ADDR (0x004F09F0)
#define sithSurface_detachthing_ADDR (0x004F0A30)
#define sithSurface_GetByIdx_ADDR (0x004F0AA0)
#define sithSurface_Alloc_ADDR (0x004F0AF0)
#define sithSurface_Sync_ADDR (0x004F0B50)
#define sithSurface_ScrollSky_ADDR (0x004F0BC0)

typedef struct sithSector sithSector;
typedef struct sithAdjoin sithAdjoin;
typedef struct rdMaterial rdMaterial;

typedef struct sithSurfaceInfo
{
    uint32_t field_0;
    uint32_t faceType;
    uint32_t geoMode;
    uint32_t lightMode;
    uint32_t texMode;
    uint32_t numVertices;
    int* vertexIdxs;
    uint32_t field_1C;
    rdMaterial* material;
    uint32_t wallCel;
    uint32_t field_28;
    uint32_t field_2C;
    uint32_t field_30;
    rdVector3 surfaceNormal;
    uint32_t field_40;
    uint32_t field_44;
} sithSurfaceInfo;

typedef struct sithSurface
{
    uint32_t field_0;
    uint32_t field_4;
    sithSector* parent_sector;
    sithAdjoin* adjoin;
    uint32_t surfaceFlags;
    sithSurfaceInfo surfaceInfo;
} sithSurface;

static void (__cdecl *sithSurface_SendDamageToThing)(sithSurface *sender, sithThing *receiver, float damage, int damageType) = (void*)sithSurface_SendDamageToThing_ADDR;
static int* (*sithSurface_SurfaceAnim)(void*, float, int) = (void*)sithSurface_SurfaceAnim_ADDR;
static int* (*sithSurface_MaterialAnim)(void*, float, int) = (void*)sithSurface_MaterialAnim_ADDR;

#endif // _SITHSURFACE_H
