#ifndef _RDCACHE_H
#define _RDCACHE_H

#include "Primitives/rdVector.h"
#include "Engine/rdMaterial.h"

#define rdCache_Startup_ADDR (0x0043AD60)
#define rdCache_AdvanceFrame_ADDR (0x0043AD70)
#define rdCache_FinishFrame_ADDR (0x0043AD80)
#define rdCache_Reset_ADDR (0x0043AD90)
#define rdCache_ClearFrameCounters_ADDR (0x0043ADD0)
#define rdCache_GetProcEntry_ADDR (0x0043ADE0)
#define rdCache_Flush_ADDR (0x0043AE70)
#define rdCache_AddProcFace_ADDR (0x0043AF90)
#define rdCache_SendFaceListToHardware_ADDR (0x0043B1C0	000010F7)
#define rdCache_ResetRenderList_ADDR (0x0043C2C0)
#define rdCache_DrawRenderList_ADDR (0x0043C2E0)
#define rdCache_TriCompare_ADDR (0x0043C380)
#define rdCache_DrawFaceN_ADDR (0x0043C3C0)
#define rdCache_DrawFaceZ_ADDR (0x0043CED0)
#define rdCache_DrawFaceUser_ADDR (0x0043D9E0)
#define rdCache_ProcFaceCompare_ADDR (0x0043E170)

typedef struct rdMaterial rdMaterial;

typedef struct rdProcEntry
{
    void* extraData;
    int type;
    uint32_t geometryMode;
    uint32_t lightingMode;
    uint32_t textureMode;
    uint32_t anonymous_4;
    uint32_t anonymous_5;
    uint32_t numVertices;
    rdVector3* vertices;
    rdVector2* vertexUVs;
    float* vertex_lights_maybe;
    rdMaterial* material;
    uint32_t sith_tex_3_idx_2;
    float ambientLight;
    float light_level_static;
    float extralight;
    uint32_t colormap;
    uint32_t light_flags;
    float x_min;
    float x_max;
    float y_min;
    float y_max;
    float z_min;
    float z_max;
    float y_min_related;
    float y_max_related;
    uint32_t vertexColorMode;
} rdProcEntry;

typedef struct rdMeshinfo
{
    uint32_t numVertices;
    int* vertexPosIdx;
    int* vertexUVIdx;
    rdVector3* verticesProjected;
    rdVector2* vertexUVs;
    float* vertex_lights_maybe_;
    uint32_t field_18;
    rdVector3* verticesOrig;
} rdMeshinfo;

static int (*rdCache_Startup)(void) = (void*)rdCache_Startup_ADDR;
static void (*rdCache_ClearFrameCounters)(void) = (void*)rdCache_ClearFrameCounters_ADDR;
static void (*rdCache_AdvanceFrame)(void) = (void*)rdCache_AdvanceFrame_ADDR;
static void (*rdCache_Flush)(void) = (void*)rdCache_Flush_ADDR;
static void (*rdCache_FinishFrame)(void) = (void*)rdCache_FinishFrame_ADDR;

static rdProcEntry* (*rdCache_GetProcEntry)(void) = (void*)rdCache_GetProcEntry_ADDR;
static int (*__cdecl rdCache_AddProcFace)(int extdata, unsigned int numVertices, char flags) = (void*)rdCache_AddProcFace_ADDR;

#endif // _RDCACHE_H
