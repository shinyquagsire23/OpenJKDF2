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
#define rdCache_SendFaceListToHardware_ADDR (0x0043B1C0)
#define rdCache_ResetRenderList_ADDR (0x0043C2C0)
#define rdCache_DrawRenderList_ADDR (0x0043C2E0)
#define rdCache_TriCompare_ADDR (0x0043C380)
#define rdCache_DrawFaceN_ADDR (0x0043C3C0)
#define rdCache_DrawFaceZ_ADDR (0x0043CED0)
#define rdCache_DrawFaceUser_ADDR (0x0043D9E0)
#define rdCache_ProcFaceCompare_ADDR (0x0043E170)

#define rdCache_aHWSolidTris    ((rdTri*)0x005703A0)
#define rdCache_totalNormalTris (*(int*)0x005753A0)
#define rdCache_aIntensities    ((float*)0x005753A8)
#define rdCache_aVertices       ((rdVector3*)0x005953A8)
#define rdCache_totalVerts      (*(int*)0x005F53A8)
#define rdCache_aTexVertices    ((rdVector2*)0x005F53B0)
#define rdCache_aHWNormalTris   ((rdTri*)0x006353B0)
#define rdCache_totalSolidTris  (*(int*)0x0063A3B0)
#define rdCache_aHWVertices     ((D3DVERTEX*)0x0063A3B8) // 

#define rdCache_drawnFaces (*(int*)0x0073A3B8)
#define rdCache_numUsedVertices (*(int*)0x0073A3BC)
#define rdCache_numUsedTexVertices (*(int*)0x0073A3C0)
#define rdCache_numUsedIntensities (*(int*)0x0073A3C4)
#define rdCache_ulcExtent (*(rdVector2i*)0x0086EE70)
#define rdCache_lrcExtent (*(rdVector2i*)0x0086EE78)
#define rdCache_numProcFaces (*(int*)0x0086EE80)
#define rdCache_aProcFaces ((rdProcEntry*)0x0086EEA0)
#define dword_865258 (*(int*)0x00865258)

typedef struct rdMaterial rdMaterial;

typedef struct rdProcEntry
{
    uint32_t extraData;
    int type;
    uint32_t geometryMode;
    uint32_t lightingMode;
    uint32_t textureMode;
    uint32_t anonymous_4;
    uint32_t anonymous_5;
    uint32_t numVertices;
    rdVector3* vertices;
    rdVector2* vertexUVs;
    float* vertexIntensities;
    rdMaterial* material;
    uint32_t wallCel;
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

typedef struct v11_struct
{
  int mipmap_related;
  int field_4;
  rdMaterial *material;
} v11_struct;

typedef struct rdTri
{
  int v1;
  int v2;
  int v3;
  int flags;
  rdDDrawSurface *texture; // DirectDrawSurface*
} rdTri;

int rdCache_Startup();
void rdCache_AdvanceFrame();
void rdCache_FinishFrame();
void rdCache_Reset();
void rdCache_ClearFrameCounters();
rdProcEntry *rdCache_GetProcEntry();
void rdCache_Flush();
int rdCache_SendFaceListToHardware();
void rdCache_ResetRenderList();
void rdCache_DrawRenderList();
int rdCache_TriCompare(rdTri *a, rdTri *b);

int rdCache_ProcFaceCompare(rdProcEntry *a, rdProcEntry *b);

static void (*rdCache_DrawFaceUser)(rdProcEntry* face) = (void*)rdCache_DrawFaceUser_ADDR;
static void (*rdCache_DrawFaceN)(rdProcEntry* face) = (void*)rdCache_DrawFaceN_ADDR;
static void (*rdCache_DrawFaceZ)(rdProcEntry* face) = (void*)rdCache_DrawFaceZ_ADDR;
//static int (*rdCache_SendFaceListToHardware)(void) = (void*)rdCache_SendFaceListToHardware_ADDR;
//static void (*rdCache_ClearFrameCounters)(void) = (void*)rdCache_ClearFrameCounters_ADDR;
//static void (*rdCache_AdvanceFrame)(void) = (void*)rdCache_AdvanceFrame_ADDR;
//static void (*rdCache_Flush)(void) = (void*)rdCache_Flush_ADDR;
//static void (*rdCache_FinishFrame)(void) = (void*)rdCache_FinishFrame_ADDR;

//static rdProcEntry* (*rdCache_GetProcEntry)(void) = (void*)rdCache_GetProcEntry_ADDR;
static int (*__cdecl rdCache_AddProcFace)(int extdata, unsigned int numVertices, char flags) = (void*)rdCache_AddProcFace_ADDR;

#endif // _RDCACHE_H
