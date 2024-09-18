#ifndef _RDCACHE_H
#define _RDCACHE_H

#include "types.h"
#include "globals.h"
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
int rdCache_TriCompare(const void* a_, const void* b_);

int rdCache_ProcFaceCompare(rdProcEntry *a, rdProcEntry *b);
int rdCache_AddProcFace(int a1, unsigned int num_vertices, char flags);

#ifdef DECAL_RENDERING
void rdCache_DrawDecal(rdDecal* decal, rdMatrix34* matrix, rdVector3* color, rdVector3* scale, float angleFade);
#endif

#ifndef __cplusplus
static void (*rdCache_DrawFaceUser)(rdProcEntry* face) = (void*)rdCache_DrawFaceUser_ADDR;
static void (*rdCache_DrawFaceN)(rdProcEntry* face) = (void*)rdCache_DrawFaceN_ADDR;
static void (*rdCache_DrawFaceZ)(rdProcEntry* face) = (void*)rdCache_DrawFaceZ_ADDR;
//static int (*rdCache_SendFaceListToHardware)(void) = (void*)rdCache_SendFaceListToHardware_ADDR;
//static void (*rdCache_ClearFrameCounters)(void) = (void*)rdCache_ClearFrameCounters_ADDR;
//static void (*rdCache_AdvanceFrame)(void) = (void*)rdCache_AdvanceFrame_ADDR;
//static void (*rdCache_Flush)(void) = (void*)rdCache_Flush_ADDR;
//static void (*rdCache_FinishFrame)(void) = (void*)rdCache_FinishFrame_ADDR;

//static rdProcEntry* (*rdCache_GetProcEntry)(void) = (void*)rdCache_GetProcEntry_ADDR;
//static int (*__cdecl rdCache_AddProcFace)(int extdata, unsigned int numVertices, char flags) = (void*)rdCache_AddProcFace_ADDR;
#endif

#endif // _RDCACHE_H
