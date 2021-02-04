#ifndef _RDACTIVE_H
#define _RDACTIVE_H

#include "types.h"

#define rdActive_Startup_ADDR (0x0044BBC0)
#define rdActive_AdvanceFrame_ADDR (0x0044BBD0)
#define rdActive_ClearFrameCounters_ADDR (0x0044BC70)
#define rdActive_DrawScene_ADDR (0x0044BC80)
#define rdActive_BuildSpans_ADDR (0x0044BE00)
#define rdActive_AddNewEdges_ADDR (0x0044C640)
#define rdActive_BuildEdges_ADDR (0x0044C690)
#define rdActive_AddActiveFace_ADDR (0x0044C7E0)

typedef struct rdEdge
{
    uint32_t field_0;
    uint32_t field_4;
    uint32_t field_8;
    uint32_t field_C;
    uint32_t field_10;
    uint32_t field_14;
    uint32_t field_18;
    uint32_t field_1C;
    uint32_t field_20;
    uint32_t field_24;
    uint32_t field_28;
    uint32_t field_2C;
    uint32_t field_30;
    uint32_t field_34;
    uint32_t field_38;
    uint32_t field_3C;
    uint32_t field_40;
    uint32_t field_44;
    uint32_t field_48;
    rdEdge* prev;
    rdEdge* next;
} rdEdge;

int rdActive_Startup();
void rdActive_AdvanceFrame();
void rdActive_ClearFrameCounters();

//static int (*rdActive_Startup)(void) = (void*)rdActive_Startup_ADDR;
//static void (*__cdecl rdActive_AdvanceFrame)(void) = (void*)rdActive_AdvanceFrame_ADDR;
static void (*__cdecl rdActive_DrawScene)(void) = (void*)rdActive_DrawScene_ADDR;
//static void (*rdActive_ClearFrameCounters)(void) = (void*)rdActive_ClearFrameCounters_ADDR;

#define activeEdgeTail (*(rdEdge*)0x0082D688)
#define activeEdgeHead (*(rdEdge*)0x0073E618)
#define apNewActiveEdges ((rdEdge**)0x0073D610)
#define apRemoveActiveEdges ((rdEdge**)0x00754680)
#define yMinEdge (*(int*)0x0073E610)
#define yMaxEdge (*(int*)0x0073E670)
#define numActiveSpans (*(int*)0x0073E674)
#define numActiveFaces (*(int*)0x0082D684)
#define numActiveEdges (*(int*)0x0082D680)

#define aActiveEdges ((void*)0x00755680)

#define rdActive_drawnFaces (*(int*)0x0082D6E0)
 
 
 

#endif // _RDACTIVE_H
