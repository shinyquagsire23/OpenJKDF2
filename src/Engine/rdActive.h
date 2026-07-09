#ifndef _RDACTIVE_H
#define _RDACTIVE_H

#include "types.h"
#include "globals.h"

#define rdActive_Startup_ADDR (0x0044BBC0)
#define rdActive_AdvanceFrame_ADDR (0x0044BBD0)
#define rdActive_ClearFrameCounters_ADDR (0x0044BC70)
#define rdActive_DrawScene_ADDR (0x0044BC80)
#define rdActive_BuildSpans_ADDR (0x0044BE00)
#define rdActive_FlushSpans_ADDR (0x0044C640)  // JK label rdActive_AddNewEdges is a misnomer; it is FlushSpans
#define rdActive_BuildEdges_ADDR (0x0044C690)
#define rdActive_AddActiveFace_ADDR (0x0044C7E0)

int rdActive_Startup();
void rdActive_AdvanceFrame();
void rdActive_ClearFrameCounters();

#ifdef RDRASTER_SOFTWARE_RENDERER
void rdActive_DrawScene();
void rdActive_BuildEdges();
void rdActive_BuildSpans();
void rdActive_FlushSpans();
rdActiveSpan* rdActive_pSpanPoolBegin(void);
rdActiveSpan* rdActive_pSpanPoolEnd(void);
// Defined by the rdAFRaster family (P3): dispatches a proc face to the setup routine
// that matches its shading/surface/bit-depth and admits it to the active-face pool.
int rdActive_AddActiveFace(rdProcEntry* pProcEntry);
#endif

//static int (*rdActive_Startup)(void) = (void*)rdActive_Startup_ADDR;
//static void (*__cdecl rdActive_AdvanceFrame)(void) = (void*)rdActive_AdvanceFrame_ADDR;
//static void (*__cdecl rdActive_DrawScene)(void) = (void*)rdActive_DrawScene_ADDR;
//static void (*rdActive_ClearFrameCounters)(void) = (void*)rdActive_ClearFrameCounters_ADDR;

#endif // _RDACTIVE_H
