#include "rdActive.h"

#include "Engine/rdCanvas.h"
#include "Engine/rdCamera.h"
#include "jk.h"

int rdActive_Startup()
{
    return 1;
}

void rdActive_AdvanceFrame()
{
    rdCanvas *v0; // eax
    int v1; // edx
    unsigned int v2; // esi

    rdCanvas* canvas = rdCamera_pCurCamera->canvas;

    activeEdgeHead.field_28 = -65536;
    activeEdgeHead.next = &activeEdgeTail;
    activeEdgeTail.prev = &activeEdgeHead;
    v1 = canvas->yStart;
    v2 = 4 * (canvas->heightMinusOne - v1 + 1);
    _memset((void *)&apNewActiveEdges[v1], 0, v2);
    _memset((void *)&apRemoveActiveEdges[v1], 0, v2);
    yMinEdge = 0x7FFFFFFF;
    yMaxEdge = 0;
    activeEdgeHead.prev = 0;
    activeEdgeTail.field_28 = 0x7FFFFFFF;
    activeEdgeTail.next = 0;
    numActiveFaces = 0;
    numActiveEdges = 0;
    numActiveSpans = 0;
}

void rdActive_ClearFrameCounters()
{
    rdActive_drawnFaces = 0;
}
