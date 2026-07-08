#include "rdCanvas.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "Engine/rdroid.h"

rdCanvas* rdCanvas_New(int bIdk, tVBuffer *vbuf1, tVBuffer *vbuf2, int x, int y, int w, int h, int a8)
{
    rdCanvas *result; // eax
    rdCanvas *v9; // esi

    result = (rdCanvas *)RDROID_ALLOC(sizeof(rdCanvas));
    v9 = result;
    if ( result )
    {
        rdCanvas_NewEntry(result, bIdk, vbuf1, vbuf2, x, y, w, h, a8);
        result = v9;
    }
    return result;
}

int rdCanvas_NewEntry(rdCanvas *pCanvas, int bIdk, tVBuffer *vbuf, tVBuffer *a4, int x, int y, int width, int height, int a9)
{
    int v9; // eax
    signed int result; // eax

    pCanvas->d3d_vbuf = a4;
    pCanvas->bIdk = bIdk;
    pCanvas->pVBuffer = vbuf;
    pCanvas->field_14 = a9;
    if ( bIdk & 1 )
    {
        pCanvas->xStart = x;
        pCanvas->yStart = y;
        pCanvas->widthMinusOne = width;
        pCanvas->heightMinusOne = height;
    }
    else
    {
        pCanvas->xStart = 0;
        pCanvas->yStart = 0;
        pCanvas->widthMinusOne = vbuf->format.width - 1;
        pCanvas->heightMinusOne = vbuf->format.height - 1;
    }
    pCanvas->half_screen_width = (flex_d_t)(pCanvas->widthMinusOne - pCanvas->xStart + 1) * 0.5 + (flex_d_t)pCanvas->xStart;
    pCanvas->half_screen_height = (flex_d_t)(pCanvas->heightMinusOne - pCanvas->yStart + 1) * 0.5 + (flex_d_t)pCanvas->yStart;
    return 1;
}

void rdCanvas_Free(rdCanvas *pCanvas)
{
    if ( pCanvas )
        RDROID_FREE(pCanvas);
}

void rdCanvas_FreeEntry(rdCanvas *pCanvas)
{
}
