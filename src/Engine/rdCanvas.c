#include "rdCanvas.h"

#include "Engine/rdroid.h"

rdCanvas* rdCanvas_New(int bIdk, stdVBuffer *vbuf1, stdVBuffer *vbuf2, int x, int y, int w, int h, int a8)
{
    rdCanvas *result; // eax
    rdCanvas *v9; // esi

    result = (rdCanvas *)rdroid_pHS->alloc(sizeof(rdCanvas));
    v9 = result;
    if ( result )
    {
        rdCanvas_NewEntry(result, bIdk, vbuf1, vbuf2, x, y, w, h, a8);
        result = v9;
    }
    return result;
}

int rdCanvas_NewEntry(rdCanvas *canvas, int bIdk, stdVBuffer *vbuf, stdVBuffer *a4, int x, int y, int width, int height, int a9)
{
    int v9; // eax
    signed int result; // eax

    canvas->d3d_vbuf = a4;
    canvas->bIdk = bIdk;
    canvas->vbuffer = vbuf;
    canvas->field_14 = a9;
    if ( bIdk & 1 )
    {
        canvas->xStart = x;
        canvas->yStart = y;
        canvas->widthMinusOne = width;
        canvas->heightMinusOne = height;
    }
    else
    {
        canvas->xStart = 0;
        canvas->yStart = 0;
        canvas->widthMinusOne = vbuf->format.width - 1;
        canvas->heightMinusOne = vbuf->format.height - 1;
    }
    canvas->screen_height_half = (flex_d_t)(canvas->widthMinusOne - canvas->xStart + 1) * 0.5 + (flex_d_t)canvas->xStart;
    canvas->screen_width_half = (flex_d_t)(canvas->heightMinusOne - canvas->yStart + 1) * 0.5 + (flex_d_t)canvas->yStart;
    return 1;
}

void rdCanvas_Free(rdCanvas *canvas)
{
    if ( canvas )
        rdroid_pHS->free(canvas);
}

void rdCanvas_FreeEntry(rdCanvas *canvas)
{
}
