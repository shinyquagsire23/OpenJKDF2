#include "rdPrimit2.h"

#include <stdlib.h>
#include "General/stdMath.h"
#include "Engine/rdClip.h"

int rdPrimit2_DrawLine(rdCanvas *pCanvas, int x1, int y1, int x2, int y2, uint16_t color16, int mask)
{
    stdVBuffer *v7; // ebx
    int v8; // ebp
    int v9; // edi
    int v10; // esi
    int v11; // ecx
    int v12; // ebp
    int v13; // edi
    int v14; // esi
    int v15; // ecx
    int v17; // [esp+4h] [ebp-14h]
    int v18; // [esp+4h] [ebp-14h]
    unsigned int v19; // [esp+8h] [ebp-10h]
    int v20; // [esp+Ch] [ebp-Ch]
    int v21; // [esp+Ch] [ebp-Ch]
    int v22; // [esp+10h] [ebp-8h]
    int v23; // [esp+10h] [ebp-8h]
    int v24; // [esp+14h] [ebp-4h]
    int v25; // [esp+14h] [ebp-4h]

    v7 = pCanvas->vbuffer;
    v19 = 0x80000000;
    if ( v7->format.format.bpp == 8 )
    {
        v17 = y2 - y1;
        v20 = x2 - x1;
        v8 = x1;
        v9 = y1;
        v22 = x2 - x1 <= 0 ? -1 : 1;
        v24 = y2 - y1 <= 0 ? -1 : 1;
        if ( v22 < 0 )
            v17 = y1 - y2;
        if ( (y2 - y1 <= 0 ? -1 : 1) > 0 )
            v20 = x1 - x2;
        if ( mask < 0 )
            v7->surface_lock_alloc[y1 * v7->format.width_in_bytes + x1] = color16;// crashes here
        v10 = 0;
        while ( v8 != x2 || v9 != y2 )
        {
            v19 >>= 1;
            if ( !v19 )
                v19 = 0x80000000;
            v11 = v10 + v17;
            v10 += v20;
            if ( (int)abs(v11) >= (int)abs(v10) )
            {
                v9 += v24;
            }
            else
            {
                v10 = v11;
                v8 += v22;
            }
            if ( (v19 & mask) != 0 )
                pCanvas->vbuffer->surface_lock_alloc[v9 * pCanvas->vbuffer->format.width_in_bytes + v8] = color16;
        }
    }
    else
    {
        v18 = y2 - y1;
        v21 = x2 - x1;
        v12 = x1;
        v13 = y1;
        v23 = x2 - x1 <= 0 ? -1 : 1;
        v25 = y2 - y1 <= 0 ? -1 : 1;
        if ( v23 < 0 )
            v18 = y1 - y2;
        if ( (y2 - y1 <= 0 ? -1 : 1) > 0 )
            v21 = x1 - x2;
        if ( mask < 0 )
            *(uint16_t *)&v7->surface_lock_alloc[2 * x1 + 2 * y1 * v7->format.width_in_pixels] = color16;
        v14 = 0;
        while ( v12 != x2 || v13 != y2 )
        {
            v19 >>= 1;
            if ( !v19 )
                v19 = 0x80000000;
            v15 = v14 + v18;
            v14 += v21;
            if ( (int)abs(v15) >= (int)abs(v14) )
            {
                v13 += v25;
            }
            else
            {
                v14 = v15;
                v12 += v23;
            }
            if ( (v19 & mask) != 0 )
                *(uint16_t*)&pCanvas->vbuffer->surface_lock_alloc[2 * v12 + 2 * v13 * pCanvas->vbuffer->format.width_in_pixels] = color16;
        }
    }
    return 1;
}

int rdPrimit2_DrawClippedLine(rdCanvas *pCanvas, int x1, int y1, int x2, int y2, uint16_t color16, int mask)
{
    if ( !rdClip_Line2(pCanvas, &x1, &y1, &x2, &y2) )
        return 0;
    return rdPrimit2_DrawLine(pCanvas, x1, y1, x2, y2, color16, mask);
}


void rdPrimit2_DrawCircle(rdCanvas *pCanvas, int x1, int y1, float a4, float radius, uint16_t color16, int mask)
{
    __int64 v7; // rax
    int v8; // edi
    int v9; // ebx
    int v10; // ebp
    int v11; // esi
    int v12; // edi
    double v13; // st7
    float a2a; // [esp+0h] [ebp-Ch]
    float a4a; // [esp+4h] [ebp-8h] BYREF
    float a3a; // [esp+8h] [ebp-4h] BYREF

    v7 = (__int64)(a4 - -0.5);
    v8 = x1;
    if ( (int)v7 + x1 >= pCanvas->xStart && x1 - (int)v7 <= pCanvas->widthMinusOne && (int)v7 + y1 >= pCanvas->yStart && y1 - (int)v7 <= pCanvas->heightMinusOne )
    {
        stdMath_SinCos(0.0, &a3a, &a4a);
        v9 = x1 + (__int64)(a4a * a4 - -0.5);
        a2a = radius;
        v10 = y1 + (__int64)(a3a * a4 - -0.5);
        if ( radius <= 360.0 )
        {
            while ( 1 )
            {
                stdMath_SinCos(a2a, &a3a, &a4a);
                v11 = v8 + (__int64)(a4a * a4 - -0.5);
                v12 = y1 + (__int64)(a3a * a4 - -0.5);
                rdPrimit2_DrawClippedLine(pCanvas, v9, v10, v11, v12, color16, mask);
                v13 = a2a + radius;
                v9 = v11;
                v10 = v12;
                a2a = v13;
                if ( v13 > 360.0 )
                    break;
                v8 = x1;
            }
        }
    }
}


void rdPrimit2_DrawRectangle(rdCanvas *pCanvas, int x1, int y1, int x2, int y2, int16_t color, int mask)
{
    rdPrimit2_DrawClippedLine(pCanvas, x1, y1, x2, y1, color, mask);
    rdPrimit2_DrawClippedLine(pCanvas, x2, y1, x2, y2, color, mask);
    rdPrimit2_DrawClippedLine(pCanvas, x1, y1, x1, y2, color, mask);
    rdPrimit2_DrawClippedLine(pCanvas, x1, y2, x2, y2, color, mask);
}

void rdPrimit2_DrawTriangle(rdCanvas *pCanvas, int x1, int y1, int x2, int y2, int x3, int y3, int16_t color, int mask)
{
    rdPrimit2_DrawClippedLine(pCanvas, x1, y1, x2, y2, color, mask);
    rdPrimit2_DrawClippedLine(pCanvas, x2, y2, x3, y3, color, mask);
    rdPrimit2_DrawClippedLine(pCanvas, x3, y3, x1, y1, color, mask);
}