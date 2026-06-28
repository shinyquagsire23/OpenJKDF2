#include "stdColor.h"

#include <math.h>
#include "jk.h"

#ifdef RDMATERIAL_MINIMIZE_STRUCTS

// Forced to RGB555
#define STDCOLOR_RGB15(r, g, b)      ((r) | ((g) << 5) | ((b) << 10))
int stdColor_Indexed8ToRGB16(uint8_t idx, rdColor24 *pal, rdTexFormatMin *fmt)
{
    rdColor24* pColor = (rdColor24 *)((char *)pal + 2 * idx + idx);
    return STDCOLOR_RGB15(pColor->r >> 3, pColor->g >> 3, pColor->b >> 3);
}
#else
int stdColor_Indexed8ToRGB16(uint8_t idx, rdColor24 *pal, rdTexFormat *fmt)
{
    rdColor24 *v3; // esi

    v3 = (rdColor24 *)((char *)pal + 2 * idx + idx);
    return ((uint8_t)((uint8_t)v3->g >> (fmt->g_bitdiff & 0xFF)) << fmt->g_shift) | ((uint8_t)((uint8_t)v3->r >> (fmt->r_bitdiff & 0xFF)) << fmt->r_shift) | ((uint8_t)v3->b >> (fmt->b_bitdiff & 0xFF) << fmt->b_shift);
}
#endif

uint32_t stdColor_ColorConvertOnePixel(rdTexFormat *formatTo, int color, rdTexFormat *formatFrom)
{
    uint32_t tmp;
    stdColor_ColorConvertOneRow((uint8_t*)&tmp, formatTo, (uint8_t*)&color, formatFrom, 1);
    return tmp;
}

int stdColor_ColorConvertOneRow(uint8_t *outPixels, rdTexFormat *formatTo, uint8_t *inPixels, rdTexFormat *formatFrom, int numPixels)
{
    int v6; // eax
    int v8; // edx
    int v9; // edi
    int result; // eax
    uint32_t v11; // ebx
    uint32_t v12; // bx
    uint32_t v13; // edx
    uint32_t v14; // eax
    unsigned int v15; // ebx
    uint32_t v16; // edx
    uint32_t v17; // eax
    unsigned int v18; // ebx
    unsigned int v19; // eax
    uint8_t *v20; // ecx
    int v21; // zf
    unsigned int v22; // [esp+10h] [ebp-14h]
    unsigned int v23; // [esp+14h] [ebp-10h]
    int v24; // [esp+1Ch] [ebp-8h]
    int v25; // [esp+20h] [ebp-4h]
    int formatToa; // [esp+2Ch] [ebp+8h]
    int formatFroma; // [esp+34h] [ebp+10h]

    v6 = formatFrom->r_bits;
    v22 = 0xFFFFFFFF >> (32 - v6);
    v8 = formatFrom->g_bits;
    v23 = 0xFFFFFFFF >> (32 - v8);
    v9 = formatFrom->b_bits;
    v24 = v6 - formatTo->r_bits;
    result = numPixels;
    v25 = v8 - formatTo->g_bits;
    formatFroma = v9 - formatTo->b_bits;
    if ( numPixels > 0 )
    {
        v11 = (uint32_t)((intptr_t)inPixels & 0xFFFFFFFF);
        formatToa = numPixels;
        do
        {
            switch ( formatFrom->bpp )
            {
                case 8:
                    v11 = *inPixels;
                    break;
                case 16:
                    v11 = *(uint16_t*)inPixels;
                    break;
                case 24:
                    v12 = 0;
                    v12 |= ((uint32_t)inPixels[0]) << 8;
                    v12 |= ((uint32_t)inPixels[1]);
                    v11 = inPixels[2] | (v12 << 8);
                    break;
                case 32:
                    v11 = *(uint32_t*)inPixels;
                    break;
                default:
                    std_pHS->assert(
                        "Unsupported pixel depth.  Only 8, 16, 24, & 32 bits per pixel supported at the moment.",
                        ".\\General\\stdColor.c",
                        525);
                    break;
            }
            v13 = v22 & (v11 >> formatFrom->r_shift);
            v14 = v23 & (v11 >> formatFrom->g_shift);
            v15 = (0xFFFFFFFF >> (32 - v9)) & (v11 >> formatFrom->b_shift);
            if ( v24 <= 0 )
                v16 = v13 << -(char)v24;
            else
                v16 = v13 >> v24;
            if ( v25 <= 0 )
                v17 = v14 << -(char)v25;
            else
                v17 = v14 >> v25;
            if ( v24 <= 0 )
                v18 = v15 << -(char)formatFroma;
            else
                v18 = v15 >> formatFroma;
            v11 = (v16 << formatTo->r_shift) | (v18 << formatTo->b_shift) | (v17 << formatTo->g_shift);
            v19 = formatTo->bpp;
            switch ( v19 )
            {
                case 8u:
                    *outPixels = v11;
                    break;
                case 16u:
                    *(uint16_t*)outPixels = v11;
                    break;
                case 24u:
                    outPixels[0] = (v11 >> 16) & 0xFF;
                    outPixels[1] = (v11 >> 8) & 0xFF;
                    outPixels[2] = v11;
                    break;
                case 32u:
                    *(uint32_t*)outPixels = v11;
                    break;
                default:
                    break;
            }
            v20 = &outPixels[v19 >> 3];
            result = formatToa - 1;
            v21 = formatToa == 1;
            inPixels += (unsigned int)formatFrom->bpp >> 3;
            outPixels = v20;
            --formatToa;
        }
        while ( !v21 );
    }
    return result;
}

void stdColor_LoadPalette(rdColor24 *dst, rdColor24 *src)
{
    _memcpy(dst, src, 0x300);
}

uint8_t stdColor_FindClosest(rdColor24 *palette, uint32_t numColors, flex_t r, flex_t g, flex_t b)
{
    uint32_t bestIdx = 0;
    flex_t bestDist = 3.4e+38f;

    for (uint32_t i = 0; i < numColors; i++)
    {
        if ( bestDist <= 0.01f )
            return (uint8_t)bestIdx;

        flex_t dr = (flex_t)palette[i].r - r;
        flex_t dg = (flex_t)palette[i].g - g;
        flex_t db = (flex_t)palette[i].b - b;
        flex_t dist = dr * dr * 0.30f + dg * dg * 0.59f + db * db * 0.11f;
        if ( dist < bestDist )
        {
            bestIdx = i;
            bestDist = dist;
        }
    }
    return (uint8_t)bestIdx;
}

void stdColor_RGBtoHSV(flex_t r, flex_t g, flex_t b, flex_t *pH, flex_t *pS, flex_t *pV)
{
    r /= 255.0f;
    g /= 255.0f;
    b /= 255.0f;

    flex_t maxVal = r;
    if ( g > maxVal ) maxVal = g;
    if ( b > maxVal ) maxVal = b;

    flex_t minVal = r;
    if ( r > g ) minVal = g;
    if ( minVal > b ) minVal = b;

    flex_t delta = maxVal - minVal;
    *pV = maxVal;

    if ( maxVal == 0.0f )
        *pS = 0.0f;
    else
        *pS = delta / maxVal;

    if ( *pS == 0.0f )
    {
        *pH = 0.0f;
        return;
    }

    flex_t rc = (maxVal - r) / delta;
    flex_t gc = (maxVal - g) / delta;
    flex_t bc = (maxVal - b) / delta;
    flex_t h;

    if ( r == maxVal )
        h = bc - gc;
    else if ( g == maxVal )
        h = rc - bc + 2.0f;
    else
        h = gc - rc + 4.0f;

    *pH = h * 60.0f;
    if ( *pH < 0.0f )
        *pH += 360.0f;
}

void stdColor_HSVtoRGB(flex_t h, flex_t s, flex_t v, flex_t *pR, flex_t *pG, flex_t *pB)
{
    if ( s == 0.0f )
    {
        flex_t val = v * 255.0f;
        *pR = val;
        *pG = val;
        *pB = val;
        return;
    }

    int sector = (__int64)(h / 60.0f);
    flex_t frac = h / 60.0f - (flex_t)sector;
    flex_t p = (1.0f - s) * v;
    flex_t q = (1.0f - frac * s) * v;
    flex_t t = (1.0f - (1.0f - frac) * s) * v;

    flex_t rr, gg, bb;
    switch ( sector )
    {
        case 0: rr = v;  gg = t;  bb = p;  break;
        case 1: rr = q;  gg = v;  bb = p;  break;
        case 2: rr = p;  gg = v;  bb = t;  break;
        case 3: rr = p;  gg = q;  bb = v;  break;
        case 4: rr = t;  gg = p;  bb = v;  break;
        case 5: rr = v;  gg = p;  bb = q;  break;
        default: return;
    }
    *pR = rr * 255.0f;
    *pG = gg * 255.0f;
    *pB = bb * 255.0f;
}

int stdColor_BuildRGB16LUT(rdColor24 *palette, uint16_t *lut, rdTexFormat *format)
{
    for (int i = 0; i < 256; i++)
    {
        lut[i] = (uint16_t)((palette[i].r >> format->r_bitdiff) << format->r_shift)
               | (uint16_t)((palette[i].g >> format->g_bitdiff) << format->g_shift)
               | (uint16_t)((palette[i].b >> format->b_bitdiff) << format->b_shift);
    }
    return 1;
}

int stdColor_BuildRGBAKEY16LUT(rdColor24 *palette, uint16_t *lut, rdTexFormat *format)
{
    for (uint32_t i = 0; i < 256; i++)
    {
        uint16_t alpha = (i != 0) ? 0xFF : 0;
        alpha = (alpha >> format->unk_48) << format->unk_40;
        lut[i] = (uint16_t)((palette[i].r >> format->r_bitdiff) << format->r_shift)
               | (uint16_t)((palette[i].g >> format->g_bitdiff) << format->g_shift)
               | (uint16_t)((palette[i].b >> format->b_bitdiff) << format->b_shift)
               | alpha;
    }
    return 1;
}

int stdColor_BuildRGBA16LUT(rdColor24 *palette, uint16_t *lut, rdTexFormat *format, uint32_t alphaVal)
{
    for (uint32_t i = 0; i < 256; i++)
    {
        uint32_t alpha = (i == 0) ? 0 : (alphaVal & 0xFF);
        alpha = (alpha >> format->unk_48) << format->unk_40;
        lut[i] = (uint16_t)((palette[i].r >> format->r_bitdiff) << format->r_shift)
               | (uint16_t)((palette[i].g >> format->g_bitdiff) << format->g_shift)
               | (uint16_t)((palette[i].b >> format->b_bitdiff) << format->b_shift)
               | (uint16_t)alpha;
    }
    return 1;
}

int stdColor_GammaCorrect(uint8_t *pOut, uint8_t *pIn, int numColors, flex_d_t gamma)
{
    for (int i = 0; i < numColors; i++)
    {
        pOut[0] = (uint8_t)(__int64)(powf((flex_d_t)pIn[0] / 255.0, gamma) * 255.0);
        pOut[1] = (uint8_t)(__int64)(powf((flex_d_t)pIn[1] / 255.0, gamma) * 255.0);
        pOut[2] = (uint8_t)(__int64)(powf((flex_d_t)pIn[2] / 255.0, gamma) * 255.0);
        pOut += 3;
        pIn += 3;
    }
    return 1;
}