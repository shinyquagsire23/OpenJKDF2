#include "stdColor.h"

#include "jk.h"

int stdColor_Indexed8ToRGB16(uint8_t idx, rdColor24 *pal, rdTexformat *fmt)
{
    rdColor24 *v3; // esi

    v3 = (rdColor24 *)((char *)pal + 2 * idx + idx);
    return ((uint8_t)((uint8_t)v3->g >> (fmt->g_bitdiff & 0xFF)) << fmt->g_shift) | ((uint8_t)((uint8_t)v3->r >> (fmt->r_bitdiff & 0xFF)) << fmt->r_shift) | ((uint8_t)v3->b >> (fmt->b_bitdiff & 0xFF) << fmt->b_shift);
}

uint32_t stdColor_ColorConvertOnePixel(rdTexformat *formatTo, int color, rdTexformat *formatFrom)
{
    uint32_t tmp;
    stdColor_ColorConvertOneRow((uint8_t*)&tmp, formatTo, (uint8_t*)&color, formatFrom, 1);
    return tmp;
}

int stdColor_ColorConvertOneRow(uint8_t *outPixels, rdTexformat *formatTo, uint8_t *inPixels, rdTexformat *formatFrom, int numPixels)
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
                
                 //   std_pHS->assert(
                   //     "Unsupported pixel depth.  Only 8, 16, 24, & 32 bits per pixel supported at the moment.",
                     //   ".\\General\\stdColor.c",
                       // 525);
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

int stdColor_GammaCorrect(uint8_t *a1, uint8_t *a2, int a3, flex_d_t a4) {
    jk_printf("OpenJKDF2: Unimplemented function stdColor_GammaCorrect!!\n");
    return 1;
}