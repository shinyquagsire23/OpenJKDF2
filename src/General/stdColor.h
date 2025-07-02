#ifndef _STDCOLOR_H
#define _STDCOLOR_H

#include "types.h"
#include "globals.h"

#define stdColor_LoadPalette_ADDR (0x00433680)
#define stdColor_GammaCorrect_ADDR (0x004336A0)
#define stdColor_FindClosest_ADDR (0x004337A0)
#define stdColor_RGBtoHSV_ADDR (0x00433890)
#define stdColor_HSVtoRGB_ADDR (0x00433A50)
#define stdColor_BuildRGB16LUT_ADDR (0x00433BD0)
#define stdColor_BuildRGBAKEY16LUT_ADDR (0x00433C70)
#define stdColor_BuildRGBA16LUT_ADDR (0x00433D40)
#define stdColor_ColorConvertOneRow_ADDR (0x00433E10)
#define stdColor_ColorConvertOnePixel_ADDR (0x00434040)
#define stdColor_Indexed8ToRGB16_ADDR (0x00434070)

int stdColor_Indexed8ToRGB16(uint8_t idx, rdColor24 *pal, rdTexformat *fmt);
uint32_t stdColor_ColorConvertOnePixel(rdTexformat *formatTo, int color, rdTexformat *formatFrom);
int stdColor_ColorConvertOneRow(uint8_t *outPixels, rdTexformat *formatTo, uint8_t *inPixels, rdTexformat *formatFrom, int numPixels);
int stdColor_GammaCorrect(uint8_t *a1, uint8_t *a2, int a3, flex_d_t a4);

//static int (*stdColor_GammaCorrect)(uint8_t *a1, uint8_t *a2, int a3, flex_d_t a4) = (void*)stdColor_GammaCorrect_ADDR;
//static int (*stdColor_ColorConvertOneRow)(uint8_t *outPixels, rdTexformat *formatTo, uint8_t *inPixels, rdTexformat *formatFrom, int numPixels) = (void*)stdColor_ColorConvertOneRow_ADDR;

#endif // _STDCOLOR_H
