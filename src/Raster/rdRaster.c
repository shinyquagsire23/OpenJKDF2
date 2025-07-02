#include "rdRaster.h"

void rdRaster_Startup()
{
    rdRaster_aOneDivXLUT[0] = 3.4e38;
    rdRaster_aOneDivXQuantLUT[0] = 0x7FFFFFFF;

    for (int i = 1; i < 2048; i++)
    {
        rdRaster_aOneDivXLUT[i] = 1.0 / (flex_d_t)i;
        rdRaster_aOneDivXQuantLUT[i] = (int)(1.0 / (flex_d_t)i * 65536.0);
    }

    for (int j = 0; j < 16; j++)
    {
        rdRaster_aOtherLUT[j] = rdRaster_aOneDivXLUT[j] * rdRaster_fixedScale;
    }
}
