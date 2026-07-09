#include "rdRaster.h"

void rdRaster_Startup()
{
    rdRaster_aOneOverNFlex[0] = 3.4e38;
    rdRaster_aOneOverNFixed[0] = 0x7FFFFFFF;

    for (int i = 1; i < 2048; i++)
    {
        rdRaster_aOneOverNFlex[i] = 1.0 / (flex_d_t)i;
        rdRaster_aOneOverNFixed[i] = (int)(1.0 / (flex_d_t)i * 65536.0);
    }

    for (int j = 0; j < 16; j++)
    {
        rdRaster_aLerpAndScale[j] = rdRaster_aOneOverNFlex[j] * rdRaster_fixedScale;
    }
}
