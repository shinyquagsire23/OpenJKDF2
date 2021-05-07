#ifndef _RDRASTER_H
#define _RDRASTER_H

#define rdRaster_Startup_ADDR (0x0044BB40)

void rdRaster_Startup();

//static int (*rdRaster_Startup)(void) = (void*)rdRaster_Startup_ADDR;

#define rdRaster_aOneDivXQuantLUT ((int*)0x0086ADE0)
#define rdRaster_aOtherLUT ((float*)0x86CDDC)
#define rdRaster_aOneDivXLUT ((float*)0x0086CE20)

#define rdRaster_fixedScale (*(float*)0x00548E28)


#endif // _RDRASTER_H
