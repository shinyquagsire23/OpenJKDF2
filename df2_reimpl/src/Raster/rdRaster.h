#ifndef _RDRASTER_H
#define _RDRASTER_H

#define rdRaster_Startup_ADDR (0x0044BB40)

static int (*rdRaster_Startup)(void) = (void*)rdRaster_Startup_ADDR;

#endif // _RDRASTER_H
