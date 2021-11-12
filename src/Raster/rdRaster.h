#ifndef _RDRASTER_H
#define _RDRASTER_H

#include "types.h"
#include "globals.h"

#define rdRaster_Startup_ADDR (0x0044BB40)

void rdRaster_Startup();

//static int (*rdRaster_Startup)(void) = (void*)rdRaster_Startup_ADDR;


#endif // _RDRASTER_H
