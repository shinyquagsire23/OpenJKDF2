// dcDebug: Dreamcast on-screen debug overlay helpers. See header.
#include "dcDebug.h"

#ifdef TARGET_DREAMCAST

#include <stdio.h>

#include <dc/maple.h>
#include <dc/maple/controller.h>

#include "stdPlatform.h"

int dcDebug_PadInPort4(void)
{
    // Maple ports are 0=A .. 3=D; unit 0 is the base device in the port.
    maple_device_t* dev = maple_enum_dev(3, 0);
    return dev && dev->valid && (dev->info.functions & MAPLE_FUNC_CONTROLLER);
}

int dcDebug_GetOverlayLine(int idx, char* pOut, size_t outSz)
{
    uint32_t sysUsed, sysFree, vramUsed, vramTotal, allocs;
    DC_GetMemStats(&sysUsed, &sysFree, &vramUsed, &vramTotal, &allocs);

    switch (idx) {
        case 0:
            snprintf(pOut, outSz, "SYS %uK USED  %uK FREE", sysUsed, sysFree);
            return 1;
        case 1:
            snprintf(pOut, outSz, "VRAM %u/%uK  %u ALLOCS", vramUsed, vramTotal, allocs);
            return 1;
        default:
            return 0;
    }
}

#endif // TARGET_DREAMCAST
