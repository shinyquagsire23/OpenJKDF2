#include "Video.h"

#include "Win95/stdDisplay.h"
#include "General/stdPalEffects.h"
#include "Main/jkHud.h"

static uint32_t aGammaTable[20] = {
    0x00000000,
    0x3FF00000,
    0xD1745D17,
    0x3FED1745,
    0xAAAAAAAB,
    0x3FEAAAAA,
    0xB6DB6DB7,
    0x3FE6DB6D,
    0x00000000,
    0x3FE40000,
    0x71C71C72,
    0x3FE1C71C,
    0x35E50D79,
    0x3FE0D794,
    0x00000000,
    0x3FE00000,
    0x9E79E79E,
    0x3FDE79E7,
    0x6F4DE9BE,
    0x3FDBD37A,
};

int Video_Startup()
{
    if (stdDisplay_Startup())
    {
        stdDisplay_SetGammaTable(10, aGammaTable);
#ifndef LINUX
        jkHud_Startup();
#endif
        Video_pOtherBuf = &Video_otherBuf;
        Video_pMenuBuffer = &Video_menuBuffer;
#ifndef LINUX
        stdPalEffects_Open(stdDisplay_SetMasterPalette);
#endif
        sithCamera_Startup();
        Video_bInitted = 1;
        return 1;
    }
    return 0;
}
