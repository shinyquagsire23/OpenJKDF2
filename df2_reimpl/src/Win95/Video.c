#include "Video.h"

#include "Engine/rdroid.h"
#include "Engine/sithCamera.h"
#include "Win95/stdDisplay.h"
#include "Win95/std3D.h"
#include "General/stdPalEffects.h"
#include "Main/jkHud.h"
#include "Main/jkHudInv.h"
#include "Main/jkDev.h"
#include "Main/jkGame.h"

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

void Video_SwitchToGDI()
{
    jkDev_Close();
#ifndef LINUX_TMP
    jkHud_Deinit();
    jkHudInv_deinit_menu_graphics_maybe();
#endif
    sithCamera_Close();

    rdCanvas_Free(Video_pCanvas);
    rdClose();
    if ( Video_modeStruct.b3DAccel )
    {
        std3D_PurgeTextureCache();
        std3D_Shutdown();
    }

#ifndef LINUX
    stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);
    stdDisplay_DDrawGdiSurfaceFlip();
    stdDisplay_ddraw_surface_flip2();
    stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);

    if ( !Video_modeStruct.b3DAccel )
        stdDisplay_VBufferFree(Video_pVbufIdk);
#else
    jkGame_isDDraw = 0;
#endif
    Video_bOpened = 0;
}

int Video_Startup()
{
    if (stdDisplay_Startup())
    {
        stdDisplay_SetGammaTable(10, aGammaTable);
#ifndef LINUX_TMP
        jkHud_Startup();
#endif
        Video_pOtherBuf = &Video_otherBuf;
        Video_pMenuBuffer = &Video_menuBuffer;
#ifndef LINUX_TMP
        stdPalEffects_Open(stdDisplay_SetMasterPalette);
#endif
        sithCamera_Startup();
        Video_bInitted = 1;
        return 1;
    }
    return 0;
}
