#include "Video.h"

#include "Engine/rdroid.h"
#include "Engine/sithCamera.h"
#include "Engine/sithRender.h"
#include "Win95/stdDisplay.h"
#include "Platform/std3D.h"
#include "General/stdPalEffects.h"
#include "Main/jkHud.h"
#include "Main/jkHudInv.h"
#include "Main/jkHudScope.h"
#include "Main/jkHudCameraView.h"
#include "Main/jkDev.h"
#include "Main/jkGame.h"
#include "World/jkPlayer.h"

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

#ifdef SDL2_RENDER
rdCanvas* Video_pCanvasOverlayMap = NULL;
stdVBuffer* Video_pOverlayMapBuffer = NULL;
stdVBuffer Video_overlayMapBuffer;
#endif

void Video_SwitchToGDI()
{
    jkDev_Close();
#ifndef LINUX_TMP
    jkHud_Close();
    jkHudInv_Close();
#endif
    sithCamera_Close();

#ifdef SDL2_RENDER
    rdCanvas_Free(Video_pCanvasOverlayMap);
#endif
    rdCanvas_Free(Video_pCanvas);
    rdClose();
    if ( Video_modeStruct.b3DAccel )
    {
        //std3D_PurgeTextureCache(); // Added: Don't purge
        std3D_Shutdown();
    }

    stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);
    stdDisplay_DDrawGdiSurfaceFlip();
    stdDisplay_ddraw_surface_flip2();
    stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);

#ifndef SDL2_RENDER
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
        jkHud_Startup();
        if (Main_bMotsCompat) {
            jkHudScope_Startup();
            jkHudCameraView_Startup();
        }
        Video_pOtherBuf = &Video_otherBuf;
        Video_pMenuBuffer = &Video_menuBuffer;
#ifdef SDL2_RENDER
        Video_pOverlayMapBuffer = &Video_overlayMapBuffer;
#endif
        stdPalEffects_Open(stdDisplay_SetMasterPalette);
        sithCamera_Startup();
        Video_bInitted = 1;
        return 1;
    }
    return 0;
}

void Video_Shutdown()
{
    sithCamera_Shutdown();
    jkHud_Shutdown();
    if (Main_bMotsCompat) {
        jkHudScope_Shutdown();
        jkHudCameraView_Shutdown();
    }
    stdPalEffects_Close();
    stdDisplay_Close();
    stdDisplay_RestoreDisplayMode();
    Video_bInitted = 0;
}

int Video_camera_related()
{
    int y; // edi
    int v1; // ebp
    uint32_t v2; // ecx
    int64_t v3; // rax
    int x; // ebx
    int64_t v5; // rax
    unsigned int w; // esi
    unsigned int h; // eax
    int v8; // edx
    int v10; // [esp+10h] [ebp-20h]
    signed int v11; // [esp+14h] [ebp-1Ch]
    flex_t a1; // [esp+18h] [ebp-18h]
    int a1a; // [esp+18h] [ebp-18h]
    rdRect viewRect; // [esp+20h] [ebp-10h] BYREF

    y = 0;
    v10 = 0;
    stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);
    stdDisplay_DDrawGdiSurfaceFlip();
    stdDisplay_ddraw_surface_flip2();
    stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);
    v1 = Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].xMin;
    v2 = Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].yMin;
    v11 = v2;
    if ( v1 == Video_format.width && v2 == Video_format.height )
        v10 = 1;
    a1 = (double)(unsigned int)v1 * 0.5;
    v3 = (int64_t)(Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].xMax - a1);
    if ( (int)v3 < 0 )
    {
        x = 0;
    }
    else if ( (int)v3 > (signed int)(Video_format.width - 1) )
    {
        x = Video_format.width - 1;
    }
    else
    {
        x = (int64_t)(Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].xMax - a1);
    }
    v5 = (int64_t)(Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].yMax - (double)v2 * 0.5);
    if ( (int)v5 >= 0 )
    {
        y = Video_format.height - 1;
        if ( (int)v5 <= Video_format.height - 1 )
            y = (int64_t)(Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].yMax - (double)v2 * 0.5);
    }
    w = x + v1 - 1;
    if ( w > Video_format.width - 1 )
        w = Video_format.width - 1;
    h = y + v2 - 1;
    if ( h > Video_format.height - 1 )
        h = Video_format.height - 1;
    v8 = 2;
    a1a = 2;
    if ( Video_modeStruct.b3DAccel )
        a1a = 0x2A;
    if ( !v10 )
        v8 = 3;
    Video_pCanvas = rdCanvas_New(v8, Video_pMenuBuffer, Video_pVbufIdk, x, y, w, h, 6);
    if ( Video_modeStruct.b3DAccel )
    {
        viewRect.x = x;
        viewRect.y = y;
        viewRect.width = v1;
        viewRect.height = v11;
        std3D_InitializeViewport(&viewRect);
    }
    sithRender_SetSomeRenderflag(a1a);
    sithRender_SetGeoMode(Video_modeStruct.geoMode);
    sithRender_SetLightMode(Video_modeStruct.lightMode);
    sithRender_SetTexMode(Video_modeStruct.texMode);
    sithCamera_Open(Video_pCanvas, stdDisplay_pCurVideoMode->widthMaybe);
    return 1;
}

int Video_SetVideoDesc(const void *color_buf)
{
    int v1; // ecx
    signed int result; // eax
    int v3; // eax
    int v4; // eax
    int v5; // eax
    int v6; // eax
    char *v7; // eax

    stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);
    stdDisplay_DDrawGdiSurfaceFlip();
    stdDisplay_ddraw_surface_flip2();
    stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);
    if ( stdDisplay_bOpen )
    {
        if ( Video_dword_866D78 == Video_modeStruct.modeIdx )
        {
            v1 = 0;
            goto LABEL_9;
        }
        if ( stdDisplay_bOpen )
            stdDisplay_Close();
    }
    if ( !stdDisplay_Open(Video_modeStruct.modeIdx) )
        return 0;
    v1 = 1;
LABEL_9:
    v3 = Video_modeStruct.b3DAccel != 0;
    if ( !v1 && stdDisplay_bModeSet && Video_modeStruct.descIdx == Video_curMode && v3 == stdDisplay_bPaged )
    {
        if ( !Video_renderSurface[Video_modeStruct.descIdx].format.format.is16bit )
            stdDisplay_GammaCorrect(color_buf);
    }
    else if ( !stdDisplay_SetMode(Video_modeStruct.descIdx, color_buf, v3) )
    {
        return 0;
    }
    stdDisplay_GammaCorrect3(Video_modeStruct.Video_8606A4);
    _memcpy(&Video_format, &stdDisplay_pCurVideoMode->format, sizeof(Video_format));
    _memcpy(Video_aPalette, color_buf, sizeof(Video_aPalette));
    Video_pOtherBuf = &Video_otherBuf;
    Video_pMenuBuffer = &Video_menuBuffer;
    if ( !Video_modeStruct.b3DAccel )
    {
        Video_pMenuBuffer = stdDisplay_VBufferNew(&Video_format, 0, 0, color_buf);
        if ( !Video_modeStruct.b3DAccel )
        {
            result = rdOpen(0);
            if ( !result )
                return result;
            v6 = rdGetRenderOptions();
            v6 &= ~0x100;
            rdSetRenderOptions(v6);
            _memcpy(&Video_format2, &Video_format, sizeof(Video_format2));
            Video_format2.format.bpp = 16;
            Video_pVbufIdk = stdDisplay_VBufferNew(&Video_format2, 0, 0, 0);
            goto LABEL_25;
        }
    }
    std3D_Startup();
    if ( !std3D_FindClosestDevice(Video_modeStruct.Video_8605C8, 1) )
    {
        std3D_Shutdown();
        return 0;
    }
    if ( !d3d_device_ptr->hasColorModel )
    {
        v4 = std3D_GetRenderList();
        std3D_SetRenderList(v4 & ~0x1B2u);
    }
    std3D_GetValidDimensions(Video_modeStruct.Video_8606A8, Video_modeStruct.Video_8606A8, 256, 256);
    result = rdOpen(1);
    if ( result )
    {
        v5 = rdGetRenderOptions();
        v5 |= 0x100;
        rdSetRenderOptions(v5);
        Video_pVbufIdk = &Video_bufIdk;
LABEL_25:
        sithRender_SetRenderWeaponHandle(jkPlayer_renderSaberWeaponMesh);
        Video_camera_related();
        stdPalEffects_RefreshPalette();
        v7 = (char*)stdDisplay_GetPalette();
        sithRender_SetPalette(v7);
        jkHudInv_LoadItemRes();
        jkHud_Open();
        if (Main_bMotsCompat) {
            jkHudScope_Open();
            jkHudCameraView_Open();
        }
        jkDev_Open();
        result = 1;
        Video_dword_5528A0 = 0;
        Video_dword_5528A4 = 0;
        Video_dword_5528A8 = 0;
        Video_lastTimeMsec = 0;
        _memcpy(&Video_modeStruct2, &Video_modeStruct, sizeof(Video_modeStruct2));
        Video_bOpened = 1;
    }
    return result;
}