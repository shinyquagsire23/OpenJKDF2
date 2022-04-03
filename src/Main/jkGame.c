#include "jkGame.h"

#include "General/stdPalEffects.h"
#include "Engine/sith.h"
#include "Engine/rdroid.h"
#include "Engine/rdCache.h"
#include "Engine/sithRender.h"
#include "Engine/sithNet.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithSector.h"
#include "Win95/Video.h"
#include "Win95/sithDplay.h"
#include "Platform/std3D.h"
#include "Win95/stdDisplay.h"
#include "Main/jkHud.h"
#include "Main/jkHudInv.h"
#include "Main/jkDev.h"
#include "Engine/rdColormap.h"
#include "Engine/sithCamera.h"

#include "stdPlatform.h"
#include "jk.h"

int jkGame_Initialize()
{
    sithWorld_SetSectionParser("jk", jkGame_ParseSection);
    jkGame_bInitted = 1;
    return 1;
}

int jkGame_ParseSection(sithWorld* a1, int a2)
{
    return a2 == 0;
}

void jkGame_ForceRefresh()
{
    sithCamera_Close();
    rdCanvas_Free(Video_pCanvas);
}

void jkGame_Shutdown()
{
    jkGame_bInitted = 0;
}

void jkGame_ScreensizeIncrease()
{
    if ( Video_modeStruct.viewSizeIdx < 0xAu )
    {
#ifndef LINUX_TMP
        sithCamera_Close();
        rdCanvas_Free(Video_pCanvas);
        ++Video_modeStruct.viewSizeIdx;
        Video_camera_related();
#endif
    }
}

void jkGame_ScreensizeDecrease()
{
    if ( Video_modeStruct.viewSizeIdx )
    {
#ifndef LINUX_TMP
        sithCamera_Close();
        rdCanvas_Free(Video_pCanvas);
        --Video_modeStruct.viewSizeIdx;
        Video_camera_related();
#endif
    }
}

void jkGame_SetDefaultSettings()
{
    jkPlayer_setFullSubtitles = 0;
    jkPlayer_setDisableCutscenes = 0;
    jkPlayer_setRotateOverlayMap = 1;
    jkPlayer_setDrawStatus = 1;
    jkPlayer_setCrosshair = 0;
    jkPlayer_setSaberCam = 0;
}

#ifndef SDL2_RENDER
int jkGame_Update()
{
    int64_t v0; // rcx
    char *v1; // eax
    sithThing *v2; // esi
    int v3; // eax
    double v4; // st7
    int result; // eax
    int v6; // [esp+1Ch] [ebp-1Ch]

    if ( Video_modeStruct.Video_8606C0 || Video_modeStruct.geoMode <= 2 )
        stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);
    jkDev_DrawLog();
    jkHudInv_ClearRects();
    jkHud_ClearRects(0);
    v1 = stdDisplay_GetPalette();
    stdPalEffects_UpdatePalette(v1);
    if ( Video_modeStruct.b3DAccel )
        rdSetColorEffects(&stdPalEffects_state.effect);
    rdAdvanceFrame();
    if ( Video_modeStruct.b3DAccel )
    {
        sith_UpdateCamera();
    }
    else
    {
        stdDisplay_VBufferLock(Video_pMenuBuffer);
        stdDisplay_VBufferLock(Video_pVbufIdk);
        sith_UpdateCamera();
        stdDisplay_VBufferUnlock(Video_pVbufIdk);
        stdDisplay_VBufferUnlock(Video_pMenuBuffer);
    }
    jkPlayer_DrawPov();
    rdFinishFrame();
    /*if ( Main_bDispStats )
    {
        v2 = sithWorld_pCurrentWorld->playerThing;
        ++Video_dword_5528A0;
        v3 = stdPlatform_GetTimeMsec();
        v0 = v3 - Video_lastTimeMsec;
        Video_dword_5528A8 = v3;
        if ( (unsigned int)(v3 - Video_lastTimeMsec) > 0x3E8 )
        {
            if ( Main_bDispStats )
            {
                v6 = v2->sector->id;
                Video_flt_55289C = (double)(Video_dword_5528A0 - Video_dword_5528A4) * 1000.0 / (double)v0;
                _sprintf(
                    std_genBuffer,
                    "%02.3f (%02d%%)f %3ds %3da %3dz %4dp %3d curSector %3d fo",
                    Video_flt_55289C,
                    (unsigned int)(__int64)((double)(unsigned int)jkGame_updateMsecsTotal / (double)(int)v0 * 100.0),
                    sithRender_surfacesDrawn,
                    sithRender_831980,
                    sithRender_831984,
                    rdCache_drawnFaces,
                    v6,
                    net_things_idx);
                if ( net_isMulti )
                    _sprintf(&std_genBuffer[_strlen(std_genBuffer)], " %d m %d b", sithDplay_dword_8321F4, sithDplay_dword_8321F0);
                jkDev_sub_41FC40(100, std_genBuffer);
                v3 = Video_dword_5528A8;
            }
            Video_lastTimeMsec = v3;
            Video_dword_5528A4 = Video_dword_5528A0;
            jkGame_dword_552B5C = 0;
            jkGame_updateMsecsTotal = 0;
            sithDplay_dword_8321F0 = 0;
            sithDplay_dword_8321F4 = 0;
        }
    }
    else if ( Main_bFrameRate )
    {
        ++Video_dword_5528A0;
        Video_dword_5528A8 = stdPlatform_GetTimeMsec();
        if ( (unsigned int)(Video_dword_5528A8 - Video_lastTimeMsec) > 0x3E8 )
        {
            v4 = (double)(Video_dword_5528A0 - Video_dword_5528A4) * 1000.0 / (double)(unsigned int)(Video_dword_5528A8 - Video_lastTimeMsec);
            Video_flt_55289C = v4;
            _sprintf(std_genBuffer, "%02.3f", v4);
            jkDev_sub_41FC40(100, std_genBuffer);
            Video_lastTimeMsec = Video_dword_5528A8;
            Video_dword_5528A4 = Video_dword_5528A0;
        }
    }*/
    if ( (playerThings[playerThingIdx].actorThing->actorParams.typeflags & THING_TYPEFLAGS_800000) == 0 )
        jkHud_Draw();
    jkDev_sub_41F950();
    jkHudInv_Draw();
    if ( Video_modeStruct.b3DAccel )
        std3D_DrawOverlay();

    if ( Video_modeStruct.b3DAccel )
        result = stdDisplay_DDrawGdiSurfaceFlip();
    else
        result = stdDisplay_VBufferCopy(Video_pOtherBuf, Video_pMenuBuffer, 0, 0, 0, 0);

    return result;
}
#else
int jkGame_Update()
{
    int64_t v0; // rcx
    char *v1; // eax
    sithThing *v2; // esi
    int v3; // eax
    double v4; // st7
    int result; // eax
    int v6; // [esp+1Ch] [ebp-1Ch]

    // HACK
    Video_modeStruct.b3DAccel = 1;
    
    //if ( Video_modeStruct.Video_8606C0 || Video_modeStruct.geoMode <= 2 )
        stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);
    jkDev_DrawLog();
    jkHudInv_ClearRects();
    jkHud_ClearRects(0);

    v1 = stdDisplay_GetPalette();
    stdPalEffects_UpdatePalette(v1);
    //if ( Video_modeStruct.b3DAccel )
        rdSetColorEffects(&stdPalEffects_state.effect);

    _memcpy(stdDisplay_masterPalette, sithWorld_pCurrentWorld->colormaps->colors, 0x300);
    rdAdvanceFrame();
    //if ( Video_modeStruct.b3DAccel )
    {
        sith_UpdateCamera();
    }
    /*else
    {
        stdDisplay_VBufferLock(Video_pMenuBuffer);
        stdDisplay_VBufferLock(Video_pVbufIdk);
        sith_UpdateCamera();
        stdDisplay_VBufferUnlock(Video_pVbufIdk);
        stdDisplay_VBufferUnlock(Video_pMenuBuffer);
    }*/
    jkPlayer_DrawPov();

    /*if ( Main_bDispStats )
    {
        v2 = sithWorld_pCurrentWorld->playerThing;
        ++Video_dword_5528A0;
        v3 = stdPlatform_GetTimeMsec();
        v0 = v3 - Video_lastTimeMsec;
        Video_dword_5528A8 = v3;
        if ( (unsigned int)(v3 - Video_lastTimeMsec) > 0x3E8 )
        {
            if ( Main_bDispStats )
            {
                v6 = v2->sector->id;
                Video_flt_55289C = (double)(Video_dword_5528A0 - Video_dword_5528A4) * 1000.0 / (double)v0;
                _sprintf(
                    std_genBuffer,
                    "%02.3f (%02d%%)f %3ds %3da %3dz %4dp %3d curSector %3d fo",
                    Video_flt_55289C,
                    (unsigned int)(__int64)((double)(unsigned int)jkGame_updateMsecsTotal / (double)(int)v0 * 100.0),
                    sithRender_surfacesDrawn,
                    sithRender_831980,
                    sithRender_831984,
                    rdCache_drawnFaces,
                    v6,
                    net_things_idx);
                if ( net_isMulti )
                    _sprintf(&std_genBuffer[_strlen(std_genBuffer)], " %d m %d b", sithDplay_dword_8321F4, sithDplay_dword_8321F0);
                jkDev_sub_41FC40(100, std_genBuffer);
                v3 = Video_dword_5528A8;
            }
            Video_lastTimeMsec = v3;
            Video_dword_5528A4 = Video_dword_5528A0;
            jkGame_dword_552B5C = 0;
            jkGame_updateMsecsTotal = 0;
            sithDplay_dword_8321F0 = 0;
            sithDplay_dword_8321F4 = 0;
        }
    }
    else if ( Main_bFrameRate )
    {
        ++Video_dword_5528A0;
        Video_dword_5528A8 = stdPlatform_GetTimeMsec();
        if ( (unsigned int)(Video_dword_5528A8 - Video_lastTimeMsec) > 0x3E8 )
        {
            v4 = (double)(Video_dword_5528A0 - Video_dword_5528A4) * 1000.0 / (double)(unsigned int)(Video_dword_5528A8 - Video_lastTimeMsec);
            Video_flt_55289C = v4;
            _sprintf(std_genBuffer, "%02.3f", v4);
            jkDev_sub_41FC40(100, std_genBuffer);
            Video_lastTimeMsec = Video_dword_5528A8;
            Video_dword_5528A4 = Video_dword_5528A0;
        }
    }*/

    if ( (playerThings[playerThingIdx].actorThing->actorParams.typeflags & THING_TYPEFLAGS_800000) == 0 )
        jkHud_Draw();
    jkDev_sub_41F950();
    jkHudInv_Draw();
    //if ( Video_modeStruct.b3DAccel )
    //    std3D_DrawOverlay();


    std3D_DrawMenu();
    rdFinishFrame();

    if ( Video_modeStruct.b3DAccel )
        result = stdDisplay_DDrawGdiSurfaceFlip();
    else
        result = stdDisplay_VBufferCopy(Video_pOtherBuf, Video_pMenuBuffer, 0, 0, 0, 0);
    return result;
}
#endif

#ifdef SDL2_RENDER
void jkGame_Screenshot()
{
    printf("TODO: Implement screenshots\n");
}
#endif

void jkGame_Gamma()
{
    int v0; // eax
    char *v1; // eax

    v0 = ++Video_modeStruct.Video_8606A4;
    if ( Video_modeStruct.Video_8606A4 >= 0xAu )
    {
        v0 = 0;
        Video_modeStruct.Video_8606A4 = 0;
    }
    stdDisplay_GammaCorrect3(v0);
#ifndef SDL2_RENDER
    stdPalEffects_RefreshPalette();
    if ( Video_modeStruct.b3DAccel )
    {
        v1 = stdDisplay_GetPalette();
        sithRender_SetPalette(v1);
    }
#endif
}
