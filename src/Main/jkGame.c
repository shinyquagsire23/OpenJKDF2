#include "jkGame.h"

#include "General/stdPalEffects.h"
#include "Main/sithMain.h"
#include "Engine/rdroid.h"
#include "Raster/rdCache.h"
#include "Engine/sithRender.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithSector.h"
#include "Win95/Video.h"
#include "Win95/stdComm.h"
#include "Platform/std3D.h"
#include "Win95/stdDisplay.h"
#include "Main/jkHud.h"
#include "Main/jkHudInv.h"
#include "Main/jkHudScope.h"
#include "Main/jkHudCameraView.h"
#include "Main/jkDev.h"
#include "Main/jkQuakeConsole.h"
#include "Engine/rdColormap.h"
#include "Engine/sithCamera.h"
#include "General/stdString.h"

#include "stdPlatform.h"
#include "jk.h"

int jkGame_Startup()
{
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);
    
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
#ifdef SDL2_RENDER
    rdCanvas_Free(Video_pCanvasOverlayMap);
#endif
}

void jkGame_Shutdown()
{
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);
    
    jkGame_bInitted = 0;
}

void jkGame_ScreensizeIncrease()
{
    if ( Video_modeStruct.viewSizeIdx < 0xAu )
    {
        // MOTS added
        if (Main_bMotsCompat) {
            jkHudScope_Close();
            jkHudCameraView_Close();
        }

#ifndef LINUX_TMP
        sithCamera_Close();
        rdCanvas_Free(Video_pCanvas);
#ifdef SDL2_RENDER
        rdCanvas_Free(Video_pCanvasOverlayMap);
#endif
        ++Video_modeStruct.viewSizeIdx;
        Video_camera_related();
#endif
        // MOTS added
        if (Main_bMotsCompat) {
            jkHudScope_Open();
            jkHudCameraView_Open();
        }
    }
}

void jkGame_ScreensizeDecrease()
{
    if ( Video_modeStruct.viewSizeIdx )
    {
        // MOTS added
        if (Main_bMotsCompat) {
            jkHudScope_Close();
            jkHudCameraView_Close();
        }

#ifndef LINUX_TMP
        sithCamera_Close();
        rdCanvas_Free(Video_pCanvas);
#ifdef SDL2_RENDER
        rdCanvas_Free(Video_pCanvasOverlayMap);
#endif
        --Video_modeStruct.viewSizeIdx;
        Video_camera_related();
#endif
        // MOTS added
        if (Main_bMotsCompat) {
            jkHudScope_Open();
            jkHudCameraView_Open();
        }
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

int jkGame_Update()
{
    int64_t v0; // rcx
    sithThing *v2; // esi
    int v3; // eax
    flex_d_t v4; // st7
    int result; // eax
    int v6; // [esp+1Ch] [ebp-1Ch]

    static int jkGame_Update_Start = 0;
    static int jkGame_Update_ClearScreen = 0;
    static int jkGame_Update_AdvanceFrame = 0;
    static int jkGame_Update_UpdateCamera = 0;
    static int jkGame_Update_DrawPov = 0;
    static int jkGame_Update_HudDrawn = 0;
    static int jkGame_Update_End = 0;

    jkGame_Update_Start = stdPlatform_GetTimeMsec();

    // HACK HACK HACK: Adjust zNear depending on if we're using the scope/camera views
#if defined(SDL2_RENDER) || defined(TARGET_TWL)
    if (sithCamera_cameras[0].rdCam.pClipFrustum) {
        sithCamera_cameras[0].rdCam.pClipFrustum->zNear = SITHCAMERA_ZNEAR_FIRSTPERSON;

        if (Main_bMotsCompat) {
            if (playerThings[playerThingIdx].actorThing->actorParams.typeflags & SITH_AF_SCOPEHUD) {
                sithCamera_cameras[0].rdCam.pClipFrustum->zNear = SITHCAMERA_ZNEAR;
            }
            if ((playerThings[playerThingIdx].actorThing->actorParams.typeflags & SITH_AF_80000000) != 0) {
                sithCamera_cameras[0].rdCam.pClipFrustum->zNear = SITHCAMERA_ZNEAR;
            }
        }
    }
    
#endif

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
    // HACK
    Video_modeStruct.b3DAccel = 1;
#endif

#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
    if ( Video_modeStruct.Video_8606C0 || Video_modeStruct.geoMode <= 2 )
#endif
#if !defined(TARGET_TWL)
        stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0); // Significant delay on TWL
#endif
    jkDev_DrawLog();
    jkHudInv_ClearRects();
    jkHud_ClearRects(0);
    jkGame_Update_ClearScreen = stdPlatform_GetTimeMsec();

    stdPalEffects_UpdatePalette(stdDisplay_GetPalette());
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
    if ( Video_modeStruct.b3DAccel )
#endif
        rdSetColorEffects(&stdPalEffects_state.effect);

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
    _memcpy(stdDisplay_masterPalette, sithWorld_pCurrentWorld->colormaps->colors, 0x300);
#endif
    rdAdvanceFrame();
    jkGame_Update_AdvanceFrame = stdPlatform_GetTimeMsec();
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
    if ( Video_modeStruct.b3DAccel )
#endif
    {
        sithMain_UpdateCamera();
    }
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
    else
    {
        stdDisplay_VBufferLock(Video_pMenuBuffer);
        stdDisplay_VBufferLock(Video_pVbufIdk);
        sithMain_UpdateCamera();
        stdDisplay_VBufferUnlock(Video_pVbufIdk);
        stdDisplay_VBufferUnlock(Video_pMenuBuffer);
    }
#endif
    jkGame_Update_UpdateCamera = stdPlatform_GetTimeMsec();
    jkPlayer_DrawPov();
    jkGame_Update_DrawPov = stdPlatform_GetTimeMsec();

#if 1
    //if (Main_bMotsCompat)
    ++Video_dword_5528A0; // MOTS added
    if ( Main_bDispStats )
    {
        v2 = sithWorld_pCurrentWorld->playerThing;
        //++Video_dword_5528A0; // MOTS removed
        v3 = stdPlatform_GetTimeMsec();
        v0 = v3 - Video_lastTimeMsec;
        Video_dword_5528A8 = v3;
        if ( (unsigned int)(v3 - Video_lastTimeMsec) > 0x3E8 )
        {
            if ( Main_bDispStats )
            {
                v6 = v2->sector->id;
                Video_flt_55289C = (flex_d_t)(Video_dword_5528A0 - Video_dword_5528A4) * 1000.0 / (flex_d_t)v0;
                _sprintf(
                    std_genBuffer,
                    "%02.3f (%02d%%)f %3ds %3da %3dz %4dp %3d curSector %3d fo",
                    Video_flt_55289C,
                    (unsigned int)(__int64)((flex_d_t)(unsigned int)jkGame_updateMsecsTotal / (flex_d_t)(int)v0 * 100.0),
                    sithRender_sectorsDrawn,
                    sithRender_geoThingsDrawn,
                    sithRender_nongeoThingsDrawn,
                    rdCache_drawnFaces,
                    v6,
                    sithNet_thingsIdx);
                if ( sithNet_isMulti )
                    _sprintf(&std_genBuffer[_strlen(std_genBuffer)], " %d m %d b", stdComm_dword_8321F4, stdComm_dword_8321F0);
                jkDev_sub_41FC40(100, std_genBuffer);
                v3 = Video_dword_5528A8;
            }
            Video_lastTimeMsec = v3;
            Video_dword_5528A4 = Video_dword_5528A0;
            jkGame_dword_552B5C = 0;
            jkGame_updateMsecsTotal = 0;
            stdComm_dword_8321F0 = 0;
            stdComm_dword_8321F4 = 0;
        }
    }
    else if ( Main_bFrameRate )
    {
        //++Video_dword_5528A0; // MOTS removed
        Video_dword_5528A8 = stdPlatform_GetTimeMsec();
        if ( (unsigned int)(Video_dword_5528A8 - Video_lastTimeMsec) > 1000 )
        {
            v4 = (flex_d_t)(Video_dword_5528A0 - Video_dword_5528A4) * 1000.0 / (flex_d_t)(unsigned int)(Video_dword_5528A8 - Video_lastTimeMsec);
            Video_flt_55289C = v4;
            _sprintf(std_genBuffer, "%02.3f", v4);
            jkDev_sub_41FC40(100, std_genBuffer);
            Video_lastTimeMsec = Video_dword_5528A8;
            Video_dword_5528A4 = Video_dword_5528A0;
        }
    }
#endif

#if defined(SDL2_RENDER)
    stdVBuffer* pOverlayBuffer = Video_pCanvasOverlayMap->vbuffer;
    stdDisplay_VBufferLock(pOverlayBuffer);
    stdDisplay_VBufferFill(pOverlayBuffer, Video_fillColor, 0);
    stdDisplay_VBufferUnlock(pOverlayBuffer);
#endif

    // MOTS added: scope/security cam overlays
    if (!Main_bMotsCompat) {
        if ( (playerThings[playerThingIdx].actorThing->actorParams.typeflags & SITH_AF_NOHUD) == 0 ) {
            jkHud_Draw();
        }
    }
    else {
        if (playerThings[playerThingIdx].actorThing->actorParams.typeflags & SITH_AF_SCOPEHUD) {
            jkHudScope_Draw();
        }
        if ((playerThings[playerThingIdx].actorThing->actorParams.typeflags & SITH_AF_80000000) == 0) {
            if ((playerThings[playerThingIdx].actorThing->actorParams.typeflags & SITH_AF_NOHUD) == 0) {
                jkHud_Draw();
            }
        }
        else {
            jkHudCameraView_Draw();
        }
    }

    jkGame_Update_HudDrawn = stdPlatform_GetTimeMsec();

    jkDev_BlitLogToScreen();
    jkHudInv_Draw();
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
    if ( Video_modeStruct.b3DAccel )
        std3D_DrawOverlay();
#endif

    // MOTS added
    /*
    if (Main_bRecord != 0) {
        jkGame_Screenshot();
    }
    */

#if defined(SDL2_RENDER)
    jkQuakeConsole_Render();
#endif

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
    std3D_DrawMenu();
    rdFinishFrame();
#endif

    // MOTS removed
    if ( Video_modeStruct.b3DAccel )
        result = stdDisplay_DDrawGdiSurfaceFlip();
    else
        result = stdDisplay_VBufferCopy(Video_pOtherBuf, Video_pMenuBuffer, 0, 0, 0, 0);
    // end MOTS removed

    // MOTS added
    /*
    if ((Video_modeStruct.Video_motsNew1 != 0) && (Video_modeStruct.b3DAccel == 0)) {
        result = stdDisplay_VBufferCopy(Video_pOtherBuf,Video_pMenuBuffer,0,0,NULL,0);
        return result;
    }
    result = stdDisplay_DDrawGdiSurfaceFlip();
    */

    jkGame_Update_End = stdPlatform_GetTimeMsec();

#if defined(TARGET_TWL)
    int jkGame_Delta_Start_ClearScreen = jkGame_Update_ClearScreen - jkGame_Update_Start;
    int jkGame_Delta_ClearScreen_AdvanceFrame = jkGame_Update_AdvanceFrame - jkGame_Update_ClearScreen;
    int jkGame_Delta_AdvanceFrame_UpdateCamera = jkGame_Update_UpdateCamera - jkGame_Update_AdvanceFrame;
    int jkGame_Delta_UpdateCamera_DrawPov = jkGame_Update_DrawPov - jkGame_Update_UpdateCamera;
    int jkGame_Delta_DrawPov_HudDrawn = jkGame_Update_HudDrawn - jkGame_Update_DrawPov;
    int jkGame_Delta_HudDrawn_End = jkGame_Update_End - jkGame_Update_HudDrawn;
    
    static int last_time_ms = 0;
    int now_ms = stdPlatform_GetTimeMsec();
    int total_delta = now_ms - last_time_ms;
    last_time_ms = now_ms;
    extern int std3D_timeWastedWaitingAround;
    extern int32_t sithRender_numSectors;
    //stdPlatform_Printf("dlt all=%d mn=%d %d wrld=%d\n pov=%d hud=%d drw=%d wst=%d %d\n", total_delta-std3D_timeWastedWaitingAround, sithMain_tickEndMs-sithMain_tickStartMs, jkGame_Delta_ClearScreen_AdvanceFrame, jkGame_Delta_AdvanceFrame_UpdateCamera, jkGame_Delta_UpdateCamera_DrawPov, jkGame_Delta_DrawPov_HudDrawn, jkGame_Delta_HudDrawn_End - std3D_timeWastedWaitingAround, std3D_timeWastedWaitingAround, sithRender_numSectors);
    //world=28 drw=15 emu
    //world=48 drw=33 dsi, 33 down to 25 with jank phys?
#endif

    return result;
}

#ifdef SDL2_RENDER
void jkGame_Screenshot()
{
    //stdPlatform_Printf("TODO: Implement screenshots\n");
    char local_80[128];
    int bVar2 = 0;
    do {
        stdString_snprintf(local_80, sizeof(local_80), "SHOT%04d.PNG", Video_dword_5528B0);
        stdFile_t fp = pHS->fileOpen(local_80, "r");
        if (fp == 0) {
            bVar2 = 1;
        }
        else {
            pHS->fileClose(fp);
        }
        Video_dword_5528B0++;
        if (Video_dword_5528B0 > 9999) {
            bVar2 = 1;
        }
    } while (!bVar2);

    std3D_Screenshot(local_80);
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
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
    stdPalEffects_RefreshPalette();
    if ( Video_modeStruct.b3DAccel )
    {
        v1 = stdDisplay_GetPalette();
        sithRender_SetPalette(v1);
    }
#endif
}

void jkGame_PrecalcViewSizes(int width, int height, jkViewSize *aOut)
{
    flex_d_t v5; // st7
    flex_d_t v6; // st6
    flex_t v7; // [esp+4h] [ebp-Ch]
    flex_t v8;
    flex_t widtha; // [esp+14h] [ebp+4h]
    flex_t widthb; // [esp+14h] [ebp+4h]
    flex_t heighta; // [esp+18h] [ebp+8h]

    v5 = (flex_d_t)width;

    widtha = (flex_t)height;
    heighta = widtha;
    v6 = widtha * 0.5;
    widthb = v5 * 0.5;
    v8 = v6;
    v7 = heighta * 0.36000001;
    aOut[10].xMax = widthb;
    aOut[10].yMax = v6;
    aOut[9].xMax = widthb;
    aOut[9].yMax = v8;
    aOut[10].xMin = width;
    aOut[10].yMin = height;
    aOut[9].xMin = width;
    aOut[9].yMin = height;
    aOut[8].xMin = (__int64)(v5 * 0.9375 - -0.5);
    aOut[8].xMax = widthb;
    aOut[8].yMax = v8;
    aOut[8].yMin = (__int64)(heighta * 0.9375 - -0.5);
    aOut[7].xMin = (__int64)(v5 * 0.875 - -0.5);
    aOut[7].xMax = widthb;
    aOut[7].yMax = v8;
    aOut[7].yMin = (__int64)(heighta * 0.875 - -0.5);
    aOut[6].xMin = (__int64)(v5 * 0.8125 - -0.5);
    aOut[6].xMax = widthb;
    aOut[6].yMax = v8;
    aOut[6].yMin = (__int64)(heighta * 0.8125 - -0.5);
    aOut[5].xMin = (__int64)(v5 * 0.71875 - -0.5);
    aOut[5].xMax = widthb;
    aOut[5].yMax = v7;
    aOut[5].yMin = (__int64)(heighta * 0.71875 - -0.5);
    aOut[4].xMin = (__int64)(v5 * 0.625 - -0.5);
    aOut[4].xMax = widthb;
    aOut[4].yMax = v7;
    aOut[4].yMin = (__int64)(heighta * 0.625 - -0.5);
    aOut[3].xMin = (__int64)(v5 * 0.53125 - -0.5);
    aOut[3].xMax = widthb;
    aOut[3].yMax = v7;
    aOut[3].yMin = (__int64)(heighta * 0.53125 - -0.5);
    aOut[2].xMin = (__int64)(v5 * 0.4375 - -0.5);
    aOut[2].xMax = widthb;
    aOut[2].yMax = v7;
    aOut[2].yMin = (__int64)(heighta * 0.4375 - -0.5);
    aOut[1].xMin = (__int64)(v5 * 0.34375 - -0.5);
    aOut[1].xMax = widthb;
    aOut[1].yMax = v7;
    aOut[1].yMin = (__int64)(heighta * 0.34375 - -0.5);
    aOut->xMin = (__int64)(v5 * 0.25 - -0.5);
    aOut->yMin = (__int64)(heighta * 0.25 - -0.5);
    aOut->xMax = widthb;
    aOut->yMax = v7;
}

void jkGame_ddraw_idk_palettes()
{
    if ( Video_bOpened )
    {
        stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);
        stdDisplay_DDrawGdiSurfaceFlip();
        stdDisplay_ddraw_surface_flip2();
        stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, 0);
        sithRender_SetPalette(stdDisplay_GetPalette());
    }
}

void jkGame_nullsub_36()
{
    ;
}