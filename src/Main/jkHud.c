#include "jkHud.h"

#include "Gameplay/sithInventory.h"
#include "Win95/Video.h"
#include "Win95/Windows.h"
#include "Platform/stdControl.h"
#include "Win95/stdDisplay.h"
#include "Devices/sithConsole.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdColor.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/stdMath.h"
#include "Primitives/rdPrimit2.h"
#include "Primitives/rdPrimit3.h"
#include "Gameplay/sithOverlayMap.h"
#include "Dss/sithMulti.h"
#include "Main/jkDev.h"
#include "Main/jkStrings.h"
#include "Gui/jkGUITitle.h"
#include "Platform/std3D.h"
#include "World/jkPlayer.h"
#include "../jk.h"
#include "types.h"
#include "types_enums.h"

//stdBitmap* jkHud_pTestbitmap = NULL;

static jkHudFont jkHud_aFonts[6] = {
    {&jkHud_pHelthNumSft, "HelthNum.sft", "HelthNum16.sft"},
    {&jkHud_pArmorNumSft, "ArmorNum.sft", "ArmorNum16.sft"},
    {&jkHud_pArmorNumsSuperSft, "ArmorNumsSuper.sft", "ArmorNumsSuper16.sft"},
    {&jkHud_pAmoNumsSft, "AmoNums.sft", "AmoNums16.sft"},
    {&jkHud_pAmoNumsSuperSft, "AmoNumsSuper.sft", "AmoNumsSuper16.sft"},
    {&jkHud_pMsgFontSft, "msgFont.sft", "msgFont16.sft"}, // TODO: msgFonts, msgFont16s
};

static jkHudBitmap jkHud_aBitmaps[8] = {
    {&jkHud_pStatusLeftBm, "statusLeft.bm", "statusLeft16.bm"},
    {&jkHud_pStatusRightBm, "statusRight.bm", "statusRight16.bm"},
    {&jkHud_pFieldlightBm, "stFieldLite.bm", "stFieldLite16.bm"},
    {&jkHud_pStFrcBm, "stFrc.bm", "stFrc16.bm"},
    {&jkHud_pStBatBm, "stBat.bm", "stBat16.bm"},
    {&jkHud_pStHealthBm, "stHealth.bm", "stHealth16.bm"},
    {&jkHud_pStShieldBm, "stShield.bm", "stShield16.bm"},
    {&jkHud_pStFrcSuperBm, "stFrcSuper.bm", "stFrcSuper16.bm"},
};

void jkHud_DrawGPU();

int jkHud_Startup()
{
    if ( Main_bNoHUD )
        return 1;
    jkHud_bHasTarget = 0;
    jkHud_pTargetThing = NULL;
    jkHud_targetBlue = 2;
    jkHud_targetRed = 1;
    jkHud_targetGreen = 3;
    jkHud_bInitted = 1;
    return 1;
}

void jkHud_Shutdown()
{
    // Added: clean reset
    jkHud_Close();

    if ( !Main_bNoHUD )
    {
        jkHud_pTargetThing = NULL;
        jkHud_bInitted = 0;
    }
}

// MOTS altered: Added a font for smaller (bigger?) screens
int jkHud_Open()
{
    signed int result; // eax
    jkHudBitmap* bitmapIter; // esi
    stdBitmap *v3; // eax
    jkHudFont* fontIter; // esi
    stdFont *v5; // eax
    stdVBuffer *v6; // ecx
    int v7; // esi
    int *aTeamColors; // esi
    char tmp[128]; // [esp+Ch] [ebp-80h] BYREF

    if ( Main_bNoHUD )
        return 1;
    if ( jkHud_bOpened )
        return 0;
    bitmapIter = &jkHud_aBitmaps[0];
    for (int i = 0; i < 8; i++)
    {
#ifndef SDL2_RENDER
        if ( Video_format.format.bpp == 8 )
            _sprintf(tmp, "ui\\bm\\%s", bitmapIter->path8bpp);
        else
#endif
            _sprintf(tmp, "ui\\bm\\%s", bitmapIter->path16bpp);
        v3 = stdBitmap_Load(tmp, 0, 0);
        *bitmapIter->pBitmap = v3;
        if ( !v3 )
            Windows_GameErrorMsgbox("ERR_CANNOT_LOAD_FILE %s", tmp);
        stdBitmap_ConvertColorFormat(&Video_format.format, v3);
        ++bitmapIter;
    }

    //jkHud_pTestbitmap = stdBitmap_Load("ui\\bm\\statusLeft16.bm",0,0);
    
    jkHud_blittedAmmoAmt = 0;
    jkHud_blittedHealthIdx = 0;
    jkHud_blittedBatteryAmt = 0;
    jkHud_blittedFieldlightAmt = 0;
    jkHud_blittedShieldIdx = 0;
    jkHud_blittedForceIdx = -1;
    jkHud_isSuper = 0;
    jkHud_idk14 = 0;
    jkHud_idk15 = 0;
    jkHud_idk16 = 0;
    fontIter = &jkHud_aFonts[0];
    for (int i = 0; i < 6; i++)
    {
#ifndef SDL2_RENDER
        if ( Video_format.format.bpp == 8 )
            _sprintf(tmp, "ui\\sft\\%s", fontIter->path8bpp);
        else
#endif
            _sprintf(tmp, "ui\\sft\\%s", fontIter->path16bpp);
        v5 = stdFont_Load(tmp, 0, 0);
        *fontIter->pFont = v5;
        if ( !v5 )
            Windows_GameErrorMsgbox("ERR_CANNOT_LOAD_FILE %s", tmp);
        stdBitmap_ConvertColorFormat(&Video_format.format, v5->bitmap);
        ++fontIter;
    }
    jkHud_leftBlitX = 0;
    jkHud_leftBlitY = Video_format.height - HUD_SCALED((*jkHud_pStatusLeftBm->mipSurfaces)->format.height);
    v6 = *jkHud_pStatusRightBm->mipSurfaces;
    jkHud_rightBlitX = Video_format.width - HUD_SCALED(v6->format.width);
    jkHud_rightBlitY = Video_format.height - HUD_SCALED(v6->format.height);
    for (v7 = 0; v7 < 5; v7++)
    {
        jkHud_aTeamColors16bpp[v7] = stdColor_Indexed8ToRGB16(jkHud_aTeamColors8bpp[v7], Video_aPalette, &Video_format.format);
    }

    if ( Video_format.format.bpp == 8 )
    {
        jkHud_mapRendConfig.paColors = jkHud_aColors8bpp;
        jkHud_mapRendConfig.otherColor = 48;
        jkHud_mapRendConfig.playerColor = 6;
        jkHud_mapRendConfig.playerLineColor = 7;
        jkHud_mapRendConfig.actorColor = 114;
        jkHud_mapRendConfig.actorLineColor = 116;
        jkHud_mapRendConfig.itemColor = 11;
        jkHud_mapRendConfig.weaponColor = 17;
        aTeamColors = jkHud_aTeamColors8bpp;
    }
    else
    {
        for (int i = 0; i < 5; ++i)
            jkHud_aColors16bpp[i] = stdColor_Indexed8ToRGB16(jkHud_aColors8bpp[i], Video_aPalette, &Video_format.format);
        jkHud_mapRendConfig.paColors = jkHud_aColors16bpp;
        jkHud_mapRendConfig.otherColor = stdColor_Indexed8ToRGB16(0x30u, Video_aPalette, &Video_format.format);
        jkHud_mapRendConfig.playerColor = stdColor_Indexed8ToRGB16(6u, Video_aPalette, &Video_format.format);
        jkHud_mapRendConfig.playerLineColor = stdColor_Indexed8ToRGB16(7u, Video_aPalette, &Video_format.format);
        jkHud_mapRendConfig.actorColor = stdColor_Indexed8ToRGB16(0x72u, Video_aPalette, &Video_format.format);
        jkHud_mapRendConfig.actorLineColor = stdColor_Indexed8ToRGB16(0x74u, Video_aPalette, &Video_format.format);
        jkHud_mapRendConfig.itemColor = stdColor_Indexed8ToRGB16(0xBu, Video_aPalette, &Video_format.format);
        jkHud_mapRendConfig.weaponColor = stdColor_Indexed8ToRGB16(0x11u, Video_aPalette, &Video_format.format);
        aTeamColors = jkHud_aTeamColors16bpp;
    }
    _memcpy(jkHud_mapRendConfig.aTeamColors, aTeamColors, sizeof(jkHud_mapRendConfig.aTeamColors));
    jkHud_mapRendConfig.numArr = 5;
    jkHud_mapRendConfig.unkArr = jkHud_aFltIdk;
    jkHud_mapRendConfig.bRotateOverlayMap = jkPlayer_setRotateOverlayMap;
    sithOverlayMap_Startup(&jkHud_mapRendConfig);
    jkHud_targetRed16 = stdColor_Indexed8ToRGB16(jkHud_targetRed, Video_aPalette, &Video_format.format);
    jkHud_targetGreen16 = stdColor_Indexed8ToRGB16(jkHud_targetBlue, Video_aPalette, &Video_format.format);
    jkHud_targetBlue16 = stdColor_Indexed8ToRGB16(jkHud_targetGreen, Video_aPalette, &Video_format.format);
    jkHud_rectViewScores.x = (int32_t)(Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].xMax - -0.5) - HUD_SCALED(110);
    jkHud_bViewScores = 0;
    jkHud_dword_553EDC = 0;
    jkHud_rectViewScores.y = HUD_SCALED(60);
    jkHud_rectViewScores.width = HUD_SCALED(240);
    jkHud_rectViewScores.height = HUD_SCALED(120);
    jkHud_bOpened = 1;
    return 1;
}

void jkHud_Close()
{
    if ( jkHud_bChatOpen )
    {
        jkHud_chatStrPos = 0;
        jkHud_bChatOpen = 0;
        jkDev_sub_41FC90(103);
        stdControl_Flush();
        stdControl_bDisableKeyboard = 0;
    }
    if ( !Main_bNoHUD )
    {
        sithOverlayMap_Shutdown();

        for (int i = 0; i < 8; i++)
        {
            if ( jkHud_aBitmaps[i].pBitmap )
            {
                stdBitmap_Free(*jkHud_aBitmaps[i].pBitmap);
                *jkHud_aBitmaps[i].pBitmap = NULL;
            }
        }

        for (int i = 0; i < 6; i++)
        {
            if ( jkHud_aFonts[i].pFont )
            {
                stdFont_Free(*jkHud_aFonts[i].pFont);
                *jkHud_aFonts[i].pFont = NULL;
            }
        }        
    }
    if ( jkHud_bOpened )
        jkHud_bOpened = 0;
}

int jkHud_ClearRects(int unk)
{
    int v0; // ecx
    int v1; // edi    
    int v3; // eax
    int v5; // esi
    int v7; // eax

    int v2; // eax
    int v4; // eax
    int v6; // ecx
    int v8; // eax
    int result; // eax
    rdRect a4; // [esp+Ch] [ebp-10h] BYREF

    v0 = Video_pCanvas->xStart;
    v1 = 0;
    if ( jkHud_rectViewScores.x < v0 )
        v2 = 0;
    else
        v2 = jkHud_rectViewScores.x <= Video_pCanvas->widthMinusOne;
    if ( !v2
      || ((v3 = jkHud_rectViewScores.x + jkHud_rectViewScores.width - 1, v3 < v0) ? (v4 = 0) : (v4 = v3 <= Video_pCanvas->widthMinusOne),
          !v4
       || ((v5 = Video_pCanvas->yStart, jkHud_rectViewScores.y < v5) ? (v6 = 0) : (v6 = jkHud_rectViewScores.y <= Video_pCanvas->heightMinusOne),
           !v6 || ((v7 = jkHud_rectViewScores.y + jkHud_rectViewScores.height - 1, v7 < v5) ? (v8 = 0) : (v8 = v7 <= Video_pCanvas->heightMinusOne), !v8))) )
    {
        v1 = 1;
    }
    if ( v1 && (jkHud_bViewScores || jkHud_tallyWhich) ) {
        stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, &jkHud_rectViewScores);
    }
    if ( !jkHud_bViewScores && jkHud_tallyWhich )
        --jkHud_tallyWhich;
    if ( (playerThings[playerThingIdx].actorThing->actorParams.typeflags & SITH_AF_NOHUD) == 0 )
    {
        result = 0;
LABEL_29:
        jkHud_dword_553EDC = result;
        if ( !result )
            return result;
        goto LABEL_30;
    }
    if ( !jkHud_dword_553EDC )
    {
        jkHud_dword_553EE0 = 2;
        result = 1;
        goto LABEL_29;
    }
LABEL_30:
    result = jkHud_dword_553EE0;
    if ( jkHud_dword_553EE0 )
    {
        if ( Video_modeStruct.viewSizeIdx < 0xAu )
        {
            a4.x = jkHud_leftBlitX;
            a4.y = jkHud_leftBlitY;
            a4.width = (*jkHud_pStatusLeftBm->mipSurfaces)->format.width;
            a4.height = (*jkHud_pStatusLeftBm->mipSurfaces)->format.height;
            stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, &a4);
            a4.x = jkHud_rightBlitX;
            a4.y = jkHud_rightBlitY;
            a4.width = (*jkHud_pStatusRightBm->mipSurfaces)->format.width;
            a4.height = (*jkHud_pStatusRightBm->mipSurfaces)->format.height;
            stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, &a4);
            result = --jkHud_dword_553EE0;
        }
    }
    return result;
}

// MOTS altered
void jkHud_Draw()
{
    sithThing *playerThing; // esi
    sithItemInfo *v1; // eax
    int v2; // eax
    int v3; // eax
    sithThing *v4; // ebp
    int32_t v5; // eax
    int v6; // eax
    int32_t v7; // eax
    unsigned int v8; // kr00_4
    int32_t v9; // rax
    int v10; // esi
    int v11; // edi
    stdFont *v12; // edi
    int v13; // esi
    int32_t v14; // rax
    unsigned int v15; // ebx
    int v16; // eax
    stdFont *healthFont; // edi
    int v18; // eax
    stdFont *ammoFont; // esi
    double v20; // st7
    int32_t v21; // rax
    int v22; // esi
    int v23; // edi
    int v24; // ebp
    int v25; // ebx
    int v26; // ecx
    int v27; // ecx
    size_t v29; // edx
    unsigned int v30; // ebx
    sithPlayerInfo* playerInfoIter; // edi
    sithPlayerInfo *v32; // esi
    char *v33; // ecx
    wchar_t *v34; // eax
    int v35; // edx
    int v36; // ecx
    jkHudTeamScore* v39; // ecx
    int *v40; // eax
    int v41; // edx
    wchar_t *v42; // eax
    int v43; // eax
    int v44; // edi
    unsigned int v45; // ebp
    jkHudPlayerScore* v46; // esi
    int v47; // eax
    int v48; // edx
    wchar_t *v49; // eax
    wchar_t *v50; // eax
    wchar_t *v51; // eax
    wchar_t *v52; // eax
    int v53; // esi
    jkHudTeamScore *v54; // edi
    wchar_t *v55; // eax
    float v56; // [esp+0h] [ebp-168h]
    float v57; // [esp+0h] [ebp-168h]
    float v58; // [esp+0h] [ebp-168h]
    float v59; // [esp+0h] [ebp-168h]
    float v60; // [esp+0h] [ebp-168h]
    float a2; // [esp+4h] [ebp-164h]
    float a2a; // [esp+4h] [ebp-164h]
    float a2b; // [esp+4h] [ebp-164h]
    float a2c; // [esp+4h] [ebp-164h]
    float a2d; // [esp+4h] [ebp-164h]
    wchar_t *v66; // [esp+8h] [ebp-160h]
    rdRect a4; // [esp+28h] [ebp-140h] BYREF
    char tmp[32]; // [esp+48h] [ebp-120h] BYREF
    wchar_t a6[128]; // [esp+68h] [ebp-100h] BYREF
    float tmpFloat1;

    if (!jkHud_bOpened)
        return;

    if ( Main_bDispStats )
    {
        playerThing = sithWorld_pCurrentWorld->playerThing;
        if ( playerThing->type == SITH_THING_PLAYER )
        {
            v1 = sithInventory_GetBin(playerThing, SITHBIN_FORCEMANA);
            if ( v1 )
            {
                tmpFloat1 = v1->ammoAmt;
            }
            else
            {
                tmpFloat1 = 0.0;
            }
            stdString_snprintf(std_genBuffer, 1024, "force: %3.0f, ", tmpFloat1);
            jkHud_GetWeaponAmmo(playerThing);
            if ( playerThing->type == SITH_THING_PLAYER )
            {
                v2 = playerThing->actorParams.playerinfo->curItem;
                if ( v2 >= 0 )
                    stdString_snprintf(
                        &std_genBuffer[_strlen(std_genBuffer)],
                        1024 - _strlen(std_genBuffer),
                        " item: %s,",
                        sithInventory_aDescriptors[v2].fpath);
                if ( playerThing->type == SITH_THING_PLAYER )
                {
                    v3 = playerThing->actorParams.playerinfo->curPower;
                    if ( v3 >= 0 )
                        stdString_snprintf(
                            &std_genBuffer[_strlen(std_genBuffer)],
                            1024 - _strlen(std_genBuffer),
                            " force: %s,",
                            sithInventory_aDescriptors[v3].fpath);
                }
            }
        }
        jkDev_sub_41FC40(0x66, std_genBuffer);
    }

#ifdef SDL2_RENDER
    jkHud_DrawGPU();
    return;
#endif

    //std3D_DrawUIBitmap(0,0,64,64,0,0,4.0,jkHud_pTestbitmap);

#ifndef SDL2_RENDER
    stdVBuffer* pOverlayBuffer = Video_pMenuBuffer;
    rdCanvas* pOverlayCanvas = Video_pCanvas;
#else
    stdVBuffer* pOverlayBuffer = Video_pCanvasOverlayMap->vbuffer;
    rdCanvas* pOverlayCanvas = Video_pCanvasOverlayMap;
#endif

    if (Main_bNoHUD) {
#ifdef SDL2_RENDER
    stdDisplay_VBufferUnlock(Video_pCanvas->vbuffer);
#endif
        return;
    }

    v4 = sithWorld_pCurrentWorld->playerThing;
    if ( Video_modeStruct.b3DAccel )
        stdDisplay_VBufferLock(Video_pMenuBuffer);

#ifdef SDL2_RENDER
    stdDisplay_VBufferLock(pOverlayBuffer);
#endif

    sithOverlayMap_Render1(pOverlayCanvas);
    if ( Video_modeStruct.b3DAccel )
        stdDisplay_VBufferUnlock(Video_pMenuBuffer);

#ifdef SDL2_RENDER
    stdDisplay_VBufferLock(Video_pCanvas->vbuffer);
#endif

    if ( v4->type == SITH_THING_PLAYER && !(sithNet_isServer && jkGuiNetHost_bIsDedicated) )
    {
        v5 = (int32_t)sithInventory_GetBinAmount(v4, SITHBIN_BATTERY);
        if ( v5 < 0 )
        {
            v5 = 0;
        }
        else if ( v5 > SITHBIN_NUMBINS )
        {
            v5 = SITHBIN_NUMBINS;
        }
        if ( jkHud_blittedBatteryAmt != v5 )
        {
            jkHud_blittedBatteryAmt = v5;
            stdDisplay_VBufferCopy(
                *jkHud_pStatusRightBm->mipSurfaces,
                jkHud_pStBatBm->mipSurfaces[v5 * (jkHud_pStBatBm->numMips - 1) / 200],
                jkHud_pStBatBm->xPos,
                jkHud_pStBatBm->yPos,
                0,
                1);
        }
        v6 = sithInventory_GetActivate(v4, SITHBIN_FIELDLIGHT);
        if ( jkHud_blittedFieldlightAmt != v6 )
        {
            jkHud_blittedFieldlightAmt = v6;
            stdDisplay_VBufferCopy(
                *jkHud_pStatusRightBm->mipSurfaces,
                jkHud_pFieldlightBm->mipSurfaces[v6],
                jkHud_pFieldlightBm->xPos,
                jkHud_pFieldlightBm->yPos,
                0,
                1);
        }
        v7 = (int32_t)sithInventory_GetBinAmount(v4, SITHBIN_FORCEMANA);
        if ( v7 < 0 )
        {
            v7 = 0;
        }
        else if ( v7 > 400 )
        {
            v7 = 400;
        }
        v8 = (jkHud_pStFrcBm->numMips - 1) * (400 - v7);
        if ( jkHud_blittedForceIdx != v8 / 400 || jkHud_idk15 != playerThings[playerThingIdx].bHasForceSurge )
        {
            jkHud_idk15 = playerThings[playerThingIdx].bHasForceSurge;
            if ( jkHud_idk15 )
            {
                stdDisplay_VBufferCopy(
                    *jkHud_pStatusRightBm->mipSurfaces,
                    *jkHud_pStFrcSuperBm->mipSurfaces,
                    jkHud_pStFrcSuperBm->xPos,
                    jkHud_pStFrcSuperBm->yPos,
                    0,
                    1);
            }
            else
            {
                stdDisplay_VBufferCopy(
                    *jkHud_pStatusRightBm->mipSurfaces,
                    jkHud_pStFrcBm->mipSurfaces[v8 / 400],
                    jkHud_pStFrcBm->xPos,
                    jkHud_pStFrcBm->yPos,
                    0,
                    1);
                jkHud_blittedForceIdx = v8 / 400;
            }
        }
        v9 = (int32_t)sithInventory_GetBinAmount(v4, SITHBIN_SHIELDS);
        v10 = v9;
        if ( (int)v9 < 0 )
        {
            v10 = 0;
        }
        else if ( (int)v9 > SITHBIN_NUMBINS )
        {
            v10 = SITHBIN_NUMBINS;
        }
        v11 = playerThingIdx;
        if ( jkHud_blittedShieldIdx != v10 || jkHud_isSuper != playerThings[playerThingIdx].bHasSuperShields )
        {
            jkHud_blittedShieldIdx = v10;
            v12 = jkHud_pArmorNumsSuperSft;
            if ( !playerThings[playerThingIdx].bHasSuperShields )
                v12 = jkHud_pArmorNumSft;
            stdString_snprintf(tmp, 32, "%03d", v10); // v10
            stdFont_DrawAscii(*jkHud_pStatusLeftBm->mipSurfaces, v12, 23u, 43, 999, tmp, 0);
            stdDisplay_VBufferCopy(
                *jkHud_pStatusLeftBm->mipSurfaces,
                jkHud_pStShieldBm->mipSurfaces[(jkHud_pStShieldBm->numMips - 1) * (SITHBIN_NUMBINS - v10) / SITHBIN_NUMBINS],
                jkHud_pStShieldBm->xPos,
                jkHud_pStShieldBm->yPos,
                0,
                1);
            v11 = playerThingIdx;
        }
        v13 = (int32_t)v4->actorParams.health;
        v14 = (int32_t)v4->actorParams.maxHealth;
        v15 = v14;
        if ( v13 < 0 )
        {
            v13 = 0;
        }
        else if ( v13 > (int)v14 )
        {
            v13 = v14;
        }
        if ( jkHud_blittedHealthIdx != v13 || jkHud_isSuper != playerThings[v11].bHasSuperShields )
        {
            jkHud_blittedHealthIdx = v13;
            v16 = v11;
            healthFont = jkHud_pArmorNumsSuperSft;
            jkHud_isSuper = playerThings[v16].bHasSuperShields;
            if ( !jkHud_isSuper )
                healthFont = jkHud_pHelthNumSft;
            stdString_snprintf(tmp, 32, "%03d", v13);
            stdFont_DrawAscii(*jkHud_pStatusLeftBm->mipSurfaces, healthFont, 13u, 35, 999, tmp, 0);
            stdDisplay_VBufferCopy(
                *jkHud_pStatusLeftBm->mipSurfaces,
                jkHud_pStHealthBm->mipSurfaces[(jkHud_pStHealthBm->numMips - 1) * (v15 - v13) / v15],
                jkHud_pStHealthBm->xPos,
                jkHud_pStHealthBm->yPos,
                0,
                1);
        }
        v18 = jkHud_GetWeaponAmmo(v4);
        if ( jkHud_blittedAmmoAmt != v18 || jkHud_idk14 != playerThings[playerThingIdx].bHasSuperWeapon )
        {
            ammoFont = jkHud_pAmoNumsSuperSft;
            jkHud_blittedAmmoAmt = v18;
            jkHud_idk14 = playerThings[playerThingIdx].bHasSuperWeapon;
            if ( !jkHud_idk14 )
                ammoFont = jkHud_pAmoNumsSft;
            if ( v18 == -999 )
            {
                _strncpy(tmp, ":::", 0x1Fu);
                tmp[31] = 0;
            }
            else
            {
                stdString_snprintf(tmp, 32, "%03d", v18);
            }
            stdFont_DrawAscii(*jkHud_pStatusRightBm->mipSurfaces, ammoFont, 13u, 19, 999, tmp, 0);
        }
    }

    if (
        jkPlayer_setCrosshair 
        && sithCamera_currentCamera->cameraPerspective == 1
        && !(sithPlayer_pLocalPlayerThing->thingflags & SITH_TF_DEAD) 
        && MOTS_ONLY_COND(!(sithPlayer_pLocalPlayerThing->actorParams.typeflags & SITH_AF_SCOPEHUD))
#ifdef QOL_IMPROVEMENTS
        && jkHud_shouldCrosshairBeShownForWeapon(sithPlayer_pLocalPlayerThing)
#endif /* ifdef QOL_IMPROVEMENTS */

    )

    {
        uint32_t tmpInt;
#ifdef QOL_IMPROVEMENTS
        // Scale crosshair with vertical resolution, not horizontal.
        v20 = (double)Video_format.height * (0.0015625 / 3.0) * 4.0;
#else
        v20 = (double)Video_format.width * 0.0015625;
#endif // QOL_IMPROVEMENTS
        v21 = (int32_t)(v20 + v20 + Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].xMax - -0.5);
        v22 = v21;
        v23 = (int32_t)((double)(unsigned int)Video_format.height * 0.0020833334
                      + (double)(unsigned int)Video_format.height * 0.0020833334
                      + Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].yMax
                      - -0.5);
        if ( Video_format.format.bpp == 8 )
            tmpInt = 48;
        else
            tmpInt = stdColor_Indexed8ToRGB16(0x30u, (rdColor24 *)Video_aPalette, &Video_format.format);
        v24 = (int32_t)(v20 * 18.0 - -0.5);
        v25 = (int32_t)(v20 * 6.0 - -0.5);
        
        rdPrimit2_DrawClippedLine(Video_pCanvas, v22 - v24, v23,       v22 - v25, v23,       tmpInt, -1);
        rdPrimit2_DrawClippedLine(Video_pCanvas, v22 + v25, v23,       v22 + v24, v23,       tmpInt, -1);
        rdPrimit2_DrawClippedLine(Video_pCanvas, v22,       v23 - v24, v22,       v23 - v25, tmpInt, -1);
        rdPrimit2_DrawClippedLine(Video_pCanvas, v22,       v23 + v25, v22,       v23 + v24, tmpInt, -1);
    }

    rdScreenPoint tmpScreenPt;
    if ( jkHud_bHasTarget && jkHud_pTargetThing && rdPrimit3_GetScreenCoord(&jkHud_pTargetThing->position, &tmpScreenPt) )
    {
        float valSin, valCos;
        a2 = sithTime_curSeconds * 200.0;
        if ( Video_format.format.is16bit )
        {
            stdMath_SinCos(a2, &valSin, &valCos);
            v58 = valSin * 20.0;
            rdPrimit2_DrawCircle(pOverlayCanvas, tmpScreenPt.x, tmpScreenPt.y, v58, 20.0, jkHud_targetRed16, -1);
            a2c = (sithTime_curSeconds - 0.1) * 200.0;
            stdMath_SinCos(a2c, &valSin, &valCos);
            v59 = valSin * 20.0;
            rdPrimit2_DrawCircle(pOverlayCanvas, tmpScreenPt.x, tmpScreenPt.y, v59, 20.0, jkHud_targetGreen16, -1);
            a2d = (sithTime_curSeconds - 0.2) * 200.0;
            stdMath_SinCos(a2d, &valSin, &valCos);
            v26 = jkHud_targetBlue16;
        }
        else
        {
            stdMath_SinCos(a2, &valSin, &valCos);
            v56 = valSin * 20.0;
            rdPrimit2_DrawCircle(pOverlayCanvas, tmpScreenPt.x, tmpScreenPt.y, v56, 20.0, jkHud_targetRed, -1);
            a2a = (sithTime_curSeconds - 0.1) * 200.0;
            stdMath_SinCos(a2a, &valSin, &valCos);
            v57 = valSin * 20.0;
            rdPrimit2_DrawCircle(pOverlayCanvas, tmpScreenPt.x, tmpScreenPt.y, v57, 20.0, jkHud_targetBlue, -1);
            a2b = (sithTime_curSeconds - 0.2) * 200.0;
            stdMath_SinCos(a2b, &valSin, &valCos);
            v26 = jkHud_targetGreen;
        }
        v60 = valSin * 20.0;
        rdPrimit2_DrawCircle(pOverlayCanvas, tmpScreenPt.x, tmpScreenPt.y, v60, 20.0, v26, -1);
    }

    
    if ( jkHud_bViewScores )
    {
        char tmpFname[16];
        for (v27 = 0; v27 < 5; v27++)
        {
            jkHud_aTeamScores[v27].field_0 = v27;
            jkHud_aTeamScores[v27].field_8 = 0;
            jkHud_aTeamScores[v27].field_C = 0;
        }
        v29 = 0;
        v30 = 0;
        jkHud_numPlayers = 0;
        if ( jkPlayer_maxPlayers )
        {
            playerInfoIter = &jkPlayer_playerInfos[0];
            do
            {
                v32 = playerInfoIter;
                if ((playerInfoIter->flags & 1) != 0)
                {
                    stdString_SafeWStrCopy(jkHud_aPlayerScores[v29].playerName, playerInfoIter->player_name, 0x20);
                    v33 = v32->playerThing->rdthing.model3->filename;
                    stdFnames_CopyShortName(tmpFname, 16, v33);
                    jkGuiTitle_sub_4189A0(tmpFname);
                    v34 = jkStrings_GetUniStringWithFallback(tmpFname);
                    stdString_SafeWStrCopy(jkHud_aPlayerScores[jkHud_numPlayers].modelName, v34, 0x20);
                    v35 = jkHud_numPlayers;
                    v36 = v32->score;
                    jkHud_aPlayerScores[jkHud_numPlayers].score = v36;
                    jkHud_aPlayerScores[jkHud_numPlayers].teamNum = playerInfoIter->teamNum;
                    jkHud_aTeamScores[playerInfoIter->teamNum].field_8 = 1;
                    jkHud_aTeamScores[playerInfoIter->teamNum].field_C++;
                    v29 = v35 + 1;
                    jkHud_numPlayers = v29;
                }
                ++v30;
                ++playerInfoIter;
            }
            while ( v30 < jkPlayer_maxPlayers );
        }
        _qsort(jkHud_aPlayerScores, v29, sizeof(jkHudPlayerScore), jkHud_SortPlayerScore);
        if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
        {
            v39 = &jkHud_aTeamScores[0];
            v40 = sithNet_teamScore;
            for (int i = 0; i < 5; i++)
            {
                v41 = *v40++;
                v39->score = v41;
                v39++;
            }
            _qsort(jkHud_aTeamScores, 5u, sizeof(jkHudTeamScore), jkHud_SortTeamScore);
        }
        if ( jkHud_bViewScores == 1 )
        {
            a4.width = 9;
            a4.x = jkHud_rectViewScores.x + 20;
            a4.height = (*jkHud_pMsgFontSft->bitmap->mipSurfaces)->format.height - 2;
            v49 = jkStrings_GetUniStringWithFallback("HUD_TEAMSCORESTITLE");
            stdFont_Draw4(
                Video_pMenuBuffer,
                jkHud_pMsgFontSft,
                jkHud_rectViewScores.x,
                60,
                jkHud_rectViewScores.width,
                jkHud_rectViewScores.height,
                1,
                v49,
                1);
            v50 = jkStrings_GetUniStringWithFallback("HUD_TEAMNAME");
            stdFont_Draw4(
                Video_pMenuBuffer,
                jkHud_pMsgFontSft,
                jkHud_rectViewScores.x + 40,
                80,
                jkHud_rectViewScores.width,
                jkHud_rectViewScores.height,
                0,
                v50,
                1);
            v51 = jkStrings_GetUniStringWithFallback("HUD_TEAMPLAYERS");
            stdFont_Draw4(
                Video_pMenuBuffer,
                jkHud_pMsgFontSft,
                jkHud_rectViewScores.x + 80,
                80,
                jkHud_rectViewScores.width,
                jkHud_rectViewScores.height,
                0,
                v51,
                1);
            v52 = jkStrings_GetUniStringWithFallback("HUD_TEAMSCORE");
            stdFont_Draw4(
                Video_pMenuBuffer,
                jkHud_pMsgFontSft,
                jkHud_rectViewScores.x + 140,
                80,
                jkHud_rectViewScores.width,
                jkHud_rectViewScores.height,
                0,
                v52,
                1);
            v53 = 100;
            v54 = jkHud_aTeamScores;
            for (int i = 0; i < 5; i++)
            {
                if ( v54->field_8 )
                {
                    a4.y = v53 + 1;
                    if ( Video_format.format.is16bit )
                        stdDisplay_VBufferFill(Video_pMenuBuffer, jkHud_aTeamColors16bpp[v54->field_0], &a4);
                    else
                        stdDisplay_VBufferFill(Video_pMenuBuffer, jkHud_aTeamColors8bpp[v54->field_0], &a4);
                    switch ( v54->field_0 )
                    {
                        case 1:
                            v55 = jkStrings_GetUniStringWithFallback("GUI_RED");
                            goto LABEL_115;
                        case 2:
                            v55 = jkStrings_GetUniStringWithFallback("GUI_GOLD");
                            goto LABEL_115;
                        case 3:
                            v66 = jkStrings_GetUniStringWithFallback("GUI_BLUE");
                            stdFont_Draw1(Video_pMenuBuffer, jkHud_pMsgFontSft, jkHud_rectViewScores.x + 40, v53, jkHud_rectViewScores.width, v66, 1);
                            goto LABEL_116;
                        case 4:
                            v55 = jkStrings_GetUniStringWithFallback("GUI_GREEN");
                            goto LABEL_115;
                        default:
                            v55 = jkStrings_GetUniStringWithFallback("GUI_NONE");
LABEL_115:
                            stdFont_Draw1(Video_pMenuBuffer, jkHud_pMsgFontSft, jkHud_rectViewScores.x + 40, v53, jkHud_rectViewScores.width, v55, 1);
LABEL_116:
                            jk_snwprintf(a6, 0x80u, L"%4d", v54->field_C);
                            stdFont_Draw1(Video_pMenuBuffer, jkHud_pMsgFontSft, jkHud_rectViewScores.x + 90, v53, jkHud_rectViewScores.width, a6, 1);
                            jk_snwprintf(a6, 0x80u, L"%4d", v54->score);
                            stdFont_Draw1(Video_pMenuBuffer, jkHud_pMsgFontSft, jkHud_rectViewScores.x + 150, v53, jkHud_rectViewScores.width, a6, 1);
                            v53 += (*jkHud_pMsgFontSft->bitmap->mipSurfaces)->format.height + jkHud_pMsgFontSft->marginY;
                            break;
                    }
                }
                ++v54;
            }
            jkHud_idk16 = 1;
        }
        else if ( jkHud_bViewScores == 2 )
        {
            a4.x = jkHud_rectViewScores.x;
            a4.width = 9;
            a4.height = (*jkHud_pMsgFontSft->bitmap->mipSurfaces)->format.height - 2;
            v42 = jkStrings_GetUniStringWithFallback("HUD_PLAYERSCORES");
            stdFont_Draw4(
                Video_pMenuBuffer,
                jkHud_pMsgFontSft,
                jkHud_rectViewScores.x,
                60,
                jkHud_rectViewScores.width,
                jkHud_rectViewScores.height,
                1,
                v42,
                1);
            v43 = jkHud_dword_553ED0;
            v44 = 80;
            v45 = jkHud_dword_553ED0;
            if ( jkHud_dword_553ED0 < jkHud_numPlayers )
            {
                v46 = &jkHud_aPlayerScores[jkHud_dword_553ED0];
                while ( v45 < v43 + 8 )
                {
                    a4.y = v44 + 1;
                    if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
                    {
                        v47 = v46->teamNum;
                        if ( v46->teamNum )
                        {
                            if ( Video_format.format.is16bit )
                                v48 = jkHud_aTeamColors16bpp[v47];
                            else
                                v48 = jkHud_aTeamColors8bpp[v47];
                            stdDisplay_VBufferFill(Video_pMenuBuffer, v48, &a4);
                        }
                    }
                    jk_snwprintf(a6, 0x11u, L"%.16ls", v46);
                    stdFont_Draw1(Video_pMenuBuffer, jkHud_pMsgFontSft, jkHud_rectViewScores.x + 10, v44, jkHud_rectViewScores.width, a6, 1);
                    jk_snwprintf(a6, 0x80u, L"(%.8ls)", v46->modelName);
                    stdFont_Draw1(Video_pMenuBuffer, jkHud_pMsgFontSft, jkHud_rectViewScores.x + 130, v44, jkHud_rectViewScores.width, a6, 1);
                    jk_snwprintf(a6, 0x80u, L"%4d", v46->score);
                    stdFont_Draw1(Video_pMenuBuffer, jkHud_pMsgFontSft, jkHud_rectViewScores.x + 190, v44, jkHud_rectViewScores.width, a6, 1);
                    ++v46;
                    v44 += (*jkHud_pMsgFontSft->bitmap->mipSurfaces)->format.height + jkHud_pMsgFontSft->marginY;
                    if ( ++v45 >= jkHud_numPlayers )
                        break;
                    v43 = jkHud_dword_553ED0;
                }
            }
            jkHud_idk16 = 2;
        }
    }
    else
    {
        jkHud_idk16 = 0;
    }
    if ( Video_modeStruct.viewSizeIdx < 0xAu  && !(sithNet_isServer && jkGuiNetHost_bIsDedicated))
    {
        stdDisplay_VBufferCopy(Video_pMenuBuffer, *jkHud_pStatusLeftBm->mipSurfaces, jkHud_leftBlitX, jkHud_leftBlitY, 0, 1);
        stdDisplay_VBufferCopy(Video_pMenuBuffer, *jkHud_pStatusRightBm->mipSurfaces, jkHud_rightBlitX, jkHud_rightBlitY, 0, 1);
    }

#ifdef DEBUG_QOL_CHEATS
    int fps = (int)sithTime_TickHz;
    if (fps > 999)
        fps = 999;
    if (fps < 0)
        fps = 0;
    memset(tmp, 0, 32);
    stdString_snprintf(tmp, 32, "%03d", fps);
    stdFont_DrawAscii(Video_pMenuBuffer, jkHud_pMsgFontSft, jkHud_leftBlitX, jkHud_leftBlitY, 999, tmp, 0);
#endif

#ifdef SDL2_RENDER
    stdDisplay_VBufferUnlock(Video_pCanvasOverlayMap->vbuffer);
    stdDisplay_VBufferUnlock(Video_pCanvas->vbuffer);
#endif

    jkHud_DrawGPU();
}

// MOTS altered
void jkHud_DrawGPU()
{
    sithThing *playerThing; // esi
    sithItemInfo *v1; // eax
    int v2; // eax
    int v3; // eax
    sithThing *v4; // ebp
    int32_t v5; // eax
    int v6; // eax
    int32_t v7; // eax
    unsigned int v8; // kr00_4
    int32_t v9; // rax
    int v10; // esi
    int v11; // edi
    stdFont *v12; // edi
    int v13; // esi
    int32_t v14; // rax
    unsigned int v15; // ebx
    int v16; // eax
    stdFont *healthFont; // edi
    int v18; // eax
    stdFont *ammoFont; // esi
    double v20; // st7
    int32_t v21; // rax
    int v22; // esi
    int v23; // edi
    int v24; // ebp
    int v25; // ebx
    int v26; // ecx
    int v27; // ecx
    size_t v29; // edx
    unsigned int v30; // ebx
    sithPlayerInfo* playerInfoIter; // edi
    sithPlayerInfo *v32; // esi
    char *v33; // ecx
    wchar_t *v34; // eax
    int v35; // edx
    int v36; // ecx
    jkHudTeamScore* v39; // ecx
    int *v40; // eax
    int v41; // edx
    wchar_t *v42; // eax
    int v43; // eax
    int v44; // edi
    unsigned int v45; // ebp
    jkHudPlayerScore* v46; // esi
    int v47; // eax
    int v48; // edx
    wchar_t *v49; // eax
    wchar_t *v50; // eax
    wchar_t *v51; // eax
    wchar_t *v52; // eax
    int v53; // esi
    jkHudTeamScore *v54; // edi
    wchar_t *v55; // eax
    float v56; // [esp+0h] [ebp-168h]
    float v57; // [esp+0h] [ebp-168h]
    float v58; // [esp+0h] [ebp-168h]
    float v59; // [esp+0h] [ebp-168h]
    float v60; // [esp+0h] [ebp-168h]
    float a2; // [esp+4h] [ebp-164h]
    float a2a; // [esp+4h] [ebp-164h]
    float a2b; // [esp+4h] [ebp-164h]
    float a2c; // [esp+4h] [ebp-164h]
    float a2d; // [esp+4h] [ebp-164h]
    wchar_t *v66; // [esp+8h] [ebp-160h]
    rdRect a4; // [esp+28h] [ebp-140h] BYREF
    char tmp[32]; // [esp+48h] [ebp-120h] BYREF
    wchar_t a6[128]; // [esp+68h] [ebp-100h] BYREF
    float tmpFloat1;

    if (!jkHud_bOpened)
        return;

    if (!(Video_modeStruct.viewSizeIdx < 0xAu  && !(sithNet_isServer && jkGuiNetHost_bIsDedicated)))
    {
        return;
    }

    //std3D_DrawUIBitmap(0,0,64,64,0,0,4.0,jkHud_pTestbitmap);

#ifndef SDL2_RENDER
    stdVBuffer* pOverlayBuffer = Video_pMenuBuffer;
    rdCanvas* pOverlayCanvas = Video_pCanvas;
#else
    stdVBuffer* pOverlayBuffer = Video_pCanvasOverlayMap->vbuffer;
    rdCanvas* pOverlayCanvas = Video_pCanvasOverlayMap;
#endif

    if (Main_bNoHUD) {
#ifdef SDL2_RENDER
    stdDisplay_VBufferUnlock(Video_pCanvas->vbuffer);
#endif
        return;
    }

    v4 = sithWorld_pCurrentWorld->playerThing;
    if ( Video_modeStruct.b3DAccel )
        stdDisplay_VBufferLock(Video_pMenuBuffer);

#ifdef SDL2_RENDER
    stdDisplay_VBufferLock(pOverlayBuffer);
#endif

    sithOverlayMap_Render1(pOverlayCanvas);
    if ( Video_modeStruct.b3DAccel )
        stdDisplay_VBufferUnlock(Video_pMenuBuffer);

#ifdef SDL2_RENDER
    stdDisplay_VBufferLock(Video_pCanvas->vbuffer);
#endif

    // The rendering for GPU is kind of inverted from how the original does it.
    // The original blits onto the left/right statuses, then blits those to the screen.
    // We have to blit the left/right status, then everything on top of it.
    std3D_DrawUIBitmap(jkHud_pStatusLeftBm, 0, jkHud_leftBlitX, jkHud_leftBlitY, NULL, jkPlayer_hudScale, 1);
    std3D_DrawUIBitmap(jkHud_pStatusRightBm, 0, jkHud_rightBlitX, jkHud_rightBlitY, NULL, jkPlayer_hudScale, 1);

    if ( v4->type == SITH_THING_PLAYER && !(sithNet_isServer && jkGuiNetHost_bIsDedicated) )
    {
        v5 = (int32_t)sithInventory_GetBinAmount(v4, SITHBIN_BATTERY);
        if ( v5 < 0 )
        {
            v5 = 0;
        }
        else if ( v5 > SITHBIN_NUMBINS )
        {
            v5 = SITHBIN_NUMBINS;
        }
        //if ( jkHud_blittedBatteryAmt != v5 )
        {
            jkHud_blittedBatteryAmt = v5;
            /*stdDisplay_VBufferCopy(
                *jkHud_pStatusRightBm->mipSurfaces,
                jkHud_pStBatBm->mipSurfaces[v5 * (jkHud_pStBatBm->numMips - 1) / 200],
                jkHud_pStBatBm->xPos,
                jkHud_pStBatBm->yPos,
                0,
                1);*/
            //std3D_DrawUIBitmap(jkHud_pStatusRightBm,0, 0,0,64,64,0,0,4.0);
            std3D_DrawUIBitmap(jkHud_pStBatBm, v5 * (jkHud_pStBatBm->numMips - 1) / 200, jkHud_rightBlitX + HUD_SCALED(jkHud_pStBatBm->xPos), jkHud_rightBlitY + HUD_SCALED(jkHud_pStBatBm->yPos), NULL, jkPlayer_hudScale, 1);
        }
        v6 = sithInventory_GetActivate(v4, SITHBIN_FIELDLIGHT);
        //if ( jkHud_blittedFieldlightAmt != v6 )
        {
            jkHud_blittedFieldlightAmt = v6;
            /*stdDisplay_VBufferCopy(
                *jkHud_pStatusRightBm->mipSurfaces,
                jkHud_pFieldlightBm->mipSurfaces[v6],
                jkHud_pFieldlightBm->xPos,
                jkHud_pFieldlightBm->yPos,
                0,
                1);*/
            std3D_DrawUIBitmap(jkHud_pFieldlightBm, v6, jkHud_rightBlitX + (int)((float)jkHud_pFieldlightBm->xPos * jkPlayer_hudScale), jkHud_rightBlitY + (int)((float)jkHud_pFieldlightBm->yPos * jkPlayer_hudScale), NULL, jkPlayer_hudScale, 1);
        }
        v7 = (int32_t)sithInventory_GetBinAmount(v4, SITHBIN_FORCEMANA);
        if ( v7 < 0 )
        {
            v7 = 0;
        }
        else if ( v7 > 400 )
        {
            v7 = 400;
        }
        v8 = (jkHud_pStFrcBm->numMips - 1) * (400 - v7);
        //if ( jkHud_blittedForceIdx != v8 / 400 || jkHud_idk15 != playerThings[playerThingIdx].bHasForceSurge )
        {
            jkHud_idk15 = playerThings[playerThingIdx].bHasForceSurge;
            if ( jkHud_idk15 )
            {
                /*stdDisplay_VBufferCopy(
                    *jkHud_pStatusRightBm->mipSurfaces,
                    *jkHud_pStFrcSuperBm->mipSurfaces,
                    jkHud_pStFrcSuperBm->xPos,
                    jkHud_pStFrcSuperBm->yPos,
                    0,
                    1);*/
                std3D_DrawUIBitmap(jkHud_pStFrcSuperBm, 0, jkHud_rightBlitX + HUD_SCALED(jkHud_pStFrcSuperBm->xPos), jkHud_rightBlitY + HUD_SCALED(jkHud_pStFrcSuperBm->yPos), NULL, jkPlayer_hudScale, 1);
            }
            else
            {
                /*stdDisplay_VBufferCopy(
                    *jkHud_pStatusRightBm->mipSurfaces,
                    jkHud_pStFrcBm->mipSurfaces[v8 / 400],
                    jkHud_pStFrcBm->xPos,
                    jkHud_pStFrcBm->yPos,
                    0,
                    1);*/

                std3D_DrawUIBitmap(jkHud_pStFrcBm, v8 / 400, jkHud_rightBlitX + HUD_SCALED(jkHud_pStFrcBm->xPos), jkHud_rightBlitY + HUD_SCALED(jkHud_pStFrcBm->yPos), NULL, jkPlayer_hudScale, 1);
                jkHud_blittedForceIdx = v8 / 400;
            }
        }
        v9 = (int32_t)sithInventory_GetBinAmount(v4, SITHBIN_SHIELDS);
        v10 = v9;
        if ( (int)v9 < 0 )
        {
            v10 = 0;
        }
        else if ( (int)v9 > SITHBIN_NUMBINS )
        {
            v10 = SITHBIN_NUMBINS;
        }
        v11 = playerThingIdx;
        //if ( jkHud_blittedShieldIdx != v10 || jkHud_isSuper != playerThings[playerThingIdx].bHasSuperShields )
        {
            jkHud_blittedShieldIdx = v10;
            v12 = jkHud_pArmorNumsSuperSft;
            if ( !playerThings[playerThingIdx].bHasSuperShields )
                v12 = jkHud_pArmorNumSft;
            stdString_snprintf(tmp, 32, "%03d", v10); // v10
            stdFont_DrawAsciiGPU(v12, jkHud_leftBlitX + HUD_SCALED(23u), jkHud_leftBlitY + HUD_SCALED(43), 999, tmp, 0, jkPlayer_hudScale);
            /*stdDisplay_VBufferCopy(
                *jkHud_pStatusLeftBm->mipSurfaces,
                jkHud_pStShieldBm->mipSurfaces[(jkHud_pStShieldBm->numMips - 1) * (SITHBIN_NUMBINS - v10) / SITHBIN_NUMBINS],
                jkHud_pStShieldBm->xPos,
                jkHud_pStShieldBm->yPos,
                0,
                1);*/
            std3D_DrawUIBitmap(jkHud_pStShieldBm, (jkHud_pStShieldBm->numMips - 1) * (SITHBIN_NUMBINS - v10) / SITHBIN_NUMBINS, jkHud_leftBlitX + HUD_SCALED(jkHud_pStShieldBm->xPos), jkHud_leftBlitY + HUD_SCALED(jkHud_pStShieldBm->yPos), NULL, jkPlayer_hudScale, 1);
            v11 = playerThingIdx;
        }
        v13 = (int32_t)v4->actorParams.health;
        v14 = (int32_t)v4->actorParams.maxHealth;
        v15 = v14;
        if ( v13 < 0 )
        {
            v13 = 0;
        }
        else if ( v13 > (int)v14 )
        {
            v13 = v14;
        }
        //if ( jkHud_blittedHealthIdx != v13 || jkHud_isSuper != playerThings[v11].bHasSuperShields )
        {
            jkHud_blittedHealthIdx = v13;
            v16 = v11;
            healthFont = jkHud_pArmorNumsSuperSft;
            jkHud_isSuper = playerThings[v16].bHasSuperShields;
            if ( !jkHud_isSuper )
                healthFont = jkHud_pHelthNumSft;
            stdString_snprintf(tmp, 32, "%03d", v13);
            stdFont_DrawAsciiGPU(healthFont, jkHud_leftBlitX + HUD_SCALED(13u), jkHud_leftBlitY + HUD_SCALED(35), 999, tmp, 0, jkPlayer_hudScale);
            /*stdDisplay_VBufferCopy(
                *jkHud_pStatusLeftBm->mipSurfaces,
                jkHud_pStHealthBm->mipSurfaces[(jkHud_pStHealthBm->numMips - 1) * (v15 - v13) / v15],
                jkHud_pStHealthBm->xPos,
                jkHud_pStHealthBm->yPos,
                0,
                1);*/
            std3D_DrawUIBitmap(jkHud_pStHealthBm, (jkHud_pStHealthBm->numMips - 1) * (v15 - v13) / v15, jkHud_leftBlitX + HUD_SCALED(jkHud_pStHealthBm->xPos), jkHud_leftBlitY + HUD_SCALED(jkHud_pStHealthBm->yPos), NULL, jkPlayer_hudScale, 1);
        }
        v18 = jkHud_GetWeaponAmmo(v4);
        //if ( jkHud_blittedAmmoAmt != v18 || jkHud_idk14 != playerThings[playerThingIdx].bHasSuperWeapon )
        {
            ammoFont = jkHud_pAmoNumsSuperSft;
            jkHud_blittedAmmoAmt = v18;
            jkHud_idk14 = playerThings[playerThingIdx].bHasSuperWeapon;
            if ( !jkHud_idk14 )
                ammoFont = jkHud_pAmoNumsSft;
            if ( v18 == -999 )
            {
                _strncpy(tmp, ":::", 0x1Fu);
                tmp[31] = 0;
            }
            else
            {
                stdString_snprintf(tmp, 32, "%03d", v18);
            }
            stdFont_DrawAsciiGPU(ammoFont, jkHud_rightBlitX + HUD_SCALED(13u), jkHud_rightBlitY + HUD_SCALED(19), 999, tmp, 0, jkPlayer_hudScale);
        }
    }

    // MoTS altered: Scope hud
    if (
        jkPlayer_setCrosshair
        && sithCamera_currentCamera->cameraPerspective == 1 
        && !(sithPlayer_pLocalPlayerThing->thingflags & SITH_TF_DEAD) 
        && MOTS_ONLY_COND(!(sithPlayer_pLocalPlayerThing->actorParams.typeflags & SITH_AF_SCOPEHUD))
#ifdef QOL_IMPROVEMENTS
        && jkHud_shouldCrosshairBeShownForWeapon(sithPlayer_pLocalPlayerThing)
#endif /* ifdef QOL_IMPROVEMENTS */
  )
    {
        uint32_t tmpInt;
#ifdef QOL_IMPROVEMENTS
        // Scale crosshair with vertical resolution, not horizontal.
        v20 = (double)Video_format.height * (0.0015625 / 3.0) * 4.0;
#else
        v20 = (double)Video_format.width * 0.0015625;
#endif // QOL_IMPROVEMENTS
        v21 = (int32_t)(v20 + v20 + Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].xMax - -0.5);
        v22 = v21;
        v23 = (int32_t)((double)(unsigned int)Video_format.height * 0.0020833334
                      + (double)(unsigned int)Video_format.height * 0.0020833334
                      + Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].yMax
                      - -0.5);
        if ( Video_format.format.bpp == 8 )
            tmpInt = 48;
        else
            tmpInt = stdColor_Indexed8ToRGB16(0x30u, (rdColor24 *)Video_aPalette, &Video_format.format);
        v24 = (int32_t)(v20 * 18.0 * jkPlayer_crosshairScale - -0.5);
        v25 = (int32_t)(v20 * 6.0 * jkPlayer_crosshairScale - -0.5);
        
        //rdPrimit2_DrawClippedLine(Video_pCanvas, v22 - v24, v23,       v22 - v25, v23,       tmpInt, -1);
        //rdPrimit2_DrawClippedLine(Video_pCanvas, v22 + v25, v23,       v22 + v24, v23,       tmpInt, -1);
        //rdPrimit2_DrawClippedLine(Video_pCanvas, v22,       v23 - v24, v22,       v23 - v25, tmpInt, -1);
        //rdPrimit2_DrawClippedLine(Video_pCanvas, v22,       v23 + v25, v22,       v23 + v24, tmpInt, -1);

        float line_len = v24 - v25 + 1;
        float line_width = jkPlayer_crosshairLineWidth;

        rdRect rect1 = {v22 - v24, v23-(line_width/2), line_len, line_width}; // left
        rdRect rect2 = {v22 + v25, v23-(line_width/2), line_len, line_width}; // right
        rdRect rect3 = {v22-(line_width/2), v23 - v24, line_width, line_len}; // up
        rdRect rect4 = {v22-(line_width/2), v23 + v25, line_width, line_len}; // down

        std3D_DrawUIClearedRect(tmpInt, &rect1);
        std3D_DrawUIClearedRect(tmpInt, &rect2);
        std3D_DrawUIClearedRect(tmpInt, &rect3);
        std3D_DrawUIClearedRect(tmpInt, &rect4);

        //rdRect rect1a = {(double)Video_format.width/2, (double)Video_format.height/2, 20, 20};
        //std3D_DrawUIClearedRect(tmpInt, &rect1a);
    }

    rdScreenPoint tmpScreenPt;
    if ( jkHud_bHasTarget && jkHud_pTargetThing && rdPrimit3_GetScreenCoord(&jkHud_pTargetThing->position, &tmpScreenPt) )
    {
        float valSin, valCos;
        a2 = sithTime_curSeconds * 200.0;
        if ( Video_format.format.is16bit )
        {
            stdMath_SinCos(a2, &valSin, &valCos);
            v58 = valSin * 20.0;
            rdPrimit2_DrawCircle(pOverlayCanvas, tmpScreenPt.x, tmpScreenPt.y, v58, 20.0, jkHud_targetRed16, -1);
            a2c = (sithTime_curSeconds - 0.1) * 200.0;
            stdMath_SinCos(a2c, &valSin, &valCos);
            v59 = valSin * 20.0;
            rdPrimit2_DrawCircle(pOverlayCanvas, tmpScreenPt.x, tmpScreenPt.y, v59, 20.0, jkHud_targetGreen16, -1);
            a2d = (sithTime_curSeconds - 0.2) * 200.0;
            stdMath_SinCos(a2d, &valSin, &valCos);
            v26 = jkHud_targetBlue16;
        }
        else
        {
            stdMath_SinCos(a2, &valSin, &valCos);
            v56 = valSin * 20.0;
            rdPrimit2_DrawCircle(pOverlayCanvas, tmpScreenPt.x, tmpScreenPt.y, v56, 20.0, jkHud_targetRed, -1);
            a2a = (sithTime_curSeconds - 0.1) * 200.0;
            stdMath_SinCos(a2a, &valSin, &valCos);
            v57 = valSin * 20.0;
            rdPrimit2_DrawCircle(pOverlayCanvas, tmpScreenPt.x, tmpScreenPt.y, v57, 20.0, jkHud_targetBlue, -1);
            a2b = (sithTime_curSeconds - 0.2) * 200.0;
            stdMath_SinCos(a2b, &valSin, &valCos);
            v26 = jkHud_targetGreen;
        }
        v60 = valSin * 20.0;
        rdPrimit2_DrawCircle(pOverlayCanvas, tmpScreenPt.x, tmpScreenPt.y, v60, 20.0, v26, -1);
    }

    
    if ( jkHud_bViewScores )
    {
        char tmpFname[16];
        for (v27 = 0; v27 < 5; v27++)
        {
            jkHud_aTeamScores[v27].field_0 = v27;
            jkHud_aTeamScores[v27].field_8 = 0;
            jkHud_aTeamScores[v27].field_C = 0;
        }
        v29 = 0;
        v30 = 0;
        jkHud_numPlayers = 0;
        if ( jkPlayer_maxPlayers )
        {
            playerInfoIter = &jkPlayer_playerInfos[0];
            do
            {
                v32 = playerInfoIter;
                if ((playerInfoIter->flags & 1) != 0)
                {
                    stdString_SafeWStrCopy(jkHud_aPlayerScores[v29].playerName, playerInfoIter->player_name, 0x20);
                    v33 = v32->playerThing->rdthing.model3->filename;
                    stdFnames_CopyShortName(tmpFname, 16, v33);
                    jkGuiTitle_sub_4189A0(tmpFname);
                    // MOTS altered here "_SHORT" TODO
                    /*
                            _sprintf(local_11c,"%s_SHORT",&local_14c);
                            pwVar7 = jkStrings_GetUniString(local_11c);
                            if (pwVar7 == (wchar_t *)0x0) {
                                pwVar7 = jkStrings_GetUniStringWithFallback((char *)&local_14c);
                            }
                    */
                    v34 = jkStrings_GetUniStringWithFallback(tmpFname);
                    stdString_SafeWStrCopy(jkHud_aPlayerScores[jkHud_numPlayers].modelName, v34, 0x20);
                    v35 = jkHud_numPlayers;
                    v36 = v32->score;
                    jkHud_aPlayerScores[jkHud_numPlayers].score = v36;
                    jkHud_aPlayerScores[jkHud_numPlayers].teamNum = playerInfoIter->teamNum;
                    jkHud_aTeamScores[playerInfoIter->teamNum].field_8 = 1;
                    jkHud_aTeamScores[playerInfoIter->teamNum].field_C++;
                    v29 = v35 + 1;
                    jkHud_numPlayers = v29;
                }
                ++v30;
                ++playerInfoIter;
            }
            while ( v30 < jkPlayer_maxPlayers );
        }
        _qsort(jkHud_aPlayerScores, v29, sizeof(jkHudPlayerScore), jkHud_SortPlayerScore);
        if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
        {
            v39 = &jkHud_aTeamScores[0];
            v40 = sithNet_teamScore;
            for (int i = 0; i < 5; i++)
            {
                v41 = *v40++;
                v39->score = v41;
                v39++;
            }
            _qsort(jkHud_aTeamScores, 5u, sizeof(jkHudTeamScore), jkHud_SortTeamScore);
        }
        if ( jkHud_bViewScores == 1 )
        {
            a4.width = HUD_SCALED(9);
            a4.x = jkHud_rectViewScores.x + HUD_SCALED(20);
            a4.height = HUD_SCALED((*jkHud_pMsgFontSft->bitmap->mipSurfaces)->format.height - 2);
            v49 = jkStrings_GetUniStringWithFallback("HUD_TEAMSCORESTITLE");
            stdFont_Draw4GPU(
                jkHud_pMsgFontSft,
                jkHud_rectViewScores.x,
                HUD_SCALED(60),
                jkHud_rectViewScores.width,
                jkHud_rectViewScores.height,
                1,
                v49,
                1,
                jkPlayer_hudScale);
            v50 = jkStrings_GetUniStringWithFallback("HUD_TEAMNAME");
            stdFont_Draw4GPU(
                jkHud_pMsgFontSft,
                jkHud_rectViewScores.x + HUD_SCALED(40),
                HUD_SCALED(80),
                jkHud_rectViewScores.width,
                jkHud_rectViewScores.height,
                0,
                v50,
                1,
                jkPlayer_hudScale);
            v51 = jkStrings_GetUniStringWithFallback("HUD_TEAMPLAYERS");
            stdFont_Draw4GPU(
                jkHud_pMsgFontSft,
                jkHud_rectViewScores.x + HUD_SCALED(80),
                HUD_SCALED(80),
                jkHud_rectViewScores.width,
                jkHud_rectViewScores.height,
                0,
                v51,
                1,
                jkPlayer_hudScale);
            v52 = jkStrings_GetUniStringWithFallback("HUD_TEAMSCORE");
            stdFont_Draw4GPU(
                jkHud_pMsgFontSft,
                jkHud_rectViewScores.x + HUD_SCALED(140),
                HUD_SCALED(80),
                jkHud_rectViewScores.width,
                jkHud_rectViewScores.height,
                0,
                v52,
                1,
                jkPlayer_hudScale);
            v53 = HUD_SCALED(100);
            v54 = jkHud_aTeamScores;
            for (int i = 0; i < 5; i++)
            {
                if ( v54->field_8 )
                {
                    a4.y = v53 + 1;
                    /*if ( Video_format.format.is16bit )
                        stdDisplay_VBufferFill(Video_pMenuBuffer, jkHud_aTeamColors16bpp[v54->field_0], &a4);
                    else
                        stdDisplay_VBufferFill(Video_pMenuBuffer, jkHud_aTeamColors8bpp[v54->field_0], &a4);*/
                    std3D_DrawUIClearedRect(jkHud_aTeamColors8bpp[v54->field_0], &a4);
                    switch ( v54->field_0 )
                    {
                        case 1:
                            v55 = jkStrings_GetUniStringWithFallback("GUI_RED");
                            goto LABEL_115;
                        case 2:
                            v55 = jkStrings_GetUniStringWithFallback("GUI_GOLD");
                            goto LABEL_115;
                        case 3:
                            v66 = jkStrings_GetUniStringWithFallback("GUI_BLUE");
                            stdFont_Draw1GPU(jkHud_pMsgFontSft, jkHud_rectViewScores.x + HUD_SCALED(40), v53, jkHud_rectViewScores.width, v66, 1, jkPlayer_hudScale);
                            goto LABEL_116;
                        case 4:
                            v55 = jkStrings_GetUniStringWithFallback("GUI_GREEN");
                            goto LABEL_115;
                        default:
                            v55 = jkStrings_GetUniStringWithFallback("GUI_NONE");
LABEL_115:
                            stdFont_Draw1GPU(jkHud_pMsgFontSft, jkHud_rectViewScores.x + HUD_SCALED(40), v53, jkHud_rectViewScores.width, v55, 1, jkPlayer_hudScale);
LABEL_116:
                            jk_snwprintf(a6, 0x80u, L"%4d", v54->field_C);
                            stdFont_Draw1GPU(jkHud_pMsgFontSft, jkHud_rectViewScores.x + HUD_SCALED(90), v53, jkHud_rectViewScores.width, a6, 1, jkPlayer_hudScale);
                            jk_snwprintf(a6, 0x80u, L"%4d", v54->score);
                            stdFont_Draw1GPU(jkHud_pMsgFontSft, jkHud_rectViewScores.x + HUD_SCALED(150), v53, jkHud_rectViewScores.width, a6, 1, jkPlayer_hudScale);
                            v53 += HUD_SCALED((*jkHud_pMsgFontSft->bitmap->mipSurfaces)->format.height + jkHud_pMsgFontSft->marginY);
                            break;
                    }
                }
                ++v54;
            }
            jkHud_idk16 = 1;
        }
        else if ( jkHud_bViewScores == 2 )
        {
            a4.x = jkHud_rectViewScores.x;
            a4.width = HUD_SCALED(9);
            a4.height = HUD_SCALED((*jkHud_pMsgFontSft->bitmap->mipSurfaces)->format.height - 2);
            v42 = jkStrings_GetUniStringWithFallback("HUD_PLAYERSCORES");
            stdFont_Draw4GPU(
                jkHud_pMsgFontSft,
                jkHud_rectViewScores.x,
                HUD_SCALED(60),
                jkHud_rectViewScores.width,
                jkHud_rectViewScores.height,
                1,
                v42,
                1,
                jkPlayer_hudScale);
            v43 = jkHud_dword_553ED0;
            v44 = HUD_SCALED(80);
            v45 = jkHud_dword_553ED0;
            if ( jkHud_dword_553ED0 < jkHud_numPlayers )
            {
                v46 = &jkHud_aPlayerScores[jkHud_dword_553ED0];
                while ( v45 < v43 + 8 )
                {
                    a4.y = v44 + 1;
                    if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
                    {
                        v47 = v46->teamNum;
                        if ( v46->teamNum )
                        {
                            if ( Video_format.format.is16bit )
                                v48 = jkHud_aTeamColors16bpp[v47];
                            else
                                v48 = jkHud_aTeamColors8bpp[v47];
                            //stdDisplay_VBufferFill(Video_pMenuBuffer, v48, &a4);
                            std3D_DrawUIClearedRect(v48, &a4);
                        }
                    }
                    jk_snwprintf(a6, 0x11u, L"%.16ls", v46);
                    stdFont_Draw1GPU(jkHud_pMsgFontSft, jkHud_rectViewScores.x + HUD_SCALED(10), v44, jkHud_rectViewScores.width, a6, 1, jkPlayer_hudScale);
                    jk_snwprintf(a6, 0x80u, L"(%.8ls)", v46->modelName);
                    stdFont_Draw1GPU(jkHud_pMsgFontSft, jkHud_rectViewScores.x + HUD_SCALED(130), v44, jkHud_rectViewScores.width, a6, 1, jkPlayer_hudScale);
                    jk_snwprintf(a6, 0x80u, L"%4d", v46->score);
                    stdFont_Draw1GPU(jkHud_pMsgFontSft, jkHud_rectViewScores.x + HUD_SCALED(190), v44, jkHud_rectViewScores.width, a6, 1, jkPlayer_hudScale);
                    ++v46;
                    v44 += HUD_SCALED((*jkHud_pMsgFontSft->bitmap->mipSurfaces)->format.height + jkHud_pMsgFontSft->marginY);
                    if ( ++v45 >= jkHud_numPlayers )
                        break;
                    v43 = jkHud_dword_553ED0;
                }
            }
            jkHud_idk16 = 2;
        }
    }
    else
    {
        jkHud_idk16 = 0;
    }

#ifdef DEBUG_QOL_CHEATS
    int fps = (int)sithTime_TickHz;
    if (fps > 999)
        fps = 999;
    if (fps < 0)
        fps = 0;
    memset(tmp, 0, 32);
    stdString_snprintf(tmp, 32, "%03d", fps);
    stdFont_DrawAsciiGPU(jkHud_pMsgFontSft, jkHud_leftBlitX, jkHud_leftBlitY, 999, tmp, 1, jkPlayer_hudScale);
#endif

#ifdef SDL2_RENDER
    stdDisplay_VBufferUnlock(Video_pCanvasOverlayMap->vbuffer);
    stdDisplay_VBufferUnlock(Video_pCanvas->vbuffer);
#endif
}

int jkHud_GetWeaponAmmo(sithThing *player)
{
    if (Main_bMotsCompat) {
        int binIdxWeap;
        int binIdx;
        sithItemInfo *pItemInfo;
        int weaponToAmmo [21];
        
        weaponToAmmo[5] = SITHBIN_CARBPELLETS;
        weaponToAmmo[20] = SITHBIN_CARBPELLETS;
        weaponToAmmo[2] = SITHBIN_ENERGY;
        weaponToAmmo[3] = SITHBIN_ENERGY;
        weaponToAmmo[12] = SITHBIN_ENERGY;
        weaponToAmmo[13] = SITHBIN_ENERGY;
        weaponToAmmo[6] = SITHBIN_POWER;
        weaponToAmmo[9] = SITHBIN_POWER;
        weaponToAmmo[15] = SITHBIN_POWER;
        weaponToAmmo[0] = -1;
        weaponToAmmo[1] = -1;
        weaponToAmmo[4] = SITHBIN_MOTS_THERMAL_DETONATOR;
        weaponToAmmo[7] = SITHBIN_RAILCHARGES;
        weaponToAmmo[8] = SITHBIN_MOTS_SEQUENCER_CHARGE;
        weaponToAmmo[10] = SITHBIN_EWEB_ROUNDS;
        weaponToAmmo[11] = -1;
        weaponToAmmo[14] = SITHBIN_MOTS_FLASH_BOMB;
        weaponToAmmo[16] = -1;
        weaponToAmmo[17] = SITHBIN_SEEKRAILS;
        weaponToAmmo[18] = SITHBIN_MOTS_SEQUENCER_CHARGE;
        weaponToAmmo[19] = -1;

        binIdxWeap = sithInventory_SelectWeaponPrior(player->actorParams.playerinfo->curWeapon);
        if (binIdxWeap < 0) {
            return -999;
        }
        binIdx = weaponToAmmo[binIdxWeap];
        if (binIdx < 0xb) {
            binIdx = sithInventory_SelectWeaponFollowing(binIdx);
        }
        if (binIdx == -1) {
            return -999;
        }
        pItemInfo = sithInventory_GetBin(player,binIdx);
        if (!pItemInfo) {
            return -999;
        }
        binIdxWeap = (int)pItemInfo->ammoAmt;
        if (binIdxWeap < 0) {
            binIdxWeap = 0;
        }
        return binIdxWeap;
    }
    else {
        sithPlayerInfo *v1; // eax
        int v2; // eax
        BOOL v3; // ecx
        int v4; // eax
        int binidx; // eax
        sithItemInfo *v6; // eax
        int weaponToAmmo[11]; // [esp+4h] [ebp-2Ch]

        weaponToAmmo[2] = SITHBIN_ENERGY;
        weaponToAmmo[3] = SITHBIN_ENERGY;
        weaponToAmmo[5] = SITHBIN_POWER;
        weaponToAmmo[6] = SITHBIN_POWER;
        weaponToAmmo[9] = SITHBIN_POWER;
        v1 = player->actorParams.playerinfo;
        weaponToAmmo[4] = SITHBIN_THERMAL_DETONATOR;
        v2 = v1->curWeapon;
        weaponToAmmo[0] = -1;
        weaponToAmmo[1] = -1;
        weaponToAmmo[7] = SITHBIN_RAILCHARGES;
        weaponToAmmo[8] = SITHBIN_SEQUENCER_CHARGE;
        weaponToAmmo[10] = -1;
        if ( v2 < 0 )
            return -999;
        if (v2 > 10)
            return -999;
        binidx = weaponToAmmo[v2];
        if ( binidx == -1 )
            return -999;
        v6 = sithInventory_GetBin(player, binidx);
        if ( !v6 )
            return -999;
        v4 = (int32_t)v6->ammoAmt;
        if ( v4 < 0 )
            v4 = 0;
        return v4;
    }
}

int jkHud_Chat()
{
    size_t v0; // eax
    wchar_t *v2; // [esp-8h] [ebp-108h]
    wchar_t *v3; // [esp-8h] [ebp-108h]
    wchar_t tmp[256]; // [esp+0h] [ebp-100h] BYREF

    jkHud_bChatOpen = 1;
    jkHud_chatStr[0] = 0;
    jkHud_chatStrPos = 0;
    jkHud_dword_552D10 = (sithNet_isMulti != 0) - 2;
    stdControl_bDisableKeyboard = 1;
    if ( sithNet_isMulti )
    {
        if ( sithNet_isMulti != 0 )
        {
            v2 = jkStrings_GetUniStringWithFallback("HUD_SENDTOALL");
            stdString_SafeWStrCopy(tmp, v2, 0x80u);
        }
    }
    else
    {
        v3 = jkStrings_GetUniStringWithFallback("HUD_COMMAND");
        stdString_SafeWStrCopy(tmp, v3, 0x80u);
    }
    v0 = _wcslen(tmp);
    stdString_CharToWchar(&tmp[v0], jkHud_chatStr, 127 - v0);
    tmp[127] = 0;
    return jkDev_sub_41FB80(103, tmp);
}

// MOTS altered
void jkHud_SendChat(char a1)
{
    int v1; // eax
    size_t v2; // eax
    wchar_t *v3; // [esp-8h] [ebp-10Ch]
    wchar_t *v4; // [esp-8h] [ebp-10Ch]
    wchar_t tmp[256]; // [esp+4h] [ebp-100h] BYREF

    if ( a1 == VK_RETURN )
    {
        if ( jkHud_chatStrPos )
        {
            if ( jkHud_dword_552D10 == -1 && sithNet_isMulti )
            {
                _sprintf(std_genBuffer, "You say, '%s'", jkHud_chatStr);
                jkDev_DebugLog(std_genBuffer);
                sithMulti_SendChat(jkHud_chatStr, -1, playerThingIdx);
            }
            else if ( !jkDev_TryCommand(jkHud_chatStr) )
            {
                sithConsole_TryCommand(jkHud_chatStr);
            }
        }
        jkHud_chatStrPos = 0;
        jkHud_bChatOpen = 0;
        jkDev_sub_41FC90(103);
        stdControl_Flush();
        stdControl_bDisableKeyboard = 0;
    }
    else
    {
        if ( a1 == VK_BACK )
        {
            if ( jkHud_chatStrPos )
                jkHud_chatStr[--jkHud_chatStrPos] = 0;
        }
        else if ( a1 == VK_TAB )
        {
            if ( sithNet_isMulti )
                jkHud_dword_552D10 = (jkHud_dword_552D10 == -2) - 2;
        }
        else
        {
            v1 = jkHud_chatStrPos;
            if ( (unsigned int)jkHud_chatStrPos < 0x7F )
            {
                jkHud_chatStr[jkHud_chatStrPos] = a1;
                jkHud_chatStr[v1 + 1] = 0;
                jkHud_chatStrPos = v1 + 1;
            }
        }
        if ( jkHud_dword_552D10 == -2 )
        {
            v4 = jkStrings_GetUniStringWithFallback("HUD_COMMAND");
            stdString_SafeWStrCopy(tmp, v4, 0x80u);
        }
        else if ( jkHud_dword_552D10 == -1 )
        {
            v3 = jkStrings_GetUniStringWithFallback("HUD_SENDTOALL");
            stdString_SafeWStrCopy(tmp, v3, 0x80u);
        }
        v2 = _wcslen(tmp);
        stdString_CharToWchar(&tmp[v2], jkHud_chatStr, 127 - v2);
        tmp[127] = 0;
        jkDev_sub_41FB80(103, tmp);
    }
}

void jkHud_SetTargetColors(int *color_idxs)
{
    jkHud_targetRed = color_idxs[0];
    jkHud_targetBlue = color_idxs[1];
    jkHud_targetGreen = color_idxs[2];
    jkHud_targetRed16 = stdColor_Indexed8ToRGB16(color_idxs[0] & 0xFF, (rdColor24 *)Video_aPalette, &Video_format.format);
    jkHud_targetGreen16 = stdColor_Indexed8ToRGB16(color_idxs[1] & 0xFF, (rdColor24 *)Video_aPalette, &Video_format.format);
    jkHud_targetBlue16 = stdColor_Indexed8ToRGB16(color_idxs[2] & 0xFF, (rdColor24 *)Video_aPalette, &Video_format.format);
}

void jkHud_SetTarget(sithThing *target)
{
    jkHud_pTargetThing = target;
    if ( target )
        jkHud_bHasTarget = 1;
}

void jkHud_EndTarget()
{
    jkHud_bHasTarget = 0;
    jkHud_pTargetThing = NULL;
}

int jkHud_SortPlayerScore(const void* a, const void* b)
{
    const jkHudPlayerScore *a1 = (const jkHudPlayerScore *)a;
    const jkHudPlayerScore *a2 = (const jkHudPlayerScore *)b;
    return a2->score - a1->score;
}

int jkHud_SortTeamScore(const void* a, const void* b)
{
    const jkHudTeamScore *a1 = (const jkHudTeamScore *)a;
    const jkHudTeamScore *a2 = (const jkHudTeamScore *)b;
    return a2->score - a1->score;
}

void jkHud_Tally()
{
    if ( !sithNet_isMulti )
        return;
    switch ( jkHud_bViewScores )
    {
        case 0:
            if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
            {
                jkHud_bViewScores = 1;
                return;
            }
            goto LABEL_9;
        case 1:
LABEL_9:
            jkHud_bViewScores = 2;
            jkHud_dword_553ED0 = 0;
            jkHud_numPlayers = 0;
            return;
        case 2:
            jkHud_dword_553ED0 += 8;
            if ( jkHud_dword_553ED0 > jkHud_numPlayers )
            {
                jkHud_bViewScores = 0;
                jkHud_tallyWhich = 2;
            }
            break;
    }
}

void jkHud_idk_time()
{
    jkHud_chatStrPos = 0;
    jkHud_bChatOpen = 0;
    jkDev_sub_41FC90(103);
    stdControl_Flush();
    stdControl_bDisableKeyboard = 0;
}

int jkHud_chat2()
{
    size_t v0; // eax
    wchar_t *v2; // [esp-8h] [ebp-108h]
    wchar_t *v3; // [esp-8h] [ebp-108h]
    wchar_t a1[128]; // [esp+0h] [ebp-100h] BYREF

    if ( jkHud_dword_552D10 == -2 )
    {
        v3 = jkStrings_GetUniStringWithFallback("HUD_COMMAND");
        _wcsncpy(a1, v3, 0x80u);
    }
    else if ( jkHud_dword_552D10 == -1 )
    {
        v2 = jkStrings_GetUniStringWithFallback("HUD_SENDTOALL");
        _wcsncpy(a1, v2, 0x80u);
    }
    v0 = _wcslen(a1);
    stdString_CharToWchar(&a1[v0], jkHud_chatStr, 127 - v0);
    a1[127] = 0;
    return jkDev_sub_41FB80(103, a1);
}

#ifdef QOL_IMPROVEMENTS
BOOL jkHud_shouldCrosshairBeShownForWeapon(sithThing *player) {
  int currentWeapon = sithInventory_GetCurWeapon(player);
  if(currentWeapon == SITHBIN_FISTS) {
    return jkPlayer_setCrosshairOnFist;
  }

  if(currentWeapon == SITHBIN_LIGHTSABER){
    return jkPlayer_setCrosshairOnLightsaber;
  }

  return 1;
}
#endif /* ifdef QOL_IMPROVEMENTS */
