#include "jkHudScope.h"

#include "Win95/Windows.h"
#include "Win95/stdDisplay.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdString.h"
#include "stdPlatform.h"
#include "Cog/sithCog.h"
#include "Main/Main.h"
#include "Platform/std3D.h"
#include "jk.h"

static int jkHudScope_bInitted = 0;
static int jkHudScope_bOpened = 0;
static int jkHudScope_w_005b08e0 = 0;
static int jkHudScope_h_005b08e4 = 0;

static stdBitmap* jkHudScope_pBitmap1 = NULL;
static stdFont* jkHudScope_pFont1 = NULL;

static jkHudMotsBitmap jkHudScope_aBitmaps[1] = {
    {&jkHudScope_pBitmap1, "00SiteA8.bm", "00SiteA16.bm", 0x43, 320, 240, 0x0, 0x0},
};

static jkHudMotsFont jkHudScope_aFonts[1] = {
    {&jkHudScope_pFont1, "AmoNums.sft", "AmoNums.sft"},
};

void jkHudScope_Startup(void)
{
    jkHudScope_bInitted = 1;
}

void jkHudScope_Shutdown(void)
{
    jkHudScope_bInitted = 0;
}


int jkHudScope_Open(void)
{
#ifdef TARGET_TWL
    return 1;
#endif
    int iVar1;
    int iVar2;
    stdBitmap *psVar3;
    int lVar7;
    int lVar8;
    char *pcVar9;
    char *pcVar10;
    char local_80 [128];
    
    iVar1 = Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].xMin;
    iVar2 = Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].yMin;
    lVar7 = (int)(Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].xMax - (flex_t)(iVar1 / 2));
    lVar8 = (int)(Video_modeStruct.aViewSizes[Video_modeStruct.viewSizeIdx].yMax - (flex_t)(iVar2 / 2));
#ifdef SDL2_RENDER
    iVar1 = Video_format.width;
    iVar2 = Video_format.height;
    lVar7 = 0;
    lVar8 = 0;
#endif
    jkHudScope_w_005b08e0 = (iVar1 * 1000 + 320) / 640;
    jkHudScope_h_005b08e4 = (iVar2 * 1000 + 240) / 480;

    if (jkHudScope_bOpened != 0) {
        return 0;
    }

    jkHudMotsBitmap* pBmIter = jkHudScope_aBitmaps;

    do 
    {
#ifndef SDL2_RENDER
        if (Video_format.format.bpp == 8) {
            pcVar10 = pBmIter->path8bpp;
            pcVar9 = "ui\\bm\\%s";
        }
        else 
#endif
        {
            pcVar10 = pBmIter->path16bpp;
            pcVar9 = "ui\\bm\\%s";
        }
        _sprintf(local_80,pcVar9,pcVar10);
        psVar3 = stdBitmap_Load2(local_80,0,0);
        *pBmIter->pBitmap = psVar3;
        pBmIter->unk4 = (int)(((flex_t)pBmIter->unk2 * iVar1) / 640.0) + lVar7;
        pBmIter->unk5 = (int)(((flex_t)pBmIter->unk3 * iVar2) / 480.0) + lVar8;
        switch(pBmIter->unk1) 
        {
            case 0x42:
                pBmIter->unk4 -= ((uint32_t)((*(*pBmIter->pBitmap)->mipSurfaces)->format).width >> 1);
                pBmIter->unk5 -= ((*(*pBmIter->pBitmap)->mipSurfaces)->format).height;
                break;
            case 0x43:
                pBmIter->unk4 -= ((uint32_t)((*(*pBmIter->pBitmap)->mipSurfaces)->format).width >> 1);
                pBmIter->unk5 -= ((uint32_t)((*(*pBmIter->pBitmap)->mipSurfaces)->format).height >> 1);
                break;
            case 0x4c:
                pBmIter->unk5 -= ((uint32_t)((*(*pBmIter->pBitmap)->mipSurfaces)->format).height >> 1);
                break;
            case 0x52:
                pBmIter->unk4 -= ((*(*pBmIter->pBitmap)->mipSurfaces)->format).width;
                pBmIter->unk5 -= (uint32_t)((*(*pBmIter->pBitmap)->mipSurfaces)->format).height >> 1;
                break;
            case 0x54:
                pBmIter->unk4 -= ((uint32_t)((*(*pBmIter->pBitmap)->mipSurfaces)->format).width >> 1);
                break;
            default:
                break;
        }
        if (*pBmIter->pBitmap == (stdBitmap *)0x0) {
            Windows_GameErrorMsgbox("ERR_CANNOT_LOAD_FILE %s",local_80);
        }
        else {
            stdBitmap_ConvertColorFormat(&Video_format.format,*pBmIter->pBitmap);
        }

        pBmIter++;
        
        if (pBmIter >= &jkHudScope_aBitmaps[1]) {
            break;
        }
    } while( 1 );

    jkHudScope_bOpened = 1;
    return 1;
}


void jkHudScope_Close(void)
{
#ifdef TARGET_TWL
    return;
#endif
    jkHudMotsBitmap *pjVar1;
    jkHudMotsFont *pjVar2;
    
    pjVar1 = jkHudScope_aBitmaps;
    do {
        if (*pjVar1->pBitmap) {
            stdBitmap_Free(*pjVar1->pBitmap);
            *pjVar1->pBitmap = NULL;
        }
        pjVar1 = pjVar1 + 1;
    } while (pjVar1 < &jkHudScope_aBitmaps[1]);

    pjVar2 = jkHudScope_aFonts;
    do {
        if (*pjVar2->pFont) {
            stdFont_Free(*pjVar2->pFont);
            *pjVar2->pFont = NULL;
        }
        pjVar2 = pjVar2 + 1;
    } while (pjVar2 < &jkHudScope_aFonts[1]);

    if (jkHudScope_bOpened != 0) {
        jkHudScope_bOpened = 0;
    }
}


void jkHudScope_Draw(void)
{
#ifdef TARGET_TWL
    return;
#endif

    if (!jkHudScope_bOpened) return;
    if (sithWorld_pCurrentWorld->playerThing->type != SITH_THING_PLAYER) return;

    jkHudMotsBitmap* pBmIter = jkHudScope_aBitmaps;

#ifndef SDL2_RENDER
    stdVBuffer* pOverlayBuffer = Video_pMenuBuffer;
    rdCanvas* pOverlayCanvas = Video_pCanvas;
#else
    stdVBuffer* pOverlayBuffer = Video_pCanvasOverlayMap->vbuffer;
    rdCanvas* pOverlayCanvas = Video_pCanvasOverlayMap;
    stdDisplay_VBufferLock(pOverlayBuffer);
#endif

    do 
    {
#ifndef SDL2_RENDER
        stdDisplay_VBufferCopy(pOverlayBuffer, *(*pBmIter->pBitmap)->mipSurfaces, pBmIter->unk4, pBmIter->unk5, NULL, 1);
#else
        std3D_DrawUIBitmap(*pBmIter->pBitmap, 0, pBmIter->unk4, pBmIter->unk5, NULL, 1.0, 1);
#endif
        pBmIter++;
    } while (pBmIter < &jkHudScope_aBitmaps[1]);

#ifdef SDL2_RENDER
    stdDisplay_VBufferUnlock(pOverlayBuffer);
#endif
}

