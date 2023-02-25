#include "jkGUIMap.h"

#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUISetup.h"
#include "World/jkPlayer.h"
#include "World/sithMap.h"
#include "Win95/Window.h"
#include "Win95/stdDisplay.h"
#include "Platform/stdControl.h"
#include "Engine/rdroid.h"

static int jkGuiMap_idk2[12] = { 24, 25, 26, 18, 10, 19, 27, 28, 20, 21, 22, 0 };
static int jkGuiMap_idk[5] = {0, 0x38, 1, 0x37, 0x18};

static jkGuiElement jkGuiMap_aElements[16] =
{
    {ELEMENT_TEXT, 0, 8, NULL, 3, { 40, 360, 520, 20 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0}, 
    {ELEMENT_CUSTOM, 0, 0, NULL, 0, { 40, 40, 520, 320 }, 1, 0, NULL, jkGuiMap_DrawMapScreen, NULL, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 100, 0, NULL, 25, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B60, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 101, 0, NULL, 26, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B60, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 102, 0, NULL, 21, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B60, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 103, 0, NULL, 22, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B60, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 104, 0, NULL, 23, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B60, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 105, 0, NULL, 24, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B60, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 106, 0, NULL, 27, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B60, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 107, 0, NULL, 28, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B60, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 108, 0, NULL, 29, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B60, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 109, 0, NULL, 30, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B60, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 110, 0, NULL, 31, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B40, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 111, 0, NULL, 32, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, jkGuiMap_sub_415B70, NULL, {0}, 0}, 
    {ELEMENT_PICBUTTON, 1, 0, NULL, 20, { -1, -1, -1, -1 }, 1, 0, NULL, NULL, NULL, NULL, {0}, 0}, 
    {ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, {0}, 0},
};

static jkGuiMenu jkGuiMap_menu = { &jkGuiMap_aElements, 0, 0xFFFF, 0xFFFF, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, jkGuiMap_sub_415720, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL };

void jkGuiMap_Startup()
{
    jkGui_InitMenu(&jkGuiMap_menu, jkGui_stdBitmaps[JKGUI_BM_BK_FIELD_LOG]);
}

void jkGuiMap_Shutdown()
{
    ;
}

void jkGuiMap_DrawMapScreen(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw)
{
    if ( g_app_suspended )
    {
        rdCamera_SetCurrent(jkGuiMap_pCamera);
        stdControl_ShowCursor(1);
#ifdef SDL2_RENDER
        stdDisplay_VBufferLock(jkGuiMap_pVbuffer);
#endif
        stdDisplay_VBufferFill(jkGuiMap_pVbuffer, 0, 0);
        rdAdvanceFrame();
        sithMap_DrawCircle(jkGuiMap_pCamera, &jkGuiMap_matTmp);
#ifndef SDL2_RENDER
        rdFinishFrame();
#endif
        stdDisplay_VBufferCopy(vbuf, jkGuiMap_pVbuffer, 0x28u, 40, 0, 0);

#ifdef SDL2_RENDER
        stdDisplay_VBufferUnlock(jkGuiMap_pVbuffer);
#endif

        stdControl_ShowCursor(0);
#ifdef SDL2_RENDER
        // rdFinishFrame calls stdDisplay_ddraw_waitforvblank which causes flickering on SDL2
        rdCache_Flush();
        rdCache_FinishFrame();
        //stdDisplay_ddraw_waitforvblank();
        rdCache_ClearFrameCounters();
        //rdActive_ClearFrameCounters();
        rdModel3_ClearFrameCounters();
#endif
    }
}

void jkGuiMap_sub_415720(jkGuiMenu *menu)
{
    unsigned int v1; // edi
    jkGuiElement *v2; // eax
    int v3; // eax
    int v4; // eax
    double v5; // st7
    sithThing *v6; // ecx
    rdVector3 a2; // [esp+8h] [ebp-18h] BYREF
    rdVector3 v8; // [esp+14h] [ebp-Ch] BYREF

    v1 = stdPlatform_GetTimeMsec();
    v2 = menu->lastMouseDownClickable;
    if ( v2 )
    {
        if ( v1 > jkGuiMap_dword_55666C )
        {
            v3 = v2->hoverId;
            switch ( v3 )
            {
                case 100:
                case 101:
                    v4 = v3 - 100;
                    if ( v4 )
                    {
                        if ( v4 == 1 && -jkGuiMap_viewMat.scale.y < 10.0 )
                        {
                            a2.x = 0.0;
                            a2.y = -0.1;
                            a2.z = 0.0;
                            rdMatrix_PostTranslate34(&jkGuiMap_viewMat, &a2);
                        }
                    }
                    else if ( -jkGuiMap_viewMat.scale.y > 0.3 )
                    {
                        a2.x = 0.0;
                        a2.y = 0.1;
                        a2.z = 0.0;
LABEL_24:
                        rdMatrix_PostTranslate34(&jkGuiMap_viewMat, &a2);
                    }
                    goto LABEL_25;
                case 102:
                case 103:
                case 104:
                case 105:
                    switch ( v3 )
                    {
                        case 102:
                            jkGuiMap_vec3Idk2.y = jkGuiMap_vec3Idk2.y - -5.0;
                            break;
                        case 103:
                            jkGuiMap_vec3Idk2.y = jkGuiMap_vec3Idk2.y - 5.0;
                            break;
                        case 104:
                            if ( jkGuiMap_vec3Idk2.x > -90.0 )
                            {
                                v5 = jkGuiMap_vec3Idk2.x - 5.0;
                                goto LABEL_17;
                            }
                            break;
                        case 105:
                            if ( jkGuiMap_vec3Idk2.x < 90.0 )
                            {
                                v5 = jkGuiMap_vec3Idk2.x - -5.0;
LABEL_17:
                                jkGuiMap_vec3Idk2.x = v5;
                            }
                            break;
                        default:
                            break;
                    }
                    a2.x = -sithWorld_pCurrentWorld->playerThing->position.x;
                    a2.y = -sithWorld_pCurrentWorld->playerThing->position.y;
                    a2.z = -sithWorld_pCurrentWorld->playerThing->position.z;
                    rdMatrix_BuildTranslate34(&jkGuiMap_matTmp, &a2);
                    rdMatrix_PostRotate34(&jkGuiMap_matTmp, &jkGuiMap_vec3Idk);
                    rdMatrix_PostRotate34(&jkGuiMap_matTmp, &jkGuiMap_vec3Idk2);
                    rdMatrix_Normalize34(&jkGuiMap_matTmp);
                    goto LABEL_26;
                case 106:
                case 107:
                case 108:
                case 109:
                    switch ( v3 )
                    {
                        case 106:
                            a2.x = 0.1;
                            a2.y = 0.0;
                            a2.z = 0.0;
                            goto LABEL_24;
                        case 107:
                            a2.x = -0.1;
                            a2.y = 0.0;
                            a2.z = 0.0;
                            rdMatrix_PostTranslate34(&jkGuiMap_viewMat, &a2);
                            break;
                        case 108:
                            a2.x = 0.0;
                            a2.y = 0.0;
                            a2.z = -0.1;
                            rdMatrix_PostTranslate34(&jkGuiMap_viewMat, &a2);
                            break;
                        case 109:
                            a2.x = 0.0;
                            a2.y = 0.0;
                            a2.z = 0.1;
                            goto LABEL_24;
                        default:
                            break;
                    }
LABEL_25:
                    rdCamera_SetCurrent(jkGuiMap_pCamera);
                    rdCamera_Update(&jkGuiMap_viewMat);
LABEL_26:
                    jkGuiRend_UpdateAndDrawClickable(&jkGuiMap_aElements[1], menu, 1);
                    break;
                default:
                    break;
            }
            jkGuiMap_dword_55666C = v1 + 50;
        }
    }
    else if ( v1 > jkGuiMap_dword_556668 && jkGuiMap_dword_556664 )
    {
        v6 = sithWorld_pCurrentWorld->playerThing;
        jkGuiMap_vec3Idk.x = 0.0 + jkGuiMap_vec3Idk.x;
        jkGuiMap_vec3Idk.y = 0.5 + jkGuiMap_vec3Idk.y;
        jkGuiMap_vec3Idk.z = 0.0 + jkGuiMap_vec3Idk.z;
        v8.x = -v6->position.x;
        v8.y = -sithWorld_pCurrentWorld->playerThing->position.y;
        v8.z = -sithWorld_pCurrentWorld->playerThing->position.z;
        rdMatrix_BuildTranslate34(&jkGuiMap_matTmp, &v8);
        rdMatrix_PostRotate34(&jkGuiMap_matTmp, &jkGuiMap_vec3Idk);
        rdMatrix_PostRotate34(&jkGuiMap_matTmp, &jkGuiMap_vec3Idk2);
        rdMatrix_Normalize34(&jkGuiMap_matTmp);
        jkGuiRend_UpdateAndDrawClickable(&jkGuiMap_aElements[1], menu, 1);
        jkGuiMap_dword_556668 = v1 + 50;
    }
}

int jkGuiMap_sub_415B40(jkGuiElement* pElement, jkGuiMenu *menu, int mouseX, int mouseY, int bRedraw)
{
    jkGuiMap_dword_556664 = jkGuiMap_dword_556664 == 0;
    return 0;
}

int jkGuiMap_sub_415B60(jkGuiElement* pElement, jkGuiMenu *menu, int mouseX, int mouseY, int bRedraw)
{
    return 0;
}

int jkGuiMap_sub_415B70(jkGuiElement* pElement, jkGuiMenu *menu, int mouseX, int mouseY, int bRedraw)
{
    rdVector3 a2a; // [esp+0h] [ebp-Ch] BYREF

    a2a.x = 0.0;
    a2a.y = -2.0;
    a2a.z = 0.3;
    rdMatrix_BuildTranslate34(&jkGuiMap_viewMat, &a2a);
    a2a.x = -sithWorld_pCurrentWorld->playerThing->position.x;
    a2a.y = -sithWorld_pCurrentWorld->playerThing->position.y;
    a2a.z = -sithWorld_pCurrentWorld->playerThing->position.z;
    rdMatrix_BuildTranslate34(&jkGuiMap_matTmp, &a2a);
    rdCamera_SetCurrent(jkGuiMap_pCamera);
    rdCamera_Update(&jkGuiMap_viewMat);
    jkGuiMap_vec3Idk2.x = 0.0;
    jkGuiMap_vec3Idk.x = 0.0;
    jkGuiMap_vec3Idk2.y = 0.0;
    jkGuiMap_vec3Idk.y = 0.0;
    jkGuiMap_vec3Idk2.z = 0.0;
    jkGuiMap_vec3Idk.z = 0.0;
    jkGuiRend_UpdateAndDrawClickable(&jkGuiMap_aElements[1], menu, 1);
    return 0;
}

int jkGuiMap_Show()
{
    int v0; // esi
    int result; // eax
    rdVector3 a2; // [esp+4h] [ebp-58h] BYREF
    stdVBufferTexFmt v3; // [esp+10h] [ebp-4Ch] BYREF

    v3.width = 520;
    v3.height = 320;
    v3.format.bpp = 8;
    v3.format.is16bit = 0;
    jkGuiMap_pVbuffer = stdDisplay_VBufferNew(&v3, 0, 0, 0);
    stdDisplay_VBufferFill(jkGuiMap_pVbuffer, 0, 0);
    if ( rdOpen(0) )
    {
        jkGuiMap_pCanvas = rdCanvas_New(1, jkGuiMap_pVbuffer, 0, 0, 0, 519, 319, 6);
        jkGuiMap_pCamera = rdCamera_New(90.0, 1.0, 0.2, 10.0, 1.0);
        rdCamera_SetCanvas(jkGuiMap_pCamera, jkGuiMap_pCanvas);
        jkGuiMap_unk4.anonymous_1 = jkGuiMap_idk2;
        jkGuiMap_unk4.playerColor = 255;
        jkGuiMap_unk4.actorColor = 1;
        jkGuiMap_unk4.itemColor = 251;
        jkGuiMap_unk4.weaponColor = 208;
        jkGuiMap_unk4.otherColor = 44;
        jkGuiMap_unk4.numArr = 11;
        jkGuiMap_unk4.unkArr = sithMap_unkArr;
        _memcpy(jkGuiMap_unk4.teamColors, jkGuiMap_idk, sizeof(jkGuiMap_unk4.teamColors));
        sithMap_Startup(&jkGuiMap_unk4);
        a2.x = 0.0;
        a2.y = -2.0;
        a2.z = 0.3;
        rdMatrix_BuildTranslate34(&jkGuiMap_viewMat, &a2);
        a2.x = -sithWorld_pCurrentWorld->playerThing->position.x;
        a2.y = -sithWorld_pCurrentWorld->playerThing->position.y;
        a2.z = -sithWorld_pCurrentWorld->playerThing->position.z;
        rdMatrix_BuildTranslate34(&jkGuiMap_matTmp, &a2);
        jkGuiMap_vec3Idk2.x = 0.0;
        jkGuiMap_vec3Idk.x = 0.0;
        jkGuiMap_vec3Idk2.y = 0.0;
        jkGuiMap_vec3Idk.y = 0.0;
        jkGuiMap_vec3Idk2.z = 0.0;
        jkGuiMap_vec3Idk.z = 0.0;
        rdCamera_SetCurrent(jkGuiMap_pCamera);
        rdCamera_Update(&jkGuiMap_viewMat);
        jkGuiMap_dword_556664 = 0;
        jkGuiMap_dword_556660 = 1;
    }
    v0 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMap_menu);
    sithMap_Shutdown();
    rdCanvas_Free(jkGuiMap_pCanvas);
    rdClose();
    stdDisplay_VBufferFree(jkGuiMap_pVbuffer);
    result = v0;
    jkGuiMap_dword_556660 = 0;
    return result;
}
