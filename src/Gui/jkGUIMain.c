#include "jkGUIMain.h"

#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "World/jkPlayer.h"
#include "Main/jkStrings.h"
#include "General/stdFnames.h"
#include "General/Darray.h"
#include "Gui/jkGUITitle.h"
#include "Gui/jkGUISingleplayer.h"
#include "Gui/jkGUIMultiplayer.h"
#include "Gui/jkGUIDialog.h"
#include "Gui/jkGUIPlayer.h"
#include "Gui/jkGUISetup.h"
#include "Gui/jkGUIMods.h"
#include "Win95/stdComm.h"
#include "Win95/stdGdi.h"
#include "Win95/Windows.h"
#include "Main/Main.h"
#include "Main/jkMain.h"
#include "Main/jkRes.h"
#include "General/stdString.h"
#include "General/util.h"
#include "General/stdFnames.h"
#include "Main/sithCvar.h"
#include "stdPlatform.h"

// Added
extern int jkCredits_cdOverride;
static wchar_t jkGuiMain_versionBuffer[64];

static int jkGuiMain_bIdk = 1;
static int jkGuiCutscenes_initted;

static uint32_t jkGuiMain_listboxIdk[2] = {0xd, 0xe};

static jkGuiElement jkGuiMain_cutscenesElements[5] = {
    {ELEMENT_TEXT, 0, 5, "GUI_VIEWCUTSCENES", 3, {0, 50, 640, 60}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_LISTBOX, 1, 2, 0, 0, {160, 135, 320, 240}, 1, 0, 0, 0, 0, jkGuiMain_listboxIdk, {0}, 0},
    {ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {340, 400, 140, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, -1, 2, "GUI_CANCEL", 3, {150, 400, 180, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0}
};

static jkGuiMenu jkGuiMain_cutscenesMenu = {jkGuiMain_cutscenesElements, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

static jkGuiElement jkGuiMain_elements[11] = {
    {ELEMENT_TEXTBUTTON, 10, 5, "GUI_SINGLEPLAYER", 3, {0, 160, 0x280, 0x3C}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 11, 5, "GUI_MULTIPLAYER", 3, {0, 220, 0x280, 0x3C}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 12, 5, "GUI_QUIT", 3, {0, 0x118, 0x280, 0x3C}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 14, 2, "GUI_CHOOSEPLAYER", 3, {20, 380, 150, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 15, 2, "GUI_VIEWCUTSCENES", 3, {250, 380, 150, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 13, 2, "GUI_SETUP", 3, {470, 380, 150, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
#ifdef QOL_IMPROVEMENTS
    {ELEMENT_TEXTBUTTON, 16, 2, "GUI_CREDITS", 3, {130, 430, 150, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 17, 2, L"Expansions & Mods", 3, {370, 430, 150, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT,  0,  0,  NULL,  3, {560, 440, 70, 15},  1,  0,  0,  0,  0,  0, {0},  0},
    {ELEMENT_TEXT,  0,  0,  NULL,  3, {560, 455, 70, 15},  1,  0,  0,  0,  0,  0, {0},  0},
#else
    {ELEMENT_TEXTBUTTON, 16, 2, "GUI_CREDITS", 3, {250, 420, 150, 40}, 1, 0, 0, 0, 0, 0, {0}, 0},
#endif
    {ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0}
};

static jkGuiMenu jkGuiMain_menu = {jkGuiMain_elements, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

// MOTS altered
void jkGuiMain_Show()
{
    int v1; // esi
    wchar_t *v2; // eax
    wchar_t *v4; // [esp-4h] [ebp-Ch]

    if (!Main_bMotsCompat) {
        jkGuiMain_elements[0].rect.y = 160;
        jkGuiMain_elements[1].rect.y = 220;
        jkGuiMain_elements[2].rect.y = 280;
        jkGuiMain_elements[3].rect.y = 380;
        jkGuiMain_elements[4].rect.y = 380;
        jkGuiMain_elements[5].rect.y = 380;
#ifdef QOL_IMPROVEMENTS
        jkGuiMain_elements[6].rect.y = 430;
        jkGuiMain_elements[7].rect.y = 430;
#else
        jkGuiMain_elements[6].rect.y = 420;
#endif
    }
    else {
        jkGuiMain_elements[0].rect.y = 160+25;
        jkGuiMain_elements[1].rect.y = 220+25;
        jkGuiMain_elements[2].rect.y = 280+25;
        jkGuiMain_elements[3].rect.y = 380+5;
        jkGuiMain_elements[4].rect.y = 380+5;
        jkGuiMain_elements[5].rect.y = 380+5;
#ifdef QOL_IMPROVEMENTS
        jkGuiMain_elements[6].rect.y = 430;
        jkGuiMain_elements[7].rect.y = 430;
#else
        jkGuiMain_elements[6].rect.y = 420+5;
#endif
    }

    // Added: OpenJKDF2 version
    jkGuiMain_elements[8].wstr = openjkdf2_waReleaseVersion;
    jkGuiMain_elements[9].wstr = openjkdf2_waReleaseCommitShort;

    jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->palette);
    if ( !jkGuiMain_bIdk || (jkGuiMain_bIdk = 0, jkGuiPlayer_ShowNewPlayer(1), !stdComm_dword_8321F8) || jkGuiMultiplayer_Show2() != 1 )
    {
        if (Main_bMotsCompat) {
            jkGuiMain_elements[4].bIsVisible = Main_bDevMode; // MOTS added
        }
        else {
            jkGuiMain_elements[4].bIsVisible = 1;
        }

        do
        {
            if (g_should_exit) return; // Added

            jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMain_menu, &jkGuiMain_elements[2]);
            v1 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMain_menu);
            switch ( v1 )
            {
                case 10:
                    v1 = jkGuiSingleplayer_Show();
                    break;
                case 11:
                    v1 = jkGuiMultiplayer_Show();
                    break;
                case 12:
                    v4 = jkStrings_GetUniStringWithFallback("GUI_QUITCONFIRM_Q");
                    v2 = jkStrings_GetUniStringWithFallback("GUI_QUITCONFIRM");
                    if ( !jkGuiDialog_YesNoDialog(v2, v4) )
                        goto LABEL_12;

                    // TODO proper shutdown?
#ifdef WIN32_BLOBS
                    jk_PostMessageA(stdGdi_GetHwnd(), 16, 0, 0);
#else
                    sithCvar_SaveGlobals();
                    jkPlayer_WriteConf(jkPlayer_playerShortName); // Added
                    g_should_exit = 1;
                    //exit(0);
                    return;
#endif
                    break;
                case 13:
                    jkGuiSetup_Show();
                    v1 = -1;
                    break;
                case 14:
                    jkGuiPlayer_ShowNewPlayer(0);
LABEL_12:
                    v1 = -1;
                    break;
                case 15:
                    jkMain_SwitchTo12();
                    break;
                case 16:
                    jkCredits_cdOverride = 1; // Added: Simulate disk 1 in menu for jkCredits
                    jkMain_SwitchTo13();
                    break;
#ifdef QOL_IMPROVEMENTS
                case 17:
                    jkGuiMods_Show();
                    v1 = -1;
                    break;
#endif
                default:
                    break;
            }
        }
        while ( v1 == -1 );
    }
    jkGui_SetModeGame();
}

void jkGuiMain_ShowCutscenes()
{
    char *v0; // ebx
    char *v1; // ebp
    char *v2; // edx
    wchar_t *v3; // eax
    int v4; // eax
    const char *v5; // eax
    const char *v6; // eax
    int v7; // esi
    void *i; // eax
    int v9; // [esp+10h] [ebp-15Ch]
    Darray darray; // [esp+14h] [ebp-158h] BYREF
    char v11[64]; // [esp+2Ch] [ebp-140h] BYREF
    char v12[256]; // [esp+6Ch] [ebp-100h] BYREF

    if ( !jkGuiCutscenes_initted )
        jkGui_InitMenu(&jkGuiMain_cutscenesMenu, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
    jkGuiCutscenes_initted = 1;
    jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]->palette);
    jkGuiRend_DarrayNewStr(&darray, 32, 1);
    if ( !jkPlayer_ReadConf(jkPlayer_playerShortName) )
    {
        stdString_WcharToChar(v11, jkPlayer_playerShortName, 31);
        v11[31] = 0;
        Windows_ErrorMsgboxWide("ERR_CANNOT_SET_PLAYER %s", v11);
    }
    
    jkGuiMain_PopulateCutscenes(&darray, &jkGuiMain_cutscenesElements[1]);
    do
    {
        while ( 1 )
        {
            jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiMain_cutscenesMenu, &jkGuiMain_cutscenesElements[2]);
            jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMain_cutscenesMenu, &jkGuiMain_cutscenesElements[3]);
            v4 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMain_cutscenesMenu);
            if ( v4 != 1 )
                break;

            // Added: Moved these up
            v5 = (const char *)jkGuiRend_GetId(&darray, jkGuiMain_cutscenesElements[1].selectedTextEntry);
            snprintf(v12, 256, "video%c%s", '\\', v5); // Added: sprintf -> snprintf
            if ( util_FileExists(v12) || jkRes_LoadCD(jkPlayer_aCutsceneVal[jkGuiMain_cutscenesElements[1].selectedTextEntry]) ) // Added: Don't need a CD switch if it exists.
            {
                // Added: move up
                //v5 = (const char *)jkGuiRend_GetId(&darray, jkGuiMain_cutscenesElements[1].selectedTextEntry);
                //snprintf(v12, 256, "video%c%s", '\\', v5); // Added: sprintf -> snprintf
                if ( util_FileExists(v12) )
                {
                    jkMain_SwitchTo4(v12);
                    goto LABEL_17;
                }
                v6 = (const char *)jkGuiRend_GetId(&darray, jkGuiMain_cutscenesElements[1].selectedTextEntry);
                stdPrintf(pHS->errorPrint, ".\\Gui\\jkGUIMain.c", 297, "Cannot find cutscene '%s'.\n", v6);
            }
        }
    }
    while ( v4 != -1 );
    jkMain_MenuReturn();
LABEL_17:
    v7 = 0;
    for ( i = (void *)jkGuiRend_GetId(&darray, 0); i; i = (void *)jkGuiRend_GetId(&darray, v7) )
    {
        pHS->free(i);
        ++v7;
    }
    jkGui_SetModeGame();
}

void jkGuiMain_Startup()
{
    jkGui_InitMenu(&jkGuiMain_menu, jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]);

    // Added: clean reset
    jkGuiMain_bIdk = 1;
}

void jkGuiMain_Shutdown()
{
    // Added: clean reset
    jkGuiCutscenes_initted = 0;
}

void jkGuiMain_PopulateCutscenes(Darray *list, jkGuiElement *element)
{
    char* v2;
    char *v3; // ebx
    wchar_t *v5; // eax
    int v6; // [esp+4h] [ebp-44h]
    char key[64]; // [esp+8h] [ebp-40h] BYREF

    v2 = jkPlayer_cutscenePath;
    for (v6 = 0; v6 < jkPlayer_setNumCutscenes; v6++)
    {
        v3 = _strcpy((char *)pHS->alloc(_strlen(v2) + 1), v2);
        stdFnames_CopyShortName(key, 64, v3); // TODO aaaaaaa ??? disassembly was wrong?
        jkGuiTitle_sub_4189A0(key);
        v5 = jkStrings_GetUniString(key);
        jkGuiRend_DarrayReallocStr(list, v5, (intptr_t)v3);
        v2 += 32;
    }
    jkGuiRend_AddStringEntry(list, 0, 0);
    jkGuiRend_SetClickableString(element, list);
    element->selectedTextEntry = 0;
}

void jkGuiMain_FreeCutscenes(Darray *a1)
{
    int v1; // esi
    void *i; // eax

    v1 = 0;
    for ( i = (void *)jkGuiRend_GetId(a1, 0); i; i = (void *)jkGuiRend_GetId(a1, v1) )
    {
        pHS->free(i);
        ++v1;
    }
}
