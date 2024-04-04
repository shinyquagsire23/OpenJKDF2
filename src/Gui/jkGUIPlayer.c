#include "jkGUIPlayer.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdStrTable.h"
#include "General/stdFileUtil.h"
#include "General/util.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIDialog.h"
#include "Cog/jkCog.h"
#include "Main/jkStrings.h"
#include "Win95/stdDisplay.h"
#include "Win95/Windows.h"
#include "World/sithWorld.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/stdFileUtil.h"
#include "World/jkPlayer.h"

static int jkGuiPlayer_bInitted = 0;

static wchar_t jkGuiPlayer_awTmp_555D28[0x100] = {0};
static char* jkGuiPlayer_GuiDifficulties[3] = {"GUI_EASY", "GUI_MED", "GUI_HARD"};

static int jkGuiPlayer_menuSelectIdk[2] = {0xFA, 0};
static int jkGuiPlayer_menuSelectIdk2[2] = {0xd, 0xe};

static jkGuiElement jkGuiPlayer_menuSelectElements[8] = {
    {ELEMENT_TEXT, 0, 0, 0, 3, {0, 0x19A, 0x280, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 5, "GUI_CHOOSEPLAYER", 3, {0, 0x82, 0x280, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_LISTBOX, 1, 0, 0, 0, {0x82, 0xC8, 0x17C, 0xB4}, 1, 0, 0, 0, 0, jkGuiPlayer_menuSelectIdk2, {0}, 0},
    {ELEMENT_TEXTBUTTON, 0xFFFFFFFF, 2, "GUI_CANCEL", 3, {0, 0x1AE, 0xA0, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 2, 2, "GUI_NEWPLAYER", 3, {0xA0, 0x1AE, 0xA0, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 3, 2, "GUI_REMOVE", 3, {0x140, 0x1AE, 0xA0, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {0x1E0, 0x1AE, 0xA0, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0},
};

static jkGuiMenu jkGuiPlayer_menuSelect = {jkGuiPlayer_menuSelectElements, 0, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, (intptr_t)jkGuiPlayer_menuSelectIdk, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0,0};

static jkGuiElement jkGuiPlayer_menuNewElements[12] = {
    { ELEMENT_TEXT, 0, 0, 0, 3, {0, 0x19A, 280, 14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    { ELEMENT_TEXT, 0, 5, "GUI_NEWPLAYER", 3, {0, 0x82, 0x280, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    { ELEMENT_TEXT, 0, 0, "GUI_NAME", 2, {0xC8, 0xD2, 0xC8, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBOX, 0, 0, 0, 10, {0xC8, 0xF0, 0xC8, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    { ELEMENT_TEXT, 0, 0, "GUI_DIFFICULTY", 2, {0xC8, 0x118, 0xC8, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    { ELEMENT_CHECKBOX, 0, 0, "GUI_EASY", 0, {0xC8, 0x136, 0xC8, 0x14}, 1, 0, 0, 0, jkGuiPlayer_DifficultyDraw, 0, {0}, 0},
    { ELEMENT_CHECKBOX, 0, 0, "GUI_MED", 0, {0xC8, 0x154, 0xC8, 0x14}, 1, 0, 0, 0, jkGuiPlayer_DifficultyDraw, 0, {0}, 0},
    { ELEMENT_CHECKBOX, 0, 0, "GUI_HARD", 0, {0xC8, 0x172, 0xC8, 0x14}, 1, 0, 0, 0, jkGuiPlayer_DifficultyDraw, 0, {0}, 0},
    { ELEMENT_TEXT, 0, 0, 0, 3, {0, 0x19A, 0x280, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON, 0xFFFFFFFF, 2, "GUI_CANCEL", 3, {0x14, 0x1AE, 0xC8, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    { ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {0x1A4, 0x1AE, 0xC8, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    { ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0},
};

static jkGuiMenu jkGuiPlayer_menuNew = {jkGuiPlayer_menuNewElements, 0, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0,0};

int jkGuiPlayer_Startup()
{
    // MOTS added: Move the UI stuff around for MoTS
    if (Main_bMotsCompat) {
        jkGuiPlayer_menuSelectElements[1].rect.y = 0xAF;
        jkGuiPlayer_menuSelectElements[2].rect.y = 0xF0;
        jkGuiPlayer_menuSelectElements[2].rect.height = 0x9C;

        jkGuiPlayer_menuNewElements[1].rect.y = 0xAF;
        jkGuiPlayer_menuNewElements[2].rect.y = 0xE6;
        jkGuiPlayer_menuNewElements[3].rect.y = 0x104;
        jkGuiPlayer_menuNewElements[4].rect.y = 0x131;
        jkGuiPlayer_menuNewElements[5].rect.y = 0x14A;
        jkGuiPlayer_menuNewElements[6].rect.y = 0x163;
        jkGuiPlayer_menuNewElements[7].rect.y = 0x17C;
    }

    jkGui_InitMenu(&jkGuiPlayer_menuSelect, jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]);
    jkGui_InitMenu(&jkGuiPlayer_menuNew, jkGui_stdBitmaps[JKGUI_BM_BK_MAIN]);
    jkGuiPlayer_bInitted = 1;
    return 1;
}

void jkGuiPlayer_Shutdown()
{
    jkGuiPlayer_bInitted = 0;

    // Added: clean reset
    memset(jkGuiPlayer_awTmp_555D28, 0, sizeof(jkGuiPlayer_awTmp_555D28));
}

int jkGuiPlayer_sub_410640(Darray *array, jkGuiElement *element)
{
    int v2; // edi
    stdFileSearch *v3; // eax
    stdFileSearch *v4; // ebp
    int v5; // eax
    wchar_t *v6; // eax
    int v8; // [esp+10h] [ebp-3B4h] BYREF
    int v9; // [esp+14h] [ebp-3B0h] BYREF
    char a1a[32]; // [esp+18h] [ebp-3ACh] BYREF
    stdFileSearchResult searchRes; // [esp+38h] [ebp-38Ch] BYREF
    char jkl_fname[128]; // [esp+144h] [ebp-280h] BYREF
    wchar_t tmp[256]; // [esp+1C4h] [ebp-200h] BYREF

    v2 = 0;
    stdString_WcharToChar(a1a, jkPlayer_playerShortName, 31);
    a1a[31] = 0;
    jkGuiRend_DarrayFreeEntry(array);
    v3 = stdFileUtil_NewFind("player", 2, 0);
    v4 = v3;
    if ( v3 )
    {
        if ( stdFileUtil_FindNext(v3, &searchRes) )
        {
            do
            {
                stdString_snprintf(jkl_fname, 128, "player%c%s%c%s.plr", LEC_PATH_SEPARATOR_CHR, searchRes.fpath, LEC_PATH_SEPARATOR_CHR, searchRes.fpath);
                if ( searchRes.is_subdirectory && searchRes.fpath[0] != '.' && util_FileExists(jkl_fname) )
                {
                    _memset(tmp, 0, sizeof(tmp));
                    stdString_CharToWchar(tmp, searchRes.fpath, 255);
                    tmp[255] = 0;
                    wchar_t tab[2] = {'\t', 0};
                    __wcscat(tmp, tab);
                    
                    if ( stdConffile_OpenRead(jkl_fname) )
                    {
                        if ( stdConffile_ReadLine() && _sscanf(stdConffile_aLine, "version %d", &v8) == 1 && v8 == 1 && stdConffile_ReadLine() )
                        {
                            _sscanf(stdConffile_aLine, "diff %d", &v9);
                            stdConffile_Close();
                            v5 = v9;
                            if ( v9 < 0 )
                            {
                                v5 = 0;
                            }
                            else if ( v9 > 2 )
                            {
                                v5 = 2;
                            }
                        }
                        else
                        {
                            stdConffile_Close();
                            v5 = 1;
                        }
                    }
                    else
                    {
                        v5 = 1;
                    }
                    v6 = jkStrings_GetUniStringWithFallback(jkGuiPlayer_GuiDifficulties[v5]);
                    if (v6) // Added: avoid nullptr deref
                        __wcscat(tmp, v6);
                    jkGuiRend_DarrayReallocStr(array, tmp, 0);
                    if ( !__strcmpi(searchRes.fpath, a1a) )
                        element->selectedTextEntry = v2;
                    ++v2;
                }
            }
            while ( stdFileUtil_FindNext(v4, &searchRes) );
        }
        stdFileUtil_DisposeFind(v4);
    }
    jkGuiRend_DarrayReallocStr(array, 0, 0);
    jkGuiRend_SetClickableString(element, array);
    return v2;
}

void jkGuiPlayer_ShowNewPlayer(int a1)
{
    int v1; // eax
    int v2; // ebp
    jkGuiStringEntry *v3; // eax
    const wchar_t *v4; // esi
    wchar_t *v5; // eax
    int v6; // esi
    int v7; // edi
    const wchar_t *v8; // eax
    wchar_t *v9; // eax
    wchar_t *v10; // eax
    jkGuiStringEntry *v11; // eax
    const wchar_t *v12; // esi
    wchar_t *v13; // eax
    int v14; // [esp+10h] [ebp-664h]
    int v15; // [esp+14h] [ebp-660h]
    Darray a1a; // [esp+1Ch] [ebp-658h] BYREF
    char v17[32]; // [esp+34h] [ebp-640h] BYREF
    char v18[32]; // [esp+54h] [ebp-620h] BYREF
    char v19[128]; // [esp+74h] [ebp-600h] BYREF
    char v20[128]; // [esp+F4h] [ebp-580h] BYREF
    char v21[128]; // [esp+174h] [ebp-500h] BYREF
    char PathName[128]; // [esp+1F4h] [ebp-480h] BYREF
    wchar_t a2[256]; // [esp+274h] [ebp-400h] BYREF
    wchar_t v24[256]; // [esp+474h] [ebp-200h] BYREF

    jkPlayer_playerShortName[0] = 0; // Added

    v15 = 0; 
    jkGuiRend_DarrayNewStr(&a1a, 5, 1);
    do
    {
        v1 = jkGuiPlayer_sub_410640(&a1a, &jkGuiPlayer_menuSelectElements[2]);
        v14 = 0;
        jkGuiPlayer_menuSelectElements[3].bIsVisible = a1 == 0;
        if ( v1 )
        {
            jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiPlayer_menuSelect, &jkGuiPlayer_menuSelectElements[6]);
            if ( a1 )
                jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiPlayer_menuSelect, 0);
            else
                jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiPlayer_menuSelect, &jkGuiPlayer_menuSelectElements[3]);
            v2 = jkGuiRend_DisplayAndReturnClicked(&jkGuiPlayer_menuSelect);
        }
        else
        {
            v15 = 1;
            v2 = 2;
        }
        v3 = jkGuiRend_GetStringEntry(&a1a, jkGuiPlayer_menuSelectElements[2].selectedTextEntry);
        if ( v3 && v3->str )
        {
            _memset(a2, 0, sizeof(a2));
            v4 = v3->str;
            v5 = __wcschr(v3->str, '\t');
            __wcsncpy(a2, v4, v5 - v4);
        }
        switch ( v2 )
        {
            case -1:
                if ( !jkPlayer_ReadConf(a2) )
                {
                    v11 = jkGuiRend_GetStringEntry(&a1a, 0);
                    if ( v11 && v11->str )
                    {
                        _memset(a2, 0, sizeof(a2));
                        v12 = v11->str;
                        v13 = __wcschr(v11->str, '\t');
                        __wcsncpy(a2, v12, v13 - v12);
                    }
                    if ( !jkPlayer_ReadConf(a2) )
                    {
                        stdString_WcharToChar(v17, jkPlayer_playerShortName, 31);
                        v17[31] = 0;
                        Windows_ErrorMsgboxWide("ERR_CANNOT_SET_PLAYER %s", v17);
                    }
                }
                continue;
            case 1:
                if ( !jkPlayer_ReadConf(a2) )
                {
                    stdString_WcharToChar(v18, jkPlayer_playerShortName, 31);
                    v18[31] = 0;
                    Windows_ErrorMsgboxWide("ERR_CANNOT_SET_PLAYER %s", v18);
                }
                continue;
            case 2:
                jkGuiPlayer_menuNewElements[9].bIsVisible = v15 == 0;
                jkGuiPlayer_menuNewElements[3].wstr = jkGuiPlayer_awTmp_555D28;
                _memset(jkGuiPlayer_awTmp_555D28, 0, 16 * sizeof(wchar_t));
                jkGuiPlayer_menuNewElements[3].selectedTextEntry = 16;
                jkGuiPlayer_menuNewElements[8].unistr = 0;
                jkGuiPlayer_menuNewElements[5].selectedTextEntry = 0;
                jkGuiPlayer_menuNewElements[6].selectedTextEntry = 1;
                jkGuiPlayer_menuNewElements[7].selectedTextEntry = 0;
                break;
            case 3:
                v9 = jkStrings_GetUniStringWithFallback("GUI_CONFIRM_REMOVE_PLAYER");
                jk_snwprintf(v24, 0x100u, v9, a2);
                v10 = jkStrings_GetUniStringWithFallback("GUI_REMOVE");
                if ( jkGuiDialog_YesNoDialog(v10, v24) )
                {
                    stdString_WcharToChar(v20, a2, 127);
                    v20[127] = 0;
                    stdFnames_MakePath(PathName, 128, "player", v20);
                    stdString_snprintf(PathName, 128, "player%c%s", LEC_PATH_SEPARATOR_CHR, v20);
                    stdFileUtil_Deltree(PathName);
                }
                v14 = 1;
                continue;
            default:
                continue;
        }
        do
        {
            v6 = 0;
            jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiPlayer_menuNew, &jkGuiPlayer_menuNewElements[10]);
            if ( !v15 )
                jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiPlayer_menuNew, &jkGuiPlayer_menuNewElements[9]);
            v7 = jkGuiRend_DisplayAndReturnClicked(&jkGuiPlayer_menuNew);
            if ( v7 == 1 )
            {
                if ( jkGuiPlayer_awTmp_555D28[0] )
                {
                    if ( jkPlayer_VerifyWcharName(jkGuiPlayer_awTmp_555D28) )
                    {
                        stdString_WcharToChar(v19, jkGuiPlayer_awTmp_555D28, 127);
                        v19[127] = 0;
                        stdFnames_MakePath(v21, 128, "player", v19);
                        stdString_snprintf(v21, 128, "player%c%s%c%s.plr", LEC_PATH_SEPARATOR_CHR, v19, LEC_PATH_SEPARATOR_CHR, v19);
                        if ( !util_FileExists(v21) )
                            continue;
                        v6 = 1;
                        v8 = jkStrings_GetUniStringWithFallback("ERR_PLAYER_ALREADY_EXISTS");
                    }
                    else
                    {
                        v6 = 1;
                        v8 = jkStrings_GetUniStringWithFallback("ERR_BAD_PLAYER_NAME");
                    }
                }
                else
                {
                    v6 = 1;
                    v8 = jkStrings_GetUniStringWithFallback("ERR_NO_PLAYER_NAME");
                }
                jkGuiPlayer_menuNewElements[8].wstr = v8;
            }
        }
        while ( v6 );
        if ( v7 == 1 )
        {
            if ( jkGuiPlayer_menuNewElements[5].selectedTextEntry )
                jkPlayer_setDiff = 0;
            else
                jkPlayer_setDiff = 2 - (jkGuiPlayer_menuNewElements[6].selectedTextEntry != 0);
            jkPlayer_CreateConf(jkGuiPlayer_awTmp_555D28);
        }
        if ( v7 < 0 )
            v14 = 1;
    }
    while ( v14 );
    jkGuiRend_DarrayFree(&a1a);
}

int jkGuiPlayer_DifficultyDraw(jkGuiElement *element, jkGuiMenu *menu, int mouseX, int mouseY, int bRedraw)
{
    jkGuiPlayer_menuNewElements[5].selectedTextEntry = 0;
    jkGuiPlayer_menuNewElements[6].selectedTextEntry = 0;
    jkGuiPlayer_menuNewElements[7].selectedTextEntry = 0;
    element->selectedTextEntry = 1;
    jkGuiRend_UpdateAndDrawClickable(&jkGuiPlayer_menuNewElements[5], &jkGuiPlayer_menuNew, 1);
    jkGuiRend_UpdateAndDrawClickable(&jkGuiPlayer_menuNewElements[6], &jkGuiPlayer_menuNew, 1);
    jkGuiRend_UpdateAndDrawClickable(&jkGuiPlayer_menuNewElements[7], &jkGuiPlayer_menuNew, 1);
    return 0;
}
