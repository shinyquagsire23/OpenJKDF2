#include "jkGUISingleplayer.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdStrTable.h"
#include "General/stdFileUtil.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUISaveLoad.h"
#include "Gui/jkGUITitle.h"
#include "Main/Main.h"
#include "Main/jkGame.h"
#include "Main/jkRes.h"
#include "Main/jkEpisode.h"
#include "Main/jkMain.h"
#include "Main/jk.h"
#include "Win95/Windows.h"
#include "Primitives/rdVector.h"
#include "General/stdString.h"

static rdVector2i unk_52B170 = {0xd, 0xe};

static jkGuiElement jkGuiSingleplayer_buttons1[7] = {
    { ELEMENT_TEXT,        0,               0,  NULL,              3, {0,  410,  640, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXT,        0,               6, "GUI_SINGLEPLAYER", 3, {190, 40,  440, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_NEWGAME,   2, "GUI_NEWGAME",      3, {190, 90,  210, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_LOAD,      2, "GUI_LOAD",         3, {430, 90,  200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_DEBUGPLAY, 2, "GUI_DEBUG_PLAY",    3, {8,   90,  180, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON, -1,               2, "GUI_CANCEL",       3, {200, 430, 200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_END,         0,               0,  NULL,              0, {0},                  0,  0,  0,  0,  0,  0, {0},  0}
};

static jkGuiMenu jkGuiSingleplayer_menu1 = {jkGuiSingleplayer_buttons1, 0, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

static jkGuiElement jkGuiSingleplayer_buttons2[10] = {
    { ELEMENT_TEXT,        0,               0,  NULL,               3, {0,  410,  640, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXT,        0,               6, "GUI_SINGLEPLAYER",  3, {190, 40,  440, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_NEWGAME,   2, "GUI_NEWGAME",       3, {190, 90,  210, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_LOAD,      2, "GUI_LOAD",          3, {430, 90,  200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_DEBUGPLAY, 2, "GUI_DEBUG_PLAY",     3, {8,   90,  180, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXT,        0,               0, "GUI_CHOOSEEPISODE", 2, {250, 170, 320, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_LISTBOX,     1,               0,  NULL,               0, {250, 210, 320, 170}, 1,  0,  0, 0,  0, &unk_52B170, {0},  0},
    { ELEMENT_TEXTBUTTON,  1,               2, "GUI_OK",            3, {400, 430, 200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON, -1,               2, "GUI_CANCEL",        3, {200, 430, 200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_END,         0,               0,  NULL,               0, {0},                  0,  0,  0,  0,  0,  0, {0},  0}
};

static jkGuiMenu jkGuiSingleplayer_menu2 = {jkGuiSingleplayer_buttons2, 0, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

static jkGuiElement jkGuiSingleplayer_buttons3[10] = {
    { ELEMENT_TEXT,        0,               0,  NULL,               3, {0,  410,  640, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXT,        0,               6, "GUI_SINGLEPLAYER",  3, {190, 40,  440, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_NEWGAME,   2, "GUI_NEWGAME",       3, {190, 90,  210, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_LOAD,      2, "GUI_LOAD",          3, {430, 90,  200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_DEBUGPLAY, 2, "GUI_DEBUG_PLAY",     3, {8,   90,  180, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXT,        0,               0, "GUI_CHOOSELEVEL",   2, {250, 170, 320, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_LISTBOX,     1,               0,  NULL,               0, {250, 210, 320, 170}, 1,  0,  0, 0,  0, &unk_52B170, {0},  0},
    { ELEMENT_TEXTBUTTON,  1,               2, "GUI_OK",            3, {400, 430, 200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON, -1,               2, "GUI_CANCEL",        3, {200, 430, 200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_END,         0,               0,  NULL,               0, {0},                  0,  0,  0,  0,  0,  0, {0},  0}
};

static jkGuiMenu jkGuiSingleplayer_menu3 = {jkGuiSingleplayer_buttons3, 0, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

void jkGuiSingleplayer_Startup()
{
    jkGui_InitMenu(&jkGuiSingleplayer_menu1, jkGui_stdBitmaps[JKGUI_BM_BK_SINGLE]);
    jkGui_InitMenu(&jkGuiSingleplayer_menu2, jkGui_stdBitmaps[JKGUI_BM_BK_SINGLE]);
    jkGui_InitMenu(&jkGuiSingleplayer_menu3, jkGui_stdBitmaps[JKGUI_BM_BK_SINGLE]);

    int old_Main_bDevMode = Main_bDevMode;
    Main_bDevMode = 1;
    jkGuiSingleplayer_buttons1[4].bIsVisible = Main_bDevMode;
    jkGuiSingleplayer_buttons2[4].bIsVisible = Main_bDevMode;
    jkGuiSingleplayer_buttons3[4].bIsVisible = Main_bDevMode;
    Main_bDevMode = old_Main_bDevMode;
}

void jkGuiSingleplayer_Shutdown()
{
    // Added: memleak
    if ( jkGui_episodeLoad.paEntries )
    {
        pHS->free(jkGui_episodeLoad.paEntries);
        jkGui_episodeLoad.paEntries = 0;
    }
}

int jkGuiSingleplayer_Show()
{
    const char *v4; // eax
    const char *v9; // eax
    int i; // ebx
    jkGuiStringEntry *v11; // eax
    void *v13; // eax
    int v15; // ebx
    int v16; // edi
    jkEpisode *v17; // esi
    const char *v18; // eax
    Darray darray; // [esp+10h] [ebp-1C8h]
    Darray array2; // [esp+28h] [ebp-1B0h]
    Darray array; // [esp+40h] [ebp-198h]
    char a1[128]; // [esp+58h] [ebp-180h]
    char v24[128]; // [esp+D8h] [ebp-100h]
    char v25[128]; // [esp+158h] [ebp-80h]

    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSingleplayer_menu1, &jkGuiSingleplayer_buttons1[2]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSingleplayer_menu1, &jkGuiSingleplayer_buttons1[5]);
    int clicked = jkGuiRend_DisplayAndReturnClicked(&jkGuiSingleplayer_menu1);
    if ( clicked == -1 )
        return clicked;

    while ( 1 )
    {
        while ( clicked >= JKGUI_NEWGAME )
        {
            if ( clicked > JKGUI_DEBUGPLAY )
                break;
            switch ( clicked )
            {
                case JKGUI_NEWGAME:
                    v24[0] = 0;
                    jkGui_sub_412E20(&jkGuiSingleplayer_menu2, JKGUI_NEWGAME, JKGUI_DEBUGPLAY, JKGUI_NEWGAME);
                    jkGuiRend_DarrayNewStr(&darray, jkEpisode_var2 + 1, 0);
                    v15 = 0;
                    jkEpisode_LoadVerify();
                    jkGuiRend_DarrayFreeEntry(&darray);
                    v16 = 0;
                    if ( jkEpisode_var2 > 0 )
                    {
                        v17 = jkEpisode_aEpisodes;
                        do
                        {
                            if ( v17->type & JK_EPISODE_SINGLEPLAYER )
                            {
                                jkGuiRend_DarrayReallocStr(&darray, v17->unistr, (intptr_t)v17);
                                ++v15;
                            }
                            ++v16;
                            ++v17;
                        }
                        while ( v16 < jkEpisode_var2 );
                    }
                    jkGuiRend_DarrayReallocStr(&darray, 0, (intptr_t)0);
                    jkGuiRend_SetClickableString(&jkGuiSingleplayer_buttons2[6], &darray);
                    if ( v15 == 1 )
                    {
                        clicked = 1;
                        jkGuiSingleplayer_buttons2[6].selectedTextEntry = 0;
                    }
                    else
                    {
                        jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSingleplayer_menu2, &jkGuiSingleplayer_buttons2[7]);
                        jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSingleplayer_menu2, &jkGuiSingleplayer_buttons2[8]);
                        clicked = jkGuiRend_DisplayAndReturnClicked(&jkGuiSingleplayer_menu2);
                    }
                    if ( clicked == 1 )
                    {
                        v18 = (const char *)jkGuiRend_GetId(&darray, jkGuiSingleplayer_buttons2[6].selectedTextEntry);
                        _strncpy(v24, v18, 0x7Fu);
                        v24[127] = 0;
                    }
                    jkGuiRend_DarrayFree(&darray);
                    if ( clicked == 1 && !jkMain_LoadFile(v24) )
                        clicked = -1;
                    break;
                case JKGUI_LOAD:
                    clicked = jkGuiSaveLoad_Show(0);
                    if ( clicked == 34 || clicked == 1 )
                        clicked = 1;
                    break;
                case JKGUI_DEBUGPLAY:
                    a1[0] = 0;
                    jkGui_sub_412E20(&jkGuiSingleplayer_menu2, JKGUI_NEWGAME, JKGUI_DEBUGPLAY, JKGUI_DEBUGPLAY);
                    jkGuiRend_DarrayNewStr(&array, jkEpisode_var2 + 1, 0);
                    if ( jkGuiSingleplayer_EnumEpisodes(&array, &jkGuiSingleplayer_buttons2[6], 0, JK_EPISODE_ALL) == 1 )
                    {
                        clicked = 1;
                        jkGuiSingleplayer_buttons2[6].selectedTextEntry = 0;
                    }
                    else
                    {
                        jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSingleplayer_menu2, &jkGuiSingleplayer_buttons2[7]);
                        jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSingleplayer_menu2, &jkGuiSingleplayer_buttons2[8]);
                        clicked = jkGuiRend_DisplayAndReturnClicked(&jkGuiSingleplayer_menu2);
                    }
                    if ( clicked == 1 )
                    {
                        v4 = (const char *)jkGuiRend_GetId(&array, jkGuiSingleplayer_buttons2[6].selectedTextEntry);
                        _strncpy(a1, v4, 0x7Fu);
                        a1[127] = 0;
                    }
                    jkGuiRend_DarrayFree(&array);
                    if ( clicked == 1 )
                    {
                        jkRes_LoadGob(a1);
                        if ( !jkEpisode_Load(&jkGui_episodeLoad) )
                        {
                            Windows_ErrorMsgboxWide("ERR_CANNOT_LOAD_FILE %s", a1);
                            clicked = -1;
                        }
                        if ( clicked == 1 )
                        {
                            jkGui_sub_412E20(&jkGuiSingleplayer_menu3, JKGUI_NEWGAME, JKGUI_DEBUGPLAY, JKGUI_DEBUGPLAY);
                            jkGuiRend_DarrayNewStr(&array2, 10, 1);
                            jkGuiSingleplayer_sub_41AA30(&array2, &jkGuiSingleplayer_buttons3[6], 0, jkRes_episodeGobName, jkGui_episodeLoad.type, jkGui_episodeLoad.numSeq, jkGui_episodeLoad.field_8, jkGui_episodeLoad.paEntries);
                            jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSingleplayer_menu3, &jkGuiSingleplayer_buttons3[7]);
                            jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSingleplayer_menu3, &jkGuiSingleplayer_buttons3[8]);
                            clicked = jkGuiRend_DisplayAndReturnClicked(&jkGuiSingleplayer_menu3);
                            if ( clicked == 1 )
                            {
                                v9 = (const char *)jkGuiRend_GetId(&array2, jkGuiSingleplayer_buttons3[6].selectedTextEntry);
                                _strncpy(v25, v9, 0x7Fu);
                                v25[127] = 0;
                            }
                            for ( i = 0; i < (signed int)array2.total; ++i )
                            {
                                v11 = jkGuiRend_GetStringEntry(&array2, i);
                                v13 = (void *)v11->id;
                                if ( v13 )
                                {
                                    pHS->free(v13);
                                    v11->id = 0;
                                }
                            }
                            jkGuiRend_DarrayFree(&array2);
                            if ( clicked == 1 ) {
                                jkMain_sub_403470(v25);

#ifdef QOL_IMPROVEMENTS
                                // Added: progress end of level normally from debug menu, instead of exiting to main menu
                                if (jkEpisode_mLoad.paEntries) {
                                    pHS->free(jkEpisode_mLoad.paEntries);
                                    jkEpisode_mLoad.paEntries = NULL;
                                }
                                jkEpisode_mLoad = jkGui_episodeLoad;
                                size_t aEnts_size = (jkEpisode_mLoad.numSeq + 1) * sizeof(jkEpisodeEntry);
                                jkEpisode_mLoad.paEntries = (jkEpisodeEntry *)pHS->alloc(aEnts_size);
                                memcpy(jkEpisode_mLoad.paEntries, jkGui_episodeLoad.paEntries, aEnts_size);
                                
                                for (int j = 0; j < jkEpisode_mLoad.numSeq; j++)
                                {
                                    //printf("%s %s\n", jkEpisode_mLoad.paEntries[j].fileName, v25);
                                    if (!__strcmpi(jkEpisode_mLoad.paEntries[j].fileName, v25)) {
                                        jkEpisode_mLoad.field_8 = j;
                                        jkMain_pEpisodeEnt = &jkEpisode_mLoad.paEntries[j];
                                        jkMain_pEpisodeEnt2 = &jkEpisode_mLoad.paEntries[j];
                                        break;
                                    }
                                }
#endif
                                //printf("pre %x %x %x\n", jkEpisode_mLoad.numSeq, jkEpisode_mLoad.type, jkEpisode_mLoad.field_8);
                            }
                        }
                    }
                    break;
            }
            if ( clicked < JKGUI_NEWGAME )
                break;
            if ( clicked <= JKGUI_DEBUGPLAY )
            {
                jkGui_sub_412E20(&jkGuiSingleplayer_menu1, JKGUI_NEWGAME, JKGUI_DEBUGPLAY, clicked);
                jkGuiRend_Paint(&jkGuiSingleplayer_menu1);
            }
        }
        jkGuiRend_UpdateSurface();
        if ( clicked == 1 )
            break;
        jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSingleplayer_menu1, &jkGuiSingleplayer_buttons1[2]);
        jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSingleplayer_menu1, &jkGuiSingleplayer_buttons1[5]);
        clicked = jkGuiRend_DisplayAndReturnClicked(&jkGuiSingleplayer_menu1);
        if ( clicked == -1 )
            return clicked;
    }
    return 1;
}

int jkGuiSingleplayer_EnumEpisodes(Darray *array, jkGuiElement *element, int a3, jkEpisodeTypeFlags_t typeMask)
{
    int ret = 0;

    jkEpisode_LoadVerify();
    jkGuiRend_DarrayFreeEntry(array);

    for (int i = 0; i < jkEpisode_var2; i++)
    {
        if ( jkEpisode_aEpisodes[i].type & typeMask )
        {
            jkGuiRend_DarrayReallocStr(array, jkEpisode_aEpisodes[i].unistr, (intptr_t)&jkEpisode_aEpisodes[i]);
            ++ret;
        }
    }

    jkGuiRend_DarrayReallocStr(array, 0, (intptr_t)0);
    jkGuiRend_SetClickableString(element, array);
    return ret;
}

// MOTS added
int jkGuiSingleplayer_FUN_0041d590(const char* pName)
{
    for (int i = 0; i < jkEpisode_var2; i++)
    {
        //printf("%s %s %x\n", pName, jkEpisode_aEpisodes[i].name, jkEpisode_aEpisodes[i].type);
        if (!strcmp(jkEpisode_aEpisodes[i].name, pName))
            return jkEpisode_aEpisodes[i].type;
    }

    return 0;
}

void jkGuiSingleplayer_sub_41AA30(Darray *array, jkGuiElement *element, int a3, char *episodeDir, int a5, int a6, int a7, jkEpisodeEntry* a8)
{
    int i; // edi
    jkGuiStringEntry *v9; // eax
    jkGuiStringEntry *v10; // esi
    void *v11; // eax
    stdFileSearch *search; // eax
    stdFileSearch *v13; // esi
    char *v14; // edx
    char *v15; // ebx
    wchar_t *v16; // eax
    jkEpisodeEntry *v17; // esi
    char *v18; // edx
    char *v19; // ebx
    wchar_t *v20; // eax
    int v22; // [esp+10h] [ebp-1A4h]
    int v23; // [esp+10h] [ebp-1A4h]
    stdFileSearch *a1; // [esp+14h] [ebp-1A0h]
    stdStrTable strtable; // [esp+18h] [ebp-19Ch]
    char tmp[128]; // [esp+28h] [ebp-18Ch]
    stdFileSearchResult a2; // [esp+A8h] [ebp-10Ch]

    stdStrTable_Load(&strtable, "misc\\cogStrings.uni");

    for ( i = 0; i < (signed int)array->total; ++i )
    {
        v9 = jkGuiRend_GetStringEntry(array, i);
        v10 = v9;
        v11 = (void *)v9->id;
        if ( v11 )
        {
            pHS->free(v11);
            v10->id = 0;
        }
    }
    jkGuiRend_DarrayFreeEntry(array);
    v22 = 0;
    stdString_snprintf(tmp, 128, "episode\\%s\\jkl", episodeDir);
    search = stdFileUtil_NewFind(tmp, 3, "JKL");
    v13 = search;
    a1 = search;
    if ( search )
    {
        while ( stdFileUtil_FindNext(search, &a2) )
        {
            v14 = (char *)pHS->alloc(_strlen(a2.fpath) + 1);
            v15 = _strcpy(v14, a2.fpath);
            v16 = jkGuiTitle_quicksave_related_func1(&strtable, v14);
            jkGuiRend_DarrayReallocStr(array, v16, (intptr_t)v15);
            ++v22;
        }
        stdFileUtil_DisposeFind(search);
    }
    
    if ( (!v13 || !v22) && a6 > 0 )
    {
        v23 = a6;
        v17 = a8;
        do
        {
            if ( !v17->type )
            {
                uint32_t alloc_sz = _strlen(v17->fileName) + 1;
                v18 = (char *)pHS->alloc(alloc_sz);
                v19 = _strncpy(v18, v17->fileName, alloc_sz); // Added: strcpy -> strncpy
                v20 = jkGuiTitle_quicksave_related_func1(&strtable, v18);
                jkGuiRend_DarrayReallocStr(array, v20, (intptr_t)v19);
                
            }
            v17++;

            --v23;
        }
        while ( v23 >= 1 ); // Added: != -> >
    }
    jkGuiRend_AddStringEntry(array, 0, 0);
    jkGuiRend_SetClickableString(element, array);
    element->selectedTextEntry = a3;
    stdStrTable_Free(&strtable);
}

void jkGuiSingleplayer_sub_41AC70(Darray *array, jkGuiElement *element, int idx)
{
    int i; // ebx
    jkGuiStringEntry *strEnt; // eax
    jkGuiStringEntry *v5; // esi
    void *v6; // eax
    stdStrTable strtable; // [esp+10h] [ebp-10h]

    stdStrTable_Load(&strtable, "misc\\cogStrings.uni");
    for ( i = 0; i < (signed int)array->total; ++i )
    {
        strEnt = jkGuiRend_GetStringEntry(array, i);
        v5 = strEnt;
        v6 = (void *)strEnt->id;
        if ( v6 )
        {
            pHS->free(v6);
            v5->id = 0;
        }
    }
    jkGuiRend_DarrayFreeEntry(array);
    jkGuiRend_AddStringEntry(array, 0, 0);
    jkGuiRend_SetClickableString(element, array);
    element->selectedTextEntry = idx;
    stdStrTable_Free(&strtable);
}

int jkGuiSingleplayer_sub_41AD00(Darray *array)
{
    int result; // eax
    jkGuiStringEntry *v3; // eax
    jkGuiStringEntry *v4; // esi
    void *v5; // eax

    result = array->total;
    for (int i = 0; i < result; ++i )
    {
        v3 = jkGuiRend_GetStringEntry(array, i);
        v4 = v3;
        v5 = (void *)v3->id;
        if ( v5 )
        {
            pHS->free(v5);
            v4->id = 0;
        }
        result = array->total;
    }
    return result;
}
