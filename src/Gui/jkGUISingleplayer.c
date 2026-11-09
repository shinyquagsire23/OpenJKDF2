#include "jkGUISingleplayer.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdStrTable.h"
#include "General/stdFileUtil.h"
#include "Engine/rdMaterial.h" // TODO move tVBuffer
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
#include "Platform/wuRegistry.h"  // Added: Persistent Debug Play checkbox preferences.
#include "Primitives/rdVector.h"
#include "General/stdString.h"

// Added: Remember the Show Cutscenes checkbox state during this session.
static int jkGuiSingleplayer_bShowCutscenes = 0;

// Added: Callback for toggling cinematic entries in the debug level list.
static int jkGuiSingleplayer_ShowCutscenesClicked(
    jkGuiElement* pElement,
    jkGuiMenu* pMenu,
    int32_t mouseX,
    int32_t mouseY,
    int redraw);

static int32_t jkGuiSingleplayer_unk_52B170[2] = {0xd, 0xe};

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
    { ELEMENT_LISTBOX,     1,               0,  NULL,               0, {250, 210, 320, 170}, 1,  0,  0, 0,  0, jkGuiSingleplayer_unk_52B170, {0},  0},
    { ELEMENT_TEXTBUTTON,  1,               2, "GUI_OK",            3, {400, 430, 200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON, -1,               2, "GUI_CANCEL",        3, {200, 430, 200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_END,         0,               0,  NULL,               0, {0},                  0,  0,  0,  0,  0,  0, {0},  0}
};

static jkGuiMenu jkGuiSingleplayer_menu2 = {jkGuiSingleplayer_buttons2, 0, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

static jkGuiElement jkGuiSingleplayer_buttons3[11] = {
    { ELEMENT_TEXT,        0,               0,  NULL,               3, {0,  410,  640, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXT,        0,               6, "GUI_SINGLEPLAYER",  3, {190, 40,  440, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_NEWGAME,   2, "GUI_NEWGAME",       3, {190, 90,  210, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_LOAD,      2, "GUI_LOAD",          3, {430, 90,  200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON,  JKGUI_DEBUGPLAY, 2, "GUI_DEBUG_PLAY",     3, {8,   90,  180, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXT,        0,               0, "GUI_CHOOSELEVEL",   2, {250, 170, 320, 20},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_LISTBOX,     1,               0,  NULL,               0, {250, 210, 320, 170}, 1,  0,  0, 0,  0, jkGuiSingleplayer_unk_52B170, {0},  0},
    { ELEMENT_TEXTBUTTON,  1,               2, "GUI_OK",            3, {400, 430, 200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    { ELEMENT_TEXTBUTTON, -1,               2, "GUI_CANCEL",        3, {200, 430, 200, 40},  1,  0,  0,  0,  0,  0, {0},  0},
    // Added: Toggle cinematic entries in the debug level list.
    { ELEMENT_CHECKBOX, 0, 0, "GUIEXT_SHOW_CUTSCENES", 0,{ 250, 390, 320, 20 }, 1, 0, NULL, NULL, &jkGuiSingleplayer_ShowCutscenesClicked, NULL,{ 0 }, 0 },
    { ELEMENT_END, 0, 0, NULL, 0,{ 0 }, 0, 0, 0, 0, 0, 0,{ 0 }, 0 }
};

static jkGuiMenu jkGuiSingleplayer_menu3 = {jkGuiSingleplayer_buttons3, 0, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

// Added: Preserve the selected episode for returning after debug video playback.
static char jkGuiSingleplayer_debugReturnEpisode[128] = { 0 };
static int jkGuiSingleplayer_bDebugReturnPending = 0;
// Added: Active debug-level list, used when toggling Show Cutscenes.
static Darray* jkGuiSingleplayer_pDebugLevelArray = NULL;
// Added: Free the filename buffers stored in the debug level list.
static void jkGuiSingleplayer_FreeDebugLevelIds(Darray* array)
{
    if (!array)
        return;

    for (int i = 0; i < (int)array->total; i++)
    {
        jkGuiStringEntry* entry = jkGuiRend_GetStringEntry(array, i);

        if (entry && entry->id)
        {
            JK_FREE((void*)entry->id);
            entry->id = 0;
        }
    }
}
// Added: Rebuild the debug level list when Show Cutscenes is toggled.
static int jkGuiSingleplayer_ShowCutscenesClicked(
    jkGuiElement* pElement,
    jkGuiMenu* pMenu,
    int32_t mouseX,
    int32_t mouseY,
    int redraw)
{
    Darray* array = jkGuiSingleplayer_pDebugLevelArray;

    if (!array)
        return 0;

    // Added: Toggle the checkbox state explicitly.
    pElement->selectedTextEntry = !pElement->selectedTextEntry;

    // Added: Remember the Show Cutscenes checkbox state.
    jkGuiSingleplayer_bShowCutscenes = pElement->selectedTextEntry;

    // Added: Save the Show Cutscenes preference across game restarts.
    wuRegistry_SaveBool(
        "DebugPlayShowCutscenes",
        jkGuiSingleplayer_bShowCutscenes
    );

    // Added: Rebuild the list using the current checkbox state.
    jkGuiSingleplayer_sub_41AA30(
        array,
        &jkGuiSingleplayer_buttons3[6],
        0,
        jkRes_episodeGobName,
        jkGui_episodeLoad.type,
        jkGui_episodeLoad.numSeq,
        jkGui_episodeLoad.currentEpisodeEntryIdx,
        jkGui_episodeLoad.paEntries
    );

    // Added: Redraw the checkbox and updated list.
    if (pMenu)
    {
        jkGuiRend_UpdateAndDrawClickable(pElement, pMenu, 1);
        jkGuiRend_UpdateAndDrawClickable(&jkGuiSingleplayer_buttons3[6], pMenu, 1);
        jkGuiRend_Paint(pMenu);
    }

    return 0;
}
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
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__); // Added
    // Added: memleak
    if ( jkGui_episodeLoad.paEntries )
    {
        JK_FREE(jkGui_episodeLoad.paEntries);
        jkGui_episodeLoad.paEntries = 0;
    }
}

// Added: Save the episode used to launch a debug cutscene.
void jkGuiSingleplayer_SetDebugReturnEpisode(const char* episode)
{
    if (!episode)
        return;

    stdString_SafeStrCopy(
        jkGuiSingleplayer_debugReturnEpisode,
        episode,
        sizeof(jkGuiSingleplayer_debugReturnEpisode)
    );
}

// Added: Request reopening the saved Debug Play episode.
void jkGuiSingleplayer_RequestDebugReturn(void)
{
    if (jkGuiSingleplayer_debugReturnEpisode[0])
        jkGuiSingleplayer_bDebugReturnPending = 1;
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
    int debug_episode_idx = 0;

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
                            // Added: %s wants char16_t*, a1 is narrow
                            char16_t wTmp[128];
                            stdString_CharToWchar(wTmp, a1, 127);
                            wTmp[127] = 0;
                            Windows_ErrorMsgboxWide("ERR_CANNOT_LOAD_FILE %s", wTmp);
                            clicked = -1;
                        }
                        if ( clicked == 1 )
                        {
                            jkGui_sub_412E20(&jkGuiSingleplayer_menu3, JKGUI_NEWGAME, JKGUI_DEBUGPLAY, JKGUI_DEBUGPLAY);
                            jkGuiRend_DarrayNewStr(&array2, 10, 1);
                            // Added: Make the active debug list available to the checkbox callback.
                            jkGuiSingleplayer_pDebugLevelArray = &array2;

                            // Added: Load the saved Show Cutscenes preference.
                            jkGuiSingleplayer_bShowCutscenes =
                                wuRegistry_GetBool("DebugPlayShowCutscenes", 0);

                            // Added: Restore the saved Show Cutscenes preference.
                            jkGuiSingleplayer_buttons3[9].selectedTextEntry =
                                jkGuiSingleplayer_bShowCutscenes;

                            jkGuiSingleplayer_sub_41AA30(&array2, &jkGuiSingleplayer_buttons3[6], 0, jkRes_episodeGobName, jkGui_episodeLoad.type, jkGui_episodeLoad.numSeq, jkGui_episodeLoad.currentEpisodeEntryIdx, jkGui_episodeLoad.paEntries);
                            jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSingleplayer_menu3, &jkGuiSingleplayer_buttons3[7]);
                            jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSingleplayer_menu3, &jkGuiSingleplayer_buttons3[8]);
                            clicked = jkGuiRend_DisplayAndReturnClicked(&jkGuiSingleplayer_menu3);
                            // Added: The debug menu has closed; its array is no longer available to callbacks.
                            jkGuiSingleplayer_pDebugLevelArray = NULL;

                            debug_episode_idx = 0;
                            if ( clicked == 1 )
                            {
                                v9 = (const char *)jkGuiRend_GetId(&array2, jkGuiSingleplayer_buttons3[6].selectedTextEntry);
                                _strncpy(v25, v9+sizeof(int), 0x7Fu);
                                v25[127] = 0;
                                debug_episode_idx = *(int*)v9; // Added
                            }
                            // Added: Release debug list filename buffers before freeing the array.
                            jkGuiSingleplayer_FreeDebugLevelIds(&array2);
                            jkGuiRend_DarrayFree(&array2);
                            if (clicked == 1) {
                                // Added: Launch SAN and SMK cutscenes through the existing video player.
                                const char* pExt = strrchr(v25, '.');

                                if (pExt && (!__strcmpi(pExt, ".san") || !__strcmpi(pExt, ".smk")))
                                {
                                    char videoPath[256];

                                    snprintf(videoPath, sizeof(videoPath), "video\\%s", v25);

                                    if (util_FileExists(videoPath))
                                    {
                                        // Added: Remember the episode before starting standalone video playback.
                                        jkGuiSingleplayer_SetDebugReturnEpisode(a1);

                                        // Added: Launch video as an episode cutscene.
                                        jkMain_SwitchToDebugEpisodeVideo(videoPath);
                                    }
                                    else
                                    {
                                        stdPlatform_Printf("Debug Play: Cannot find cutscene '%s'\n", videoPath);
                                    }
                                }
                                else
                                {
                                    // Added: Identify cinematic JKLs selected through Debug Play.
                                    int bCinematicJkl = 0;

                                    if (debug_episode_idx >= 0 &&
                                        debug_episode_idx < jkGui_episodeLoad.numSeq &&
                                        jkGui_episodeLoad.paEntries)
                                    {
                                        jkEpisodeEntry* pEntry =
                                            &jkGui_episodeLoad.paEntries[debug_episode_idx];

                                        const char* pEntryExt = strrchr(pEntry->fileName, '.');

                                        if (pEntry->type == 1 &&
                                            pEntryExt &&
                                            !__strcmpi(pEntryExt, ".jkl"))
                                        {
                                            bCinematicJkl = 1;
                                        }
                                    }

                                    // Added: Skip mission confirmation only for cinematic JKLs.
                                    jkMain_bLoadingCinematicJkl = bCinematicJkl;

                                    // Added: Preserve the existing JKL level-loading behavior.
                                    jkMain_sub_403470(v25);
                                }

#ifdef QOL_IMPROVEMENTS
                                // Added: progress end of level normally from debug menu, instead of exiting to main menu
                                if (jkEpisode_mLoad.paEntries) {
                                    JK_FREE(jkEpisode_mLoad.paEntries);
                                    jkEpisode_mLoad.paEntries = NULL;
                                }
                                jkEpisode_mLoad = jkGui_episodeLoad;
                                size_t aEnts_size = (jkEpisode_mLoad.numSeq + 1) * sizeof(jkEpisodeEntry);
                                jkEpisode_mLoad.paEntries = (jkEpisodeEntry *)JK_ALLOC(aEnts_size);
                                memcpy(jkEpisode_mLoad.paEntries, jkGui_episodeLoad.paEntries, aEnts_size);
                                
                                jkEpisode_mLoad.currentEpisodeEntryIdx = 0;
                                for (int j = 0; j < jkEpisode_mLoad.numSeq; j++)
                                {
                                    //printf("%s %s\n", jkEpisode_mLoad.paEntries[j].fileName, v25);
                                    if (jkEpisode_mLoad.paEntries[j].lineNum == debug_episode_idx) {
                                        jkEpisode_mLoad.currentEpisodeEntryIdx = j;
                                        jkMain_pEpisodeEnt = &jkEpisode_mLoad.paEntries[j];
                                        jkMain_pEpisodeEnt2 = &jkEpisode_mLoad.paEntries[j];
                                        break;
                                    }
                                }

                                if (!jkEpisode_mLoad.currentEpisodeEntryIdx)
                                {
                                    for (int j = 0; j < jkEpisode_mLoad.numSeq; j++)
                                    {
                                        //printf("%s %s\n", jkEpisode_mLoad.paEntries[j].fileName, v25);
                                        if (!__strcmpi(jkEpisode_mLoad.paEntries[j].fileName, v25)) {
                                            jkEpisode_mLoad.currentEpisodeEntryIdx = j;
                                            jkMain_pEpisodeEnt = &jkEpisode_mLoad.paEntries[j];
                                            jkMain_pEpisodeEnt2 = &jkEpisode_mLoad.paEntries[j];
                                            break;
                                        }
                                    }
                                }
                                // Added: Prepare episode progression after a Debug Play cutscene.
                                if (pExt && (!__strcmpi(pExt, ".san") || !__strcmpi(pExt, ".smk")))
                                {
                                    jkPlayer_bLoadingSomething = 1;
                                }
#endif
                                //printf("pre %x %x %x\n", jkEpisode_mLoad.numSeq, jkEpisode_mLoad.type, jkEpisode_mLoad.currentEpisodeEntryIdx);
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
    char16_t *v16; // eax
    jkEpisodeEntry *v17; // esi
    char *v18; // edx
    char16_t *v20; // eax
    int v22; // [esp+10h] [ebp-1A4h]
    int v23; // [esp+10h] [ebp-1A4h]
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
            JK_FREE(v11);
            v10->id = 0;
        }
    }
    jkGuiRend_DarrayFreeEntry(array);
    // Added: Show LEVEL and CUT entries in episode.jk order when enabled.
    if (jkGuiSingleplayer_buttons3[9].selectedTextEntry)
    {
        if (a8 && a6 > 0)
        {
            for (int i = 0; i < a6; i++)
            {
                jkEpisodeEntry* ent = &a8[i];

                // Added: Include LEVEL entries and supported CUT entries.
                if (ent->type)
                {
                    const char* ext = strrchr(ent->fileName, '.');

                    if (!ext ||
                        (__strcmpi(ext, ".jkl") &&
                            __strcmpi(ext, ".san") &&
                            __strcmpi(ext, ".smk")))
                    {
                        continue;
                    }
                }

                // Added: Allocate space for the episode line number and filename.
                uint32_t alloc_sz = _strlen(ent->fileName) + 1 + sizeof(int);
                char* entryData = (char*)JK_ALLOC(alloc_sz);

                if (!entryData)
                    continue;

                // Added: Preserve the episode line number.
                *(int*)entryData = ent->lineNum;

                _strncpy(
                    entryData + sizeof(int),
                    ent->fileName,
                    alloc_sz - sizeof(int) - 1
                );

                entryData[alloc_sz - 1] = 0;

                // Added: Resolve the display name using the existing title lookup.
                char16_t* displayName =
                    jkGuiTitle_quicksave_related_func1(
                        &strtable,
                        entryData + sizeof(int)
                    );

                if (!jkGuiRend_DarrayReallocStr(
                    array,
                    displayName,
                    (intptr_t)entryData))
                {
                    JK_FREE(entryData);
                }
            }
        }
    }
    else
    {
        // Added: Preserve original debug-level filesystem discovery.
        v22 = 0;
        stdString_snprintf(tmp, 128, "episode\\%s\\jkl", episodeDir);
        search = stdFileUtil_NewFind(tmp, 3, "JKL");
        v13 = search;

        if (search)
        {
            while (stdFileUtil_FindNext(search, &a2))
            {
                // Added: Allocate space for the filename and episode index.
                uint32_t alloc_sz = _strlen(a2.fpath) + 1 + sizeof(int);
                v14 = (char*)JK_ALLOC(alloc_sz);

                if (!v14)
                    continue;

                _strncpy(v14 + sizeof(int), a2.fpath,
                    alloc_sz - sizeof(int) - 1);
                v14[alloc_sz - 1] = 0;

                // Added: Filesystem entries have no known episode line number.
                *(int*)v14 = 0;

                v16 = jkGuiTitle_quicksave_related_func1(
                    &strtable, v14 + sizeof(int));

                if (!jkGuiRend_DarrayReallocStr(
                    array, v16, (intptr_t)v14))
                {
                    JK_FREE(v14);
                }
                else
                {
                    ++v22;
                }
            }

            stdFileUtil_DisposeFind(search);
        }

        // Added: Fall back to episode.jk LEVEL entries if no JKL files found.
        if ((!v13 || !v22) && a8 && a6 > 0)
        {
            v23 = a6;
            v17 = a8;

            do
            {
                if (!v17->type)
                {
                    uint32_t alloc_sz =
                        _strlen(v17->fileName) + 1 + sizeof(int);

                    v18 = (char*)JK_ALLOC(alloc_sz);

                    if (v18)
                    {
                        _strncpy(v18 + sizeof(int), v17->fileName,
                            alloc_sz - sizeof(int) - 1);
                        v18[alloc_sz - 1] = 0;

                        // Added: Preserve the episode line number.
                        *(int*)v18 = v17->lineNum;

                        v20 = jkGuiTitle_quicksave_related_func1(
                            &strtable, v18 + sizeof(int));

                        if (!jkGuiRend_DarrayReallocStr(
                            array, v20, (intptr_t)v18))
                        {
                            JK_FREE(v18);
                        }
                    }
                }

                v17++;
                --v23;
            } while (v23 >= 1);
        }
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
            JK_FREE(v6);
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
            JK_FREE(v5);
            v4->id = 0;
        }
        result = array->total;
    }
    return result;
}
