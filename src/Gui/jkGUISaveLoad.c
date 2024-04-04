#include "jkGUISaveLoad.h"

#include "Main/jkEpisode.h"
#include "General/stdFileUtil.h"
#include "General/Darray.h"
#include "General/stdString.h"
#include "Dss/sithGamesave.h"
#include "Main/Main.h"
#include "Main/jkMain.h"
#include "Main/jkStrings.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUIDialog.h"
#include "Gui/jkGUITitle.h"
#include "World/jkPlayer.h"
#include "World/sithWorld.h"
#include "Cog/jkCog.h"
#include "stdPlatform.h"

#include "jk.h"

static int jkGuiSaveLoad_listIdk[2] = {0xd, 0xe};

static jkGuiElement jkGuiSaveLoad_aElements[15] = {
    {ELEMENT_TEXT, 0, 5, 0, 3, {0x32, 0x32, 0x1F4, 0x1E}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_SLENTERGAMENAME", 2, {0x190, 82, 0x0C8, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBOX, 0, 0, jkGuiSaveLoad_word_559830, 100, {0x190, 0xAF, 0x0C8, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_SLGAMESELECT", 2, {0x28, 0x69, 0x14A, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_LISTBOX, 3039, 0x0, 0, 0, {0x28, 0x82, 0x14A, 0x10F}, 1, 0, 0, 0, jkGuiSaveLoad_ListClick, jkGuiSaveLoad_listIdk, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_SLEPISODE", 0, {0x190, 0xD2, 0x0C8, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, jkGuiSaveLoad_wtextEpisode, 0, {0x1A4, 0x0E6, 0x0C8, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, "GUI_SLLEVEL", 0, {0x190, 0x104, 0x0C8, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, jkGuiSaveLoad_wtextSaveName, 0, {0x1A4, 0x118, 0x0C8, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, jkGuiSaveLoad_wtextHealth, 0x0, {0x190, 0x14A, 0x0C8, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXT, 0, 0, jkGuiSaveLoad_wtextShields, 0, {0x190, 0x168, 0x0C8, 0x14}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, {0x1B8, 0x1AE, 0x0C8, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 0xFFFFFFFF, 0x2, "GUI_CANCEL", 3, {0, 0x1AE, 0x0C8, 0x28}, 1, 0, 0, 0, 0, 0, {0}, 0},
    {ELEMENT_TEXTBUTTON, 0, 2, "GUI_SLDELETE", 3, {0xE6, 0x1AE, 0x0B4, 0x28}, 1, 0, 0, 0, jkGuiSaveLoad_DeleteOnClick, 0, {0}, 0},
    {ELEMENT_END, 0, 0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, {0}, 0},
};

static jkGuiMenu jkGuiSaveLoad_menu = {jkGuiSaveLoad_aElements, 0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xF, 0, 0, jkGui_stdBitmaps, jkGui_stdFonts, 0, 0, "thermloop01.wav", "thrmlpu2.wav", 0, 0, 0, 0, 0, 0};

int jkGuiSaveLoad_ListClick(jkGuiElement *element, jkGuiMenu *menu, int mouseX, int mouseY, BOOL redraw)
{
    jkGuiRend_ClickSound(element, menu, mouseX, mouseY, redraw);
    if ( redraw )
        return 12345;
    jkGuiSaveLoad_PopulateInfo(1);
    return 0;
}

void jkGuiSaveLoad_PopulateInfo(int bRedraw)
{
    char *v1; // ebx
    float shieldsAmt; // edx
    jkGuiSaveLoad_Entry *entry; // esi
    wchar_t *v4; // eax
    float playerHealth; // eax
    float playerMaxHealth; // ecx
    jkGuiSaveLoad_Entry* v7; // eax
    int v8; // esi
    jkEpisode *episodeIter; // edi
    wchar_t *v10; // eax
    wchar_t *v11; // eax
    wchar_t *saveName; // [esp+10h] [ebp-10h]
    float playerMaxHealth_; // [esp+14h] [ebp-Ch]
    float playerHealth_; // [esp+18h] [ebp-8h]
    float shieldsAmt_; // [esp+1Ch] [ebp-4h]

    if ( jkGuiSaveLoad_bIsSaveMenu && jkGuiSaveLoad_menu.focusedElement == &jkGuiSaveLoad_aElements[2] )
    {
        saveName = jkGuiTitle_quicksave_related_func1(&jkCog_strings, sithWorld_pCurrentWorld->map_jkl_fname);
        v1 = sithWorld_pCurrentWorld->episodeName;
        playerHealth_ = sithPlayer_pLocalPlayerThing->actorParams.health;
        shieldsAmt = sithPlayer_pLocalPlayer->iteminfo[SITHBIN_SHIELDS].ammoAmt;
        playerMaxHealth_ = sithPlayer_pLocalPlayerThing->actorParams.maxHealth;
    }
    else
    {
        if ( !jkGuiSaveLoad_numEntries )
        {
            // Added: this area had weird sizes with jkGuiSaveLoad_wtextShields and jkGuiSaveLoad_wtextHealth 
            _wcsncpy(jkGuiSaveLoad_wtextEpisode, jkGuiSaveLoad_word_559C54, 0xFFu);
            jkGuiSaveLoad_wtextEpisode[255] = 0;
            _wcsncpy(jkGuiSaveLoad_wtextSaveName, &jkGuiSaveLoad_word_559C54[2], 0xFFu);
            jkGuiSaveLoad_wtextSaveName[255] = 0;
            _wcsncpy(jkGuiSaveLoad_wtextHealth, &jkGuiSaveLoad_word_559C54[4], 63);
            jkGuiSaveLoad_wtextHealth[63] = 0;
            _wcsncpy(jkGuiSaveLoad_wtextShields, &jkGuiSaveLoad_word_559C54[6], 63);
            jkGuiSaveLoad_wtextShields[63] = 0;
            return;
        }
        entry = (jkGuiSaveLoad_Entry *)jkGuiRend_GetId(&jkGuiSaveLoad_DarrayEntries, jkGuiSaveLoad_aElements[4].selectedTextEntry);
        v4 = jkGuiRend_GetString(&jkGuiSaveLoad_DarrayEntries, jkGuiSaveLoad_aElements[4].selectedTextEntry);
        _wcsncpy(jkGuiSaveLoad_word_559830, v4, 0xFFu);
        playerHealth = entry->saveHeader.playerHealth;
        playerMaxHealth = entry->saveHeader.playerMaxHealth;
        saveName = entry->saveHeader.saveName;
        shieldsAmt = entry->saveHeader.binAmts[SITHBIN_SHIELDS];
        jkGuiSaveLoad_word_559830[255] = 0;
        v1 = entry->saveHeader.episodeName;
        playerHealth_ = playerHealth;
        playerMaxHealth_ = playerMaxHealth;
    }
    shieldsAmt_ = shieldsAmt;
    if ( jkGuiSaveLoad_numEntries > 0 )
    {
        v7 = (jkGuiSaveLoad_Entry*)jkGuiRend_GetId(&jkGuiSaveLoad_DarrayEntries, jkGuiSaveLoad_aElements[4].selectedTextEntry);
        jkGuiSaveLoad_aElements[13].bIsVisible = __strcmpi(v7->fpath, "quicksave.jks") != 0;
    }
    v8 = 0;
    if ( jkEpisode_var2 > 0 )
    {
        episodeIter = jkEpisode_aEpisodes;
        while ( __strcmpi(episodeIter->name, v1) )
        {
            ++v8;
            ++episodeIter;
            if ( v8 >= jkEpisode_var2 )
                goto LABEL_15;
        }
        _wcsncpy(jkGuiSaveLoad_wtextEpisode, jkEpisode_aEpisodes[v8].unistr, 0xFFu);
        jkGuiSaveLoad_wtextEpisode[255] = 0;
    }
LABEL_15:
    if ( v8 == jkEpisode_var2 )
    {
        stdString_CharToWchar(jkGuiSaveLoad_wtextEpisode, v1, 255);
        jkGuiSaveLoad_wtextEpisode[255] = 0;
    }
    _wcsncpy(jkGuiSaveLoad_wtextSaveName, saveName, 0xFFu);
    jkGuiSaveLoad_wtextSaveName[255] = 0;
    v10 = jkStrings_GetUniStringWithFallback("GUI_SLHEALTH");
    jk_snwprintf(jkGuiSaveLoad_wtextHealth, 0x40u, v10, (unsigned int)(__int64)playerHealth_, (unsigned int)(__int64)playerMaxHealth_);
    v11 = jkStrings_GetUniStringWithFallback("GUI_SLSHIELDS");
    jk_snwprintf(jkGuiSaveLoad_wtextShields, 0x40u, v11, (unsigned int)(__int64)shieldsAmt_);
    if ( bRedraw )
    {
        jkGuiRend_UpdateAndDrawClickable(&jkGuiSaveLoad_aElements[13], &jkGuiSaveLoad_menu, 1);
        jkGuiRend_UpdateAndDrawClickable(&jkGuiSaveLoad_aElements[2], &jkGuiSaveLoad_menu, 1);
        jkGuiRend_UpdateAndDrawClickable(&jkGuiSaveLoad_aElements[6], &jkGuiSaveLoad_menu, 1);
        jkGuiRend_UpdateAndDrawClickable(&jkGuiSaveLoad_aElements[8], &jkGuiSaveLoad_menu, 1);
        jkGuiRend_UpdateAndDrawClickable(&jkGuiSaveLoad_aElements[9], &jkGuiSaveLoad_menu, 1);
        jkGuiRend_UpdateAndDrawClickable(&jkGuiSaveLoad_aElements[10], &jkGuiSaveLoad_menu, 1);
    }
}

int jkGuiSaveLoad_DeleteOnClick(jkGuiElement *element, jkGuiMenu *menu, int mouseX, int mouseY, int bRedraw)
{
    jkGuiSaveLoad_Entry *v2; // esi
    wchar_t *wstr_del; // eax
    int i; // esi
    jkGuiSaveLoad_Entry *entry; // eax
    wchar_t *wstr_confirmDel; // [esp-4h] [ebp-8Ch]
    char FileName[128]; // [esp+8h] [ebp-80h] BYREF

    jkGuiRend_PlayWav(menu->soundClick);
    if ( jkGuiSaveLoad_aElements[4].selectedTextEntry < jkGuiSaveLoad_DarrayEntries.total )
    {
        v2 = (jkGuiSaveLoad_Entry *)(jkGuiRend_GetId(&jkGuiSaveLoad_DarrayEntries, jkGuiSaveLoad_aElements[4].selectedTextEntry) + 1580);
        if ( __strcmpi((const char *)v2, "quicksave.jks") )
        {
            wstr_confirmDel = jkStrings_GetUniStringWithFallback("GUI_SLCONFIRM_DELETE");
            wstr_del = jkStrings_GetUniStringWithFallback("GUI_SLDELETE");
            if ( jkGuiDialog_YesNoDialog(wstr_del, wstr_confirmDel) )
            {
                sithGamesave_GetProfilePath(FileName, 128, (char *)v2);
                stdFileUtil_DelFile(FileName);
                for ( i = 0; i < jkGuiSaveLoad_numEntries; ++i )
                {
                    entry = (jkGuiSaveLoad_Entry *)jkGuiRend_GetId(&jkGuiSaveLoad_DarrayEntries, i);
                    if ( entry )
                        pHS->free(entry);
                }
                jkGuiRend_DarrayFree(&jkGuiSaveLoad_DarrayEntries);
                jkGuiSaveLoad_numEntries = 0;
                jkGuiSaveLoad_PopulateList();
                jkGuiRend_SetClickableString(&jkGuiSaveLoad_aElements[4], &jkGuiSaveLoad_DarrayEntries);
                jkGuiSaveLoad_aElements[4].selectedTextEntry = 0;
                if ( jkGuiSaveLoad_bIsSaveMenu || (jkGuiSaveLoad_aElements[11].bIsVisible = 0, jkGuiSaveLoad_numEntries > 0) )
                    jkGuiSaveLoad_aElements[11].bIsVisible = 1;
                jkGuiSaveLoad_PopulateInfo(1);
                element->bIsVisible = jkGuiSaveLoad_numEntries > 0;
            }
            jkGuiRend_Paint(menu);
        }
    }
    return 0;
}

// MOTS altered
void jkGuiSaveLoad_PopulateList()
{
    stdFileSearch *v0; // eax
    stdFileSearch *v1; // edi
    int v2; // esi
    wchar_t *v3; // eax
    wchar_t *v4; // ebx
    jkGuiSaveLoad_Entry *v6; // edi
    stdFileSearch *v7; // [esp+10h] [ebp-7C0h]
    char path[128]; // [esp+18h] [ebp-7B8h] BYREF
    stdFileSearchResult a2; // [esp+98h] [ebp-738h] BYREF
    sithGamesave_Header saveHeader; // [esp+1A4h] [ebp-62Ch] BYREF

    jkGuiRend_DarrayNewStr(&jkGuiSaveLoad_DarrayEntries, 50, 1);
    jkGuiSaveLoad_numEntries = 0;
    sithGamesave_GetProfilePath(path, 128, jkGuiSaveLoad_byte_559C50);
    v0 = stdFileUtil_NewFind(path, 3, "jks");
    v1 = v0;
    v7 = v0;
    if ( v0 && stdFileUtil_FindNext(v0, &a2) )
    {
        do
        {
            if ( __strnicmp("_JKAUTO_", a2.fpath, 8u) )
            {
                sithGamesave_GetProfilePath(path, 128, a2.fpath);
                v2 = pHS->fileOpen(path, "rb");
                if ( v2 )
                {
                    if ( pHS->fileRead(v2, &saveHeader, sizeof(sithGamesave_Header)) == sizeof(sithGamesave_Header) && (saveHeader.version == 6 || saveHeader.version == 0x7D6) ) // MOTS altered: 6 -> 0x7D6
                    {
                        v3 = __wcschr(saveHeader.saveName, U'~');
                        v4 = v3;
                        if ( v3 )
                        {
                            *v3 = 0;
                            v6 = (jkGuiSaveLoad_Entry *)pHS->alloc(sizeof(jkGuiSaveLoad_Entry));
                            _memcpy(v6, &saveHeader, sizeof(sithGamesave_Header));
                            _strncpy(v6->fpath, a2.fpath, 0x7Fu);
                            v6->fpath[127] = 0;
                            _strtolower(v6->fpath);
                            jkGuiRend_DarrayReallocStr(&jkGuiSaveLoad_DarrayEntries, v4 + 1, (intptr_t)v6);
                            v1 = v7;
                            ++jkGuiSaveLoad_numEntries;
                        }
                    }
                    pHS->fileClose(v2);
                }
            }
        }
        while ( stdFileUtil_FindNext(v1, &a2) );
    }
    if ( jkGuiSaveLoad_DarrayEntries.total >= 2 )
        _qsort(
            jkGuiSaveLoad_DarrayEntries.alloc,
            jkGuiSaveLoad_DarrayEntries.total,
            jkGuiSaveLoad_DarrayEntries.entrySize,
            jkGuiSaveLoad_SaveSort);
    stdFileUtil_DisposeFind(v1);
    jkGuiRend_DarrayReallocStr(&jkGuiSaveLoad_DarrayEntries, 0, 0);
}

int jkGuiSaveLoad_SaveSort(const void* a_, const void* b_)
{
    const jkGuiStringEntry *a = (const jkGuiStringEntry *)a_;
    const jkGuiStringEntry *b = (const jkGuiStringEntry *)b_;
    if ( !a->str )
        return 1;
    if ( b->str )
        return __wcsicmp(a->str, b->str);
    return -1;
}

int jkGuiSaveLoad_Show(int bIsSave)
{
    const char *v1; // eax
    int v2; // eax
    signed int v3; // edi
    wchar_t *v4; // eax
    int v5; // eax
    jkGuiSaveLoad_Entry *v6; // esi
    int v7; // edi
    int v8; // esi
    wchar_t *v9; // eax
    jkGuiSaveLoad_Entry *v10; // eax
    wchar_t *v11; // eax
    wchar_t *v12; // eax
    char *v13; // eax
    int v14; // edx
    char *v15; // ebp
    int v16; // si
    int v19; // esi
    jkGuiSaveLoad_Entry *v20; // eax
    int i; // eax
    wchar_t *v22; // eax
    int j; // esi
    jkGuiSaveLoad_Entry *v24; // eax
    signed int result; // eax
    wchar_t *v26; // [esp-4h] [ebp-298h]
    wchar_t *v27; // [esp-4h] [ebp-298h]
    wchar_t *v28; // [esp-4h] [ebp-298h]
    int v29; // [esp+10h] [ebp-284h] BYREF
    char v30[128]; // [esp+14h] [ebp-280h] BYREF
    wchar_t v31[256]; // [esp+94h] [ebp-200h] BYREF

    jkGuiSaveLoad_bIsSaveMenu = bIsSave;
    jkGuiSaveLoad_PopulateList();
    jkGuiRend_SetClickableString(&jkGuiSaveLoad_aElements[4], &jkGuiSaveLoad_DarrayEntries);
    jkGuiSaveLoad_aElements[3].bIsVisible = bIsSave == 0;
    jkGuiSaveLoad_aElements[4].selectedTextEntry = 0;
    jkGuiSaveLoad_aElements[1].bIsVisible = bIsSave;
    jkGuiSaveLoad_aElements[2].bIsVisible = bIsSave;
    jkGuiSaveLoad_aElements[2].clickHandlerFunc = jkGuiSaveLoad_PopulateInfoInit;
    jkGuiSaveLoad_aElements[13].bIsVisible = jkGuiSaveLoad_numEntries > 0;
    if ( bIsSave || (jkGuiSaveLoad_aElements[11].bIsVisible = 0, jkGuiSaveLoad_numEntries > 0) )
        jkGuiSaveLoad_aElements[11].bIsVisible = 1;
    v1 = "GUI_SLSAVEGAME";
    if ( !bIsSave )
        v1 = "GUI_SLLOADGAME";
    jkGuiSaveLoad_aElements[0].wstr = jkStrings_GetUniString(v1);
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiSaveLoad_menu, &jkGuiSaveLoad_aElements[11]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiSaveLoad_menu, &jkGuiSaveLoad_aElements[12]);
    jkGuiSaveLoad_menu.focusedElement = &jkGuiSaveLoad_aElements[2];
    jkGuiSaveLoad_PopulateInfo(0);
    _wcsncpy(jkGuiSaveLoad_word_559830, &jkGuiSaveLoad_word_559C54[8], 0xFFu);
    jkGuiSaveLoad_word_559830[255] = 0;
    while ( 1 )
    {
        while ( 1 )
        {
            v2 = jkGuiRend_DisplayAndReturnClicked(&jkGuiSaveLoad_menu);
            v3 = v2;
            if ( v2 != 1 && v2 != 12345 )
                goto LABEL_46;
            if ( !bIsSave || _wcslen(jkGuiSaveLoad_word_559830) )
                break;
            v26 = jkStrings_GetUniStringWithFallback("GUI_CSLMUSTENTERNAME");
            v4 = jkStrings_GetUniStringWithFallback("ERROR");
            jkGuiDialog_ErrorDialog(v4, v26);
        }
        v5 = jkGuiSaveLoad_aElements[4].selectedTextEntry;
        if ( jkGuiSaveLoad_aElements[4].selectedTextEntry < 0 || jkGuiSaveLoad_aElements[4].selectedTextEntry >= jkGuiSaveLoad_DarrayEntries.total )
        {
            v6 = 0;
        }
        else
        {
            v6 = (jkGuiSaveLoad_Entry *)jkGuiRend_GetId(&jkGuiSaveLoad_DarrayEntries, jkGuiSaveLoad_aElements[4].selectedTextEntry);
            v5 = jkGuiSaveLoad_aElements[4].selectedTextEntry;
        }
        if ( !bIsSave )
            break;
        v7 = 0;
        v8 = 0;
        if ( jkGuiSaveLoad_DarrayEntries.total - 1 > 0 )
        {
            while ( 1 )
            {
                v9 = jkGuiRend_GetString(&jkGuiSaveLoad_DarrayEntries, v8);
                if ( !__wcscmp(v9, jkGuiSaveLoad_aElements[2].wstr) )
                    break;
                if ( ++v8 >= jkGuiSaveLoad_DarrayEntries.total - 1 )
                    goto LABEL_24;
            }
            v10 = (jkGuiSaveLoad_Entry *)jkGuiRend_GetId(&jkGuiSaveLoad_DarrayEntries, v8);
            _strncpy(v30, v10->fpath, 0x7Fu);
            v30[127] = 0;
            v7 = 1;
        }
LABEL_24:
        if ( !v7 )
        {
            v13 = (char *)pHS->alloc(jkGuiSaveLoad_numEntries + 1);
            v14 = jkGuiSaveLoad_numEntries;
            v15 = v13;
            v16 = jkGuiSaveLoad_numEntries + 1;
            _memset(v13, 0, v16);
            v19 = 0;
            if ( v14 > 0 )
            {
                do
                {
                    v20 = (jkGuiSaveLoad_Entry *)jkGuiRend_GetId(&jkGuiSaveLoad_DarrayEntries, v19);
                    if ( v20 && _sscanf(v20->fpath, "save%04d.jks", &v29) == 1 )
                    {
                        v14 = jkGuiSaveLoad_numEntries;
                        if ( v29 <= jkGuiSaveLoad_numEntries )
                            v15[v29] = 1;
                    }
                    else if (Main_bMotsCompat && v20 && _sscanf(v20->fpath, "msav%04d.jks", &v29) == 1 ) // Added: Mots
                    {
                        v14 = jkGuiSaveLoad_numEntries;
                        if ( v29 <= jkGuiSaveLoad_numEntries )
                            v15[v29] = 1;
                    }
                    else
                    {
                        v14 = jkGuiSaveLoad_numEntries;
                    }
                    ++v19;
                }
                while ( v19 < v14 );
            }
            for ( i = 0; i <= v14; ++i )
            {
                if ( !v15[i] )
                    break;
            }
            _sprintf(v30, JKSAVE_FORMATSTR, i);
            pHS->free(v15);
LABEL_44:
            v28 = jkGuiSaveLoad_aElements[2].wstr;
            v22 = jkGuiTitle_quicksave_related_func1(&jkCog_strings, sithWorld_pCurrentWorld->map_jkl_fname);
            jk_snwprintf(v31, 0x100u, L"%s~%s", v22, v28);
            sithGamesave_Write(v30, 1, 1, v31);
            sithGamesave_Flush();
            goto LABEL_45;
        }
        v27 = jkStrings_GetUniStringWithFallback("GUI_SLCONFIRM_OVERWRITE");
        v11 = jkStrings_GetUniStringWithFallback("GUI_SLOVERWRITE");
        if ( jkGuiDialog_YesNoDialog(v11, v27) )
            goto LABEL_44;
    }
    if ( !v6 )
        goto LABEL_46;
    if ( !sithWorld_pCurrentWorld )
    {
LABEL_32:
        v12 = jkGuiRend_GetString(&jkGuiSaveLoad_DarrayEntries, v5);
        jkMain_sub_4034D0(v6->saveHeader.episodeName, v6->fpath, v6->saveHeader.jklName, v12);
        v3 = 34;
        goto LABEL_46;
    }
    if ( __strcmpi(v6->saveHeader.episodeName, sithWorld_pCurrentWorld->episodeName) || __strcmpi(v6->saveHeader.jklName, sithWorld_pCurrentWorld->map_jkl_fname) )
    {
        v5 = jkGuiSaveLoad_aElements[4].selectedTextEntry;
        goto LABEL_32;
    }
    jkPlayer_LoadSave(v6->fpath);
LABEL_45:
    v3 = 1;
LABEL_46:
    for ( j = 0; j < jkGuiSaveLoad_numEntries; ++j )
    {
        v24 = (jkGuiSaveLoad_Entry *)jkGuiRend_GetId(&jkGuiSaveLoad_DarrayEntries, j);
        if ( v24 )
            pHS->free(v24);
    }
    jkGuiRend_DarrayFree(&jkGuiSaveLoad_DarrayEntries);
    result = v3;
    jkGuiSaveLoad_numEntries = 0;
    return result;
}

int jkGuiSaveLoad_PopulateInfoInit(jkGuiElement *a1, jkGuiMenu *a2, int a3, int a4, BOOL redraw)
{
    jkGuiSaveLoad_PopulateInfo(1);
    return 0;
}

void jkGuiSaveLoad_Startup()
{
    jkGui_InitMenu(&jkGuiSaveLoad_menu, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
}

void jkGuiSaveLoad_Shutdown()
{
    ;
}
