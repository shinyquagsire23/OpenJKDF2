#include "jkGUIControlSaveLoad.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdString.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIDialog.h"
#include "Main/jkStrings.h"
#include "Win95/stdDisplay.h"
#include "General/stdFileUtil.h"
#include "Devices/sithControl.h"

static int jkGuiControlSaveLoad_aIdk[2] = {0xD, 0xE};
static wchar_t jkGuiControlSaveLoad_awTmp[256];
static Darray jkGuiControlSaveLoad_darray;
static int jkGuiControlSaveLoad_dword_559C80;
static int jkGuiControlSaveLoad_dword_559C84;
static char jkGuiControlSaveLoad_tmp[5]; // ?
static wchar_t jkGuiControlSaveLoad_aUnk[1]; // ???

static jkGuiElement jkGuiControlSaveLoad_aElements[9] = {
    { ELEMENT_TEXT, 0, 5, NULL, 3, { 70, 45, 500, 80 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, "GUI_CSLENTERSETNAME", 2, { 400, 160, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBOX, 0, 0, jkGuiControlSaveLoad_awTmp, 64, { 400, 205, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, "GUI_CSLSETSELECT", 2, { 40, 135, 330, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_LISTBOX, 12345, 0, NULL, 0, { 40, 160, 330, 241 }, 1, 0, NULL, NULL, &jkGuiControlSaveLoad_sub_41E470, &jkGuiControlSaveLoad_aIdk, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, { 440, 430, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBUTTON, -1, 2, "GUI_CANCEL", 3, { 0, 430, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBUTTON, 0, 2, "GUI_CSLDELETE", 3, { 230, 430, 180, 40 }, 1, 0, NULL, NULL, &jkGuiControlSaveLoad_ConfirmDelete, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
};

static jkGuiMenu jkGuiControlSaveLoad_menu = {
    &jkGuiControlSaveLoad_aElements, -1, 0xFFFF, 0xFFFF, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, NULL, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

int jkGuiControlSaveLoad_sub_41E470(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, int bRedraw)
{
    wchar_t *v5; // eax
    signed int result; // eax

    jkGuiRend_ClickSound(pElement, pMenu, mouseX, mouseY, bRedraw);
    if ( jkGuiControlSaveLoad_dword_559C84
      && (v5 = jkGuiRend_GetString(&jkGuiControlSaveLoad_darray, jkGuiControlSaveLoad_aElements[4].selectedTextEntry),
          _wcsncpy(jkGuiControlSaveLoad_awTmp, v5, 0xFFu),
          jkGuiControlSaveLoad_awTmp[255] = 0,
          jkGuiRend_UpdateAndDrawClickable(&jkGuiControlSaveLoad_aElements[2], &jkGuiControlSaveLoad_menu, 1),
          bRedraw) )
    {
        result = 12345;
    }
    else
    {
        result = 0;
    }
    return result;
}

int jkGuiControlSaveLoad_ConfirmDelete(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, int bRedraw)
{
    jkGuiControlInfo *v5; // esi
    wchar_t *v6; // eax
    int i; // esi
    void *v8; // eax
    int v9; // eax
    wchar_t *v11; // [esp-8h] [ebp-8Ch]
    char tmp[128]; // [esp+4h] [ebp-80h] BYREF

    jkGuiRend_PlayWav(pMenu->soundClick);
    if ( jkGuiControlSaveLoad_aElements[4].selectedTextEntry < jkGuiControlSaveLoad_darray.total )
    {
        v5 = (jkGuiControlInfo *)jkGuiRend_GetId(&jkGuiControlSaveLoad_darray, jkGuiControlSaveLoad_aElements[4].selectedTextEntry);
        v11 = jkStrings_GetUniStringWithFallback("GUI_CSLCONFIRM_DELETE");
        v6 = jkStrings_GetUniStringWithFallback("GUI_CSLDELETE");
        if ( jkGuiDialog_YesNoDialog(v6, v11) )
        {
            stdString_snprintf(tmp, 128, "controls\\%s", v5->fpath); // Added: sprintf -> snprintf
            stdFileUtil_DelFile(tmp);
            for ( i = 0; i < jkGuiControlSaveLoad_dword_559C84; ++i )
            {
                v8 = (void *)jkGuiRend_GetId(&jkGuiControlSaveLoad_darray, i);
                if ( v8 )
                    free(v8);
            }
            jkGuiRend_DarrayFree(&jkGuiControlSaveLoad_darray);
            jkGuiControlSaveLoad_dword_559C84 = 0;
            jkGuiControlSaveLoad_FindFile();
            jkGuiRend_SetClickableString(&jkGuiControlSaveLoad_aElements[4], &jkGuiControlSaveLoad_darray);
            v9 = jkGuiControlSaveLoad_dword_559C84;
            pElement->bIsVisible = jkGuiControlSaveLoad_dword_559C84 > 0;
            jkGuiControlSaveLoad_aElements[4].selectedTextEntry = 0;
            if ( jkGuiControlSaveLoad_dword_559C80 || (jkGuiControlSaveLoad_aElements[5].bIsVisible = 0, v9 > 0) )
                jkGuiControlSaveLoad_aElements[5].bIsVisible = 1;
        }
        jkGuiRend_Paint(pMenu);
    }
    return 0;
}

void jkGuiControlSaveLoad_FindFile()
{
    stdFileSearch *v0; // esi
    int v1; // ebx
    jkGuiControlInfo *v2; // ebp
    stdFileSearch *v3; // [esp+4h] [ebp-214h]
    char fpath[128]; // [esp+8h] [ebp-210h] BYREF
    jkGuiControlInfoHeader v5; // [esp+88h] [ebp-190h] BYREF
    stdFileSearchResult a2; // [esp+10Ch] [ebp-10Ch] BYREF

    jkGuiRend_DarrayNewStr(&jkGuiControlSaveLoad_darray, 50, 1);
    jkGuiControlSaveLoad_dword_559C84 = 0;
    _sprintf(fpath, "controls\\%s", jkGuiControlSaveLoad_tmp);
    stdFileUtil_MkDir(fpath);
    v0 = stdFileUtil_NewFind(fpath, 3, "ctl");
    v3 = v0;
    if ( v0 && stdFileUtil_FindNext(v0, &a2) )
    {
        do
        {
            _sprintf(fpath, "controls\\%s", a2.fpath);
            v1 = pHS->fileOpen(fpath, "rb");
            if ( v1 )
            {
                if ( pHS->fileRead(v1, &v5, sizeof(jkGuiControlInfoHeader)) == sizeof(jkGuiControlInfoHeader) && v5.version == 1 )
                {
                    v2 = (jkGuiControlInfo *)pHS->alloc(sizeof(jkGuiControlInfo));
                    _memcpy(v2, &v5, sizeof(jkGuiControlInfoHeader));
                    stdString_SafeStrCopy(v2->fpath, a2.fpath, 0x80);
                    _strtolower(v2->fpath);
                    jkGuiRend_DarrayReallocStr(&jkGuiControlSaveLoad_darray, v2->header.wstr, (intptr_t)v2);
                    v0 = v3;
                    ++jkGuiControlSaveLoad_dword_559C84;
                }
                pHS->fileClose(v1);
            }
        }
        while ( stdFileUtil_FindNext(v0, &a2) );
    }
    stdFileUtil_DisposeFind(v0);
    jkGuiRend_DarrayReallocStr(&jkGuiControlSaveLoad_darray, 0, 0);
}

int jkGuiControlSaveLoad_Write(int bIdk)
{
    const char *v1; // eax
    int v2; // eax
    signed int v3; // edi
    jkGuiControlInfo *v5; // eax
    char *v6; // eax
    int v7; // edx
    char *v8; // ebp
    int v12; // esi
    jkGuiControlInfo *pInfo; // eax
    int i; // eax
    int k; // esi
    void *v16; // eax
    signed int result; // eax
    int j; // esi
    void *v19; // eax
    int v21; // [esp+10h] [ebp-188h] BYREF
    jkGuiControlInfoHeader headerTmp; // [esp+14h] [ebp-184h] BYREF
    char fpath[128]; // [esp+98h] [ebp-100h] BYREF
    char tmp1[128]; // [esp+118h] [ebp-80h] BYREF

    jkGuiControlSaveLoad_dword_559C80 = bIdk;
    jkGuiControlSaveLoad_FindFile();
    jkGuiRend_SetClickableString(&jkGuiControlSaveLoad_aElements[4], &jkGuiControlSaveLoad_darray);
    jkGuiControlSaveLoad_aElements[3].bIsVisible = bIdk == 0;
    jkGuiControlSaveLoad_aElements[4].selectedTextEntry = 0;
    jkGuiControlSaveLoad_aElements[1].bIsVisible = bIdk;
    jkGuiControlSaveLoad_aElements[2].bIsVisible = bIdk;
    jkGuiControlSaveLoad_aElements[7].bIsVisible = jkGuiControlSaveLoad_dword_559C84 > 0;
    if ( bIdk || (jkGuiControlSaveLoad_aElements[5].bIsVisible = 0, jkGuiControlSaveLoad_dword_559C84 > 0) )
        jkGuiControlSaveLoad_aElements[5].bIsVisible = 1;
    v1 = "GUI_CSLSAVESET";
    if ( !bIdk )
        v1 = "GUI_CSLLOADSET";
    jkGuiControlSaveLoad_aElements[0].wstr = (const char *)jkStrings_GetUniString(v1);
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiControlSaveLoad_menu, &jkGuiControlSaveLoad_aElements[5]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiControlSaveLoad_menu, &jkGuiControlSaveLoad_aElements[6]);
    _wcsncpy(jkGuiControlSaveLoad_awTmp, jkGuiControlSaveLoad_aUnk, 0xFFu);
    jkGuiControlSaveLoad_awTmp[255] = 0;
    while ( 1 )
    {
        v2 = jkGuiRend_DisplayAndReturnClicked(&jkGuiControlSaveLoad_menu);
        v3 = v2;
        if ( v2 != 1 && v2 != 12345 )
            goto LABEL_43;
        if ( !bIdk || _wcslen(jkGuiControlSaveLoad_awTmp) )
            break;
        jkGuiDialog_ErrorDialog(jkStrings_GetUniStringWithFallback("ERROR"), jkStrings_GetUniStringWithFallback("GUI_CSLMUSTENTERNAME"));
    }
    if ( jkGuiControlSaveLoad_aElements[4].selectedTextEntry < 0 || jkGuiControlSaveLoad_aElements[4].selectedTextEntry >= jkGuiControlSaveLoad_darray.total )
        v5 = 0;
    else
        v5 = (jkGuiControlInfo *)jkGuiRend_GetId(&jkGuiControlSaveLoad_darray, jkGuiControlSaveLoad_aElements[4].selectedTextEntry);
    if ( bIdk )
    {
        if ( v3 == 1 || !v5 )
        {
            v6 = (char *)pHS->alloc(jkGuiControlSaveLoad_dword_559C84 + 1);
            v7 = jkGuiControlSaveLoad_dword_559C84;
            v8 = v6;
            memset(v6, 0, jkGuiControlSaveLoad_dword_559C84 + 1);
            v12 = 0;
            if ( v7 > 0 )
            {
                do
                {
                    pInfo = (jkGuiControlInfo *)jkGuiRend_GetId(&jkGuiControlSaveLoad_darray, v12);
                    if ( pInfo && _sscanf(pInfo->fpath, "set%04d.ctl", &v21) == 1 )
                    {
                        v7 = jkGuiControlSaveLoad_dword_559C84;
                        if ( v21 <= jkGuiControlSaveLoad_dword_559C84 )
                            v8[v21] = 1;
                    }
                    else
                    {
                        v7 = jkGuiControlSaveLoad_dword_559C84;
                    }
                    ++v12;
                }
                while ( v12 < v7 );
            }
            for ( i = 0; i <= v7; ++i )
            {
                if ( !v8[i] )
                    break;
            }
            _sprintf(tmp1, "set%04d.ctl", i);
            pHS->free(v8);
            _sprintf(fpath, "controls\\%s", tmp1);
        }
        else
        {
            _sprintf(fpath, "controls\\%s", v5->fpath);
        }
        v3 = 1;
        headerTmp.version = 1;
        _wcsncpy(headerTmp.wstr, (const wchar_t *)jkGuiControlSaveLoad_aElements[2].wstr, 0x3Fu);
        headerTmp.wstr[63] = 0;
        if ( stdConffile_OpenWrite(fpath) )
        {
            stdConffile_Write(&headerTmp, sizeof(jkGuiControlInfoHeader));
            sithControl_WriteConf();
            stdConffile_CloseWrite();
            goto LABEL_43;
        }
    }
    else
    {
        if ( !v5 )
            goto LABEL_43;
        _sprintf(fpath, "controls\\%s", v5->fpath);
        if ( stdConffile_OpenMode(fpath, "rb") )
        {
            stdConffile_Read(&headerTmp, sizeof(jkGuiControlInfoHeader));
            if ( headerTmp.version == 1 )
            {
                sithControl_ReadConf();
                stdConffile_Close();
LABEL_43:
                for ( j = 0; j < jkGuiControlSaveLoad_dword_559C84; ++j )
                {
                    v19 = (void *)jkGuiRend_GetId(&jkGuiControlSaveLoad_darray, j);
                    if ( v19 )
                        free(v19);
                }
                jkGuiRend_DarrayFree(&jkGuiControlSaveLoad_darray);
                result = v3;
                jkGuiControlSaveLoad_dword_559C84 = 0;
                return result;
            }
        }
    }
    for ( k = 0; k < jkGuiControlSaveLoad_dword_559C84; ++k )
    {
        v16 = (void *)jkGuiRend_GetId(&jkGuiControlSaveLoad_darray, k);
        if ( v16 )
            free(v16);
    }
    jkGuiRend_DarrayFree(&jkGuiControlSaveLoad_darray);
    jkGuiControlSaveLoad_dword_559C84 = 0;
    stdConffile_Close();
    return -1;
}

void jkGuiControlSaveLoad_Startup()
{
    jkGui_InitMenu(&jkGuiControlSaveLoad_menu, jkGui_stdBitmaps[JKGUI_BM_BK_SETUP]);
}

void jkGuiControlSaveLoad_Shutdown()
{
    // Added: clean reset
    memset(jkGuiControlSaveLoad_awTmp, 0, sizeof(jkGuiControlSaveLoad_awTmp));
    memset(&jkGuiControlSaveLoad_darray, 0, sizeof(jkGuiControlSaveLoad_darray)); // TODO free?
    jkGuiControlSaveLoad_dword_559C80 = 0;
    jkGuiControlSaveLoad_dword_559C84 = 0;
    memset(jkGuiControlSaveLoad_tmp, 0, sizeof(jkGuiControlSaveLoad_tmp));
    memset(jkGuiControlSaveLoad_aUnk, 0, sizeof(jkGuiControlSaveLoad_aUnk));
}