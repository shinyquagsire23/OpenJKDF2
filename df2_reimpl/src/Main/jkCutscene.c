#include "jkCutscene.h"

#include "General/stdStrTable.h"
#include "General/stdFont.h"
#include "Win95/Window.h"
#include "Win95/Video.h"
#include "Win95/stdDisplay.h"
#include "World/jkPlayer.h"
#include "Main/jkMain.h"
#include "Main/Main.h"
#include "Main/jkStrings.h"

#include "../jk.h"

// TODO actually fill this in with an alternative Smack decoder

void jkCutscene_Initialize(char *fpath)
{
    stdStrTable_Load(&jkCutscene_strings, fpath);
    jkCutscene_subtitlefont = stdFont_Load("ui\\sft\\subtitlefont.sft", 0, 0);
    jkCutscene_rect1.x = 10;
    jkCutscene_rect2.y = 10;
    jkCutscene_rect1.y = 360;
    jkCutscene_rect1.width = 620;
    jkCutscene_rect1.height = 120;
    jkCutscene_rect2.x = 0;
    jkCutscene_rect2.width = 640;
    jkCutscene_rect2.height = 40;
    jkCutscene_bInitted = 1;
}

void jkCutscene_Shutdown()
{
    if ( jkCutscene_subtitlefont )
    {
        stdFont_Free(jkCutscene_subtitlefont);
        jkCutscene_subtitlefont = 0;
    }
    stdStrTable_Free(&jkCutscene_strings);
    jkCutscene_bInitted = 0;
}

int jkCutscene_sub_421310(int a1)
{
    // STUBBED
    return 1;
}

int jkCutscene_sub_421410()
{
    if ( !jkCutscene_smack_loaded )
        return 0;
    Window_RemoveMsgHandler(jkCutscene_Handler);
    //smack_sub_426940();
    jkCutscene_smack_loaded = 0;
    jk_ShowCursor(1);
    return 1;
}

int jkCutscene_smack_related_loops()
{
    signed int smack_finished; // esi
    int v2; // ecx

    smack_finished = 0;
    if ( !jkCutscene_smack_loaded )
        return 1;
    if ( !jkCutscene_55AA54 && g_app_suspended )
    {
        smack_finished = 1;//smack_process();
        if ( smack_finished )
        {
            if ( jkCutscene_smack_loaded )
            {
                Window_RemoveMsgHandler(jkCutscene_Handler);
                //smack_sub_426940();
                jkCutscene_smack_loaded = 0;
                jk_ShowCursor(1);
            }
        }
        else if ( jkCutscene_dword_55B750 != jkCutscene_dword_55AA50 )
        {
            stdDisplay_VBufferFill(&Video_otherBuf, 0, &jkCutscene_rect1);
            v2 = jkCutscene_dword_55B750;
            if ( (jkCutscene_dword_55B750 < 0 || jkPlayer_setFullSubtitles) && (jkCutscene_dword_55B750 & 0x7FFFFFFF) != 0 )
            {
                stdFont_Draw3(
                    &Video_otherBuf,
                    jkCutscene_subtitlefont,
                    360,
                    &jkCutscene_rect1,
                    1,
                    jkCutscene_strings.msgs[jkCutscene_dword_55B750 & 0x7FFFFFFF].uniStr,
                    0);
                v2 = jkCutscene_dword_55B750;
            }
            jkCutscene_dword_55AA50 = v2;
        }
        if ( Main_bWindowGUI )
        {
            stdDisplay_DDrawGdiSurfaceFlip();
            return smack_finished;
        }
    }
    return smack_finished;
}

int jkCutscene_PauseShow()
{
    wchar_t *v0; // eax
    int result; // eax

    if ( jkCutscene_55AA54 )
    {
        v0 = jkStrings_GetText("GUI_PAUSED");
        stdFont_Draw4(&Video_otherBuf, jkCutscene_subtitlefont, 0, 10, 640, 40, 3, v0, 0);
    }
    else
    {
        stdDisplay_VBufferFill(&Video_otherBuf, 0, &jkCutscene_rect2);
    }
    result = Main_bWindowGUI;
    if ( Main_bWindowGUI )
        result = stdDisplay_DDrawGdiSurfaceFlip();
    return result;
}

int jkCutscene_Handler(HWND a1, UINT a2, WPARAM a3, LPARAM a4, LRESULT *a5)
{
    wchar_t *v5; // eax
    int v7; // [esp-4h] [ebp-8h]

    switch ( a2 )
    {
        case 0x10u:
            //smack_sub_426940();
            break;
        case 0x20u:
            jk_SetCursor(0);
            return 1;
        case 0x102u:
            if ( a3 != 0x1B )
            {
                if ( a3 == 0x20 )
                {
                    v7 = jkCutscene_55AA54 == 0;
                    jkCutscene_55AA54 = v7;
                    //smack_off(v7);
                    if ( jkCutscene_55AA54 )
                    {
                        v5 = jkStrings_GetText("GUI_PAUSED");
                        stdFont_Draw4(&Video_otherBuf, jkCutscene_subtitlefont, 0, 10, 640, 40, 3, v5, 0);
                    }
                    else
                    {
                        stdDisplay_VBufferFill(&Video_otherBuf, 0, &jkCutscene_rect2);
                    }
                    if ( Main_bWindowGUI )
                    {
                        stdDisplay_DDrawGdiSurfaceFlip();
                        return 0;
                    }
                }
                return 0;
            }
            if ( jkCutscene_smack_loaded )
            {
                Window_RemoveMsgHandler(jkCutscene_Handler);
                //smack_sub_426940();
                jkCutscene_smack_loaded = 0;
                jk_ShowCursor(1);
                return 1;
            }
            return 1;
    }
    return 0;
}
