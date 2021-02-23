#include "jkMain.h"

#include "../jk.h"
#include "Engine/sithNet.h"
#include "Engine/sith.h"
#include "Main/jkSmack.h"
#include "Main/jkGame.h"
#include "Main/jkCutscene.h"
#include "Gui/jkGUIRend.h"
#include "World/jkPlayer.h"
#include "World/jkSaber.h"
#include "Win95/stdControl.h"
#include "stdPlatform.h"
#include "jkGame.h"

#ifdef QOL_IMPROVEMENTS
#define TICKRATE_MS (1) // no cap
#else
#define TICKRATE_MS (20) // 50fps
#endif

void jkMain_gui_loop()
{
    int v0; // edi
    unsigned int v1; // esi
    int v3; // esi
    int v4; // esi
    void (__cdecl *v5)(int, int); // ecx
    int v6; // eax
    void (__cdecl *v7)(int, int); // ecx
    int (__cdecl *v8)(int); // ecx

    if ( !g_app_suspended )
    {
        if ( thing_nine )
            stdControl_ToggleCursor(0);
        if ( thing_eight )
        {
            if ( net_isMulti )
            {
                v0 = jkSmack_currentGuiState;
                if ( !thing_six )
                {
                    v1 = stdPlatform_GetTimeMsec();
                    
                    if (v1 > jkMain_lastTickMs + TICKRATE_MS)
                    {
                        jkMain_lastTickMs = v1;
                        if (!sith_Tick()) return;
                    }
                    
                    if ( g_sithMode == 5 )
                    {
                        if ( jkGuiRend_thing_five )
                            jkGuiRend_thing_four = 1;
                        jkSmack_stopTick = 1;
                        jkSmack_nextGuiState = 3;
                        thing_nine = 0;
                        return;
                    }
                    if ( net_dword_832638 )
                    {
                        net_dword_832638 = 0;
                        if ( net_isServer )
                            jkSaber_cogMsg_SendEndLevel();
                    }
                    if ( sith_bEndLevel )
                    {
                        sith_bEndLevel = 0;
                        jkMain_EndLevel(1);
                    }
                    jkPlayer_nullsub_1(&playerThings[playerThingIdx]);
                    dword_552B5C += stdPlatform_GetTimeMsec() - v1;
                    v3 = stdPlatform_GetTimeMsec();
                    if ( g_app_suspended && v0 != 6 )
                        jkGame_Update();
                    game_updateMsecsTotal += stdPlatform_GetTimeMsec() - v3;
                }
            }
        }
        thing_nine = 0;
        return;
    }
    if ( !thing_nine )
    {
        switch ( jkSmack_currentGuiState )
        {
            case 1:
            case 4:
            case 8:
            case 10:
                jkCutscene_PauseShow(0);
                break;
            case 5:
                stdControl_ToggleCursor(1);
                jkGame_ddraw_idk_palettes(0);
                break;
            default:
                break;
        }
        stdControl_Flush();
        thing_nine = 1;
    }
    if ( jkSmack_stopTick && !jkGuiRend_thing_five )
    {
        jkGuiRend_thing_four = 0;
        v4 = jkSmack_currentGuiState;
        v5 = guiStateFuncs[jkSmack_currentGuiState].leaveFunc;
        if ( v5 )
            v5(jkSmack_currentGuiState, jkSmack_nextGuiState);
        v6 = jkSmack_nextGuiState;
        jkSmack_stopTick = 0;
        jkSmack_currentGuiState = jkSmack_nextGuiState;
        v7 = guiStateFuncs[jkSmack_nextGuiState].showFunc;
        if ( !v7 )
            goto LABEL_35;
        v7(jkSmack_nextGuiState, v4);
    }
    v6 = jkSmack_currentGuiState;
LABEL_35:
    if ( !jkSmack_stopTick )
    {
        v8 = guiStateFuncs[v6].tickFunc;
        if ( v8 )
            v8(v6);
    }
}

void jkMain_EscapeMenuTick(int a2)
{
    unsigned int v1; // esi
    int v3; // esi

    if ( net_isMulti )
    {
        if ( !thing_six )
        {
            if ( thing_eight )
            {
                v1 = stdPlatform_GetTimeMsec();
                
                if (v1 > jkMain_lastTickMs + TICKRATE_MS)
                {
                    jkMain_lastTickMs = v1;
                    if (sith_Tick()) return;
                }
                
                if ( g_sithMode == 5 )
                {
                    if ( jkGuiRend_thing_five )
                        jkGuiRend_thing_four = 1;
                    jkSmack_stopTick = 1;
                    jkSmack_nextGuiState = 3;
                }
                else
                {
                    if ( net_dword_832638 )
                    {
                        net_dword_832638 = 0;
                        if ( net_isServer )
                            jkSaber_cogMsg_SendEndLevel();
                    }
                    if ( sith_bEndLevel )
                    {
                        sith_bEndLevel = 0;
                        jkMain_EndLevel(1);
                    }
                    jkPlayer_nullsub_1(&playerThings[playerThingIdx]);
                    dword_552B5C += stdPlatform_GetTimeMsec() - v1;
                    v3 = stdPlatform_GetTimeMsec();
                    if ( g_app_suspended && a2 != 6 )
                        jkGame_Update();
                    game_updateMsecsTotal += stdPlatform_GetTimeMsec() - v3;
                }
            }
        }
    }
}

void jkMain_GameplayTick(int a2)
{
    unsigned int v1; // esi
    int v3; // esi

    if ( !thing_six )
    {
        if ( thing_eight )
        {
            v1 = stdPlatform_GetTimeMsec();
            
            if (v1 > jkMain_lastTickMs + TICKRATE_MS)
            {
                jkMain_lastTickMs = v1;
                if (sith_Tick()) return;
            }
            
            if ( g_sithMode == 5 )
            {
                if ( jkGuiRend_thing_five )
                    jkGuiRend_thing_four = 1;
                jkSmack_stopTick = 1;
                jkSmack_nextGuiState = 3;
            }
            else
            {
                if ( net_dword_832638 )
                {
                    net_dword_832638 = 0;
                    if ( net_isServer )
                        jkSaber_cogMsg_SendEndLevel();
                }
                if ( sith_bEndLevel )
                {
                    sith_bEndLevel = 0;
                    jkMain_EndLevel(1);
                }
                jkPlayer_nullsub_1(&playerThings[playerThingIdx]);
                dword_552B5C += stdPlatform_GetTimeMsec() - v1;
                v3 = stdPlatform_GetTimeMsec();
                if ( g_app_suspended && a2 != 6 )
                    jkGame_Update();
                game_updateMsecsTotal += stdPlatform_GetTimeMsec() - v3;
            }
        }
    }
}
