#include "jkMain.h"

#include "../jk.h"
#include "Engine/sithNet.h"
#include "Engine/sith.h"
#include "Main/jkSmack.h"
#include "Main/jkGame.h"
#include "Main/jkCutscene.h"
#include "Main/jkHudInv.h"
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

#define jkMain_VideoShow ((void*)(0x00404270))
#define jkMain_VideoTick ((void*)(0x00404350))
#define jkMain_VideoLeave ((void*)(0x00404430))
#define jkMain_CutsceneShow ((void*)(0x00404450))
#define jkMain_CutsceneTick ((void*)(0x00404460))
#define jkMain_CutsceneLeave ((void*)(0x00404470))
#define jkMain_CreditsShow ((void*)(0x00404480))
#define jkMain_CreditsTick ((void*)(0x004044B0))
#define jkMain_CreditsLeave ((void*)(0x004044E0))
#define jkMain_ChoiceShow ((void*)(0x004044F0))
#define jkMain_ChoiceTick ((void*)(0x00404550))
#define jkMain_ChoiceLeave ((void*)(0x00404560))
#define jkMain_UnkShow ((void*)(0x00404570))
#define jkMain_UnkTick ((void*)(0x00404580))
#define jkMain_UnkLeave ((void*)(0x004045F0))
#define jkMain_GameplayShow ((void*)(0x00403AB0))
#define jkMain_GameplayLeave ((void*)(0x00403E60))
#define jkMain_EscapeMenuShow ((void*)(0x00403F40))
#define jkMain_EscapeMenuLeave ((void*)(0x004040A0))
#define jkMain_EndLevelScreenShow ((void*)(0x004041A0))
#define jkMain_EndLevelScreenTick ((void*)(0x00404240))
#define jkMain_EndLevelScreenLeave ((void*)(0x00404250))
#define jkMain_CdSwitchShow ((void*)(0x00404260))

static jkGuiStateFuncs jkMain_aGuiStateFuncs[15] = {
    {0,  0,  0},
    {jkMain_VideoShow, jkMain_VideoTick, jkMain_VideoLeave},
    {jkMain_TitleShow, jkMain_TitleTick, jkMain_TitleLeave},
    {jkMain_MainShow, jkMain_MainTick, jkMain_MainLeave},
    {jkMain_VideoShow, jkMain_VideoTick, jkMain_VideoLeave},
    {jkMain_GameplayShow, jkMain_GameplayTick, jkMain_GameplayLeave},
    {jkMain_EscapeMenuShow, jkMain_EscapeMenuTick, jkMain_EscapeMenuLeave},
    {jkMain_CdSwitchShow,  0,  0},
    {jkMain_VideoShow, jkMain_VideoTick, jkMain_VideoLeave},
    {jkMain_EndLevelScreenShow, jkMain_EndLevelScreenTick, jkMain_EndLevelScreenLeave},
    {jkMain_VideoShow, jkMain_VideoTick, jkMain_VideoLeave},
    {jkMain_ChoiceShow, jkMain_ChoiceTick, jkMain_ChoiceLeave},
    {jkMain_CutsceneShow, jkMain_CutsceneTick, jkMain_CutsceneLeave},
    {jkMain_CreditsShow, jkMain_CreditsTick, jkMain_CreditsLeave},
    {jkMain_UnkShow, jkMain_UnkTick, jkMain_UnkLeave},
};

void jkMain_GuiAdvance()
{
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
            if ( net_isMulti && !thing_six)
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
                if ( g_app_suspended && jkSmack_currentGuiState != 6 )
                    jkGame_Update();
                game_updateMsecsTotal += stdPlatform_GetTimeMsec() - v3;
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
        v5 = jkMain_aGuiStateFuncs[jkSmack_currentGuiState].leaveFunc;
        if ( v5 )
            v5(jkSmack_currentGuiState, jkSmack_nextGuiState);
        //jk_printf("leave %u\n", jkSmack_currentGuiState);

        v6 = jkSmack_nextGuiState;
        jkSmack_stopTick = 0;
        jkSmack_currentGuiState = jkSmack_nextGuiState;
        v7 = jkMain_aGuiStateFuncs[jkSmack_nextGuiState].showFunc;
        if ( !v7 )
            goto LABEL_35;
        v7(jkSmack_nextGuiState, v4);
        //jk_printf("show %u\n", jkSmack_currentGuiState);
    }
    v6 = jkSmack_currentGuiState;
LABEL_35:
    if ( !jkSmack_stopTick )
    {
        //jk_printf("tick %u %x\n", jkSmack_currentGuiState, jkMain_aGuiStateFuncs[v6].tickFunc);
        v8 = jkMain_aGuiStateFuncs[v6].tickFunc;
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

int jkMain_TitleShow()
{
    jkGuiTitle_ShowLoadingStatic();
    sith_Load("static.jkl");
#ifdef WIN32
    return jkHudInv_items_init();
#else
    return 1;
#endif
}

void jkMain_TitleTick()
{
    jkGuiTitle_LoadingFinalize();
    if ( jkGuiRend_thing_five )
        jkGuiRend_thing_four = 1;
    jkSmack_stopTick = 1;
    jkSmack_nextGuiState = 3;
}

void jkMain_TitleLeave()
{
    ;
}

void jkMain_MainShow()
{
    jkGuiMain_Show();
}

void jkMain_MainTick()
{
    ;
}

void jkMain_MainLeave()
{
    ;
}
