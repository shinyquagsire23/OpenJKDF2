#include "sith.h"

#include "Main/jkGame.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithUnk3.h"
#include "World/sithUnk4.h"
#include "General/sithStrTable.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "Win95/sithDplay.h"
#include "Win95/DebugConsole.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "Engine/sithTimer.h"
#include "Engine/sithRender.h"
#include "Engine/sithCamera.h"
#include "Engine/sithSprite.h"
#include "Engine/sithParticle.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithMaterial.h"
#include "Engine/sithTemplate.h"
#include "Engine/sithModel.h"
#include "Engine/sithSurface.h"
#include "Engine/sithSound.h"
#include "Engine/sithSoundSys.h"
#include "Engine/sithTime.h"
#include "Engine/sithRender.h"
#include "Engine/sithControl.h"
#include "Engine/sithMulti.h"
#include "Engine/sithSave.h"
#include "Engine/sithNet.h"
#include "World/sithWeapon.h"
#include "World/sithSector.h"
#include "Cog/sithCog.h"
#include "jk.h"

int sith_Startup(struct common_functions *commonFuncs)
{
    int is_started; // esi

    pSithHS = commonFuncs;
    is_started = sithStrTable_Startup() & 1;
    is_started = sithTimer_Startup() & is_started;
    is_started = sithWorld_Startup() & is_started;
    is_started = sithRender_Startup() & is_started;
    is_started = sithUnk3_Startup() & is_started;
    is_started = sithThing_Startup() & is_started;
    is_started = sithCogVm_Startup() & is_started;
    is_started = sithDplay_Startup() & is_started;
    is_started = sithCog_Startup() & is_started;
    is_started = sithAI_Startup() & is_started;
    is_started = sithSprite_Startup() & is_started;
    is_started = sithParticle_Startup() & is_started;
    is_started = sithPuppet_Startup() & is_started;
    is_started = sithAIClass_Startup() & is_started;
    is_started = sithSoundClass_Startup() & is_started;
    is_started = sithMaterial_Startup() & is_started;
    is_started = sithTemplate_Startup() & is_started;
    is_started = sithModel_Startup() & is_started;
    is_started = sithSurface_Startup() & is_started;
    sithSound_Startup();
    sithSoundSys_Startup();
    sithWeapon_Startup();
    _memset(&g_sithMode, 0, 0x18u);

    if ( !is_started )
        return 0;

    sith_bInitialized = 1;
    return 1;
}

// sith_Shutdown

void sith_UpdateCamera()
{
    if ( (g_submodeFlags & 8) == 0 )
    {
        if ( !++dword_8EE678 )
        {
            sithWorld_sub_4D0A20(sithWorld_pCurWorld);
            dword_8EE678 = 1;
        }
#ifdef QOL_IMPROVEMENTS
        if (sithCamera_currentCamera && sithCamera_currentCamera->rdCam.canvas)
        {
            // Set screen aspect ratio
            float aspect = sithCamera_currentCamera->rdCam.canvas->screen_width_half / sithCamera_currentCamera->rdCam.canvas->screen_height_half;
            rdCamera_SetFOV(&sithCamera_currentCamera->rdCam, jkPlayer_fov);
            rdCamera_SetAspectRatio(&sithCamera_currentCamera->rdCam, aspect);
        }
#endif

        //sithCamera_currentCamera->rdCam.screenAspectRatio += 0.01;
        sithCamera_FollowFocus(sithCamera_currentCamera);
        sithCamera_SetRdCameraAndRenderidk();
    }
}

int sith_Load(char *path)
{
    sithWorld_pStatic = sithWorld_New();
    sithWorld_pStatic->level_type_maybe |= 1;
    return sithWorld_Load(sithWorld_pStatic, path) != 0;
}

// sith_Free

int sith_Mode1Init(char *a1)
{
    sithWorld_pCurWorld = sithWorld_New();

    if ( !sithWorld_Load(sithWorld_pCurWorld, a1) )
        return 0;

    sithTime_Startup();
    sithWorld_Initialize();
    bShowInvisibleThings = 0;
    sithRender_8EE678 = 1;
    sithWorld_sub_4D0A20(sithWorld_pCurWorld);
    sithTimer_Open();
    sithSurface_Open();
    sithAI_Open();
    sithSoundSys_Open();
    sithCog_Open();
    sithControl_Open();
    sithSector_Startup();
    sithRender_Open();
    sithWeapon_InitializeEntry();
    sithTime_Startup();
    g_sithMode = 1;
    sith_bOpened = 1;
    return 1;
}

int sith_Tick()
{
    if ( (g_submodeFlags & 8) != 0 )
    {
        sithTime_Tick();
        sithCogVm_Sync();
        sithSurface_Tick(sithTime_deltaSeconds);
        sithThing_TickAll(sithTime_deltaSeconds, sithTime_deltaMs);
        DebugConsole_AdvanceLogBuf();
        return 1;
    }
    else
    {
        // TODO REMOVE
        //sithWorld_pCurWorld->playerThing->physicsParams.physflags |= PHYSFLAGS_FLYING;
        //sithWorld_pCurWorld->playerThing->physicsParams.physflags &= ~PHYSFLAGS_GRAVITY;
        
        
        ++bShowInvisibleThings;
        if (sithRender_8EE678++ == -1)
        {
            sithWorld_sub_4D0A20(sithWorld_pCurWorld);
            sithRender_8EE678 = 1;
        }
        sithSoundSys_ResumeMusic(0);
        sithTime_Tick();
        sithSoundSys_Tick(sithTime_deltaSeconds);
        sithTimer_Advance();

        if ( sithCogVm_bSyncMultiplayer )
            sithCogVm_Sync();

#ifndef LINUX_TMP
        if ( (g_debugmodeFlags & 1) == 0 )
            sithAI_TickAll();

        sithSurface_Tick(sithTime_deltaSeconds);
#endif

        if ( g_sithMode != 2 )
        {
            sithControl_Tick(sithTime_deltaSeconds, sithTime_deltaMs);
        }

        sithThing_TickAll(sithTime_deltaSeconds, sithTime_deltaMs);
#ifndef LINUX_TMP
        sithCogScript_TickAll();
#endif
        DebugConsole_AdvanceLogBuf();
#ifndef LINUX_TMP
        sithMulti_HandleTimeLimit(sithTime_deltaMs);
        sithSave_WriteEntry();
#endif
        return 0;
    }
}

void sith_set_some_text_jk1(char *text)
{
    _strncpy(sithWorld_some_text_jk1, text, 0x1Fu);
    sithWorld_some_text_jk1[31] = 0;
}

void sith_AutoSave()
{
    sithWorld *v0; // ecx
    unsigned int v1; // ebx
    int v2; // edi
    sithThing *v3; // esi
    sithCog *v4; // eax
    char v5[128]; // [esp+10h] [ebp-80h] BYREF


    sithTime_Startup();
    sithInventory_Reset(g_localPlayerThing);

#ifdef LINUX_TMP
    return;
#endif

    sithCog_SendSimpleMessageToAll(SITH_MESSAGE_STARTUP, 0, 0, 0, 0);
    v0 = sithWorld_pCurWorld;
    v1 = 0;
    if ( sithWorld_pCurWorld->numThingsLoaded )
    {
        v2 = 0;
        do
        {
            v3 = &v0->things[v2];
            v4 = v3->class_cog;
            if ( v4 )
            {
                sithCog_SendMessage(v4, SITH_MESSAGE_CREATED, SENDERTYPE_THING, v3->thingIdx, 0, 0, 0);
                v0 = sithWorld_pCurWorld;
            }
            if ( v3->thingType == THINGTYPE_ACTOR )
            {
                sithUnk4_SetMaxHeathForDifficulty(v3);
                v0 = sithWorld_pCurWorld;
            }
            ++v1;
            ++v2;
        }
        while ( v1 < v0->numThingsLoaded );
    }
    if ( net_isMulti )
    {
        sithPlayer_debug_ToNextCheckpoint(g_localPlayerThing);
        sithMulti_sendmsgidk3(sithDplay_dword_8321EC, playerThingIdx, -1);
        sithMulti_sendmsgidk3(sithDplay_dword_8321EC, playerThingIdx, -1);
        sithTime_Startup();
    }
    else
    {
        stdString_snprintf(v5, 128, "%s%s", "_JKAUTO_", v0->map_jkl_fname);
        stdFnames_ChangeExt(v5, "jks");
        sithSave_Write(v5, 1, 0, 0);
        sithTime_Startup();
    }
}
