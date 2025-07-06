#include "sithMain.h"

#include "Main/jkGame.h"
#include "Main/Main.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "Engine/sithCollision.h"
#include "World/sithActor.h"
#include "General/sithStrTable.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "Win95/stdComm.h"
#include "Devices/sithConsole.h"
#include "Win95/Window.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "AI/sithAIAwareness.h"
#include "Gameplay/sithEvent.h"
#include "Engine/sithRender.h"
#include "Engine/sithCamera.h"
#include "World/sithSprite.h"
#include "Engine/sithParticle.h"
#include "Engine/sithPuppet.h"
#include "World/sithSoundClass.h"
#include "World/sithMaterial.h"
#include "World/sithTemplate.h"
#include "World/sithModel.h"
#include "World/sithSurface.h"
#include "Devices/sithSound.h"
#include "Devices/sithSoundMixer.h"
#include "Gameplay/sithTime.h"
#include "Engine/sithRender.h"
#include "Devices/sithControl.h"
#include "Dss/sithMulti.h"
#include "Dss/sithGamesave.h"
#include "World/sithWeapon.h"
#include "World/sithSector.h"
#include "World/jkPlayer.h"
#include "Cog/sithCog.h"
#include "Devices/sithComm.h"
#include "stdPlatform.h"
#include "jk.h"

#ifdef FIXED_TIMESTEP_PHYS
#include <math.h>
#endif

flex_t sithMain_lastAspect = 1.0;

int sithMain_Startup(HostServices *commonFuncs)
{
    int is_started; // esi

    pSithHS = commonFuncs;
    is_started = sithStrTable_Startup() & 1;
    is_started = sithEvent_Startup() & is_started;
    is_started = sithWorld_Startup() & is_started;
    is_started = sithRender_Startup() & is_started;
    is_started = sithCollision_Startup() & is_started;
    is_started = sithThing_Startup() & is_started;
    is_started = sithComm_Startup() & is_started;
    is_started = stdComm_Startup() & is_started;
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
    sithSoundMixer_Startup();
    sithWeapon_Startup();

#ifndef NO_JK_MMAP
    //_memset(&g_sithMode, 0, 0x18u);
#endif
    g_sithMode = 0;
    g_submodeFlags = 0;
    sithSurface_byte_8EE668 = 0;
    g_debugmodeFlags = 0;
    jkPlayer_setDiff = 0;
    g_mapModeFlags = 0;

    // Added
    if (Main_bHeadless || Main_bDedicatedServer) {
        g_debugmodeFlags |= DEBUGFLAG_IN_EDITOR;
    }

    if ( !is_started )
        return 0;

    sithMain_bInitialized = 1;
    return 1;
}

void sithMain_Shutdown()
{
    //sithWeapon
    sithSoundMixer_Shutdown();
    sithSound_Shutdown();
    sithSurface_Shutdown();
    sithModel_Shutdown();
    sithTemplate_Shutdown();
    sithMaterial_Shutdown();
    sithSoundClass_Shutdown();
    sithAIClass_Shutdown();
    sithPuppet_Shutdown();
    sithParticle_Shutdown();
    sithSprite_Shutdown();
    sithAI_Shutdown();
    sithCog_Shutdown();
    stdComm_Shutdown();
    sithComm_Shutdown();
    sithThing_Shutdown();
    sithCollision_Shutdown();
    sithRender_Shutdown();
    sithWorld_Shutdown();
    sithEvent_Shutdown();
    sithStrTable_Shutdown();
    sithMain_bInitialized = 0;
}

int sithMain_Load(char *path)
{
    sithWorld_pStatic = sithWorld_New();
    sithWorld_pStatic->level_type_maybe |= 1;
    return sithWorld_Load(sithWorld_pStatic, path) != 0;
}

void sithMain_Free()
{
    if ( sithWorld_pStatic )
    {
        sithWorld_FreeEntry(sithWorld_pStatic);
        sithWorld_pStatic = 0;
    }
}

int sithMain_Mode1Init(char *a1)
{
    sithWorld_pCurrentWorld = sithWorld_New();

    if ( !sithWorld_Load(sithWorld_pCurrentWorld, a1) )
        return 0;

    sithTime_Startup();
    sithWorld_Initialize();
    sithMain_Open();
    sithTime_Startup();
    g_sithMode = 1;
    return 1;
}

int sithMain_OpenNormal(char *path)
{
    sithWorld_pCurrentWorld = sithWorld_New();

    if ( !sithWorld_Load(sithWorld_pCurrentWorld, path) )
        return 0;

    sithWorld_Initialize();
    sithMain_Open();
    g_sithMode = 1;
    return 1;
}

int sithMain_Mode1Init_3(char *fpath)
{
    sithWorld_pCurrentWorld = sithWorld_New();
    if ( !sithWorld_Load(sithWorld_pCurrentWorld, fpath) )
        return 0;
    sithMain_Open();
    sithTime_Startup();
    sithMulti_Startup();
    g_sithMode = 1;
    return 1;
}

int sithMain_Open()
{
    bShowInvisibleThings = 0;
    sithRender_lastRenderTick = 1;
    sithWorld_sub_4D0A20(sithWorld_pCurrentWorld);
    sithEvent_Open();
    sithSurface_Open();
    sithAI_Open();
    sithSoundMixer_Open();
    sithCog_Open();
    sithControl_Open();
    sithAIAwareness_Startup();
    sithRender_Open();
    sithWeapon_StartupEntry();
    sithMain_bOpened = 1;
    return 1;
}

void sithMain_Close()
{
    if ( sithMain_bOpened )
    {
        sithSoundMixer_StopSong();
        sithRender_Close();
        sithAIAwareness_Shutdown();
        sithControl_Close();
        sithCog_Close();
        sithSoundMixer_Close();
        sithWorld_Free();
        sithAI_Close();
        sithSurface_Startup2();
        sithEvent_Close();
        sithPlayer_Close();
        sithWeapon_ShutdownEntry();
        g_sithMode = 0;
        g_submodeFlags = 0;
        sithMain_bOpened = 0;
    }
}

void sithMain_SetEndLevel()
{
    sithMain_bEndLevel = 1;
}

// MOTS altered
int sithMain_Tick()
{
#if 0
    if (sithWorld_pCurrentWorld) {
        for (int i = 0; i < sithWorld_pCurrentWorld->numKeyframesLoaded; i++) {
            rdKeyframe* keyframe = &sithWorld_pCurrentWorld->keyframes[i];
            if (keyframe->id != i) {
                stdPlatform_Printf("BAD KEYFRAME!! %d -> %d\n", i, keyframe->id);
            }
        }
        
    }
#endif
    
    if ( (g_submodeFlags & 8) != 0 )
    {
        sithTime_Tick();
        sithComm_Sync();

#ifdef FIXED_TIMESTEP_PHYS
        if (NEEDS_STEPPED_PHYS) {
            // Run all physics at a fixed timestep
            flex_d_t rolloverCombine = sithTime_deltaSeconds + sithTime_physicsRolloverFrames;

            flex_d_t framesToApply = rolloverCombine * TARGET_PHYSTICK_FPS; // get number of 50FPS steps passed
            uint32_t wholeFramesToApply = (uint32_t)(float)round((float)framesToApply);
            sithTime_physicsRolloverFrames = rolloverCombine - (((flex_d_t)wholeFramesToApply) * DELTA_PHYSTICK_FPS);

            //printf("%f %f\n", framesToApply, rolloverCombine);

            flex_t tmp = sithTime_deltaSeconds;
            uint32_t tmp2 = sithTime_deltaMs;
            sithTime_deltaSeconds = DELTA_PHYSTICK_FPS;
            sithTime_deltaMs = (int)(DELTA_PHYSTICK_FPS * 1000.0);

            for (int i = (int)framesToApply; i > 0; i--)
            {
                sithSurface_Tick(sithTime_deltaSeconds);
                sithThing_TickAll(sithTime_deltaSeconds, sithTime_deltaMs);
            }

            sithTime_deltaSeconds = tmp;
            sithTime_deltaMs = tmp2;
        }
        else
#endif
        {
            sithSurface_Tick(sithTime_deltaSeconds);
            sithThing_TickAll(sithTime_deltaSeconds, sithTime_deltaMs);
        }
        sithConsole_AdvanceLogBuf();
        return 1;
    }
    else
    {
        // TODO REMOVE
        //sithWorld_pCurrentWorld->playerThing->physicsParams.physflags |= SITH_PF_FLY;
        //sithWorld_pCurrentWorld->playerThing->physicsParams.physflags &= ~SITH_PF_USEGRAVITY;
        
        ++bShowInvisibleThings;
        sithMain_sub_4C4D80();
        sithSoundMixer_ResumeMusic(0);
        sithTime_Tick();

#ifdef FIXED_TIMESTEP_PHYS
        if (NEEDS_STEPPED_PHYS) {
            // Run all physics at a fixed timestep
            flex_d_t rolloverCombine = sithTime_deltaSeconds + sithTime_physicsRolloverFrames;

            flex_d_t framesToApply = rolloverCombine * TARGET_PHYSTICK_FPS; // get number of 50FPS steps passed
            uint32_t wholeFramesToApply = (uint32_t)(float)round((float)framesToApply);
            sithTime_physicsRolloverFrames = rolloverCombine - (((flex_d_t)wholeFramesToApply) * DELTA_PHYSTICK_FPS);

            //printf("%f %f\n", framesToApply, rolloverCombine);

            // TODO figure this out
            sithControl_ReadControls();
            if ( g_sithMode != 2 )
            {
                sithControl_Tick(sithTime_deltaSeconds, sithTime_deltaMs);
            }
            sithControl_FinishRead();

            flex_t tmp = sithTime_deltaSeconds;
            uint32_t tmp2 = sithTime_deltaMs;
            flex_t tmp3 = sithTime_TickHz;
            flex_t tmp4 = stdControl_updateKHz;
            flex_t tmp5 = stdControl_updateHz;
            uint32_t tmp6 = sithTime_curMs;
            sithTime_curMs -= sithTime_deltaMs;
            sithTime_deltaSeconds = DELTA_PHYSTICK_FPS;
            sithTime_deltaMs = (int)(DELTA_PHYSTICK_FPS * 1000.0);
            sithTime_TickHz = 1.0 / sithTime_deltaSeconds;
            //stdControl_updateKHz = 1.0 / (DELTA_PHYSTICK_FPS * 1000.0);
            //stdControl_updateHz = sithTime_TickHz;        

            //printf("%f %u %f %f\n",framesToApply, wholeFramesToApply, rolloverCombine, sithTime_physicsRolloverFrames);

            for (int i = 0; i < wholeFramesToApply; i++)
            {
                sithSoundMixer_Tick(sithTime_deltaSeconds);
                sithEvent_Advance();

                if ( sithComm_bSyncMultiplayer )
                    sithComm_Sync();

                if ( (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) == 0  && (!sithNet_isMulti || sithNet_isMulti && sithNet_isServer))
                    sithAI_TickAll();

                sithSurface_Tick(sithTime_deltaSeconds);
                // TODO
                //if (g_sithMode != 2 )
                //{
                //    sithControl_Tick(sithTime_deltaSeconds, sithTime_deltaMs);
                //}
                sithThing_TickAll(sithTime_deltaSeconds, sithTime_deltaMs);
                sithThing_MotsTick(0x1F, 0, 0);

                sithCogScript_TickAll();

                // COG scripts will sleep for periods of time based on sithTime_curMs,
                // so we have to emulate the current time as well
                sithTime_curMs += sithTime_deltaMs;
            }

            sithTime_deltaSeconds = tmp;
            sithTime_deltaMs = tmp2;
            sithTime_TickHz = tmp3;
            sithTime_curMs = tmp6;
            //stdControl_updateKHz = tmp4;
            //stdControl_updateHz = tmp5;
        }
        else
#endif
        {
            sithSoundMixer_Tick(sithTime_deltaSeconds);
            sithEvent_Advance();

            if ( sithComm_bSyncMultiplayer )
                sithComm_Sync();

            if ( (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) == 0 && (!sithNet_isMulti || sithNet_isMulti && sithNet_isServer))
                sithAI_TickAll();
        
            sithSurface_Tick(sithTime_deltaSeconds);
            if ( g_sithMode != 2 )
            {
#ifdef FIXED_TIMESTEP_PHYS
                sithControl_ReadControls();
#endif
                sithControl_Tick(sithTime_deltaSeconds, sithTime_deltaMs);
#ifdef FIXED_TIMESTEP_PHYS
                sithControl_FinishRead();
#endif
            }

            sithThing_TickAll(sithTime_deltaSeconds, sithTime_deltaMs);
            sithThing_MotsTick(0x1F, 0, 0);

            sithCogScript_TickAll();
        }

        //sithAI_PrintThings();
        
        sithConsole_AdvanceLogBuf();
        sithMulti_HandleTimeLimit(sithTime_deltaMs);
        sithGamesave_Flush();
        return 0;
    }
}

void sithMain_UpdateCamera()
{
    if ( (g_submodeFlags & 8) == 0 )
    {
        sithMain_sub_4C4D80();

#ifdef QOL_IMPROVEMENTS
        if (sithCamera_currentCamera && sithCamera_currentCamera->rdCam.canvas)
        {
            // Set screen aspect ratio
            flex_t aspect = sithCamera_currentCamera->rdCam.canvas->screen_width_half / sithCamera_currentCamera->rdCam.canvas->screen_height_half;
            
            //if (aspect != sithMain_lastAspect)
            if (!Main_bMotsCompat)
            {
                rdCamera_SetAspectRatio(&sithCamera_currentCamera->rdCam, aspect);
                rdCamera_SetFOV(&sithCamera_currentCamera->rdCam, jkPlayer_fov);
                rdCamera_SetOrthoScale(&sithCamera_currentCamera->rdCam, 250.0);
            }
            else {
                rdCamera_SetAspectRatio(&sithCamera_currentCamera->rdCam, aspect);

                // We still need this override for cameras that don't have zoom (third-person)
                if (sithCamera_currentCamera->cameraPerspective != 1) {
                    rdCamera_SetFOV(&sithCamera_currentCamera->rdCam, jkPlayer_fov);
                }
                rdCamera_SetOrthoScale(&sithCamera_currentCamera->rdCam, 250.0);
            }
            
            sithMain_lastAspect = aspect;
        }
#endif

        //sithCamera_currentCamera->rdCam.screenAspectRatio += 0.01;
        sithCamera_FollowFocus(sithCamera_currentCamera);
        sithCamera_SetRdCameraAndRenderidk();
    }
}

void sithMain_sub_4C4D80()
{
    if ( !++sithRender_lastRenderTick )
    {
        sithWorld_sub_4D0A20(sithWorld_pCurrentWorld);
        sithRender_lastRenderTick = 1;
    }
}

void sithMain_set_sithmode_5()
{
    g_sithMode = 5;
}

void sithMain_SetEpisodeName(char *text)
{
    _strncpy(sithWorld_episodeName, text, 0x1Fu);
    sithWorld_episodeName[31] = 0;
}

// MOTS altered
void sithMain_AutoSave()
{
    sithThing *v3; // esi
    sithCog *v4; // eax
    char v5[128]; // [esp+10h] [ebp-80h] BYREF


#ifdef LINUX_TMP
    //g_debugmodeFlags |= 1;
#endif

    sithTime_Startup();
    sithInventory_Reset(sithPlayer_pLocalPlayerThing);

    sithCog_SendSimpleMessageToAll(SITH_MESSAGE_STARTUP, 0, 0, 0, 0);
    for (uint32_t v2 = 0; v2 < sithWorld_pCurrentWorld->numThingsLoaded; v2++)
    {
        v3 = &sithWorld_pCurrentWorld->things[v2];
        v4 = v3->class_cog;
        if (Main_bMotsCompat && !v3->type) continue; // MOTS added

        if ( v4 )
        {
            sithCog_SendMessage(v4, SITH_MESSAGE_CREATED, SENDERTYPE_THING, v3->thingIdx, 0, 0, 0);
        }
        if ( v3->type == SITH_THING_ACTOR )
        {
            sithActor_SetMaxHeathForDifficulty(v3);
        }
    }

    if ( sithNet_isMulti )
    {
        sithPlayer_debug_ToNextCheckpoint(sithPlayer_pLocalPlayerThing);
        sithMulti_SendWelcome(stdComm_dplayIdSelf, playerThingIdx, -1);
        sithMulti_SendWelcome(stdComm_dplayIdSelf, playerThingIdx, -1);
        sithTime_Startup();
    }
    else
    {
        stdString_snprintf(v5, 128, "%s%s", "_JKAUTO_", sithWorld_pCurrentWorld->map_jkl_fname);
        stdFnames_ChangeExt(v5, "jks");
        sithGamesave_Write(v5, 1, 0, 0);
        sithTime_Startup();
    }
}
