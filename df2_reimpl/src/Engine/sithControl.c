#include "sithControl.h"

#include "General/sithStrTable.h"
#include "Win95/stdControl.h"
#include "Win95/DebugConsole.h"
#include "Win95/Window.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithPlayer.h"
#include "World/sithActor.h"
#include "World/sithSector.h"
#include "World/sithThing.h"
#include "World/sithWeapon.h"
#include "World/sithUnk4.h"
#include "Engine/sithCamera.h"
#include "Engine/sithNet.h"
#include "Engine/sithTime.h"
#include "Engine/sithSave.h"
#include "Engine/sithMapView.h"
#include "Main/jkGame.h"
#include "Main/jkMain.h"
#include "jk.h"

int sithControl_IsOpen()
{
    return sithControl_bOpened;
}

int sithControl_Open()
{
    if (stdControl_Open())
    {
        sithControl_msIdle = 0;
        sithControl_bOpened = 1;
        return 1;
    }
    return 0;
}

void sithControl_Close()
{
    if ( sithControl_bOpened )
    {
        if ( stdControl_Close() )
            sithControl_bOpened = 0;
    }
}

void sithControl_Tick(float deltaSecs, int deltaMs)
{
    if ( !sithControl_bOpened )
        return;

    if ( !g_localPlayerThing
      || (THING_TYPEFLAGS_800000 & g_localPlayerThing->actorParams.typeflags) != 0
      || (g_localPlayerThing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) != 0
      || (sithCamera_state & 1) != 0 )
    {
        if ( sithCamera_currentCamera == &sithCamera_cameras[4] )
        {
LABEL_13:
            sithCamera_DoIdleAnimation();
            goto LABEL_14;
        }
    }
    else
    {
        if ( stdControl_bControlsIdle )
        {
            sithControl_msIdle += deltaMs;
            if ( sithControl_msIdle > 30000 && sithCamera_currentCamera != &sithCamera_cameras[4] )
                sithCamera_SetCurrentCamera(&sithCamera_cameras[4]);
            goto LABEL_14;
        }
        sithControl_msIdle = 0;
        if ( sithCamera_currentCamera == &sithCamera_cameras[4] )
            goto LABEL_13;
    }
LABEL_14:
    if ( sithWorld_pCurWorld->playerThing && sithControl_numHandlers > 0 )
    {
        stdControl_ReadControls();
        for (int i = 0; i < sithControl_numHandlers; i++)
        {
            if (sithControl_aHandlers[i] && sithControl_aHandlers[i](sithWorld_pCurWorld->playerThing, deltaSecs) )
                break;
        }
        stdControl_FinishRead();
    }
}

void sithControl_AddInputHandler(void *a1)
{
    if ( sithControl_numHandlers <= 8 )
    {
        sithControl_aHandlers[sithControl_numHandlers++] = a1;
    }
}

int sithControl_HandlePlayer(sithThing *player, float deltaSecs)
{
    int v3; // esi
    int result; // eax
    double v7; // st7
    double v8; // st6
    double v9; // st7
    double v10; // st5
    double v11; // st4
    double v12; // st3
    double v13; // st4
    double v14; // st3
    double v15; // rt0
    double v16; // st3
    wchar_t *v17; // eax
    float v18; // [esp+8h] [ebp-40h]
    rdVector3 a3a; // [esp+Ch] [ebp-3Ch] BYREF
    rdMatrix34 a; // [esp+18h] [ebp-30h] BYREF
    int input_read;

#ifdef LINUX
    //g_debugmodeFlags |= 0x100;
#endif

    // TODO: fix this?
#ifdef ARCH_64BIT
    g_debugmodeFlags &= ~0x100;
#endif

    if ( player->move_type != MOVETYPE_PHYSICS )
        return 0;
    if ( (g_debugmodeFlags & 0x100) == 0 || !sithControl_ReadFunctionMap(INPUT_FUNC_DEBUG, 0) )
    {
        if ( (player->thingflags & SITH_TF_DEAD) != 0 )
        {
            if ( (player->actorParams.typeflags & THING_TYPEFLAGS_400000) == 0 )
            {
                if ( !sithControl_death_msgtimer )
                    goto LABEL_39;
                if ( sithControl_death_msgtimer <= sithTime_curMs )
                {
                    if ( sithNet_isMulti )
                    {
                        v17 = sithStrTable_GetString("PRESS_ACTIVATE_TO_RESPAWN");
                    }
                    else if ( !__strnicmp(sithSave_autosave_fname, "_JKAUTO_", 8u) )
                    {
                        v17 = sithStrTable_GetString("PRESS_ACTIVATE_TO_RESTART");
                    }
                    else
                    {
                        v17 = sithStrTable_GetString("PRESS_ACTIVATE_TO_RESTORE");
                    }
                    DebugConsole_PrintUniStr(v17);
                    DebugConsole_AlertSound();
                    sithControl_death_msgtimer = 0;
LABEL_39:
                    sithControl_ReadFunctionMap(INPUT_FUNC_ACTIVATE, &input_read);
                    if ( input_read != 0 || (sithControl_ReadFunctionMap(INPUT_FUNC_FIRE1, &input_read), input_read != 0) )
                    {
                        sithPlayer_debug_loadauto(player);
                        return 0;
                    }
                    return 0;
                }
            }
        }
        else
        {
            sithControl_PlayerLook(player, deltaSecs);
            if ( player->thingType != THINGTYPE_PLAYER || (player->actorParams.typeflags & THING_TYPEFLAGS_IMMOBILE) == 0 )
            {
                if ( player->attach_flags )
                    sithControl_PlayerMovement(player);
                else
                    sithControl_FreeCam(player);

                sithControl_ReadFunctionMap(INPUT_FUNC_ACTIVATE, &input_read);
                if ( input_read != 0 )
                    sithActor_cogMsg_OpenDoor(player);

                sithControl_ReadFunctionMap(INPUT_FUNC_MAP, &input_read);
                if ( (input_read & 1) != 0 )
                    sithMapView_ToggleMapDrawn();
                if ( sithControl_ReadFunctionMap(INPUT_FUNC_INCREASE, &input_read) )
                    sithMapView_FuncIncrease();
                if ( sithControl_ReadFunctionMap(INPUT_FUNC_DECREASE, &input_read) )
                    sithMapView_FuncDecrease();
            }
        }
        return 0;
    }
    if ( player->move_type == MOVETYPE_PHYSICS )
        sithSector_StopPhysicsThing(player);
    v3 = INPUT_FUNC_SELECT1;
    while ( 1 )
    {
        sithControl_ReadFunctionMap(v3, &input_read);
        if ( input_read )
            break;
        if ( ++v3 > (unsigned int)INPUT_FUNC_SELECT0 )
            goto LABEL_11;
    }
    sithActor_cogMsg_WarpThingToCheckpoint(player, v3 - INPUT_FUNC_SELECT1);
LABEL_11:
    sithControl_ReadFunctionMap(INPUT_FUNC_JUMP, &input_read);
    if ( input_read )
    {
        sithThing_Hit(player, player, 200.0, 1);
        result = 1;
    }
    else
    {
        sithControl_ReadFunctionMap(INPUT_FUNC_ACTIVATE, &input_read);
        if ( input_read )
        {
            if ( sithCamera_currentCamera->cameraPerspective == 128 )
                sithCamera_DoIdleAnimation();
            else
                sithCamera_SetCurrentCamera(&sithCamera_cameras[6]);
        }
        v18 = deltaSecs * 90.0;
        a3a.y = sithControl_ReadAxisStuff(1);
        a3a.x = sithControl_ReadAxisStuff(8);
        a3a.z = 0.0;
        a3a.x = v18 * a3a.x;
        a3a.y = v18 * a3a.y;
        if ( a3a.x != 0.0 || a3a.y != 0.0 || a3a.z != 0.0 )
        {
            rdMatrix_BuildRotate34(&a, &a3a);
            rdMatrix_TransformVector34Acc(&sithControl_vec3_54A570, &a);
            rdVector_Normalize3Acc(&sithControl_vec3_54A570);
        }
        v7 = -stdControl_GetAxis2(0) * (deltaSecs * 0.1);
        if ( v7 != 0.0 )
        {
            v8 = v7 + sithControl_flt_54A57C;
            v9 = player->collideSize;
            sithControl_flt_54A57C = v8;
            if ( v8 < v9 )
            {
                sithControl_flt_54A57C = player->collideSize;
            }
            else if ( sithControl_flt_54A57C > 3.0 )
            {
                sithControl_flt_54A57C = 3.0;
            }
        }
        
        v10 = -sithControl_vec3_54A570.x;
        sithCamera_viewMat.lvec.x = v10;
        v11 = -sithControl_vec3_54A570.y;
        sithCamera_viewMat.lvec.y = v11;
        v12 = -sithControl_vec3_54A570.z;
        sithCamera_viewMat.lvec.z = v12;
        v13 = v11 * 1.0 - v12 * 0.0;
        sithCamera_viewMat.rvec.x = v13;
        v14 = sithCamera_viewMat.lvec.z * 0.0 - v10 * 1.0;
        sithCamera_viewMat.rvec.y = v14;
        v15 = v14 * sithCamera_viewMat.lvec.z;
        v16 = sithCamera_viewMat.lvec.x * 0.0 - sithCamera_viewMat.lvec.y * 0.0;
        sithCamera_viewMat.rvec.z = v16;
        sithCamera_viewMat.uvec.x = v15 - v16 * sithCamera_viewMat.lvec.y;
        sithCamera_viewMat.uvec.y = sithCamera_viewMat.rvec.z * sithCamera_viewMat.lvec.x - v13 * sithCamera_viewMat.lvec.z;
        sithCamera_viewMat.uvec.z = sithCamera_viewMat.rvec.x * sithCamera_viewMat.lvec.y - sithCamera_viewMat.rvec.y * sithCamera_viewMat.lvec.x;
        rdMatrix_Normalize34(&sithCamera_viewMat);
        sithCamera_viewMat.scale.x = sithControl_flt_54A57C * sithControl_vec3_54A570.x;
        sithCamera_viewMat.scale.y = sithControl_flt_54A57C * sithControl_vec3_54A570.y;
        sithCamera_viewMat.scale.z = sithControl_flt_54A57C * sithControl_vec3_54A570.z;
        sithControl_ReadFunctionMap(INPUT_FUNC_MAP, &input_read);
        if ( input_read )
            g_mapModeFlags ^= 0x42u;
        sithCamera_currentCamera->cameraPerspective = 128;
        result = 1;
    }
    return result;
}

void sithControl_PlayerLook(sithThing *player, float deltaSecs)
{
    int v3; // edi
    double v5; // st7
    double v6; // st7
    double v8; // st6
    double v9; // st7
    double v12; // st6
    rdVector3 a2; // [esp+8h] [ebp-Ch] BYREF
    float a1a; // [esp+18h] [ebp+4h]
    float a3a; // [esp+1Ch] [ebp+8h]

    v3 = 0;
    if ( (player->thingType == THINGTYPE_ACTOR || player->thingType == THINGTYPE_PLAYER) && deltaSecs != 0.0 )
    {
        if ( (player->actorParams.typeflags & THING_TYPEFLAGS_1) != 0 )
        {
            if ( (sithWeapon_controlOptions & 4) == 0 && !sithControl_ReadFunctionMap(INPUT_FUNC_MLOOK, 0) )
                goto LABEL_20;
            a2 = player->actorParams.eyePYR;
            v5 = sithControl_GetAxis(8);
            if ( v5 != 0.0 )
            {
                v3 = 1;
                a2.x = a2.x + v5;
            }
            v6 = sithControl_ReadAxisStuff(8);
            if ( v6 != 0.0 )
            {
                v3 = 1;
                a2.x = v6 * 90.0 * deltaSecs + a2.x;
            }
            if ( v3 )
            {
                if ( a2.x < (double)player->actorParams.minHeadPitch )
                {
                    a2.x = player->actorParams.minHeadPitch;
                }
                else if ( a2.x > (double)player->actorParams.maxHeadPitch )
                {
                    a2.x = player->actorParams.maxHeadPitch;
                }
                sithUnk4_MoveJointsForEyePYR(player, &a2);
                player->actorParams.typeflags &= ~THING_TYPEFLAGS_FORCE;
            }
            else
            {
LABEL_20:
                if ( sithControl_ReadFunctionMap(INPUT_FUNC_CENTER, 0) || (player->actorParams.typeflags & 2) != 0 )
                {
                    v8 = deltaSecs * 180.0;
                    a3a = v8;
                    v9 = -player->actorParams.eyePYR.x;
                    a1a = -v8;
                    player->actorParams.typeflags |= THING_TYPEFLAGS_LIGHT;
                    if ( v9 < a1a )
                    {
                        v9 = a1a;
                    }
                    else if ( v9 > a3a )
                    {
                        v9 = a3a;
                    }
                    v12 = v9;
                    if ( v12 < 0.0 )
                        v12 = -v9;
                    if ( v12 <= 0.0000099999997 )
                        v9 = 0.0;
                    if ( v9 == 0.0 )
                    {
                        player->actorParams.typeflags &= ~THING_TYPEFLAGS_FORCE;
                        player->actorParams.typeflags |= THING_TYPEFLAGS_LIGHT;
                    }
                    else
                    {
                        player->actorParams.eyePYR.x = v9 + player->actorParams.eyePYR.x;
                        sithUnk4_MoveJointsForEyePYR(player, &player->actorParams.eyePYR);
                    }
                }
            }
        }
        else if ( sithControl_ReadFunctionMap(INPUT_FUNC_CENTER, 0) )
        {
            sithSector_ThingSetLook(player, &rdroid_zVector3, deltaSecs);
        }
    }
}

void sithControl_PlayerMovement(sithThing *player)
{
    int new_state; // eax
    double v6; // st7
    double v7; // st6
    double v8; // st7
    double v11; // st7
    double y_vel; // st6
    int v16; // eax
    double v17; // st7
    float move_multiplier_a; // [esp+4h] [ebp-8h]
    float move_multiplier_; // [esp+4h] [ebp-8h]
    int v20; // [esp+8h] [ebp-4h] BYREF
    float move_multiplier; // [esp+10h] [ebp+4h]

    move_multiplier = 1.0;
    if ( (sithWeapon_controlOptions & 2) != 0 || sithControl_ReadFunctionMap(INPUT_FUNC_FAST, 0) )
        move_multiplier = 2.0;
    if ( sithControl_ReadFunctionMap(INPUT_FUNC_SLOW, 0) )
        move_multiplier = move_multiplier * 0.5;
    int old_state = player->physicsParams.physflags;
    if ( !sithControl_ReadFunctionMap(INPUT_FUNC_DUCK, 0) )
    {
        new_state = old_state & ~PHYSFLAGS_CROUCHING;
    }
    else
    {
        new_state = old_state | PHYSFLAGS_CROUCHING;
        move_multiplier = 0.5;
    }
    player->physicsParams.physflags = new_state;
    if ( (player->physicsParams.physflags & PHYSFLAGS_200000) != 0 )
    {
        move_multiplier = 0.5;
    }

    if ( (player->attach_flags & ATTACHFLAGS_WORLDSURFACE)
         && (player->attachedSurface->surfaceFlags & (SURFACEFLAGS_100000|SURFACEFLAGS_WATER)) )
    {
        move_multiplier *= 0.5;
    }

    if ( player->thingType == THINGTYPE_ACTOR || player->thingType == THINGTYPE_PLAYER )
    {
        if ( sithControl_ReadFunctionMap(INPUT_FUNC_SLIDETOGGLE, &v20) )
        {
            move_multiplier_a = stdControl_GetAxis2(2);
            v6 = move_multiplier_a - stdControl_GetAxis2(1);
            if ( v6 < -1.0 )
            {
                v6 = -1.0;
            }
            else if ( v6 > 1.0 )
            {
                v6 = 1.0;
            }
            v7 = player->actorParams.maxThrust + player->actorParams.extraSpeed;
            player->physicsParams.angVel.y = 0.0;
            player->physicsParams.acceleration.x = v7 * v6 * 0.69999999;
        }
        else
        {
            v8 = sithControl_GetAxis(1);
            player->physicsParams.angVel.y = v8 * sithTime_TickHz;
            if ( move_multiplier > 1.0 )
                move_multiplier_ = move_multiplier;
            else
                move_multiplier_ = 1.0;
            
            player->physicsParams.angVel.y = sithControl_ReadAxisStuff(1) * player->actorParams.maxRotThrust * move_multiplier_
                                                      + player->physicsParams.angVel.y;
            player->physicsParams.acceleration.x = stdControl_GetAxis2(2)
                                                            * (player->actorParams.maxThrust + player->actorParams.extraSpeed)
                                                            * 0.69999999;
        }
        v11 = stdControl_GetAxis2(0);
        y_vel = (player->actorParams.maxThrust + player->actorParams.extraSpeed) * v11;
        if ( v11 < 0.0 )
            y_vel = y_vel * 0.5;
        player->physicsParams.acceleration.y = y_vel;
        if ( v11 > 0.2 && (sithWeapon_controlOptions & 0x10) != 0 )
        {
            if ( (player->actorParams.typeflags & THING_TYPEFLAGS_LIGHT) == 0 )
            {
                player->actorParams.typeflags |= THING_TYPEFLAGS_FORCE;
            }
        }
        player->physicsParams.acceleration.z = 0;
        if ( move_multiplier != 1.0 )
        {
            player->physicsParams.acceleration.y = player->physicsParams.acceleration.y * move_multiplier;
            player->physicsParams.acceleration.x = player->physicsParams.acceleration.x * move_multiplier;
        }
        sithControl_ReadFunctionMap(INPUT_FUNC_JUMP, &v20);
        if ( v20 )
            sithActor_JumpWithVel(player, 1.0);
    }
}

void sithControl_FreeCam(sithThing *player)
{
    sithThing *v1; // esi
    int v2; // ebp
    sithSector *v3; // eax
    double v5; // st7
    double v6; // st6
    rdVector3 *v7; // edi
    double v9; // st7
    double v11; // st7
    double v12; // st6
    float v15; // [esp+Ch] [ebp-34h]
    rdMatrix34 a; // [esp+10h] [ebp-30h] BYREF
    int tmp;

    v1 = player;
    v2 = 0;
    if ( (player->physicsParams.physflags & 0x2000) != 0 || (v3 = player->sector) != 0 && (v3->flags & SITH_SF_UNDERWATER) != 0 )
        v2 = 1;
    if ( (sithWeapon_controlOptions & 2) == 0 )
        sithControl_ReadFunctionMap(INPUT_FUNC_FAST, 0);
    sithControl_ReadFunctionMap(INPUT_FUNC_SLOW, 0);
    if ( v1->thingType == THINGTYPE_ACTOR || v1->thingType == THINGTYPE_PLAYER )
    {
        v5 = stdControl_GetAxis2(0);
        v6 = v1->actorParams.extraSpeed + v1->actorParams.maxThrust;
        v7 = &v1->physicsParams.acceleration;
        v1->physicsParams.acceleration.z = 0.0;
        v9 = v5 * v6;
        v1->physicsParams.acceleration.y = v9;
        if ( (v6 != 0.0 || v9 != 0.0) // TODO verify first comparison?
          && (v1->actorParams.eyePYR.x != 0.0 || v1->actorParams.eyePYR.y != 0.0 || v1->actorParams.eyePYR.z != 0.0)
          && v2
          && (v1->physicsParams.physflags & PHYSFLAGS_MIDAIR) == 0 )
        {
            rdMatrix_BuildRotate34(&a, &v1->actorParams.eyePYR);
            rdMatrix_TransformVector34Acc(&v1->physicsParams.acceleration, &a);
        }
        if ( sithControl_ReadFunctionMap(INPUT_FUNC_SLIDETOGGLE, &tmp) )
        {
            v15 = stdControl_GetAxis2(2);
            v11 = v15 - stdControl_GetAxis2(1);
            if ( v11 < -1.0 )
            {
                v11 = -1.0;
            }
            else if ( v11 > 1.0 )
            {
                v11 = 1.0;
            }
            v12 = v1->actorParams.extraSpeed + v1->actorParams.maxThrust;
            v1->physicsParams.angVel.y = 0.0;
            v7->x = v12 * v11 * 0.69999999;
        }
        else
        {
            v7->x = stdControl_GetAxis2(2) * (v1->actorParams.extraSpeed + v1->actorParams.maxThrust) * 0.69999999;
            v1->physicsParams.angVel.y = sithControl_GetAxis(1) * sithTime_TickHz;
            v1->physicsParams.angVel.y = sithControl_ReadAxisStuff(1) * v1->actorParams.maxRotThrust
                                                  + v1->physicsParams.angVel.y;
        }
        if ( v2 )
        {
            if ( sithControl_ReadFunctionMap(INPUT_FUNC_JUMP, &tmp) )
            {
                if ( (v1->physicsParams.physflags & PHYSFLAGS_MIDAIR) != 0 )
                {
                    if ( tmp )
                        sithActor_JumpWithVel(v1, 1.0);
                }
                else
                {
                    v1->physicsParams.acceleration.z = v1->actorParams.maxThrust * 0.5 + v1->physicsParams.acceleration.z;
                }
            }
            if ( sithControl_ReadFunctionMap(INPUT_FUNC_DUCK, &tmp) )
                v1->physicsParams.acceleration.z = v1->physicsParams.acceleration.z - v1->actorParams.maxThrust * 0.5;
        }
        else
        {
            if ( !sithControl_ReadFunctionMap(INPUT_FUNC_DUCK, &tmp) )
                v1->physicsParams.physflags &= ~PHYSFLAGS_CROUCHING;
            else
                v1->physicsParams.physflags |= PHYSFLAGS_CROUCHING;
        }
    }
}

#ifdef LINUX
#include <SDL2/SDL.h>
int sithControl_Initialize()
{
    return 1;
}

void sithControl_InputInit()
{
}

static int last_use = 0;
static int last_cam = 0;

int sithControl_ReadFunctionMap(int func, int* out)
{
    //if (jkHud_bChatOpen) return 0;

    const Uint8 *state = SDL_GetKeyboardState(NULL);
    int val = 0;
    if (func == INPUT_FUNC_DEBUG)
    {
        val = 1;
    }
    else if (func == INPUT_FUNC_SLIDETOGGLE)
    {
        val = 0;
    }
    else if (func == INPUT_FUNC_ACTIVATE)
    {
        int cur_val = !!state[SDL_SCANCODE_SPACE];
        if (!last_use)
            val = cur_val;
        last_use = !!state[SDL_SCANCODE_SPACE];
    }
    else if (func == INPUT_FUNC_FAST)
    {
        val = !!state[SDL_SCANCODE_LSHIFT];
    }
    else if (func == INPUT_FUNC_JUMP)
    {
        val = !!state[SDL_SCANCODE_X] | Window_bMouseRight;
    }
    else if (func == INPUT_FUNC_DUCK)
    {
        val = !!state[SDL_SCANCODE_C];
    }
    else if (func == INPUT_FUNC_FIRE1)
    {
        val = !!state[SDL_SCANCODE_Z] | Window_bMouseLeft;
    }
    else if (func == INPUT_FUNC_FIRE2)
    {
        val = !!state[SDL_SCANCODE_V];
    }
    else if (func == INPUT_FUNC_PREVINV)
    {
        static int lastval = 0;
        int cur_val = !!state[SDL_SCANCODE_LEFTBRACKET];
        if (!lastval)
            val = cur_val;
        lastval = !!state[SDL_SCANCODE_LEFTBRACKET];
    }
    else if (func == INPUT_FUNC_NEXTINV)
    {
        static int lastval = 0;
        int cur_val = !!state[SDL_SCANCODE_RIGHTBRACKET];
        if (!lastval)
            val = cur_val;
        lastval = !!state[SDL_SCANCODE_RIGHTBRACKET];
    }
    else if (func == INPUT_FUNC_USEINV)
    {
        static int lastval = 0;
        int cur_val = !!state[SDL_SCANCODE_RETURN];
        if (!lastval)
            val = cur_val;
        lastval = !!state[SDL_SCANCODE_RETURN];
    }
    else if (func == INPUT_FUNC_PREVSKILL)
    {
        static int lastval = 0;
        int cur_val = !!state[SDL_SCANCODE_Q];
        if (!lastval)
            val = cur_val;
        lastval = !!state[SDL_SCANCODE_Q];
    }
    else if (func == INPUT_FUNC_NEXTSKILL)
    {
        static int lastval = 0;
        int cur_val = !!state[SDL_SCANCODE_E];
        if (!lastval)
            val = cur_val;
        lastval = !!state[SDL_SCANCODE_E];
    }
    else if (func == INPUT_FUNC_USESKILL)
    {
        static int lastval = 0;
        int cur_val = !!state[SDL_SCANCODE_F];
        if (!lastval)
            val = cur_val;
        lastval = !!state[SDL_SCANCODE_F];
    }
    else if (func == INPUT_FUNC_TALK)
    {
        static int lastval = 0;
        int cur_val = !!state[SDL_SCANCODE_T];
        if (!lastval)
            val = cur_val;
        lastval = !!state[SDL_SCANCODE_T];
    }
    else if (func == INPUT_FUNC_SELECT0)
    {
        val = !!state[SDL_SCANCODE_0];
    }
    else if (func == INPUT_FUNC_SELECT1)
    {
        val = !!state[SDL_SCANCODE_1];
    }
    else if (func == INPUT_FUNC_SELECT2)
    {
        val = !!state[SDL_SCANCODE_2];
    }
    else if (func == INPUT_FUNC_SELECT3)
    {
        val = !!state[SDL_SCANCODE_3];
    }
    else if (func == INPUT_FUNC_SELECT4)
    {
        val = !!state[SDL_SCANCODE_4];
    }
    else if (func == INPUT_FUNC_SELECT5)
    {
        val = !!state[SDL_SCANCODE_5];
    }
    else if (func == INPUT_FUNC_SELECT6)
    {
        val = !!state[SDL_SCANCODE_6];
    }
    else if (func == INPUT_FUNC_SELECT7)
    {
        val = !!state[SDL_SCANCODE_7];
    }
    else if (func == INPUT_FUNC_SELECT8)
    {
        val = !!state[SDL_SCANCODE_8];
    }
    else if (func == INPUT_FUNC_SELECT9)
    {
        val = !!state[SDL_SCANCODE_9];
    }
    else if (func == INPUT_FUNC_MLOOK)
    {
        val = 1;
    }
    else if (func == INPUT_FUNC_CAMERAMODE)
    {
        int cur_val = !!state[SDL_SCANCODE_P];
        if (!last_cam)
            val = cur_val;
        last_cam = !!state[SDL_SCANCODE_P];
    }
    else if (func == INPUT_FUNC_MAP)
    {
        val = !!state[SDL_SCANCODE_TAB];
    }
    else if (func == INPUT_FUNC_INCREASE)
    {
        val = !!state[SDL_SCANCODE_EQUALS];
    }
    else if (func == INPUT_FUNC_DECREASE)
    {
        val = !!state[SDL_SCANCODE_MINUS];
    }
    
    if (!!state[SDL_SCANCODE_ESCAPE])
    {
        jkMain_do_guistate6();
    }
    
    if (out)
        *out = val;
    return val;
}

float sithControl_GetAxis(int num)
{
    return stdControl_GetAxis2(num);
}

float sithControl_ReadAxisStuff(int num)
{
    return stdControl_GetAxis2(num);
}

int sithControl_ReadConf()
{
    return 1; 
}

int sithControl_WriteConf()
{
    return 1; 
}

void sithControl_sub_4D6930(int a)
{
    
}

#endif

