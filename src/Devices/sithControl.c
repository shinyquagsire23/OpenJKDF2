#include "sithControl.h"

#include "General/sithStrTable.h"
#include "Platform/stdControl.h"
#include "Devices/sithConsole.h"
#include "Win95/Window.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "Gameplay/sithPlayer.h"
#include "Gameplay/sithPlayerActions.h"
#include "World/sithSector.h"
#include "World/sithThing.h"
#include "World/sithWeapon.h"
#include "World/sithActor.h"
#include "Engine/sithCamera.h"
#include "Gameplay/sithTime.h"
#include "Dss/sithGamesave.h"
#include "Gameplay/sithOverlayMap.h"
#include "Engine/sithPhysics.h"
#include "Main/jkGame.h"
#include "Main/jkMain.h"
#include "Dss/sithMulti.h"
#include "General/stdMath.h"
#include "jk.h"

// Added
static int sithControl_followingPlayer = 0;
static int sithControl_curDebugCam = 0;
static wchar_t sithControl_debugWStrTmp[256];

// MOTS added
static flex_t sithControl_008d7f44 = 0.0;
static int sithControl_008d7f4c = 0;
static int sithControl_008d7f50 = 0;
static int sithControl_008d7f54 = 0;
static int sithControl_008d7f58 = 0;
static int sithControl_008d7f5c = 0;

static const char *sithControl_aFunctionStrs[74] =
{
    "FORWARD",
    "TURN",
    "SLIDE",
    "SLIDETOGGLE",
    "JUMP",
    "DUCK",
    "FAST",
    "SLOW",
    "PITCH",
    "CENTER",
    "FIRE1",
    "FIRE2",
    "ACTIVATE",
    "SELECT1",
    "SELECT2",
    "SELECT3",
    "SELECT4",
    "SELECT5",
    "SELECT6",
    "SELECT7",
    "SELECT8",
    "SELECT9",
    "SELECT0",
    "GAMESAVE",
    "DEBUG",
    "NEXTINV",
    "PREVINV",
    "USEINV",
    "NEXTWEAPON",
    "PREVWEAPON",
    "NEXTSKILL",
    "PREVSKILL",
    "USESKILL",
    "MAP",
    "INCREASE",
    "DECREASE",
    "MLOOK",
    "CAMERAMODE",
    "TALK",
    "GAMMA",
    "SCREENSHOT",
    "TALLY",
    "ACTIVATE0",
    "ACTIVATE1",
    "ACTIVATE2",
    "ACTIVATE3",
    "ACTIVATE4",
    "ACTIVATE5",
    "ACTIVATE6",
    "ACTIVATE7",
    "ACTIVATE8",
    "ACTIVATE9",
    "ACTIVATE10",
    "ACTIVATE11",
    "ACTIVATE12",
    "ACTIVATE13",
    "ACTIVATE14",
    "ACTIVATE15",
    "ACTIVATE16",
    "ACTIVATE17",
    "ACTIVATE18",
    "ACTIVATE19",
    "ACTIVATE20",
    "ACTIVATE21",
    "ACTIVATE22",
    "ACTIVATE23",
    "ACTIVATE24",
    "ACTIVATE25",
    "ACTIVATE26",
    "ACTIVATE27",
    "ACTIVATE28",
    "ACTIVATE29",
    "ACTIVATE30",
    "ACTIVATE31"
};

int sithControl_Startup()
{
    if ( sithControl_bInitted )
        return 0;

    if ( stdControl_Startup() )
    {
        sithControl_InitFuncToControlType();
        _memset(sithControl_aInputFuncToKeyinfo, 0, sizeof(stdControlKeyInfo) * 74);
        stdControl_Reset();
        sithControl_bInitted = 1;
        return 1;
    }
    return 0;
}

int sithControl_Shutdown()
{
    if ( !sithControl_bInitted )
        return 0;
    stdControl_Shutdown();

    // Added: clean reset
#ifdef QOL_IMPROVEMENTS
    // Added
    sithControl_followingPlayer = 0;
    sithControl_curDebugCam = 0;
    memset(sithControl_debugWStrTmp, 0, sizeof(sithControl_debugWStrTmp));

    // MOTS added
    sithControl_008d7f44 = 0.0;
    sithControl_008d7f4c = 0;
    sithControl_008d7f50 = 0;
    sithControl_008d7f54 = 0;
    sithControl_008d7f58 = 0;
    sithControl_008d7f5c = 0;

    memset(sithControl_aHandlers, 0, sizeof(sithControl_handler_t) * SITHCONTROL_NUM_HANDLERS);
    sithControl_numHandlers = 0;
#endif

    sithControl_bInitted = 0;
    return 1;
}

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

void sithControl_InitFuncToControlType()
{
    sithControl_inputFuncToControlType[INPUT_FUNC_TURN] = 8 | 2 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_PITCH] = 8 | 2 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_FORWARD] = 2 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SLIDE] = 2 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SLIDETOGGLE] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_JUMP] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_DUCK] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_FAST] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SLOW] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_CENTER] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_FIRE1] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_FIRE2] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_ACTIVATE] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SELECT0] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SELECT1] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SELECT2] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SELECT3] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SELECT4] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SELECT5] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SELECT6] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SELECT7] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SELECT8] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SELECT9] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_GAMESAVE] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_NEXTINV] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_PREVINV] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_USEINV] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_PREVSKILL] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_NEXTSKILL] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_USESKILL] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_PREVWEAPON] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_NEXTWEAPON] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_MAP] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_INCREASE] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_DECREASE] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_MLOOK] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_CAMERAMODE] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_TALK] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_GAMMA] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_SCREENSHOT] = 4 | 1;
    sithControl_inputFuncToControlType[INPUT_FUNC_TALLY] = 4 | 1;
    if ( (g_debugmodeFlags & DEBUGFLAG_IN_EDITOR) != 0 )
        sithControl_inputFuncToControlType[INPUT_FUNC_DEBUG] = 4 | 1;
}

// MOTS altered
void sithControl_Tick(flex_t deltaSecs, int deltaMs)
{
    if ( !sithControl_bOpened )
        return;

    // MOTS altered
    if ( !sithPlayer_pLocalPlayerThing
      || (sithPlayer_pLocalPlayerThing->actorParams.typeflags & (Main_bMotsCompat ? (SITH_AF_NOHUD|SITH_AF_SCOPEHUD|SITH_AF_80000000) : SITH_AF_NOHUD))
      || (sithPlayer_pLocalPlayerThing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) != 0
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
    if ( sithWorld_pCurrentWorld->playerThing && sithControl_numHandlers > 0 )
    {
#ifndef FIXED_TIMESTEP_PHYS
        sithControl_ReadControls();
#endif
        for (int i = 0; i < sithControl_numHandlers; i++)
        {
            if (sithControl_aHandlers[i] && sithControl_aHandlers[i](sithWorld_pCurrentWorld->playerThing, deltaSecs) )
                break;
        }
#ifndef FIXED_TIMESTEP_PHYS
        sithControl_FinishRead();
#endif
    }
}

stdControlKeyInfoEntry* sithControl_MapFunc(int funcIdx, int keyNum, int flags)
{
    int v3; // eax
    int v4; // edi
    stdControlKeyInfo *v5; // esi
    uint32_t v6; // eax
    stdControlKeyInfoEntry *v7; // ecx
    int v8; // ecx
    uint32_t v9; // esi
    uint32_t v10; // edx
    stdControlKeyInfoEntry *v11; // eax
    stdControlKeyInfoEntry *v12; // edi
    uint32_t v13; // ecx
    stdControlKeyInfoEntry *v14; // eax
    int a3a; // [esp+1Ch] [ebp+Ch]

    v3 = flags;
    v3 = flags & ~9 | 2;
    a3a = v3;
    //printf("1] Map %x\n", keyNum);
    if ( (sithControl_inputFuncToControlType[funcIdx] & 1) != 0 && sithControl_aInputFuncToKeyinfo[funcIdx].numEntries != 8 )
    {
        v4 = 0;
        v5 = sithControl_aInputFuncToKeyinfo;
        while ( 1 )
        {
            v6 = 0;
            if ( v5->numEntries )
                break;
LABEL_9:
            ++v5;
            ++v4;
            if ( v5 >= &sithControl_aInputFuncToKeyinfo[INPUT_FUNC_MAX] )
                goto LABEL_14;
        }
        v7 = v5->aEntries;
        while ( (v7->flags & 2) == 0 || v7->dxKeyNum != keyNum )
        {
            ++v6;
            ++v7;
            if ( v6 >= v5->numEntries )
                goto LABEL_9;
        }
        v8 = v4;
        v9 = sithControl_aInputFuncToKeyinfo[v4].numEntries - 1;
        sithControl_aInputFuncToKeyinfo[v4].numEntries = v9;
        v10 = v6;
        if ( v6 < v9 )
        {
            v11 = &sithControl_aInputFuncToKeyinfo[v8].aEntries[v6];
            do
            {
                v12 = v11;
                ++v10;
                *v12 = *++v11;
            }
            while ( v10 < sithControl_aInputFuncToKeyinfo[v8].numEntries );
        }
LABEL_14:

        v13 = sithControl_aInputFuncToKeyinfo[funcIdx].numEntries;
        //printf("1] Map %x, %x %x %x %x\n", keyNum, funcIdx, v8, v6, v13);
        v14 = &sithControl_aInputFuncToKeyinfo[funcIdx].aEntries[v13];
        v14->flags = a3a;
        v14->dxKeyNum = keyNum;
        sithControl_aInputFuncToKeyinfo[funcIdx].numEntries = v13 + 1;

        return v14;
    }
    return NULL;
}

stdControlKeyInfoEntry* sithControl_MapAxisFunc(int funcIdx, int dxKeyNum, uint32_t flags)
{
    unsigned int v3; // eax
    int v4; // ecx
    stdControlKeyInfoEntry *result; // eax
    int v7; // edi
    stdControlKeyInfo *v8; // esi
    uint32_t v9; // eax
    stdControlKeyInfoEntry *v10; // ecx
    int v11; // ecx
    uint32_t v12; // esi
    uint32_t v13; // edx
    stdControlKeyInfoEntry *v14; // eax
    stdControlKeyInfoEntry *v15; // edi
    uint32_t v16; // ecx
    int flagsa; // [esp+1Ch] [ebp+Ch]

    v3 = flags;
    v3 = flags & ~2 | 1;
    flagsa = v3;
    v4 = stdControl_aJoysticks[dxKeyNum].flags;
    if ( (v4 & 1) == 0 )
        return 0;
    if ( (sithControl_inputFuncToControlType[funcIdx] & 1) == 0 )
        return 0;
    if ( sithControl_aInputFuncToKeyinfo[funcIdx].numEntries == 8 )
        return 0;
    if ( (v4 & 2) != 0 )
    {
        v7 = 0;
        v8 = sithControl_aInputFuncToKeyinfo;
        while ( 1 )
        {
            v9 = 0;
            if ( v8->numEntries )
                break;
LABEL_14:
            ++v8;
            ++v7;
            if ( v8 >= &sithControl_aInputFuncToKeyinfo[INPUT_FUNC_MAX] )
                goto LABEL_20;
        }
        v10 = v8->aEntries;
        while ( (v10->flags & 1) == 0 || v10->dxKeyNum != dxKeyNum )
        {
            ++v9;
            ++v10;
            if ( v9 >= v8->numEntries )
                goto LABEL_14;
        }
        v11 = v7;
        v12 = sithControl_aInputFuncToKeyinfo[v7].numEntries - 1;
        sithControl_aInputFuncToKeyinfo[v7].numEntries = v12;
        v13 = v9;
        if ( v9 < v12 )
        {
            v14 = &sithControl_aInputFuncToKeyinfo[v11].aEntries[v9];
            do
            {
                v15 = v14;
                ++v13;
                *v15 = *++v14;
            }
            while ( v13 < sithControl_aInputFuncToKeyinfo[v11].numEntries );
        }
    }
LABEL_20:
    if ( stdControl_EnableAxis(dxKeyNum) )
    {
        if ( (flagsa & 0x10) != 0 )
            stdControl_aJoysticks[dxKeyNum].flags |= 8u;
        v16 = sithControl_aInputFuncToKeyinfo[funcIdx].numEntries;
        result = &sithControl_aInputFuncToKeyinfo[funcIdx].aEntries[v16];
        result->flags = flagsa;
        result->dxKeyNum = dxKeyNum;
        sithControl_aInputFuncToKeyinfo[funcIdx].numEntries = v16 + 1;
        return result;
    }
    return 0;
}

void sithControl_ShiftFuncKeyinfo(int funcIdx, unsigned int idx)
{
    unsigned int v2; // edx
    int result; // eax
    unsigned int v4; // ecx
    stdControlKeyInfoEntry *v5; // ecx
    stdControlKeyInfoEntry *v6; // edi

    v2 = idx;
    v4 = sithControl_aInputFuncToKeyinfo[funcIdx].numEntries - 1;
    sithControl_aInputFuncToKeyinfo[funcIdx].numEntries = v4;
    if ( idx < v4 )
    {
        v5 = &sithControl_aInputFuncToKeyinfo[funcIdx].aEntries[idx];
        do
        {
            v6 = v5;
            ++v2;
            *v6 = *++v5;
        }
        while ( v2 < sithControl_aInputFuncToKeyinfo[funcIdx].numEntries );
    }
}

void sithControl_MapFuncToDxKey(int funcIdx, int dxKeyNum)
{
    int v2; // edi
    stdControlKeyInfo *v3; // esi
    int v4; // eax
    stdControlKeyInfoEntry *v5; // ecx
    int v6; // edx
    int v7; // ecx
    uint32_t v8; // esi
    stdControlKeyInfoEntry *v9; // eax
    stdControlKeyInfoEntry *v10; // edi

    v2 = 0;
    v3 = sithControl_aInputFuncToKeyinfo;
    while ( 1 )
    {
        v4 = 0;
        if ( v3->numEntries )
            break;
LABEL_7:
        ++v3;
        ++v2;
        if ( v3 >= &sithControl_aInputFuncToKeyinfo[INPUT_FUNC_MAX] )
            return;
    }
    v5 = v3->aEntries;
    while ( (funcIdx & v5->flags) == 0 || v5->dxKeyNum != dxKeyNum )
    {
        v4++;
        ++v5;
        if ( (unsigned int)v4 >= v3->numEntries )
            goto LABEL_7;
    }
    v6 = v4;
    v7 = v2;
    v8 = sithControl_aInputFuncToKeyinfo[v2].numEntries - 1;
    sithControl_aInputFuncToKeyinfo[v2].numEntries = v8;
    if ( (unsigned int)v4 < v8 )
    {
        v9 = &sithControl_aInputFuncToKeyinfo[v7].aEntries[v4];
        do
        {
            v10 = v9;
            v6++;
            *v10 = *++v9;
        }
        while ( (unsigned int)v6 < sithControl_aInputFuncToKeyinfo[v7].numEntries );
    }
}

int sithControl_ReadConf()
{
    unsigned int v0; // eax
    int v1; // esi
    unsigned int dxKeyNum; // ebx
    int v3; // eax
    int v4; // ebp
    int v5; // edi
    stdControlKeyInfo *v6; // esi
    uint32_t v7; // eax
    stdControlKeyInfoEntry *v8; // ecx
    int v9; // ecx
    uint32_t v10; // esi
    uint32_t v11; // edx
    stdControlKeyInfoEntry *v12; // eax
    stdControlKeyInfoEntry *v13; // edi
    uint32_t v14; // eax
    stdControlKeyInfoEntry *v15; // ecx
    stdControlKeyInfoEntry *v16; // ecx
    flex_t v18; // [esp+10h] [ebp-10h]
    unsigned int v19; // [esp+14h] [ebp-Ch] BYREF
    unsigned int dxKeyNum_; // [esp+18h] [ebp-8h]
    int v21; // [esp+1Ch] [ebp-4h]

    _memset(sithControl_aInputFuncToKeyinfo, 0, sizeof(stdControlKeyInfo) * 74);
    stdControl_Reset();
    if ( !stdConffile_ReadArgs()
      || !stdConffile_entry.numArgs
      || strcmp(stdConffile_entry.args[0].key, "flags")
      || _sscanf(stdConffile_entry.args[0].value, "%x", &sithWeapon_controlOptions) != 1 )
    {
        return 0;
    }
    while ( stdConffile_ReadArgs() )
    {
        if ( !_strcmp(stdConffile_entry.args[0].key, "end.") )
            break;
        v18 = 0.0;
        if ( !_strcmp(stdConffile_entry.args[0].value, "axis") )
        {
            _atoi(stdConffile_entry.args[1].value);
            _atof(stdConffile_entry.args[2].value);
        }
        else
        {
            v0 = _atoi(stdConffile_entry.args[1].value);
            v1 = v0;
            if ( v0 <= 0x4A && (sithControl_inputFuncToControlType[v0] & 1) != 0 && _sscanf(stdConffile_entry.args[3].value, "%x", &v19) == 1 )
            {
                dxKeyNum = _atoi(stdConffile_entry.args[2].value);
                dxKeyNum_ = dxKeyNum;
                if ( stdConffile_entry.numArgs > 4u )
                    v18 = _atof(stdConffile_entry.args[4].value);
                v3 = v19;
                if ( (v19 & 2) != 0 )
                {
                    if ( dxKeyNum <= JK_NUM_KEYS )
                    {
                        v3 = v19 & ~9 | 2;
                        v21 = v3;
                        if ( (sithControl_inputFuncToControlType[v1] & 1) != 0 )
                        {
                            v4 = v1;
                            if ( sithControl_aInputFuncToKeyinfo[v1].numEntries != 8 )
                            {
                                v5 = 0;
                                v6 = sithControl_aInputFuncToKeyinfo;
                                while(1)
                                {
                                    v7 = 0;
                                    if ( v6->numEntries )
                                        break;
LABEL_24:
                                    ++v6;
                                    ++v5;
                                    if ( v5 >= INPUT_FUNC_MAX )
                                        goto LABEL_30;
                                }
                                v8 = v6->aEntries;
                                while ( (v8->flags & 2) == 0 || v8->dxKeyNum != dxKeyNum )
                                {
                                    ++v7;
                                    ++v8;
                                    if ( v7 >= v6->numEntries )
                                        goto LABEL_24;
                                }
                                v9 = v5;
                                v10 = sithControl_aInputFuncToKeyinfo[v5].numEntries - 1;
                                sithControl_aInputFuncToKeyinfo[v5].numEntries = v10;
                                v11 = v7;
                                if ( v7 < v10 )
                                {
                                    v12 = &sithControl_aInputFuncToKeyinfo[v9].aEntries[v7];
                                    do
                                    {
                                        v13 = v12;
                                        ++v11;
                                        *v13 = *++v12;
                                    }
                                    while ( v11 < sithControl_aInputFuncToKeyinfo[v9].numEntries );
                                    dxKeyNum = dxKeyNum_;
                                }
LABEL_30:
                                v14 = sithControl_aInputFuncToKeyinfo[v4].numEntries;
                                v15 = &sithControl_aInputFuncToKeyinfo[v4].aEntries[v14];
                                v15->flags = v21;
                                v15->dxKeyNum = dxKeyNum;
                                sithControl_aInputFuncToKeyinfo[v4].numEntries = v14 + 1;
                            }
                        }
                    }
                }
                else if ( dxKeyNum <= JK_NUM_AXES )
                {
                    v16 = sithControl_MapAxisFunc(v1, dxKeyNum, v19);
                    if ( v16 )
                    {
                        if ( v18 != 0.0 )
                            v16->binaryAxisVal = v18;
                    }
                }
            }
        }
    }
    return 1;
}

int sithControl_WriteConf()
{
    stdControlKeyInfo *v1; // edi
    stdControlKeyInfoEntry* v3; // esi

    if (!stdConffile_Printf("flags=%x\n", sithWeapon_controlOptions))
        return 0;

    v1 = sithControl_aInputFuncToKeyinfo;
    for (int i = 0; i < INPUT_FUNC_MAX; i++)
    {
        for (int j = 0; j < v1->numEntries; j++)
        {
            v3 = &v1->aEntries[j];
            if (!stdConffile_Printf("bind %d %d 0x%x", i, v3->dxKeyNum, v3->flags))
                break;

            if ( v3->binaryAxisVal == 0.0 )
                stdConffile_Printf("\n");
            else
                stdConffile_Printf(" %f\n", v3->binaryAxisVal);
        }
        ++v1;

    }

    stdConffile_WriteLine("end.\n");
    return 1;
}

int sithControl_ReadFunctionMap(int funcIdx, int *pOut)
{
    uint32_t v2; // ebx
    stdControlKeyInfoEntry *v3; // esi
    unsigned int v4; // eax
    int v6; // [esp+10h] [ebp-4h]

    //sithWeapon_controlOptions |= 0x20;

    v6 = 0;
    if ( pOut )
        *pOut = 0;
    v2 = 0;
    if ( sithControl_aInputFuncToKeyinfo[funcIdx].numEntries )
    {
        v3 = sithControl_aInputFuncToKeyinfo[funcIdx].aEntries;
        do
        {
            v4 = v3->dxKeyNum;
            if ( !(sithWeapon_controlOptions & 0x20) || v4 < JK_EXTENDED_KEY_START || KEY_IS_MOUSE(v4) )
                v6 |= stdControl_ReadKey(v4, pOut);
            ++v2;
            ++v3;
        }
        while ( v2 < sithControl_aInputFuncToKeyinfo[funcIdx].numEntries );
    }

    return v6;
}

void sithControl_ReadControls()
{
    stdControl_ReadControls();
}

void sithControl_FinishRead()
{
    stdControl_FinishRead();
}

flex_t sithControl_GetAxis2(int axisNum)
{
    uint32_t v1; // ebp
    stdControlKeyInfoEntry *entryIter; // esi
    int v3; // ebx
    flex_d_t v4; // st7
    flex_t v6; // [esp+10h] [ebp-4h]

    v1 = 0;
    v6 = 0.0;
    if ( sithControl_aInputFuncToKeyinfo[axisNum].numEntries )
    {
        entryIter = sithControl_aInputFuncToKeyinfo[axisNum].aEntries;
        do
        {
            v3 = entryIter->flags;
            if ( (v3 & 1) != 0 )
            {
                if ( (sithWeapon_controlOptions & 0x20) == 0 || entryIter->dxKeyNum >= AXIS_MOUSE_X )
                {
                    v4 = stdControl_ReadAxis(entryIter->dxKeyNum);
LABEL_11:
                    if ( (entryIter->flags & 8) != 0 )
                        v4 = v4 * sithTime_TickHz;
                    if ( v4 != 0.0 )
                    {
                        if ( (v3 & 4) != 0 )
                            v4 = -v4;
                        if ( entryIter->binaryAxisVal != 0.0 )
                            v4 = v4 * entryIter->binaryAxisVal;
                        if ( v4 < -1.0 )
                        {
                            v4 = -1.0;
                        }
                        else if ( v4 > 1.0 )
                        {
                            v4 = 1.0;
                        }
                        v6 = v6 + v4;
                    }
                    goto LABEL_23;
                }
            }
            else if ( (sithWeapon_controlOptions & 0x20) == 0 || entryIter->dxKeyNum < JK_EXTENDED_KEY_START || KEY_IS_MOUSE(entryIter->dxKeyNum) )
            {
                v4 = stdControl_ReadKeyAsAxis(entryIter->dxKeyNum);
                goto LABEL_11;
            }
LABEL_23:
            ++v1;
            ++entryIter;
        }
        while ( v1 < sithControl_aInputFuncToKeyinfo[axisNum].numEntries );
    }
    if ( v6 < -1.0 )
        return -1.0;
    if ( v6 > 1.0 )
        return 1.0;
    return v6;
}

flex_t sithControl_ReadAxisStuff(int funcIdx)
{
    uint32_t v1; // ebp
    stdControlKeyInfoEntry *v2; // esi
    int v3; // ebx
    flex_d_t v4; // st7
    flex_t v6; // [esp+8h] [ebp-4h]

    v1 = 0;
    v6 = 0.0;
    if ( sithControl_aInputFuncToKeyinfo[funcIdx].numEntries )
    {
        v2 = sithControl_aInputFuncToKeyinfo[funcIdx].aEntries;
        do
        {
            v3 = v2->flags;
            if ( (v3 & 8) == 0 )
            {
                if ( (v3 & 1) != 0 )
                {
                    if ( (sithWeapon_controlOptions & 0x20) == 0 || v2->dxKeyNum >= AXIS_MOUSE_X )
                    {
                        v4 = stdControl_ReadAxis(v2->dxKeyNum);
                        goto LABEL_12;
                    }
                }
                else if ( (sithWeapon_controlOptions & 0x20) == 0 || v2->dxKeyNum < JK_EXTENDED_KEY_START || KEY_IS_MOUSE(v2->dxKeyNum) )
                {
                    v4 = stdControl_ReadKeyAsAxis(v2->dxKeyNum);
LABEL_12:
                    if ( v4 != 0.0 )
                    {
                        if ( (v3 & 4) != 0 )
                            v4 = -v4;
                        if ( v2->binaryAxisVal != 0.0 )
                            v4 = v4 * v2->binaryAxisVal;
                        v6 = v6 + v4;
                    }
                    goto LABEL_18;
                }
            }
LABEL_18:
            ++v1;
            ++v2;
        }
        while ( v1 < sithControl_aInputFuncToKeyinfo[funcIdx].numEntries );
    }
    return v6;
}

flex_t sithControl_GetAxis(int funcIdx)
{
    stdControlKeyInfoEntry *v1; // edi
    stdControlKeyInfoEntry *v2; // esi
    uint32_t v3; // ebp
    int v4; // ebx
    flex_d_t v5; // st7
    flex_t v7; // [esp+4h] [ebp-4h]

    v7 = 0.0;
    v1 = sithControl_aInputFuncToKeyinfo[funcIdx].aEntries;
    if ( sithControl_aInputFuncToKeyinfo[funcIdx].numEntries )
    {
        v2 = &sithControl_aInputFuncToKeyinfo[funcIdx].aEntries[0];
        v3 = sithControl_aInputFuncToKeyinfo[funcIdx].numEntries;
        do
        {
            v4 = v2->flags;
            if ( (v4 & 8) != 0 && ((sithWeapon_controlOptions & 0x20) == 0 || v1->dxKeyNum >= AXIS_MOUSE_X) )
            {
                v5 = (flex_d_t)stdControl_ReadAxisRaw(v2->dxKeyNum);
                if ( (v4 & 4) != 0 )
                    v5 = -v5;
                if ( v2->binaryAxisVal != 0.0 )
                    v5 = v5 * v2->binaryAxisVal;
                v7 = v5 + v7;
            }
            ++v2;
            ++v1;
            --v3;
        }
        while ( v3 );
    }
    return v7;
}

void sithControl_AddInputHandler(sithControl_handler_t a1)
{
    // The original engine had an off-by-one here?
    if (sithControl_numHandlers < SITHCONTROL_NUM_HANDLERS)
    {
        sithControl_aHandlers[sithControl_numHandlers++] = a1;
    }
}

// MOTS altered
int sithControl_HandlePlayer(sithThing *player, flex_t deltaSecs)
{
    int v3; // esi
    int result; // eax
    flex_d_t v7; // st7
    flex_d_t v8; // st6
    flex_d_t v9; // st7
    flex_d_t v10; // st5
    flex_d_t v11; // st4
    flex_d_t v12; // st3
    flex_d_t v13; // st4
    flex_d_t v14; // st3
    flex_d_t v15; // rt0
    flex_d_t v16; // st3
    wchar_t *v17; // eax
    flex_t v18; // [esp+8h] [ebp-40h]
    rdVector3 a3a; // [esp+Ch] [ebp-3Ch] BYREF
    rdMatrix34 a; // [esp+18h] [ebp-30h] BYREF
    int input_read;

    //g_debugmodeFlags |= 0x100;

    // TODO: fix this?
#ifdef ARCH_64BIT
    //g_debugmodeFlags &= ~0x100;
#endif

    if ( player->moveType != SITH_MT_PHYSICS )
        return 0;

    // Added: dedicated
    if (sithNet_isServer && jkGuiNetHost_bIsDedicated) {
        sithControl_PlayerLook(player, deltaSecs);
        sithControl_FreeCam(player);
        sithControl_ReadFunctionMap(INPUT_FUNC_MAP, &input_read);
        if ( (input_read & 1) != 0 )
            sithOverlayMap_ToggleMapDrawn();
        if ( sithControl_ReadFunctionMap(INPUT_FUNC_INCREASE, &input_read) )
            sithOverlayMap_FuncIncrease();
        if ( sithControl_ReadFunctionMap(INPUT_FUNC_DECREASE, &input_read) )
            sithOverlayMap_FuncDecrease();
        goto debug_controls;
    }

    if ( (g_debugmodeFlags & DEBUGFLAG_IN_EDITOR) == 0 || !sithControl_ReadFunctionMap(INPUT_FUNC_DEBUG, 0) )
    {
        if (player->thingflags & SITH_TF_DEAD)
        {
            if (!(player->actorParams.typeflags & SITH_AF_FALLING_TO_DEATH))
            {
                if ( !sithControl_death_msgtimer )
                    goto LABEL_39;
                if ( sithControl_death_msgtimer <= sithTime_curMs )
                {
                    if ( sithNet_isMulti )
                    {
                        v17 = sithStrTable_GetUniStringWithFallback("PRESS_ACTIVATE_TO_RESPAWN");
                    }
                    else if ( !__strnicmp(sithGamesave_autosave_fname, "_JKAUTO_", 8u) )
                    {
                        v17 = sithStrTable_GetUniStringWithFallback("PRESS_ACTIVATE_TO_RESTART");
                    }
                    else
                    {
                        v17 = sithStrTable_GetUniStringWithFallback("PRESS_ACTIVATE_TO_RESTORE");
                    }
                    sithConsole_PrintUniStr(v17);
                    sithConsole_AlertSound();
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
            if (!Main_bMotsCompat) {
                sithControl_008d7f44 = 1.0;
                sithControl_PlayerLook(player, deltaSecs);
            }
            if ( player->type != SITH_THING_PLAYER || (player->actorParams.typeflags & SITH_AF_DISABLED) == 0 )
            {
                // MOTS added
                if (Main_bMotsCompat) {
                    sithControl_008d7f44 = sithCamera_cameras[sithCamera_currentCamera - sithCamera_cameras].rdCam.fov * 0.01111111;
                    sithControl_PlayerLook(player, deltaSecs);
                }

                if ( player->attach_flags )
                    sithControl_PlayerMovement(player);
                else
                    sithControl_FreeCam(player);

                sithControl_ReadFunctionMap(INPUT_FUNC_ACTIVATE, &input_read);
                if ( input_read != 0 &&  sithThing_MotsTick(2,0,1.0)) // MOTS added
                    sithPlayerActions_Activate(player);

                sithControl_ReadFunctionMap(INPUT_FUNC_MAP, &input_read);
                if ( (input_read & 1) != 0 )
                    sithOverlayMap_ToggleMapDrawn();
                if ( sithControl_ReadFunctionMap(INPUT_FUNC_INCREASE, &input_read) )
                    sithOverlayMap_FuncIncrease();
                if ( sithControl_ReadFunctionMap(INPUT_FUNC_DECREASE, &input_read) )
                    sithOverlayMap_FuncDecrease();
            }
        }
        return 0;
    }

debug_controls:
    if ( player->moveType == SITH_MT_PHYSICS )
        sithPhysics_ThingStop(player);

    // Added
    if (sithControl_followingPlayer > 0) {
        sithThing* pThing = jkPlayer_playerInfos[sithControl_followingPlayer].playerThing;
        if (pThing) {
            rdVector_Copy3(&player->position, &pThing->position);
            rdMatrix_Copy34(&player->lookOrientation, &pThing->lookOrientation);
            sithThing_MoveToSector(player, pThing->sector, 0);
            sithWorld_pCurrentWorld->cameraFocus = pThing;
            sithWorld_pCurrentWorld->playerThing = jkPlayer_playerInfos[0].playerThing;
            stdPalEffects_FlushAllAdds();
        }
    }

    for (v3 = INPUT_FUNC_SELECT1; v3 <= INPUT_FUNC_SELECT0; v3++)
    {
        sithControl_ReadFunctionMap(v3, &input_read);
        if ( input_read )
        {
            sithControl_followingPlayer = 0; // Added
            int old = jkPlayer_maxPlayers;// Added
            jkPlayer_maxPlayers = 10; // Added
            sithControl_curDebugCam = v3 - INPUT_FUNC_SELECT1; // Added
            sithPlayerActions_WarpToCheckpoint(player, sithControl_curDebugCam);
            jkPlayer_maxPlayers = old; // Added

            // Added
            jk_snwprintf(sithControl_debugWStrTmp, 256, L"Spawn cam %u", sithControl_curDebugCam);
            sithConsole_PrintUniStr(sithControl_debugWStrTmp);

            break;
        }
    }
    sithControl_ReadFunctionMap(INPUT_FUNC_JUMP, &input_read);
    if ( input_read )
    {
        result = 0; // Added

        // Added: dedicated
        if (!(sithNet_isServer && jkGuiNetHost_bIsDedicated)) {
            sithActor_Hit(player, player, 200.0, 1);
            result = 1;
        }
        else {
            for (sithControl_followingPlayer++; sithControl_followingPlayer < jkPlayer_maxPlayers; sithControl_followingPlayer++) {
                if (!sithControl_followingPlayer || jkPlayer_playerInfos[sithControl_followingPlayer].flags & 1) {
                    break;
                }
            }
            if (sithControl_followingPlayer >= jkPlayer_maxPlayers) {
                sithControl_followingPlayer = 0;
            }
            if (sithControl_followingPlayer)
                jk_snwprintf(sithControl_debugWStrTmp, 256, L"Following %s", jkPlayer_playerInfos[sithControl_followingPlayer].player_name);
            else
                jk_snwprintf(sithControl_debugWStrTmp, 256, L"Spawn cam %u", sithControl_curDebugCam);
            sithConsole_PrintUniStr(sithControl_debugWStrTmp);
            
            if (!sithControl_followingPlayer) {
                sithPlayerActions_WarpToCheckpoint(player, sithControl_curDebugCam);
            }
        }
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
#ifdef QOL_IMPROVEMENTS
        // Scale appropriately to high framerates
        v18 = deltaSecs * 90.0 * (sithTime_TickHz / 50.0);
#else
        v18 = deltaSecs * 90.0;
#endif
        a3a.y = v18 * sithControl_ReadAxisStuff(INPUT_FUNC_TURN);
        a3a.x = v18 * sithControl_ReadAxisStuff(INPUT_FUNC_PITCH);
        a3a.z = 0.0;
        if (!rdVector_IsZero3(&a3a))
        {
            rdMatrix_BuildRotate34(&a, &a3a);
            rdMatrix_TransformVector34Acc(&sithControl_vec3_54A570, &a);
            rdVector_Normalize3Acc(&sithControl_vec3_54A570);
        }
#ifdef QOL_IMPROVEMENTS
        v7 = -sithControl_GetAxis2(0) * (deltaSecs * 0.1) * (sithTime_TickHz / 50.0);
#else
        v7 = -sithControl_GetAxis2(0) * (deltaSecs * 0.1);
#endif
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
        if (!(sithNet_isServer && jkGuiNetHost_bIsDedicated)) // Added
            result = 1;
        else
            result = 0;
    }
    return result;
}

void sithControl_PlayerLook(sithThing *player, flex_t deltaSecs)
{
    int v3; // edi
    flex_d_t v5; // st7
    flex_d_t v6; // st7
    flex_d_t v9;
    flex_d_t v8; // st6
    flex_d_t v12; // st6
    rdVector3 a2; // [esp+8h] [ebp-Ch] BYREF

    flex_t local_10 = 0.0;

    v3 = 0;
    if ( (player->type == SITH_THING_ACTOR || player->type == SITH_THING_PLAYER) && deltaSecs != 0.0 )
    {
        if ( (player->actorParams.typeflags & SITH_AF_CAN_ROTATE_HEAD) != 0 )
        {
            if ( (sithWeapon_controlOptions & 4) == 0 && !sithControl_ReadFunctionMap(INPUT_FUNC_MLOOK, 0) )
                goto LABEL_20;

            
            a2 = player->actorParams.eyePYR;

            // Map directly to axis, the value we have is an angular velocity
            v5 = sithControl_GetAxis(INPUT_FUNC_PITCH);
            if ( v5 != 0.0 )
            {
                v3 = 1;
                a2.x += v5 * sithControl_008d7f44;
                local_10 = v5 * sithControl_008d7f44;
            }

            // Not mapped directly to axis, accomodate w/ deltaSecs
            v6 = sithControl_ReadAxisStuff(INPUT_FUNC_PITCH);
            if ( v6 != 0.0 )
            {
                v3 = 1;
#ifdef QOL_IMPROVEMENTS
                // Scale appropriately to high framerates
                a2.x += v6 * sithControl_008d7f44 * 90.0 * deltaSecs * (sithTime_TickHz / 50.0);
                local_10 += v6 * sithControl_008d7f44 * 90.0 * deltaSecs * (sithTime_TickHz / 50.0);
#else
                a2.x += v6 * sithControl_008d7f44 * 90.0 * deltaSecs;
                local_10 += v6 * sithControl_008d7f44 * 90.0 * deltaSecs;
#endif

                
            }

            if ( v3 )
            {
                a2.x = stdMath_Clamp(a2.x, player->actorParams.minHeadPitch, player->actorParams.maxHeadPitch);
                
                // MOTS added
                if (!sithThing_MotsTick(8, (int)(local_10 * 100.0), a2.x)) return;

                sithActor_MoveJointsForEyePYR(player, &a2);
                player->actorParams.typeflags &= ~SITH_AF_CENTER_VIEW;
            }
            else
            {
LABEL_20:
                if ( sithControl_ReadFunctionMap(INPUT_FUNC_CENTER, 0) || (player->actorParams.typeflags & SITH_AF_CENTER_VIEW) != 0 )
                {
#ifdef QOL_IMPROVEMENTS
                    // Scale appropriately to high framerates
                    v8 = deltaSecs * 180.0 * (sithTime_TickHz / 50.0);
#else
                    v8 = deltaSecs * 180.0;
#endif
                    player->actorParams.typeflags |= SITH_AF_HEAD_IS_CENTERED;
                    v9 = stdMath_ClipPrecision(stdMath_ClampValue(-player->actorParams.eyePYR.x, v8));
                    if ( v9 == 0.0 )
                    {
                        player->actorParams.typeflags &= ~SITH_AF_CENTER_VIEW;
                        player->actorParams.typeflags |= SITH_AF_HEAD_IS_CENTERED;
                    }
                    else
                    {
                        player->actorParams.eyePYR.x += v9;
                        sithActor_MoveJointsForEyePYR(player, &player->actorParams.eyePYR);
                    }
                }
            }
        }
        else if ( sithControl_ReadFunctionMap(INPUT_FUNC_CENTER, 0) )
        {
            if (sithThing_MotsTick(9, 0, 1.0))
                sithPhysics_ThingSetLook(player, &rdroid_zVector3, deltaSecs);
        }
    }
}


void sithControl_PlayerMovementMots(sithThing *player)
{
    uint32_t uVar1;
    int iVar2;
    flex_t fVar3;
    flex_t fVar4;
    flex_t local_8;
    int local_4;
    sithThing *thing;
    
    thing = player;
    flex_t move_multiplier = 1.0;
    if (((sithWeapon_controlOptions & 2) != 0) ||
       (iVar2 = sithControl_ReadFunctionMap(INPUT_FUNC_FAST,(int *)0x0), iVar2 != 0)) {
        move_multiplier = 2.0;
    }
    iVar2 = sithControl_ReadFunctionMap(7,(int *)0x0);
    if (iVar2 != 0) {
        move_multiplier *= 0.5;
    }
    thing->physicsParams.physflags =
         thing->physicsParams.physflags & ~SITH_PF_CROUCHING;
    iVar2 = sithControl_ReadFunctionMap(INPUT_FUNC_DUCK,(int *)0x0);
    if (iVar2 == 0) {
        if (sithControl_008d7f58 != 0) {
            sithThing_MotsTick(1,0,0.0);
        }
        sithControl_008d7f58 = 0;
    }
    else {
        local_8 = 1.0;
        if (sithControl_008d7f58 != 0) {
            local_8 = 2.0;
        }
        sithControl_008d7f58 = 1;
        iVar2 = sithThing_MotsTick(1,0,local_8);
        if ((iVar2 != 0) && ((thing->actorParams.typeflags & SITH_AF_COMBO_FREEZE) == 0)) {
            move_multiplier = 0.5;
            thing->physicsParams.physflags =
                 thing->physicsParams.physflags | SITH_PF_CROUCHING;
        }
    }
    if ((thing->physicsParams.physflags & SITH_PF_200000) != 0) {
        move_multiplier = 0.5;
    }
    if (((thing->attach_flags & SITH_ATTACH_WORLDSURFACE) != 0) &&
       (player->attachedSurface->surfaceFlags & (SITH_SURFACE_VERYDEEPWATER|SITH_SURFACE_WATER))) {
        move_multiplier *= 0.5;
    }
    if ((thing->type != 2) && (thing->type != 10)) {
        return;
    }
    iVar2 = sithControl_ReadFunctionMap(INPUT_FUNC_SLIDETOGGLE,&local_4);
    if (iVar2 == 0) {
        fVar4 = sithControl_GetAxis(INPUT_FUNC_TURN);
#ifdef QOL_IMPROVEMENTS
        // Scale appropriately to high framerates
        fVar4 = fVar4 * 25.0;
#else
        fVar4 = fVar4 * sithTime_TickHz;
#endif
        if (1.0 <= move_multiplier) {
            local_8 = 1.0;
        }
        else {
            local_8 = move_multiplier;
        }
        fVar3 = sithControl_ReadAxisStuff(INPUT_FUNC_TURN);
#ifdef QOL_IMPROVEMENTS
        // Scale appropriately to high framerates
        //fVar3 *= (sithTime_TickHz / 50.0);
#endif

        fVar4 += fVar3 * thing->actorParams.maxRotThrust * local_8;

        if (fVar4 == 0.0) {
            if (sithControl_008d7f50 != 0) {
                sithThing_MotsTick(5,0,fVar4);
                sithControl_008d7f50 = 0;
            }
            thing->physicsParams.angVel.y = fVar4;
            fVar4 = sithControl_GetAxis2(INPUT_FUNC_SLIDE);
            fVar4 = (thing->actorParams.maxThrust +
                    thing->actorParams.extraSpeed) * -fVar4 * 0.7;
            if (fVar4 == 0.0) goto joined_r0x00527cfa;
            sithControl_008d7f54 = 1;
            iVar2 = sithThing_MotsTick(4,0,fVar4 * move_multiplier);
            if (iVar2 != 0) {
                thing->physicsParams.acceleration.x = fVar4;
                goto LAB_00527d1c;
            }
        }
        else {
            fVar4 = fVar4 * sithControl_008d7f44;
            sithControl_008d7f50 = 1;
            iVar2 = sithThing_MotsTick(5,0,fVar4);
            if (iVar2 == 0) {
                thing->physicsParams.angVel.y = 0.0;
            }
            else {
                thing->physicsParams.angVel.y = fVar4;
                fVar4 = sithControl_GetAxis2(INPUT_FUNC_SLIDE);
                fVar4 = (thing->actorParams.maxThrust +
                        thing->actorParams.extraSpeed) * -fVar4 * 0.7;
                if (fVar4 == 0.0) goto joined_r0x00527cfa;
                sithControl_008d7f54 = 1;
                iVar2 = sithThing_MotsTick(4,0,fVar4 * move_multiplier);
                if (iVar2 != 0) {
                    thing->physicsParams.acceleration.x = fVar4;
                    goto LAB_00527d1c;
                }
            }
        }
    }
    else {
        fVar3 = sithControl_GetAxis2(INPUT_FUNC_TURN);
        fVar4 = sithControl_GetAxis2(INPUT_FUNC_SLIDE);
        fVar4 = -fVar4 - fVar3;
        if (fVar4 < -1.0) {
            fVar4 = -1.0;
        }
        else if (1.0 < fVar4) {
            fVar4 = 1.0;
        }
        fVar4 = (thing->actorParams.maxThrust +
                thing->actorParams.extraSpeed) * fVar4 * 0.7;
        if (fVar4 != 0.0) {
            sithControl_008d7f54 = 1;
            iVar2 = sithThing_MotsTick(4,0,fVar4 * move_multiplier);
            if (iVar2 == 0) {
                thing->physicsParams.acceleration.x = 0.0;
                thing->physicsParams.angVel.y = 0.0;
            }
            else {
                thing->physicsParams.angVel.y = 0.0;
                thing->physicsParams.acceleration.x = fVar4;
            }
            goto LAB_00527d1c;
        }
joined_r0x00527cfa:
        if (sithControl_008d7f54 != 0) {
            sithThing_MotsTick(4,0,0.0);
        }
        sithControl_008d7f54 = 0;
    }
    thing->physicsParams.acceleration.x = 0.0;
LAB_00527d1c:
    if (((sithWeapon_controlOptions & 4) == 0) &&
       (iVar2 = sithControl_ReadFunctionMap(0x24,(int *)0x0), iVar2 != 0)) {
        local_8 = 0.0;
    }
    else {
        local_8 = sithControl_GetAxis2(INPUT_FUNC_FORWARD);
    }
    fVar4 = (thing->actorParams.maxThrust + thing->actorParams.extraSpeed)
            * local_8;
    if (local_8 <= 0.0) {
        fVar4 = fVar4 * 0.5;
    }
    if (fVar4 == 0.0) {
        thing->physicsParams.acceleration.y = fVar4;
        if (sithControl_008d7f4c != 0) {
            sithThing_MotsTick(6,0,fVar4 * move_multiplier);
            sithControl_008d7f4c = 0;
        }
    }
    else {
        iVar2 = sithThing_MotsTick(6,0,fVar4 * move_multiplier);
        if (iVar2 != 0) {
            thing->physicsParams.acceleration.y = fVar4;
        }
        sithControl_008d7f4c = 1;
    }
    if (((0.2 < local_8) && ((sithWeapon_controlOptions & 0x10) != 0)) &&
       (uVar1 = thing->actorParams.typeflags, (uVar1 & SITH_AF_HEAD_IS_CENTERED) == 0)) {
        thing->actorParams.typeflags = uVar1 | SITH_AF_CENTER_VIEW;
    }
    thing->physicsParams.acceleration.z = 0.0;
    if (move_multiplier != 1.0) {
        fVar4 = thing->physicsParams.acceleration.x;
        thing->physicsParams.acceleration.y =
             thing->physicsParams.acceleration.y * move_multiplier;
        thing->physicsParams.acceleration.x = fVar4 * move_multiplier;
    }
    iVar2 = sithControl_ReadFunctionMap(4,&local_4);
    if (iVar2 == 0) {
        if (sithControl_008d7f5c != 0) {
            sithThing_MotsTick(0,0,0.0);
        }
        sithControl_008d7f5c = 0;
    }
    else {
        sithControl_008d7f5c = 1;
    }
    if ((local_4 != 0) && (iVar2 = sithThing_MotsTick(0,0,1.0), iVar2 != 0)) {
        sithPlayerActions_JumpWithVel(thing,1.0);
    }
}

void sithControl_PlayerMovement(sithThing *player)
{
    if (Main_bMotsCompat) {
        sithControl_PlayerMovementMots(player);
        return;
    }

    int new_state; // eax
    flex_d_t v6; // st7
    flex_d_t v7; // st6
    flex_d_t v11; // st7
    flex_d_t y_vel; // st6
    int v16; // eax
    flex_d_t v17; // st7
    flex_t move_multiplier_a; // [esp+4h] [ebp-8h]
    flex_t move_multiplier_; // [esp+4h] [ebp-8h]
    int v20; // [esp+8h] [ebp-4h] BYREF
    flex_t move_multiplier; // [esp+10h] [ebp+4h]

    move_multiplier = 1.0;
    if ( (sithWeapon_controlOptions & 2) != 0 || sithControl_ReadFunctionMap(INPUT_FUNC_FAST, 0) )
        move_multiplier = 2.0;
    if ( sithControl_ReadFunctionMap(INPUT_FUNC_SLOW, 0) )
        move_multiplier = move_multiplier * 0.5;
    int old_state = player->physicsParams.physflags;
    if ( !sithControl_ReadFunctionMap(INPUT_FUNC_DUCK, 0) )
    {
        new_state = old_state & ~SITH_PF_CROUCHING;
    }
    else
    {
        new_state = old_state | SITH_PF_CROUCHING;
        move_multiplier = 0.5;
    }
    player->physicsParams.physflags = new_state;
    if ( (player->physicsParams.physflags & SITH_PF_200000) != 0 )
    {
        move_multiplier = 0.5;
    }

    if ( (player->attach_flags & SITH_ATTACH_WORLDSURFACE)
         && (player->attachedSurface->surfaceFlags & (SITH_SURFACE_VERYDEEPWATER|SITH_SURFACE_WATER)) )
    {
        move_multiplier *= 0.5;
    }

    if ( player->type == SITH_THING_ACTOR || player->type == SITH_THING_PLAYER )
    {
        if ( sithControl_ReadFunctionMap(INPUT_FUNC_SLIDETOGGLE, &v20) )
        {
            move_multiplier_a = sithControl_GetAxis2(INPUT_FUNC_SLIDE);
            v6 = move_multiplier_a - sithControl_GetAxis2(INPUT_FUNC_TURN);
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
            player->physicsParams.acceleration.x = v7 * v6 * 0.7;
        }
        else
        {
            // Player yaw handling
#ifdef QOL_IMPROVEMENTS
            // Scale appropriately to high and low framerates
            player->physicsParams.angVel.y = sithControl_GetAxis(INPUT_FUNC_TURN) * 25.0;
#else
            player->physicsParams.angVel.y = sithControl_GetAxis(INPUT_FUNC_TURN) * sithTime_TickHz;
#endif
            if ( move_multiplier > 1.0 )
                move_multiplier_ = move_multiplier;
            else
                move_multiplier_ = 1.0;
            
#ifdef QOL_IMPROVEMENTS
            // Scale appropriately to high framerates
            player->physicsParams.angVel.y += sithControl_ReadAxisStuff(INPUT_FUNC_TURN) * player->actorParams.maxRotThrust * move_multiplier_;
#else
            player->physicsParams.angVel.y += sithControl_ReadAxisStuff(INPUT_FUNC_TURN) * player->actorParams.maxRotThrust * move_multiplier_;
#endif
            player->physicsParams.acceleration.x = sithControl_GetAxis2(INPUT_FUNC_SLIDE)
                                                            * (player->actorParams.maxThrust + player->actorParams.extraSpeed)
                                                            * 0.7;
        }
        v11 = sithControl_GetAxis2(0);
        y_vel = (player->actorParams.maxThrust + player->actorParams.extraSpeed) * v11;
        if ( v11 < 0.0 )
            y_vel = y_vel * 0.5;
        player->physicsParams.acceleration.y = y_vel;
        if ( v11 > 0.2 && (sithWeapon_controlOptions & 0x10) != 0 )
        {
            if ( (player->actorParams.typeflags & SITH_AF_HEAD_IS_CENTERED) == 0 )
            {
                player->actorParams.typeflags |= SITH_AF_CENTER_VIEW;
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
            sithPlayerActions_JumpWithVel(player, 1.0);
    }
}

// MOTS altered
void sithControl_FreeCam(sithThing *player)
{
    sithThing *v1; // esi
    int v2; // ebp
    sithSector *v3; // eax
    flex_d_t v5; // st7
    flex_d_t v6; // st6
    rdVector3 *v7; // edi
    flex_d_t v9; // st7
    flex_d_t v11; // st7
    flex_d_t v12; // st6
    flex_t v15; // [esp+Ch] [ebp-34h]
    rdMatrix34 a; // [esp+10h] [ebp-30h] BYREF
    int tmp;

    if ((g_debugmodeFlags & DEBUGFLAG_NOCLIP)) // Added: noclip
    {
        rdVector_Zero3(&player->physicsParams.vel);
    }

    v1 = player;
    v2 = 0;
    if ( (player->physicsParams.physflags & SITH_PF_FLY) != 0 || (v3 = player->sector) != 0 && (v3->flags & SITH_SECTOR_UNDERWATER) != 0 )
        v2 = 1;
    if ( (sithWeapon_controlOptions & 2) == 0 )
        sithControl_ReadFunctionMap(INPUT_FUNC_FAST, 0);
    sithControl_ReadFunctionMap(INPUT_FUNC_SLOW, 0);
    if ( v1->type == SITH_THING_ACTOR || v1->type == SITH_THING_PLAYER )
    {
        v5 = sithControl_GetAxis2(0);
        v6 = v1->actorParams.extraSpeed + v1->actorParams.maxThrust;
        v7 = &v1->physicsParams.acceleration;
        v1->physicsParams.acceleration.z = 0.0;
        v9 = v5 * v6;
        v1->physicsParams.acceleration.y = v9;
        if ( (v1->physicsParams.acceleration.x != 0.0 || v1->physicsParams.acceleration.y != 0.0) // TODO verified first comparison?
          && (v1->actorParams.eyePYR.x != 0.0 || v1->actorParams.eyePYR.y != 0.0 || v1->actorParams.eyePYR.z != 0.0)
          && v2
          && (v1->physicsParams.physflags & SITH_PF_WATERSURFACE) == 0 )
        {
            rdMatrix_BuildRotate34(&a, &v1->actorParams.eyePYR);
            rdMatrix_TransformVector34Acc(&v1->physicsParams.acceleration, &a);
        }
        if ( sithControl_ReadFunctionMap(INPUT_FUNC_SLIDETOGGLE, &tmp) )
        {
            v15 = sithControl_GetAxis2(INPUT_FUNC_SLIDE);

            // Why did MoTS do this lol
            if (Main_bMotsCompat)
                v15 = -v15;

            v11 = v15 - sithControl_GetAxis2(INPUT_FUNC_TURN);
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
            v7->x = v12 * v11 * 0.7;
        }
        else
        {
            // Why did MoTS do this lol
            v7->x = (Main_bMotsCompat ? -1 : 1) * sithControl_GetAxis2(INPUT_FUNC_SLIDE) * (v1->actorParams.extraSpeed + v1->actorParams.maxThrust) * 0.7;
            
#ifdef QOL_IMPROVEMENTS
            // Scale appropriately to high framerates
            v1->physicsParams.angVel.y = sithControl_GetAxis(INPUT_FUNC_TURN) * 25.0;
            v1->physicsParams.angVel.y +=  sithControl_ReadAxisStuff(INPUT_FUNC_TURN) * v1->actorParams.maxRotThrust;
#else
            v1->physicsParams.angVel.y = sithControl_GetAxis(INPUT_FUNC_TURN) * sithTime_TickHz;
            v1->physicsParams.angVel.y += sithControl_ReadAxisStuff(INPUT_FUNC_TURN) * v1->actorParams.maxRotThrust;
#endif
        }
        if ( v2 )
        {
            // Added: noclip
            if ((g_debugmodeFlags & DEBUGFLAG_NOCLIP)) {
                rdMatrix34 a;
                rdVector3 addVec;

                flex_t mult = 1.0;
                if (sithControl_ReadFunctionMap(INPUT_FUNC_FAST, 0)) {
                    mult *= 5.0;
                }
                else if (sithControl_ReadFunctionMap(INPUT_FUNC_JUMP, &tmp)) {
#ifndef TARGET_TWL
                    mult *= 5.0;
#endif
                }
                if (sithControl_ReadFunctionMap(INPUT_FUNC_DUCK, &tmp)) {
                    mult *= 0.5;
                }
                else if ( sithControl_ReadFunctionMap(INPUT_FUNC_SLOW, 0) ) {
                    mult *= 0.5;
                }

                rdMatrix_BuildRotate34(&a, &v1->actorParams.eyePYR);
                rdVector_Zero3(&addVec);
                rdVector_MultAcc3(&addVec, &rdroid_yVector3, sithControl_ReadAxisStuff(INPUT_FUNC_FORWARD) * mult);
#ifdef TARGET_TWL
                if (sithControl_ReadFunctionMap(INPUT_FUNC_JUMP, &tmp)) {
                    rdVector_MultAcc3(&addVec, &rdroid_zVector3, 1.0);
                }
                if (sithControl_ReadFunctionMap(INPUT_FUNC_DUCK, &tmp)) {
                    rdVector_MultAcc3(&addVec, &rdroid_zVector3, -1.0);
                }
#endif

                rdMatrix_TransformVector34Acc(&addVec, &a);
                rdMatrix_TransformVector34Acc(&addVec, &v1->lookOrientation);
                rdVector_Add3Acc(&v1->physicsParams.vel, &addVec);
            }

            // Added: noclip
            if ((g_debugmodeFlags & DEBUGFLAG_NOCLIP)) {
                rdMatrix34 a;
                rdVector3 addVec;

                rdMatrix_BuildRotate34(&a, &v1->actorParams.eyePYR);
                rdVector_Zero3(&addVec);
                rdVector_MultAcc3(&addVec, &rdroid_xVector3, (Main_bMotsCompat ? -1.0 : 1.0) * sithControl_ReadAxisStuff(INPUT_FUNC_SLIDE));

                rdMatrix_TransformVector34Acc(&addVec, &a);
                rdMatrix_TransformVector34Acc(&addVec, &v1->lookOrientation);
                rdVector_Add3Acc(&v1->physicsParams.vel, &addVec);
            }

            if ( sithControl_ReadFunctionMap(INPUT_FUNC_JUMP, &tmp) )
            {
                // Added: noclip
                if ((g_debugmodeFlags & DEBUGFLAG_NOCLIP)) {

                }
                else if ( (v1->physicsParams.physflags & SITH_PF_WATERSURFACE) != 0 )
                {
                    if ( tmp )
                        sithPlayerActions_JumpWithVel(v1, 1.0);
                }
                else
                {
                    v1->physicsParams.acceleration.z = v1->actorParams.maxThrust * 0.5 + v1->physicsParams.acceleration.z;
                }
            }
            else 

            if ( sithControl_ReadFunctionMap(INPUT_FUNC_DUCK, &tmp) )
                v1->physicsParams.acceleration.z = v1->physicsParams.acceleration.z - v1->actorParams.maxThrust * 0.5;
        }
        else
        {
            if ( !sithControl_ReadFunctionMap(INPUT_FUNC_DUCK, &tmp) )
                v1->physicsParams.physflags &= ~SITH_PF_CROUCHING;
            else
                v1->physicsParams.physflags |= SITH_PF_CROUCHING;
        }
    }
}

void sithControl_DefaultHelper(int funcIdx, int dxKeyNum, int flags)
{
    uint32_t v0; // ecx
    stdControlKeyInfoEntry *v1; // eax

    if ( (sithControl_inputFuncToControlType[funcIdx] & 1) != 0 && sithControl_aInputFuncToKeyinfo[funcIdx].numEntries != 8 )
    {
        sithControl_MapFuncToDxKey(INPUT_FUNC_SLIDE, dxKeyNum);
        v0 = sithControl_aInputFuncToKeyinfo[funcIdx].numEntries + 1;
        v1 = &sithControl_aInputFuncToKeyinfo[funcIdx].aEntries[sithControl_aInputFuncToKeyinfo[funcIdx].numEntries];
        v1->flags = flags;
        v1->dxKeyNum = dxKeyNum;
        sithControl_aInputFuncToKeyinfo[funcIdx].numEntries = v0;
    }
}

void sithControl_MapDefaults()
{
    // TODO verify these
    sithControl_DefaultHelper(INPUT_FUNC_MLOOK, DIK_V, 2);
    sithControl_DefaultHelper(INPUT_FUNC_TURN, DIK_LEFT, 2);
    sithControl_DefaultHelper(INPUT_FUNC_TURN, DIK_RIGHT, 6);
    sithControl_DefaultHelper(INPUT_FUNC_TURN, DIK_NUMPAD4, 2);
    sithControl_DefaultHelper(INPUT_FUNC_TURN, DIK_NUMPAD4, 6);
    sithControl_DefaultHelper(INPUT_FUNC_TURN, DIK_LEFT, 2);
    sithControl_DefaultHelper(INPUT_FUNC_TURN, DIK_RIGHT, 6);

    sithControl_DefaultHelper(INPUT_FUNC_FORWARD, DIK_UP, 2);
    sithControl_DefaultHelper(INPUT_FUNC_FORWARD, DIK_DOWN, 6);
    sithControl_DefaultHelper(INPUT_FUNC_FORWARD, DIK_W, 2);
    sithControl_DefaultHelper(INPUT_FUNC_FORWARD, DIK_S, 6);
    sithControl_DefaultHelper(INPUT_FUNC_FORWARD, DIK_NUMPAD8, 2);

    sithControl_MapFunc(INPUT_FUNC_FORWARD, DIK_NUMPAD2, 4);

    if (Main_bMotsCompat) {
        sithControl_MapFunc(INPUT_FUNC_SLIDE, DIK_A, 0);
        sithControl_MapFunc(INPUT_FUNC_SLIDE, DIK_D, 4);
        sithControl_MapFunc(INPUT_FUNC_SLIDE, DIK_NUMPAD1, 0);
        sithControl_MapFunc(INPUT_FUNC_SLIDE, DIK_NUMPAD3, 4);
    }
    else {
        sithControl_MapFunc(INPUT_FUNC_SLIDE, DIK_A, 4);
        sithControl_MapFunc(INPUT_FUNC_SLIDE, DIK_D, 0);
        sithControl_MapFunc(INPUT_FUNC_SLIDE, DIK_NUMPAD1, 4);
        sithControl_MapFunc(INPUT_FUNC_SLIDE, DIK_NUMPAD3, 0);
    }
    
    sithControl_MapFunc(INPUT_FUNC_JUMP, DIK_ADD, 0);
    sithControl_MapFunc(INPUT_FUNC_JUMP, DIK_X, 0);
    sithControl_MapFunc(INPUT_FUNC_DUCK, DIK_C, 0);
    sithControl_MapFunc(INPUT_FUNC_FIRE1, DIK_RCONTROL, 0);
    sithControl_MapFunc(INPUT_FUNC_FIRE1, DIK_LCONTROL, 0);
    sithControl_MapFunc(INPUT_FUNC_ACTIVATE, DIK_SPACE, 0);
    sithControl_MapFunc(INPUT_FUNC_FIRE2, DIK_Z, 0);
    sithControl_MapFunc(INPUT_FUNC_FIRE2, DIK_NUMPAD0, 0);
    sithControl_MapFunc(INPUT_FUNC_SLIDETOGGLE, DIK_RMENU, 0);
    sithControl_MapFunc(INPUT_FUNC_SLIDETOGGLE, DIK_LMENU, 0);
    sithControl_MapFunc(INPUT_FUNC_SLOW, DIK_CAPITAL, 0);
    sithControl_MapFunc(INPUT_FUNC_FAST, DIK_LSHIFT, 0);
    sithControl_MapFunc(INPUT_FUNC_FAST, DIK_RSHIFT, 0);
    sithControl_MapFunc(INPUT_FUNC_PITCH, DIK_PRIOR, 4);
    sithControl_MapFunc(INPUT_FUNC_PITCH, DIK_NEXT, 0);
    sithControl_MapFunc(INPUT_FUNC_CENTER, DIK_HOME, 0);
    sithControl_MapFunc(INPUT_FUNC_CENTER, DIK_NUMPAD5, 0);
    sithControl_MapFunc(INPUT_FUNC_SELECT0, DIK_0, 0);
    sithControl_MapFunc(INPUT_FUNC_SELECT1, DIK_1, 0);
    sithControl_MapFunc(INPUT_FUNC_SELECT2, DIK_2, 0);
    sithControl_MapFunc(INPUT_FUNC_SELECT3, DIK_3, 0);
    sithControl_MapFunc(INPUT_FUNC_SELECT4, DIK_4, 0);
    sithControl_MapFunc(INPUT_FUNC_SELECT5, DIK_5, 0);
    sithControl_MapFunc(INPUT_FUNC_SELECT6, DIK_6, 0);
    sithControl_MapFunc(INPUT_FUNC_SELECT7, DIK_7, 0);
    sithControl_MapFunc(INPUT_FUNC_SELECT8, DIK_8, 0);
    sithControl_MapFunc(INPUT_FUNC_SELECT9, DIK_9, 0);
    sithControl_MapFunc(INPUT_FUNC_GAMESAVE, DIK_F9, 0);
    sithControl_MapFunc(INPUT_FUNC_NEXTINV, DIK_R, 0);
    sithControl_MapFunc(INPUT_FUNC_NEXTINV, DIK_RBRACKET, 0);
    sithControl_MapFunc(INPUT_FUNC_PREVINV, DIK_LBRACKET, 0);
    sithControl_MapFunc(INPUT_FUNC_USEINV, DIK_RETURN, 0);
    sithControl_MapFunc(INPUT_FUNC_PREVSKILL, DIK_SEMICOLON, 0);
    sithControl_MapFunc(INPUT_FUNC_NEXTSKILL, DIK_APOSTROPHE, 0);
    sithControl_MapFunc(INPUT_FUNC_PREVSKILL, DIK_Q, 0);
    sithControl_MapFunc(INPUT_FUNC_NEXTSKILL, DIK_E, 0);
    sithControl_MapFunc(INPUT_FUNC_USESKILL, DIK_F, 0);
    sithControl_MapFunc(INPUT_FUNC_PREVWEAPON, DIK_PERIOD, 0);
    sithControl_MapFunc(INPUT_FUNC_NEXTWEAPON, DIK_SLASH, 0);
    sithControl_MapFunc(INPUT_FUNC_NEXTWEAPON, DIK_G, 0);
    sithControl_MapFunc(INPUT_FUNC_MAP, DIK_TAB, 0);
    sithControl_MapFunc(INPUT_FUNC_INCREASE, DIK_EQUALS, 0);
    sithControl_MapFunc(INPUT_FUNC_DECREASE, DIK_MINUS, 0);
    if ( (g_debugmodeFlags & DEBUGFLAG_IN_EDITOR) != 0 )
        sithControl_MapFunc(INPUT_FUNC_DEBUG, DIK_BACK, 0);// DIK_BACKSPACE
    sithControl_MapFunc(INPUT_FUNC_TALK, DIK_T, 0);
    sithControl_MapFunc(INPUT_FUNC_GAMMA, DIK_F11, 0);
    sithControl_MapFunc(INPUT_FUNC_SCREENSHOT, DIK_F12, 0);
    sithControl_MapFunc(INPUT_FUNC_TALLY, DIK_GRAVE, 0);
}

void sithControl_InputInit()
{
    stdControlKeyInfoEntry *v6; // eax
    stdControlKeyInfoEntry *v7; // eax
    stdControlKeyInfoEntry *v8; // eax

    _memset(sithControl_aInputFuncToKeyinfo, 0, sizeof(stdControlKeyInfo) * 74);
#ifndef TARGET_TWL
    stdControl_Reset();
#endif
    sithWeapon_controlOptions = 36;
    sithControl_MapDefaults();
    sithControl_MapAxisFunc(INPUT_FUNC_FORWARD, AXIS_JOY1_Y, 4u);
    sithControl_MapAxisFunc(INPUT_FUNC_TURN, AXIS_JOY1_X, 4u);
#ifndef TARGET_TWL
    sithControl_DefaultHelper(INPUT_FUNC_FIRE1, KEY_JOY1_B1, 2);
    sithControl_DefaultHelper(INPUT_FUNC_FIRE2, KEY_JOY1_B2, 2);
    sithControl_DefaultHelper(INPUT_FUNC_ACTIVATE, KEY_JOY1_B3, 2);
    sithControl_MapFunc(INPUT_FUNC_JUMP, KEY_JOY1_B4, 0);
    sithControl_MapFunc(INPUT_FUNC_PITCH, KEY_JOY1_HUP, 4);
    sithControl_MapFunc(INPUT_FUNC_PITCH, KEY_JOY1_HDOWN, 0);
    sithControl_MapFunc(INPUT_FUNC_SLIDE, KEY_JOY1_HLEFT, 4);
    sithControl_MapFunc(INPUT_FUNC_SLIDE, KEY_JOY1_HRIGHT, 0);
    sithControl_MapFunc(INPUT_FUNC_NEXTINV, KEY_JOY1_B5, 0);
    sithControl_MapFunc(INPUT_FUNC_USEINV, KEY_JOY1_B7, 0);
#endif
    v6 = sithControl_MapAxisFunc(INPUT_FUNC_TURN, AXIS_MOUSE_X, 0xCu);
    if ( v6 )
        v6->binaryAxisVal = 0.4;
#ifdef QOL_IMPROVEMENTS
    v7 = sithControl_MapAxisFunc(INPUT_FUNC_PITCH, AXIS_MOUSE_Y, 0xCu); // Non-inverted by default, fight me lol
#else
    v7 = sithControl_MapAxisFunc(INPUT_FUNC_PITCH, AXIS_MOUSE_Y, 8u);
#endif
    if ( v7 ) 
        v7->binaryAxisVal = 0.3;
    v8 = sithControl_MapAxisFunc(INPUT_FUNC_PITCH, AXIS_MOUSE_Z, 0);
    if ( v8 )
        v8->binaryAxisVal = 4.0;
    
    sithControl_DefaultHelper(INPUT_FUNC_FIRE1, KEY_MOUSE_B1, 2);
    sithControl_DefaultHelper(INPUT_FUNC_JUMP, KEY_MOUSE_B2, 2);
    sithControl_DefaultHelper(INPUT_FUNC_FIRE2, KEY_MOUSE_B3, 2);

#ifdef TARGET_TWL
    sithControl_MapFunc(INPUT_FUNC_FORWARD, KEY_JOY1_HUP, 0);
    sithControl_MapFunc(INPUT_FUNC_FORWARD, KEY_JOY1_HDOWN, 4);
    sithControl_MapFunc(INPUT_FUNC_TURN, KEY_JOY1_HLEFT, 0);
    sithControl_MapFunc(INPUT_FUNC_TURN, KEY_JOY1_HRIGHT, 4);
    sithControl_DefaultHelper(INPUT_FUNC_FIRE1, KEY_JOY1_B1, 2);
    sithControl_DefaultHelper(INPUT_FUNC_DUCK, KEY_JOY1_B2, 0);
    sithControl_DefaultHelper(INPUT_FUNC_ACTIVATE, KEY_JOY1_B3, 2);
    sithControl_MapFunc(INPUT_FUNC_JUMP, KEY_JOY1_B4, 0);
    sithControl_MapFunc(INPUT_FUNC_NEXTINV, KEY_JOY1_B5, 0); // L
    sithControl_MapFunc(INPUT_FUNC_NEXTWEAPON, KEY_JOY1_B6, 0); // R
    sithControl_MapFunc(INPUT_FUNC_USEINV, KEY_JOY1_B7, 0);
    sithWeapon_controlOptions |= 2;
#endif
}

void sithControl_sub_4D6930(int funcIdx)
{
    sithControl_inputFuncToControlType[funcIdx] = 5;
}

stdControlKeyInfo* sithControl_EnumBindings(sithControlEnumFunc_t pfEnumFunction, int a2, int a3, int a4, Darray *a5)
{
    stdControlKeyInfo *result; // eax
    int v6; // ebp
    int v7; // esi
    stdControlKeyInfoEntry* v8; // eax
    int v9; // edx
    int v10; // ecx
    int v11; // ebx
    stdControlKeyInfoEntry *v12; // edi
    Darray *v13; // edi
    stdControlKeyInfoEntry *i; // [esp+10h] [ebp-1Ch]
    unsigned int v16; // [esp+14h] [ebp-18h]
    int v17; // [esp+18h] [ebp-14h]
    int v18; // [esp+1Ch] [ebp-10h]
    BOOL v19; // [esp+20h] [ebp-Ch]
    stdControlKeyInfo *v20; // [esp+24h] [ebp-8h]
    int v21; // [esp+28h] [ebp-4h]

    result = sithControl_aInputFuncToKeyinfo;
    v6 = 1;
    v7 = 0;
    v20 = sithControl_aInputFuncToKeyinfo;
    for (int j = 0; j < 74; j++)
    {
        int typeflags = sithControl_inputFuncToControlType[v7];

        v18 = 0;
        v19 = 0;
        v17 = 0;
        v21 = typeflags & 2;
        v16 = 0;
        v8 = &result->aEntries[0];

        for ( i = v8; v16 < v20->numEntries; v8 = i )
        {
            v9 = v8->flags;
            v10 = v8->dxKeyNum;
            v11 = v8->flags & 2;
            if ( (!v11 || v10 >= JK_EXTENDED_KEY_START || a2)
              && (((v9 & 1) == 0 || v10 < AXIS_MOUSE_X) 
              && (!v11 || !KEY_IS_MOUSE(v10)) || a4)
              && (((v9 & 1) == 0 || v10 >= AXIS_MOUSE_X) 
              && (!v11 || v10 < JK_EXTENDED_KEY_START || KEY_IS_MOUSE(v10)) || a3) )
            {
                v6 = pfEnumFunction(v7, sithControl_aFunctionStrs[v7], typeflags, v16, v10, v9, v8, a5);
                if ( v18 || (v12 = i, (i->dxKeyNum & 2) != 0) && (i->dxKeyNum & 4) == 0 )
                {
                    v12 = i;
                    v18 = 1;
                }
                else
                {
                    v18 = 0;
                }
                v19 = v19 || (v12->dxKeyNum & 2) != 0 && (v12->dxKeyNum & 4) != 0;
                if ( v17 || (v17 = 0, (v12->dxKeyNum & 1) != 0) )
                    v17 = 1;
            }
            ++v16;
            ++i;
            if ( !v6 )
                break;
        }
        if ( v6 && v21 && !v17 )
        {
            v13 = a5;
            v6 = pfEnumFunction(v7, sithControl_aFunctionStrs[v7], typeflags, -1u, 0, 1, 0, a5);
        }
        else
        {
            v13 = a5;
        }
        if ( v6 && !v18 || !v20->numEntries )
            v6 = pfEnumFunction(v7, sithControl_aFunctionStrs[v7], typeflags, -1u, 0, 2, 0, v13);
        if ( v6 && v21 && !v19 )
            v6 = pfEnumFunction(v7, sithControl_aFunctionStrs[v7], typeflags, -1u, 0, 6, 0, v13);
        ++v7;
        result = ++v20;
    }
    return result;
}

void sithControl_sub_4D7670()
{
    stdControlKeyInfo *v0; // edx
    uint32_t v1; // ecx
    uint32_t v2; // edi
    int v3; // ebp
    stdControlKeyInfoEntry *v4; // ebx
    int v5; // esi
    uint32_t v6; // eax
    uint32_t v7; // ecx
    stdControlKeyInfoEntry *v8; // eax
    stdControlKeyInfoEntry *v9; // ebx
    stdControlKeyInfoEntry *v10; // eax
    stdControlKeyInfoEntry *v11; // eax
    stdControlKeyInfoEntry *v12; // eax
    uint32_t v13; // ebp
    int v14; // edi
    stdControlKeyInfo *v15; // esi
    uint32_t v16; // eax
    stdControlKeyInfoEntry *v17; // ecx
    int v18; // ecx
    uint32_t v19; // edx
    uint32_t *v20; // edx
    uint32_t *v21; // edi
    stdControlKeyInfoEntry *v22; // eax
    uint32_t v23; // ebp
    int v24; // edi
    stdControlKeyInfo *v25; // esi
    unsigned int v26; // ecx
    stdControlKeyInfoEntry *v27; // eax
    stdControlKeyInfoEntry *v28; // eax
    uint32_t v29; // ecx
    stdControlKeyInfoEntry *v30; // eax
    stdControlKeyInfoEntry *v31; // [esp+10h] [ebp-4h]

    v0 = sithControl_aInputFuncToKeyinfo;
    do
    {
        while ( 1 )
        {
            v1 = v0->numEntries;
            v2 = 0;
            v3 = 0;
            if ( !v0->numEntries )
                break;
            v4 = v0->aEntries;
            v31 = v0->aEntries;
            while ( !v3 )
            {
                v5 = v4->dxKeyNum;
                if ( (v4->flags & 1) == 0 && KEY_IS_MOUSE(v5) || (v4->flags & 1) != 0 && v5 >= AXIS_MOUSE_X && v5 <= AXIS_MOUSE_Z )
                {
                    v6 = v1 - 1;
                    v7 = v2;
                    v0->numEntries = v6;
                    if ( v2 < v6 )
                    {
                        v8 = v4;
                        do
                        {
                            v9 = v8;
                            ++v7;
                            ++v8;
                            v9->dxKeyNum = v8->dxKeyNum;
                            v9->flags = v8->flags;
                            v9->binaryAxisVal = v8->binaryAxisVal;
                        }
                        while ( v7 < v0->numEntries );
                        v4 = v31;
                    }
                    v3 = 1;
                }
                v1 = v0->numEntries;
                ++v2;
                v31 = ++v4;
                if ( v2 >= v0->numEntries )
                    goto LABEL_17;
            }
        }
LABEL_17:
        ;
    }
    while ( v3 || ++v0 < &sithControl_aInputFuncToKeyinfo[74] );

    v10 = sithControl_MapAxisFunc(INPUT_FUNC_TURN, AXIS_MOUSE_X, 0xCu);
    if ( v10 )
        v10->binaryAxisVal = 0.4;
    v11 = sithControl_MapAxisFunc(INPUT_FUNC_PITCH, AXIS_MOUSE_Y, 8u);
    if ( v11 )
        v11->binaryAxisVal = 0.3;
    v12 = sithControl_MapAxisFunc(INPUT_FUNC_PITCH, AXIS_MOUSE_Z, 0);
    if ( v12 )
        v12->binaryAxisVal = 4.0;
    sithControl_DefaultHelper(INPUT_FUNC_FIRE1, KEY_MOUSE_B1, 2);
    sithControl_DefaultHelper(INPUT_FUNC_JUMP, KEY_MOUSE_B2, 2);
    sithControl_DefaultHelper(INPUT_FUNC_FIRE2, KEY_MOUSE_B3, 2);
}

void sithControl_sub_4D7350()
{
    stdControlKeyInfo *v0; // edx
    uint32_t v1; // eax
    uint32_t v2; // esi
    int v3; // ebx
    stdControlKeyInfoEntry *v4; // edi
    uint32_t v5; // eax
    uint32_t v6; // ecx
    stdControlKeyInfoEntry *v7; // eax
    stdControlKeyInfoEntry *v8; // ebx
    stdControlKeyInfoEntry *v9; // [esp+10h] [ebp-4h]

    v0 = sithControl_aInputFuncToKeyinfo;
    do
    {
        while ( 1 )
        {
            v1 = v0->numEntries;
            v2 = 0;
            v3 = 0;
            if ( !v0->numEntries )
                break;
            v4 = v0->aEntries;
            v9 = v0->aEntries;
            while ( !v3 )
            {
                if ( (v4->flags & 1) == 0 && v4->dxKeyNum < JK_EXTENDED_KEY_START )
                {
                    v5 = v1 - 1;
                    v6 = v2;
                    v0->numEntries = v5;
                    if ( v2 < v5 )
                    {
                        v7 = v4;
                        do
                        {
                            v8 = v7;
                            ++v6;
                            ++v7;
                            v8->dxKeyNum = v7->dxKeyNum;
                            v8->flags = v7->flags;
                            v8->binaryAxisVal = v7->binaryAxisVal;
                        }
                        while ( v6 < v0->numEntries );
                        v4 = v9;
                    }
                    v3 = 1;
                }
                v1 = v0->numEntries;
                ++v2;
                v9 = ++v4;
                if ( v2 >= v0->numEntries )
                    goto LABEL_13;
            }
        }
LABEL_13:
        ;
    }
    while ( v3 || ++v0 < &sithControl_aInputFuncToKeyinfo[74] );
    sithControl_MapDefaults();
}

void sithControl_JoyInputInit()
{
    stdControlKeyInfo *v0; // edx
    uint32_t v1; // ecx
    uint32_t v2; // edi
    int v3; // ebp
    stdControlKeyInfoEntry *v4; // ebx
    int v5; // esi
    uint32_t v6; // eax
    uint32_t v7; // ecx
    stdControlKeyInfoEntry *v8; // eax
    stdControlKeyInfoEntry *v9; // ebx
    uint32_t v10; // ecx
    stdControlKeyInfoEntry *v11; // eax
    uint32_t v12; // ecx
    stdControlKeyInfoEntry *v13; // eax
    uint32_t v14; // ecx
    stdControlKeyInfoEntry *v15; // eax
    uint32_t v16; // ecx
    stdControlKeyInfoEntry *v17; // eax
    uint32_t v18; // ecx
    stdControlKeyInfoEntry *v19; // eax
    uint32_t v20; // ecx
    stdControlKeyInfoEntry *v21; // eax
    stdControlKeyInfoEntry *v22; // [esp+10h] [ebp-4h]

    v0 = sithControl_aInputFuncToKeyinfo;
    do
    {
        while ( 1 )
        {
            v1 = v0->numEntries;
            v2 = 0;
            v3 = 0;
            if ( !v0->numEntries )
                break;
            v4 = v0->aEntries;
            v22 = v0->aEntries;
            while ( !v3 )
            {
                v5 = v4->dxKeyNum;
                if ( (v4->flags & 1) == 0 && KEY_IS_JOY_BUTTON(v5) || (v4->flags & 1) != 0 && v5 >= 0 && v5 <= 11 )
                {
                    v6 = v1 - 1;
                    v7 = v2;
                    v0->numEntries = v6;
                    if ( v2 < v6 )
                    {
                        v8 = v4;
                        do
                        {
                            v9 = v8;
                            ++v7;
                            ++v8;
                            v9->dxKeyNum = v8->dxKeyNum;
                            v9->flags = v8->flags;
                            v9->binaryAxisVal = v8->binaryAxisVal;
                        }
                        while ( v7 < v0->numEntries );
                        v4 = v22;
                    }
                    v3 = 1;
                }
                v1 = v0->numEntries;
                ++v2;
                v22 = ++v4;
                if ( v2 >= v0->numEntries )
                    goto LABEL_17;
            }
        }
LABEL_17:
        ;
    }
    while ( v3 || ++v0 < &sithControl_aInputFuncToKeyinfo[74] );
    sithControl_MapAxisFunc(INPUT_FUNC_FORWARD, AXIS_JOY1_Y, 4u);
    sithControl_MapAxisFunc(INPUT_FUNC_TURN, AXIS_JOY1_X, 4u);
    if ( (sithControl_inputFuncToControlType[10] & 1) != 0 && sithControl_aInputFuncToKeyinfo[10].numEntries != 8 )
    {
        sithControl_MapFuncToDxKey(INPUT_FUNC_SLIDE, KEY_JOY1_B1);
        v10 = sithControl_aInputFuncToKeyinfo[10].numEntries + 1;
        v11 = &sithControl_aInputFuncToKeyinfo[10].aEntries[sithControl_aInputFuncToKeyinfo[10].numEntries];
        v11->flags = 2;
        v11->dxKeyNum = KEY_JOY1_B1;
        sithControl_aInputFuncToKeyinfo[10].numEntries = v10;
    }
    if ( (sithControl_inputFuncToControlType[11] & 1) != 0 && sithControl_aInputFuncToKeyinfo[11].numEntries != 8 )
    {
        sithControl_MapFuncToDxKey(INPUT_FUNC_SLIDE, KEY_JOY1_B2);
        v12 = sithControl_aInputFuncToKeyinfo[11].numEntries + 1;
        v13 = &sithControl_aInputFuncToKeyinfo[11].aEntries[sithControl_aInputFuncToKeyinfo[11].numEntries];
        v13->flags = 2;
        v13->dxKeyNum = KEY_JOY1_B2;
        sithControl_aInputFuncToKeyinfo[11].numEntries = v12;
    }
    if ( (sithControl_inputFuncToControlType[12] & 1) != 0 && sithControl_aInputFuncToKeyinfo[12].numEntries != 8 )
    {
        sithControl_MapFuncToDxKey(INPUT_FUNC_SLIDE, KEY_JOY1_B3);
        v14 = sithControl_aInputFuncToKeyinfo[12].numEntries + 1;
        v15 = &sithControl_aInputFuncToKeyinfo[12].aEntries[sithControl_aInputFuncToKeyinfo[12].numEntries];
        v15->flags = 2;
        v15->dxKeyNum = KEY_JOY1_B3;
        sithControl_aInputFuncToKeyinfo[12].numEntries = v14;
    }
    if ( (sithControl_inputFuncToControlType[4] & 1) != 0 && sithControl_aInputFuncToKeyinfo[4].numEntries != 8 )
    {
        sithControl_MapFuncToDxKey(INPUT_FUNC_SLIDE, KEY_JOY1_B4);
        v16 = sithControl_aInputFuncToKeyinfo[4].numEntries + 1;
        v17 = &sithControl_aInputFuncToKeyinfo[4].aEntries[sithControl_aInputFuncToKeyinfo[4].numEntries];
        v17->flags = 2;
        v17->dxKeyNum = KEY_JOY1_B4;
        sithControl_aInputFuncToKeyinfo[4].numEntries = v16;
    }
    if ( (sithControl_inputFuncToControlType[8] & 1) != 0 )
    {
        if ( sithControl_aInputFuncToKeyinfo[8].numEntries != 8 )
        {
            sithControl_MapFuncToDxKey(INPUT_FUNC_SLIDE, KEY_JOY1_HUP);
            v18 = sithControl_aInputFuncToKeyinfo[8].numEntries + 1;
            v19 = &sithControl_aInputFuncToKeyinfo[8].aEntries[sithControl_aInputFuncToKeyinfo[8].numEntries];
            v19->flags = 6;
            v19->dxKeyNum = KEY_JOY1_HUP;
            sithControl_aInputFuncToKeyinfo[8].numEntries = v18;
        }
        if ( (sithControl_inputFuncToControlType[8] & 1) != 0 && sithControl_aInputFuncToKeyinfo[8].numEntries != 8 )
        {
            sithControl_MapFuncToDxKey(INPUT_FUNC_SLIDE, KEY_JOY1_HDOWN);
            v20 = sithControl_aInputFuncToKeyinfo[8].numEntries + 1;
            v21 = &sithControl_aInputFuncToKeyinfo[8].aEntries[sithControl_aInputFuncToKeyinfo[8].numEntries];
            v21->flags = 2;
            v21->dxKeyNum = KEY_JOY1_HDOWN;
            sithControl_aInputFuncToKeyinfo[8].numEntries = v20;
        }
    }
    sithControl_MapFunc(INPUT_FUNC_SLIDE, KEY_JOY1_HLEFT, 4);
    sithControl_MapFunc(INPUT_FUNC_SLIDE, KEY_JOY1_HRIGHT, 0);
    sithControl_MapFunc(INPUT_FUNC_NEXTINV, KEY_JOY1_B5, 0);
    sithControl_MapFunc(INPUT_FUNC_USEINV, KEY_JOY1_B7, 0);
}