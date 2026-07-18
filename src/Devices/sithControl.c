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
#include "Main/Main.h" // Added: Main_bDwCompat (DW tool-key dispatch)
#include "Dw/dwCog.h" // Added: DroidWorks droid-tool dispatch (no-ops off-desktop)
#include "jk.h"

// Added
static int sithControl_followingPlayer = 0;
static int sithControl_curDebugCam = 0;
static char16_t sithControl_debugWStrTmp[256];

// MOTS added
static flex_t sithControl_008d7f44 = 0.0;
static int sithControl_008d7f4c = 0;
static int sithControl_008d7f50 = 0;
static int sithControl_008d7f54 = 0;
static int sithControl_008d7f58 = 0;
static int sithControl_008d7f5c = 0;

static const char *sithControl_aFunctionStrs[INPUT_FUNC_MAX+1] =
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
    "ACTIVATE31",
#ifdef QOL_IMPROVEMENTS
    "USELASTSELECTED", // Common button for both items and force power usage for controllers
#endif // QOL_IMPROVEMENTS
    "INPUT_FUNC_MAX"
};

#ifdef QOL_IMPROVEMENTS
int sithControl_lastSelected = LAST_SELECTED_ITEM;
#endif // QOL_IMPROVEMENTS

int sithControl_Startup()
{
    if ( sithControl_bInitted )
        return 0;

    if ( stdControl_Startup() )
    {
        sithControl_RegisterControlFunctions();
        _memset(sithControl_aInputFuncToKeyinfo, 0, sizeof(stdControlKeyInfo) * INPUT_FUNC_MAX);
        stdControl_Reset();
        sithControl_bInitted = 1;
        return 1;
    }

#ifdef QOL_IMPROVEMENTS
    sithControl_lastSelected = LAST_SELECTED_ITEM;
#endif // QOL_IMPROVEMENTS

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
    sithControl_lastSelected = LAST_SELECTED_ITEM;
#endif // QOL_IMPROVEMENTS

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

void sithControl_RegisterAxisFunction(int functionId, uint32_t flag)
{
    SITH_ASSERTREL((functionId >= 0) && (functionId < INPUT_FUNC_MAX)); // Added: port from OpenJones3D
    sithControl_inputFuncToControlType[functionId] = flag | 3;
}

void sithControl_Reset()
{
    _memset(sithControl_aInputFuncToKeyinfo, 0, sizeof(sithControl_aInputFuncToKeyinfo));
    stdControl_Reset();
}

void sithControl_RegisterControlFunctions()
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
#ifdef QOL_IMPROVEMENTS
    sithControl_inputFuncToControlType[INPUT_FUNC_USELASTSELECTED] = 4 | 1;
#endif
}

// MOTS altered
void sithControl_Update(flex_t secDeltaTime, int msecDeltaTime)
{
    if ( !sithControl_bOpened )
        return;

    // MOTS altered
    if ( !sithPlayer_g_pLocalPlayerThing
      || (sithPlayer_g_pLocalPlayerThing->actorParams.flags & (Main_bMotsCompat ? (SITH_AF_NOIDLECAMERA|SITH_AF_SCOPEHUD|SITH_AF_ARACHNID) : SITH_AF_NOIDLECAMERA))
      || (sithPlayer_g_pLocalPlayerThing->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) != 0
      || (sithCamera_g_stateFlags & 1) != 0 )
    {
        if ( sithCamera_g_pCurCamera == &sithCamera_g_aCameras[4] )
        {
            SITHLOG_STATUS("Switch out of idle camera.\n"); // Added: port from OpenJones3D
            sithCamera_SetCurrentToCycleCamera();
        }
    }
    else
    {
        if ( stdControl_bControlsIdle )
        {
            sithControl_msIdle += msecDeltaTime;
            if ( sithControl_msIdle > 30000 && sithCamera_g_pCurCamera != &sithCamera_g_aCameras[4] )
                sithCamera_SetCurrentCamera(&sithCamera_g_aCameras[4]);
#ifdef QOL_IMPROVEMENTS
            else if (sithControl_msIdle < 30000 && sithCamera_g_pCurCamera == &sithCamera_g_aCameras[4] ) {
                sithCamera_SetCurrentToCycleCamera();
            }
#endif

        }
        else {
            sithControl_msIdle = 0;
            if ( sithCamera_g_pCurCamera == &sithCamera_g_aCameras[4] ) {
                SITHLOG_STATUS("Switch out of idle camera.\n"); // Added: port from OpenJones3D
                sithCamera_SetCurrentToCycleCamera();
            }
        }
    }
    if ( sithWorld_g_pCurrentWorld->pLocalPlayer && sithControl_numHandlers > 0 )
    {
#ifndef FIXED_TIMESTEP_PHYS
        sithControl_ReadControls();
#endif
        for (int i = 0; i < sithControl_numHandlers; i++)
        {
            if (sithControl_aHandlers[i] && sithControl_aHandlers[i](sithWorld_g_pCurrentWorld->pLocalPlayer, secDeltaTime) )
                break;
        }
#ifndef FIXED_TIMESTEP_PHYS
        sithControl_FinishRead();
#endif
    }
}

stdControlKeyInfoEntry* sithControl_BindControl(int functionId, int controlId, int flags)
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

    SITH_ASSERTREL((functionId >= 0) && (functionId < INPUT_FUNC_MAX)); // Added: port from OpenJones3D

    v3 = flags;
    v3 = flags & ~(8|1) | 2;
    a3a = v3;
    //printf("1] Map %x\n", keyNum);
    if ( (sithControl_inputFuncToControlType[functionId] & 1) != 0 && sithControl_aInputFuncToKeyinfo[functionId].numEntries != 8 )
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
        while ( (v7->flags & INPUT_MAPPING_FLAG_DXKEY) == 0 || v7->dxKeyNum != controlId )
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

        v13 = sithControl_aInputFuncToKeyinfo[functionId].numEntries;
        //printf("1] Map %x, %x %x %x %x\n", keyNum, funcIdx, v8, v6, v13);
        v14 = &sithControl_aInputFuncToKeyinfo[functionId].aEntries[v13];
        v14->flags = a3a;
        v14->dxKeyNum = controlId;
        sithControl_aInputFuncToKeyinfo[functionId].numEntries = v13 + 1;

        return v14;
    }
    return NULL;
}

stdControlKeyInfoEntry* sithControl_BindAxis(int functionId, int axis, uint32_t flags)
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

    SITH_ASSERTREL((functionId >= 0) && (functionId < INPUT_FUNC_MAX)); // Added: port from OpenJones3D

    v3 = flags;
    v3 = flags & ~2 | 1;
    flagsa = v3;
    v4 = stdControl_aAxes[axis].flags;
    if ( (v4 & 1) == 0 )
        return 0;
    if ( (sithControl_inputFuncToControlType[functionId] & 1) == 0 )
        return 0;
    if ( sithControl_aInputFuncToKeyinfo[functionId].numEntries == 8 )
        return 0;
    if ( (v4 & INPUT_MAPPING_FLAG_DXKEY) != 0 )
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
        while ( (v10->flags & 1) == 0 || v10->dxKeyNum != axis )
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
    if ( stdControl_EnableAxis(axis) )
    {
        if ( (flagsa & 0x10) != 0 )
            stdControl_aAxes[axis].flags |= 8u;
        v16 = sithControl_aInputFuncToKeyinfo[functionId].numEntries;
        result = &sithControl_aInputFuncToKeyinfo[functionId].aEntries[v16];
        result->flags = flagsa;
        result->dxKeyNum = axis;
        sithControl_aInputFuncToKeyinfo[functionId].numEntries = v16 + 1;
        return result;
    }
    return 0;
}

void sithControl_UnbindFunctionIndex(int funcId, unsigned int bindIndex)
{
    unsigned int v2; // edx
    int result; // eax
    unsigned int v4; // ecx
    stdControlKeyInfoEntry *v5; // ecx
    stdControlKeyInfoEntry *v6; // edi

    SITH_ASSERTREL((funcId >= 0) && (funcId < INPUT_FUNC_MAX)); // Added: port from OpenJones3D

    v2 = bindIndex;
    v4 = sithControl_aInputFuncToKeyinfo[funcId].numEntries - 1;
    sithControl_aInputFuncToKeyinfo[funcId].numEntries = v4;
    if ( bindIndex < v4 )
    {
        v5 = &sithControl_aInputFuncToKeyinfo[funcId].aEntries[bindIndex];
        do
        {
            v6 = v5;
            ++v2;
            *v6 = *++v5;
        }
        while ( v2 < sithControl_aInputFuncToKeyinfo[funcId].numEntries );
    }
}

void sithControl_UnbindControl(int flags, int controlId)
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
    while ( (flags & v5->flags) == 0 || v5->dxKeyNum != controlId )
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

    _memset(sithControl_aInputFuncToKeyinfo, 0, sizeof(stdControlKeyInfo) * INPUT_FUNC_MAX);
    stdControl_Reset();
    if ( !stdConffile_ReadArgs()
      || !stdConffile_g_entry.numArgs
      || strcmp(stdConffile_g_entry.aArgs[0].key, "flags")
      || _sscanf(stdConffile_g_entry.aArgs[0].value, "%x", &sithWeapon_controlOptions) != 1 )
    {
        return 0;
    }
    while ( stdConffile_ReadArgs() )
    {
        if ( !_strcmp(stdConffile_g_entry.aArgs[0].key, "end.") )
            break;
        v18 = 0.0;
        if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "axis") )
        {
            _atoi(stdConffile_g_entry.aArgs[1].value);
            _atof(stdConffile_g_entry.aArgs[2].value);
        }
        else
        {
            v0 = _atoi(stdConffile_g_entry.aArgs[1].value);
            v1 = v0;
            if ( v0 <= 0x4A && (sithControl_inputFuncToControlType[v0] & 1) != 0 && _sscanf(stdConffile_g_entry.aArgs[3].value, "%x", &v19) == 1 )
            {
                dxKeyNum = _atoi(stdConffile_g_entry.aArgs[2].value);
                dxKeyNum_ = dxKeyNum;
                if ( stdConffile_g_entry.numArgs > 4u )
                    v18 = _atof(stdConffile_g_entry.aArgs[4].value);
                v3 = v19;
                if ( (v19 & INPUT_MAPPING_FLAG_DXKEY) != 0 )
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
                                while ( (v8->flags & INPUT_MAPPING_FLAG_DXKEY) == 0 || v8->dxKeyNum != dxKeyNum )
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
                    v16 = sithControl_BindAxis(v1, dxKeyNum, v19);
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

int sithControl_GetKey(int keyId, int *pState)
{
    uint32_t v2; // ebx
    stdControlKeyInfoEntry *v3; // esi
    unsigned int v4; // eax
    int v6; // [esp+10h] [ebp-4h]

    //sithWeapon_controlOptions |= 0x20;

    SITH_ASSERTREL((keyId >= 0) && (keyId < INPUT_FUNC_MAX)); // Added: port from OpenJones3D

    v6 = 0;
    if ( pState )
        *pState = 0;
    v2 = 0;
    if ( sithControl_aInputFuncToKeyinfo[keyId].numEntries )
    {
        v3 = sithControl_aInputFuncToKeyinfo[keyId].aEntries;
        do
        {
            v4 = v3->dxKeyNum;
            if ( !(sithWeapon_controlOptions & 0x20) || v4 < JK_EXTENDED_KEY_START || KEY_IS_MOUSE(v4) )
                v6 |= stdControl_ReadKey(v4, pState);
            ++v2;
            ++v3;
        }
        while ( v2 < sithControl_aInputFuncToKeyinfo[keyId].numEntries );
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

flex_t sithControl_GetKeyAsAxisNormalized(int axisId)
{
    uint32_t v1; // ebp
    stdControlKeyInfoEntry *entryIter; // esi
    int v3; // ebx
    flex_d_t v4; // st7
    flex_t v6; // [esp+10h] [ebp-4h]

    SITH_ASSERTREL((axisId >= 0) && (axisId < INPUT_FUNC_MAX)); // Added: port from OpenJones3D

    v1 = 0;
    v6 = 0.0;
    if ( sithControl_aInputFuncToKeyinfo[axisId].numEntries )
    {
        entryIter = sithControl_aInputFuncToKeyinfo[axisId].aEntries;
        do
        {
            v3 = entryIter->flags;
            if ( (v3 & 1) != 0 )
            {
                if ( (sithWeapon_controlOptions & 0x20) == 0 || entryIter->dxKeyNum >= AXIS_MOUSE_X )
                {
                    v4 = stdControl_ReadAxis(entryIter->dxKeyNum);
LABEL_11:
                    if ( (entryIter->flags & INPUT_MAPPING_FLAG_RAW_AXIS) != 0 ) {
#ifdef QOL_IMPROVEMENTS
                        v4 = v4 * 25.0;
#else
                        v4 = v4 * sithTime_g_fps;
#endif
                    }
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
        while ( v1 < sithControl_aInputFuncToKeyinfo[axisId].numEntries );
    }
    if ( v6 < -1.0 )
        return -1.0;
    if ( v6 > 1.0 )
        return 1.0;
    return v6;
}

flex_t sithControl_GetKeyAsAxis(int axisId)
{
    uint32_t v1; // ebp
    stdControlKeyInfoEntry *v2; // esi
    int v3; // ebx
    flex_d_t v4; // st7
    flex_t v6; // [esp+8h] [ebp-4h]

    SITH_ASSERTREL((axisId >= 0) && (axisId < INPUT_FUNC_MAX)); // Added: port from OpenJones3D

    v1 = 0;
    v6 = 0.0;
    if ( sithControl_aInputFuncToKeyinfo[axisId].numEntries )
    {
        v2 = sithControl_aInputFuncToKeyinfo[axisId].aEntries;
        do
        {
            v3 = v2->flags;
            if ( (v3 & INPUT_MAPPING_FLAG_RAW_AXIS) == 0 )
            {
                if ( (v3 & INPUT_MAPPING_FLAG_AXIS) != 0 )
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
                        if ( (v3 & INPUT_MAPPING_FLAG_AXIS_REVERSED) != 0 )
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
        while ( v1 < sithControl_aInputFuncToKeyinfo[axisId].numEntries );
    }
    return v6;
}

flex_t sithControl_GetAxis(int axisId)
{
    stdControlKeyInfoEntry *v1; // edi
    stdControlKeyInfoEntry *v2; // esi
    uint32_t v3; // ebp
    int v4; // ebx
    flex_d_t v5; // st7
    flex_t v7; // [esp+4h] [ebp-4h]

    SITH_ASSERTREL((axisId >= 0) && (axisId < INPUT_FUNC_MAX)); // Added: port from OpenJones3D

    v7 = 0.0;
    v1 = sithControl_aInputFuncToKeyinfo[axisId].aEntries;
    if ( sithControl_aInputFuncToKeyinfo[axisId].numEntries )
    {
        v2 = &sithControl_aInputFuncToKeyinfo[axisId].aEntries[0];
        v3 = sithControl_aInputFuncToKeyinfo[axisId].numEntries;
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

void sithControl_RegisterControlCallback(sithControl_handler_t pfCallback)
{
    // The original engine had an off-by-one here?
    if (sithControl_numHandlers < SITHCONTROL_NUM_HANDLERS)
    {
        sithControl_aHandlers[sithControl_numHandlers++] = pfCallback;
    }
}

#ifdef QOL_IMPROVEMENTS
int sithControl_buttonPressDebounce = 0;
#endif

// MOTS altered
int sithControl_HandlePlayer(SithThing *player, flex_t deltaSecs)
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
    char16_t *v17; // eax
    flex_t v18; // [esp+8h] [ebp-40h]
    rdVector3 a3a; // [esp+Ch] [ebp-3Ch] BYREF
    rdMatrix34 a; // [esp+18h] [ebp-30h] BYREF
    int input_read;
    int tmp;

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
        sithControl_GetKey(INPUT_FUNC_MAP, &input_read);
        if ( (input_read & 1) != 0 )
            sithOverlayMap_ToggleMap();
        if ( sithControl_GetKey(INPUT_FUNC_INCREASE, &input_read) )
            sithOverlayMap_ZoomIn();
        if ( sithControl_GetKey(INPUT_FUNC_DECREASE, &input_read) )
            sithOverlayMap_ZoomOut();
        goto debug_controls;
    }

    if ( (g_debugmodeFlags & DEBUGFLAG_IN_EDITOR) == 0 || !sithControl_GetKey(INPUT_FUNC_DEBUG, 0) )
    {
        if (player->flags & SITH_TF_DEAD)
        {
            if (!(player->actorParams.flags & SITH_AF_FALLKILLED))
            {
                if ( !sithControl_death_msgtimer )
                    goto LABEL_39;
                if ( sithControl_death_msgtimer <= sithTime_g_msecGameTime )
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
                    sithConsole_PrintWString(v17);
                    sithConsole_AlertSound();
                    sithControl_death_msgtimer = 0;
LABEL_39:
#ifdef QOL_IMPROVEMENTS
                    // HACK: Prevent exploding yourself on reloading
                    tmp = sithControl_GetKey(INPUT_FUNC_ACTIVATE, &input_read);
                    if (!sithControl_buttonPressDebounce && (input_read != 0 || (sithControl_GetKey(INPUT_FUNC_FIRE1, &input_read), input_read != 0) ))
                    {
                        sithControl_buttonPressDebounce = 1;
                    }
                    else if (sithControl_buttonPressDebounce && tmp == 0 && !sithControl_GetKey(INPUT_FUNC_FIRE1, &input_read) )
                    {
                        sithControl_buttonPressDebounce = 0;
                        sithPlayer_debug_loadauto(player);
                        return 0;
                    }
                    return 0;
#else
                    sithControl_GetKey(INPUT_FUNC_ACTIVATE, &input_read);
                    if ( input_read != 0 || (sithControl_GetKey(INPUT_FUNC_FIRE1, &input_read), input_read != 0) )
                    {
                        sithPlayer_debug_loadauto(player);
                        return 0;
                    }
                    return 0;
#endif
                }
            }
        }
        else
        {
#ifdef QOL_IMPROVEMENTS
            sithControl_buttonPressDebounce = 0;
#endif
            if (!Main_bMotsCompat) {
                sithControl_008d7f44 = 1.0;
                sithControl_PlayerLook(player, deltaSecs);
            }
            if ( player->type != SITH_THING_PLAYER || (player->actorParams.flags & SITH_AF_CONTROLSDISABLED) == 0 )
            {
                // MOTS added
                if (Main_bMotsCompat) {
                    sithControl_008d7f44 = sithCamera_g_aCameras[sithCamera_g_pCurCamera - sithCamera_g_aCameras].rdCamera.fov * 0.01111111;
                    sithControl_PlayerLook(player, deltaSecs);
                }

                if ( player->attach_flags )
                    sithControl_PlayerMovement(player);
                else
                    sithControl_FreeCam(player);

#ifdef PLATFORM_DROIDWORKS
                // Added: DroidWorks tool-key dispatch (binary sithControl_FUN_004579f0,
                // called from DW's HandlePlayer where stock JK handles the activate key):
                // SELECT1 -> tool arm slot 2, SELECT2 -> tool arm slot 1, ACTIVATE ->
                // body slot 0; first pressed wins. Replaces the stock activate handling
                // (dwCog_ActivateTool is also where sithPlayerActions_Activate diverts).
                if ( Main_bDwCompat )
                {
                    sithControl_GetKey(INPUT_FUNC_SELECT1, &input_read);
                    if ( input_read != 0 )
                        dwCog_ActivateTool(player, 2);
                    else
                    {
                        sithControl_GetKey(INPUT_FUNC_SELECT2, &input_read);
                        if ( input_read != 0 )
                            dwCog_ActivateTool(player, 1);
                        else
                        {
                            sithControl_GetKey(INPUT_FUNC_ACTIVATE, &input_read);
                            if ( input_read != 0 )
                                dwCog_ActivateTool(player, 0);
                        }
                    }
                }
                else
#endif
                {
                    sithControl_GetKey(INPUT_FUNC_ACTIVATE, &input_read);
                    if ( input_read != 0 &&  sithThing_MotsTick(2,0,1.0)) // MOTS added
                        sithPlayerActions_Activate(player);
                }

                sithControl_GetKey(INPUT_FUNC_MAP, &input_read);
                if ( (input_read & 1) != 0 )
                    sithOverlayMap_ToggleMap();
                if ( sithControl_GetKey(INPUT_FUNC_INCREASE, &input_read) )
                    sithOverlayMap_ZoomIn();
                if ( sithControl_GetKey(INPUT_FUNC_DECREASE, &input_read) )
                    sithOverlayMap_ZoomOut();
            }
        }
        return 0;
    }

debug_controls:
#ifdef QOL_IMPROVEMENTS
        sithControl_buttonPressDebounce = 0;
#endif
    if ( player->moveType == SITH_MT_PHYSICS )
        sithPhysics_ResetThingMovement(player);

    // Added
    if (sithControl_followingPlayer > 0) {
        SithThing* pThing = jkPlayer_playerInfos[sithControl_followingPlayer].pLocalPlayer;
        if (pThing) {
            rdVector_Copy3(&player->position, &pThing->position);
            rdMatrix_Copy34(&player->orient, &pThing->orient);
            sithThing_SetSector(player, pThing->sector, 0);
            sithWorld_g_pCurrentWorld->pCameraFocusThing = pThing;
            sithWorld_g_pCurrentWorld->pLocalPlayer = jkPlayer_playerInfos[0].pLocalPlayer;
            stdPalEffects_FlushAllAdds();
        }
    }

    for (v3 = INPUT_FUNC_SELECT1; v3 <= INPUT_FUNC_SELECT0; v3++)
    {
        sithControl_GetKey(v3, &input_read);
        if ( input_read )
        {
            sithControl_followingPlayer = 0; // Added
            int old = jkPlayer_maxPlayers;// Added
            jkPlayer_maxPlayers = 10; // Added
            sithControl_curDebugCam = v3 - INPUT_FUNC_SELECT1; // Added
            sithPlayerActions_MoveToPlayerPosition(player, sithControl_curDebugCam);
            jkPlayer_maxPlayers = old; // Added

            // Added
            jk_snwprintf(sithControl_debugWStrTmp, 256, u"Spawn cam %u", sithControl_curDebugCam);
            sithConsole_PrintWString(sithControl_debugWStrTmp);

            break;
        }
    }
    sithControl_GetKey(INPUT_FUNC_JUMP, &input_read);
    if ( input_read )
    {
        result = 0; // Added

        // Added: dedicated
        if (!(sithNet_isServer && jkGuiNetHost_bIsDedicated)) {
            sithActor_DamageActor(player, player, 200.0, 1);
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
                jk_snwprintf(sithControl_debugWStrTmp, 256, u"Following %s", jkPlayer_playerInfos[sithControl_followingPlayer].player_name);
            else
                jk_snwprintf(sithControl_debugWStrTmp, 256, u"Spawn cam %u", sithControl_curDebugCam);
            sithConsole_PrintWString(sithControl_debugWStrTmp);
            
            if (!sithControl_followingPlayer) {
                sithPlayerActions_MoveToPlayerPosition(player, sithControl_curDebugCam);
            }
        }
    }
    else
    {
        sithControl_GetKey(INPUT_FUNC_ACTIVATE, &input_read);
        if ( input_read )
        {
            if ( sithCamera_g_pCurCamera->type == 128 )
                sithCamera_SetCurrentToCycleCamera();
            else
                sithCamera_SetCurrentCamera(&sithCamera_g_aCameras[6]);
        }
#ifdef QOL_IMPROVEMENTS
        // Scale appropriately to high framerates
        v18 = deltaSecs * 90.0;
#else
        v18 = deltaSecs * 90.0;
#endif
        a3a.y = v18 * sithControl_GetKeyAsAxis(INPUT_FUNC_TURN);
        a3a.x = v18 * sithControl_GetKeyAsAxis(INPUT_FUNC_PITCH); // I really need to sort out what needs the adjustments and what doesn't
        a3a.z = 0.0;
        if (!rdVector_IsZero3(&a3a))
        {
            rdMatrix_BuildRotate34(&a, &a3a);
            rdMatrix_TransformVector34Acc(&sithControl_vec3_54A570, &a);
            rdVector_Normalize3Acc(&sithControl_vec3_54A570);
        }
#ifdef QOL_IMPROVEMENTS
        v7 = -sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_FORWARD) * (deltaSecs * 0.1);// * (sithTime_g_fps / 50.0);
#else
        v7 = -sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_FORWARD) * (deltaSecs * 0.1);
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
        sithCamera_g_orbCamOrient.lvec.x = v10;
        v11 = -sithControl_vec3_54A570.y;
        sithCamera_g_orbCamOrient.lvec.y = v11;
        v12 = -sithControl_vec3_54A570.z;
        sithCamera_g_orbCamOrient.lvec.z = v12;
        v13 = v11 * 1.0 - v12 * 0.0;
        sithCamera_g_orbCamOrient.rvec.x = v13;
        v14 = sithCamera_g_orbCamOrient.lvec.z * 0.0 - v10 * 1.0;
        sithCamera_g_orbCamOrient.rvec.y = v14;
        v15 = v14 * sithCamera_g_orbCamOrient.lvec.z;
        v16 = sithCamera_g_orbCamOrient.lvec.x * 0.0 - sithCamera_g_orbCamOrient.lvec.y * 0.0;
        sithCamera_g_orbCamOrient.rvec.z = v16;
        sithCamera_g_orbCamOrient.uvec.x = v15 - v16 * sithCamera_g_orbCamOrient.lvec.y;
        sithCamera_g_orbCamOrient.uvec.y = sithCamera_g_orbCamOrient.rvec.z * sithCamera_g_orbCamOrient.lvec.x - v13 * sithCamera_g_orbCamOrient.lvec.z;
        sithCamera_g_orbCamOrient.uvec.z = sithCamera_g_orbCamOrient.rvec.x * sithCamera_g_orbCamOrient.lvec.y - sithCamera_g_orbCamOrient.rvec.y * sithCamera_g_orbCamOrient.lvec.x;
        rdMatrix_Normalize34(&sithCamera_g_orbCamOrient);
        sithCamera_g_orbCamOrient.scale.x = sithControl_flt_54A57C * sithControl_vec3_54A570.x;
        sithCamera_g_orbCamOrient.scale.y = sithControl_flt_54A57C * sithControl_vec3_54A570.y;
        sithCamera_g_orbCamOrient.scale.z = sithControl_flt_54A57C * sithControl_vec3_54A570.z;
        sithControl_GetKey(INPUT_FUNC_MAP, &input_read);
        if ( input_read )
            g_mapModeFlags ^= 0x42u;
        sithCamera_g_pCurCamera->type = 128;
        if (!(sithNet_isServer && jkGuiNetHost_bIsDedicated)) // Added
            result = 1;
        else
            result = 0;
    }
    return result;
}

void sithControl_PlayerLook(SithThing *player, flex_t deltaSecs)
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
        if ( (player->actorParams.flags & SITH_AF_CANROTATEHEAD) != 0 )
        {
            if ( (sithWeapon_controlOptions & 4) == 0 && !sithControl_GetKey(INPUT_FUNC_MLOOK, 0) )
                goto LABEL_20;

            
            a2 = player->actorParams.headPYR;

            // Map directly to axis, the value we have is an angular velocity
            v5 = sithControl_GetAxis(INPUT_FUNC_PITCH);

            if ( v5 != 0.0 )
            {
                v3 = 1;
                a2.x += v5 * sithControl_008d7f44;
                local_10 = v5 * sithControl_008d7f44;
            }

            // Not mapped directly to axis, accomodate w/ deltaSecs
            v6 = sithControl_GetKeyAsAxis(INPUT_FUNC_PITCH);
            if ( v6 != 0.0 )
            {
                v3 = 1;
#ifdef QOL_IMPROVEMENTS
                // Scale appropriately to high framerates
                a2.x += v6 * sithControl_008d7f44 * 90.0 * deltaSecs;// * (sithTime_g_fps / 50.0);
                local_10 += v6 * sithControl_008d7f44 * 90.0 * deltaSecs;// * (sithTime_g_fps / 50.0);
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

                sithActor_SetHeadPYR(player, &a2);
                player->actorParams.flags &= ~SITH_AF_VIEWCENTRING;
            }
            else
            {
LABEL_20:
                if ( sithControl_GetKey(INPUT_FUNC_CENTER, 0) || (player->actorParams.flags & SITH_AF_VIEWCENTRING) != 0 )
                {
#ifdef QOL_IMPROVEMENTS
                    // Scale appropriately to high framerates
                    v8 = deltaSecs * 180.0 * (sithTime_g_fps / 50.0);
#else
                    v8 = deltaSecs * 180.0;
#endif
                    player->actorParams.flags |= SITH_AF_VIEWCENTRING;
                    v9 = stdMath_ClipNearZero(stdMath_ClampValue(-player->actorParams.headPYR.x, v8));
                    if ( v9 == 0.0 )
                    {
                        player->actorParams.flags &= ~SITH_AF_VIEWCENTRING;
                        player->actorParams.flags |= SITH_AF_VIEWCENTRED;
                    }
                    else
                    {
                        player->actorParams.headPYR.x += v9;
                        sithActor_SetHeadPYR(player, &player->actorParams.headPYR);
                    }
                }
            }
        }
        else if ( sithControl_GetKey(INPUT_FUNC_CENTER, 0) )
        {
            if (sithThing_MotsTick(9, 0, 1.0))
                sithPhysics_SetThingLook(player, &rdroid_zVector3, deltaSecs);
        }
    }
}


void sithControl_PlayerMovementMots(SithThing *player)
{
    uint32_t uVar1;
    int iVar2;
    flex_t fVar3;
    flex_t fVar4;
    flex_t local_8;
    int local_4;
    SithThing *thing;
    
    thing = player;
    flex_t move_multiplier = 1.0;
    if (((sithWeapon_controlOptions & 2) != 0) ||
       (iVar2 = sithControl_GetKey(INPUT_FUNC_FAST,(int *)0x0), iVar2 != 0)) {
        move_multiplier = 2.0;
    }
    iVar2 = sithControl_GetKey(7,(int *)0x0);
    if (iVar2 != 0) {
        move_multiplier *= 0.5;
    }
    thing->physicsParams.flags =
         thing->physicsParams.flags & ~SITH_PF_CROUCHING;
    iVar2 = sithControl_GetKey(INPUT_FUNC_DUCK,(int *)0x0);
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
        if ((iVar2 != 0) && ((thing->actorParams.flags & SITH_AF_COMBO_FREEZE) == 0)) {
            move_multiplier = 0.5;
            thing->physicsParams.flags =
                 thing->physicsParams.flags | SITH_PF_CROUCHING;
        }
    }
    if ((thing->physicsParams.flags & SITH_PF_200000) != 0) {
        move_multiplier = 0.5;
    }
    if (((thing->attach_flags & SITH_ATTACH_SURFACE) != 0) &&
       (player->attachedSurface->flags & (SITH_SURFACE_VERYDEEPWATER|SITH_SURFACE_WATER))) {
        move_multiplier *= 0.5;
    }
    if ((thing->type != 2) && (thing->type != 10)) {
        return;
    }
    iVar2 = sithControl_GetKey(INPUT_FUNC_SLIDETOGGLE,&local_4);
    if (iVar2 == 0) {
        fVar4 = sithControl_GetAxis(INPUT_FUNC_TURN);
#ifdef QOL_IMPROVEMENTS
        // Scale appropriately to high framerates
        fVar4 = fVar4 * sithTime_g_fps;
#else
        fVar4 = fVar4 * sithTime_g_fps;
#endif
        if (1.0 <= move_multiplier) {
            local_8 = 1.0;
        }
        else {
            local_8 = move_multiplier;
        }
        fVar3 = sithControl_GetKeyAsAxis(INPUT_FUNC_TURN);
#ifdef QOL_IMPROVEMENTS
        // Scale appropriately to high framerates
        //fVar3 *= (sithTime_g_fps / 25.0) * 2.0;
#endif

        fVar4 += fVar3 * thing->actorParams.maxRotVelocity * local_8;

        if (fVar4 == 0.0) {
            if (sithControl_008d7f50 != 0) {
                sithThing_MotsTick(5,0,fVar4);
                sithControl_008d7f50 = 0;
            }
            thing->physicsParams.angularVelocity.y = fVar4;
            fVar4 = sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_SLIDE);
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
                thing->physicsParams.angularVelocity.y = 0.0;
            }
            else {
                thing->physicsParams.angularVelocity.y = fVar4;
                fVar4 = sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_SLIDE);
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
        fVar3 = sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_TURN);
        fVar4 = sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_SLIDE);
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
                thing->physicsParams.angularVelocity.y = 0.0;
            }
            else {
                thing->physicsParams.angularVelocity.y = 0.0;
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
       (iVar2 = sithControl_GetKey(0x24,(int *)0x0), iVar2 != 0)) {
        local_8 = 0.0;
    }
    else {
        local_8 = sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_FORWARD);
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
       (uVar1 = thing->actorParams.flags, (uVar1 & SITH_AF_VIEWCENTRED) == 0)) {
        thing->actorParams.flags = uVar1 | SITH_AF_VIEWCENTRING;
    }
    thing->physicsParams.acceleration.z = 0.0;
    if (move_multiplier != 1.0) {
        fVar4 = thing->physicsParams.acceleration.x;
        thing->physicsParams.acceleration.y =
             thing->physicsParams.acceleration.y * move_multiplier;
        thing->physicsParams.acceleration.x = fVar4 * move_multiplier;
    }
    iVar2 = sithControl_GetKey(4,&local_4);
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

void sithControl_PlayerMovement(SithThing *player)
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
    if ( (sithWeapon_controlOptions & 2) != 0 || sithControl_GetKey(INPUT_FUNC_FAST, 0) )
        move_multiplier = 2.0;
    if ( sithControl_GetKey(INPUT_FUNC_SLOW, 0) )
        move_multiplier = move_multiplier * 0.5;
    int old_state = player->physicsParams.flags;
    if ( !sithControl_GetKey(INPUT_FUNC_DUCK, 0) )
    {
        new_state = old_state & ~SITH_PF_CROUCHING;
    }
    else
    {
        new_state = old_state | SITH_PF_CROUCHING;
        move_multiplier = 0.5;
    }
    player->physicsParams.flags = new_state;
    if ( (player->physicsParams.flags & SITH_PF_200000) != 0 )
    {
        move_multiplier = 0.5;
    }

    if ( (player->attach_flags & SITH_ATTACH_SURFACE)
         && (player->attachedSurface->flags & (SITH_SURFACE_VERYDEEPWATER|SITH_SURFACE_WATER)) )
    {
        move_multiplier *= 0.5;
    }

    if ( player->type == SITH_THING_ACTOR || player->type == SITH_THING_PLAYER )
    {
        if ( sithControl_GetKey(INPUT_FUNC_SLIDETOGGLE, &v20) )
        {
            move_multiplier_a = sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_SLIDE);
            v6 = move_multiplier_a - sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_TURN);
            if ( v6 < -1.0 )
            {
                v6 = -1.0;
            }
            else if ( v6 > 1.0 )
            {
                v6 = 1.0;
            }
            v7 = player->actorParams.maxThrust + player->actorParams.extraSpeed;
            player->physicsParams.angularVelocity.y = 0.0;
            player->physicsParams.acceleration.x = v7 * v6 * 0.7;
        }
        else
        {
            // Player yaw handling

            // These base values only come from raw axis fetches
#ifdef QOL_IMPROVEMENTS
            // Scale appropriately to high and low framerates
            player->physicsParams.angularVelocity.y = sithControl_GetAxis(INPUT_FUNC_TURN) * sithTime_g_fps;
#else
            player->physicsParams.angularVelocity.y = sithControl_GetAxis(INPUT_FUNC_TURN) * sithTime_g_fps;
#endif
            if ( move_multiplier <= 1.0 )
                move_multiplier_ = move_multiplier;
            else
                move_multiplier_ = 1.0;
            
            // These axis values only come from non-raw axis fetches
#ifdef QOL_IMPROVEMENTS
            // Scale appropriately to high framerates
            player->physicsParams.angularVelocity.y += sithControl_GetKeyAsAxis(INPUT_FUNC_TURN) * player->actorParams.maxRotVelocity * move_multiplier_;// * (sithTime_g_fps / 25.0) * 2.0;
#else
            player->physicsParams.angularVelocity.y += sithControl_GetKeyAsAxis(INPUT_FUNC_TURN) * player->actorParams.maxRotVelocity * move_multiplier_;
#endif

            player->physicsParams.acceleration.x = sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_SLIDE)
                                                            * (player->actorParams.maxThrust + player->actorParams.extraSpeed)
                                                            * 0.7;
        }
        v11 = sithControl_GetKeyAsAxisNormalized(0);
        y_vel = (player->actorParams.maxThrust + player->actorParams.extraSpeed) * v11;
        if ( v11 < 0.0 )
            y_vel = y_vel * 0.5;
        player->physicsParams.acceleration.y = y_vel;
        if ( v11 > 0.2 && (sithWeapon_controlOptions & 0x10) != 0 )
        {
            if ( (player->actorParams.flags & SITH_AF_VIEWCENTRED) == 0 )
            {
                player->actorParams.flags |= SITH_AF_VIEWCENTRING;
            }
        }
        player->physicsParams.acceleration.z = 0;
        if ( move_multiplier != 1.0 )
        {
            player->physicsParams.acceleration.y = player->physicsParams.acceleration.y * move_multiplier;
            player->physicsParams.acceleration.x = player->physicsParams.acceleration.x * move_multiplier;
        }
        sithControl_GetKey(INPUT_FUNC_JUMP, &v20);
        if ( v20 )
            sithPlayerActions_JumpWithVel(player, 1.0);
    }
}

// MOTS altered
void sithControl_FreeCam(SithThing *player)
{
    SithThing *v1; // esi
    int v2; // ebp
    SithSector *v3; // eax
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
    if ( (player->physicsParams.flags & SITH_PF_FLY) != 0 || (v3 = player->sector) != 0 && (v3->flags & SITH_SECTOR_UNDERWATER) != 0 )
        v2 = 1;
    if ( (sithWeapon_controlOptions & 2) == 0 )
        sithControl_GetKey(INPUT_FUNC_FAST, 0);
    sithControl_GetKey(INPUT_FUNC_SLOW, 0);
    if ( v1->type == SITH_THING_ACTOR || v1->type == SITH_THING_PLAYER )
    {
        v5 = sithControl_GetKeyAsAxisNormalized(0);
        v6 = v1->actorParams.extraSpeed + v1->actorParams.maxThrust;
        v7 = &v1->physicsParams.acceleration;
        v1->physicsParams.acceleration.z = 0.0;
        v9 = v5 * v6;
        v1->physicsParams.acceleration.y = v9;
        if ( (v1->physicsParams.acceleration.x != 0.0 || v1->physicsParams.acceleration.y != 0.0) // TODO verified first comparison?
          && (v1->actorParams.headPYR.x != 0.0 || v1->actorParams.headPYR.y != 0.0 || v1->actorParams.headPYR.z != 0.0)
          && v2
          && (v1->physicsParams.flags & SITH_PF_ONWATERSURFACE) == 0 )
        {
            rdMatrix_BuildRotate34(&a, &v1->actorParams.headPYR);
            rdMatrix_TransformVector34Acc(&v1->physicsParams.acceleration, &a);
        }
        if ( sithControl_GetKey(INPUT_FUNC_SLIDETOGGLE, &tmp) )
        {
            v15 = sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_SLIDE);

            // Why did MoTS do this lol
            if (Main_bMotsCompat)
                v15 = -v15;

            v11 = v15 - sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_TURN);
            if ( v11 < -1.0 )
            {
                v11 = -1.0;
            }
            else if ( v11 > 1.0 )
            {
                v11 = 1.0;
            }
            v12 = v1->actorParams.extraSpeed + v1->actorParams.maxThrust;
            v1->physicsParams.angularVelocity.y = 0.0;
            v7->x = v12 * v11 * 0.7;
        }
        else
        {
            // Why did MoTS do this lol
            v7->x = (Main_bMotsCompat ? -1 : 1) * sithControl_GetKeyAsAxisNormalized(INPUT_FUNC_SLIDE) * (v1->actorParams.extraSpeed + v1->actorParams.maxThrust) * 0.7;
            
#ifdef QOL_IMPROVEMENTS
            // Scale appropriately to high framerates
            v1->physicsParams.angularVelocity.y = sithControl_GetAxis(INPUT_FUNC_TURN) * sithTime_g_fps;
            v1->physicsParams.angularVelocity.y +=  sithControl_GetKeyAsAxis(INPUT_FUNC_TURN) * v1->actorParams.maxRotVelocity;// * (sithTime_g_fps / 25.0) * 2.0;
#else
            v1->physicsParams.angularVelocity.y = sithControl_GetAxis(INPUT_FUNC_TURN) * sithTime_g_fps;
            v1->physicsParams.angularVelocity.y += sithControl_GetKeyAsAxis(INPUT_FUNC_TURN) * v1->actorParams.maxRotVelocity;
#endif
        }
        if ( v2 )
        {
            // Added: noclip
            if ((g_debugmodeFlags & DEBUGFLAG_NOCLIP)) {
                rdMatrix34 a;
                rdVector3 addVec;

                flex_t mult = 1.0;
                if (sithControl_GetKey(INPUT_FUNC_FAST, 0)) {
                    mult *= 5.0;
                }
                else if (sithControl_GetKey(INPUT_FUNC_JUMP, &tmp)) {
#ifndef TARGET_RETRO_HOMEBREW
                    mult *= 5.0;
#endif
                }
                if (sithControl_GetKey(INPUT_FUNC_DUCK, &tmp)) {
                    mult *= 0.5;
                }
                else if ( sithControl_GetKey(INPUT_FUNC_SLOW, 0) ) {
                    mult *= 0.5;
                }

                rdMatrix_BuildRotate34(&a, &v1->actorParams.headPYR);
                rdVector_Zero3(&addVec);
                rdVector_ScaleAdd3Acc(&addVec, &rdroid_yVector3, sithControl_GetKeyAsAxis(INPUT_FUNC_FORWARD) * mult);
#ifdef TARGET_RETRO_HOMEBREW
                if (sithControl_GetKey(INPUT_FUNC_JUMP, &tmp)) {
                    rdVector_ScaleAdd3Acc(&addVec, &rdroid_zVector3, 1.0);
                }
                if (sithControl_GetKey(INPUT_FUNC_DUCK, &tmp)) {
                    rdVector_ScaleAdd3Acc(&addVec, &rdroid_zVector3, -1.0);
                }
#endif

                rdMatrix_TransformVector34Acc(&addVec, &a);
                rdMatrix_TransformVector34Acc(&addVec, &v1->orient);
                rdVector_Add3Acc(&v1->physicsParams.vel, &addVec);
            }

            // Added: noclip
            if ((g_debugmodeFlags & DEBUGFLAG_NOCLIP)) {
                rdMatrix34 a;
                rdVector3 addVec;

                rdMatrix_BuildRotate34(&a, &v1->actorParams.headPYR);
                rdVector_Zero3(&addVec);
                rdVector_ScaleAdd3Acc(&addVec, &rdroid_xVector3, (Main_bMotsCompat ? -1.0 : 1.0) * sithControl_GetKeyAsAxis(INPUT_FUNC_SLIDE));

                rdMatrix_TransformVector34Acc(&addVec, &a);
                rdMatrix_TransformVector34Acc(&addVec, &v1->orient);
                rdVector_Add3Acc(&v1->physicsParams.vel, &addVec);
            }

            if ( sithControl_GetKey(INPUT_FUNC_JUMP, &tmp) )
            {
                // Added: noclip
                if ((g_debugmodeFlags & DEBUGFLAG_NOCLIP)) {

                }
                else if ( (v1->physicsParams.flags & SITH_PF_ONWATERSURFACE) != 0 )
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

            if ( sithControl_GetKey(INPUT_FUNC_DUCK, &tmp) )
                v1->physicsParams.acceleration.z = v1->physicsParams.acceleration.z - v1->actorParams.maxThrust * 0.5;
        }
        else
        {
            if ( !sithControl_GetKey(INPUT_FUNC_DUCK, &tmp) )
                v1->physicsParams.flags &= ~SITH_PF_CROUCHING;
            else
                v1->physicsParams.flags |= SITH_PF_CROUCHING;
        }
    }
}

void sithControl_DefaultHelper(int funcIdx, int dxKeyNum, int flags)
{
    uint32_t v0; // ecx
    stdControlKeyInfoEntry *v1; // eax

    if ( (sithControl_inputFuncToControlType[funcIdx] & 1) != 0 && sithControl_aInputFuncToKeyinfo[funcIdx].numEntries != 8 )
    {
        sithControl_UnbindControl(INPUT_FUNC_SLIDE, dxKeyNum);
        v0 = sithControl_aInputFuncToKeyinfo[funcIdx].numEntries + 1;
        v1 = &sithControl_aInputFuncToKeyinfo[funcIdx].aEntries[sithControl_aInputFuncToKeyinfo[funcIdx].numEntries];
        v1->flags = flags;
        v1->dxKeyNum = dxKeyNum;
        sithControl_aInputFuncToKeyinfo[funcIdx].numEntries = v0;
    }
}

void sithControl_RegisterKeyboardBindings()
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

    sithControl_BindControl(INPUT_FUNC_FORWARD, DIK_NUMPAD2, 4);

    if (Main_bMotsCompat) {
        sithControl_BindControl(INPUT_FUNC_SLIDE, DIK_A, 0);
        sithControl_BindControl(INPUT_FUNC_SLIDE, DIK_D, 4);
        sithControl_BindControl(INPUT_FUNC_SLIDE, DIK_NUMPAD1, 0);
        sithControl_BindControl(INPUT_FUNC_SLIDE, DIK_NUMPAD3, 4);
    }
    else {
        sithControl_BindControl(INPUT_FUNC_SLIDE, DIK_A, 4);
        sithControl_BindControl(INPUT_FUNC_SLIDE, DIK_D, 0);
        sithControl_BindControl(INPUT_FUNC_SLIDE, DIK_NUMPAD1, 4);
        sithControl_BindControl(INPUT_FUNC_SLIDE, DIK_NUMPAD3, 0);
    }
    
    sithControl_BindControl(INPUT_FUNC_JUMP, DIK_ADD, 0);
    sithControl_BindControl(INPUT_FUNC_JUMP, DIK_X, 0);
    sithControl_BindControl(INPUT_FUNC_DUCK, DIK_C, 0);
    sithControl_BindControl(INPUT_FUNC_FIRE1, DIK_RCONTROL, 0);
    sithControl_BindControl(INPUT_FUNC_FIRE1, DIK_LCONTROL, 0);
    sithControl_BindControl(INPUT_FUNC_ACTIVATE, DIK_SPACE, 0);
    sithControl_BindControl(INPUT_FUNC_FIRE2, DIK_Z, 0);
    sithControl_BindControl(INPUT_FUNC_FIRE2, DIK_NUMPAD0, 0);
    sithControl_BindControl(INPUT_FUNC_SLIDETOGGLE, DIK_RMENU, 0);
    sithControl_BindControl(INPUT_FUNC_SLIDETOGGLE, DIK_LMENU, 0);
    sithControl_BindControl(INPUT_FUNC_SLOW, DIK_CAPITAL, 0);
    sithControl_BindControl(INPUT_FUNC_FAST, DIK_LSHIFT, 0);
    sithControl_BindControl(INPUT_FUNC_FAST, DIK_RSHIFT, 0);
    sithControl_BindControl(INPUT_FUNC_PITCH, DIK_PRIOR, 4);
    sithControl_BindControl(INPUT_FUNC_PITCH, DIK_NEXT, 0);
    sithControl_BindControl(INPUT_FUNC_CENTER, DIK_HOME, 0);
    sithControl_BindControl(INPUT_FUNC_CENTER, DIK_NUMPAD5, 0);
    sithControl_BindControl(INPUT_FUNC_SELECT0, DIK_0, 0);
    sithControl_BindControl(INPUT_FUNC_SELECT1, DIK_1, 0);
    sithControl_BindControl(INPUT_FUNC_SELECT2, DIK_2, 0);
    sithControl_BindControl(INPUT_FUNC_SELECT3, DIK_3, 0);
    sithControl_BindControl(INPUT_FUNC_SELECT4, DIK_4, 0);
    sithControl_BindControl(INPUT_FUNC_SELECT5, DIK_5, 0);
    sithControl_BindControl(INPUT_FUNC_SELECT6, DIK_6, 0);
    sithControl_BindControl(INPUT_FUNC_SELECT7, DIK_7, 0);
    sithControl_BindControl(INPUT_FUNC_SELECT8, DIK_8, 0);
    sithControl_BindControl(INPUT_FUNC_SELECT9, DIK_9, 0);
    sithControl_BindControl(INPUT_FUNC_GAMESAVE, DIK_F9, 0);
    sithControl_BindControl(INPUT_FUNC_NEXTINV, DIK_R, 0);
    sithControl_BindControl(INPUT_FUNC_NEXTINV, DIK_RBRACKET, 0);
    sithControl_BindControl(INPUT_FUNC_PREVINV, DIK_LBRACKET, 0);
    sithControl_BindControl(INPUT_FUNC_USEINV, DIK_RETURN, 0);
    sithControl_BindControl(INPUT_FUNC_PREVSKILL, DIK_SEMICOLON, 0);
    sithControl_BindControl(INPUT_FUNC_NEXTSKILL, DIK_APOSTROPHE, 0);
    sithControl_BindControl(INPUT_FUNC_PREVSKILL, DIK_Q, 0);
    sithControl_BindControl(INPUT_FUNC_NEXTSKILL, DIK_E, 0);
    sithControl_BindControl(INPUT_FUNC_USESKILL, DIK_F, 0);
    sithControl_BindControl(INPUT_FUNC_PREVWEAPON, DIK_PERIOD, 0);
    sithControl_BindControl(INPUT_FUNC_NEXTWEAPON, DIK_SLASH, 0);
    sithControl_BindControl(INPUT_FUNC_NEXTWEAPON, DIK_G, 0);
    sithControl_BindControl(INPUT_FUNC_MAP, DIK_TAB, 0);
    sithControl_BindControl(INPUT_FUNC_INCREASE, DIK_EQUALS, 0);
    sithControl_BindControl(INPUT_FUNC_DECREASE, DIK_MINUS, 0);
    if ( (g_debugmodeFlags & DEBUGFLAG_IN_EDITOR) != 0 )
        sithControl_BindControl(INPUT_FUNC_DEBUG, DIK_BACK, 0);// DIK_BACKSPACE
    sithControl_BindControl(INPUT_FUNC_TALK, DIK_T, 0);
    sithControl_BindControl(INPUT_FUNC_GAMMA, DIK_F11, 0);
    sithControl_BindControl(INPUT_FUNC_SCREENSHOT, DIK_F12, 0);
    sithControl_BindControl(INPUT_FUNC_TALLY, DIK_GRAVE, 0);
}

void sithControl_DefaultInit()
{
    stdControlKeyInfoEntry *v6; // eax
    stdControlKeyInfoEntry *v7; // eax
    stdControlKeyInfoEntry *v8; // eax

    _memset(sithControl_aInputFuncToKeyinfo, 0, sizeof(stdControlKeyInfo) * INPUT_FUNC_MAX);
#ifndef TARGET_RETRO_HOMEBREW
    stdControl_Reset();
#endif

    // Enable joystick by default
#ifdef QOL_IMPROVEMENTS
    sithWeapon_controlOptions = 0x4;
#else
    sithWeapon_controlOptions = 0x24;
#endif

    sithControl_RegisterKeyboardBindings();
    sithControl_BindAxis(INPUT_FUNC_FORWARD, AXIS_JOY1_Y, 4u);
    sithControl_BindAxis(INPUT_FUNC_TURN, AXIS_JOY1_X, 4u);

    sithControl_RegisterMouseBindings();

#ifdef QOL_IMPROVEMENTS
    sithControl_MapDefaultsJoystick();
#endif

#ifdef TARGET_RETRO_HOMEBREW
    sithWeapon_controlOptions |= 2;
#endif // TARGET_RETRO_HOMEBREW
}

// Added: DroidWorks in-mission control bindings. Faithful port of the binary's
// sithControl_FUN_00456da0 (@0x456da0) + FUN_00457000 + FUN_00457330. DW uses an
// arrow-key / numpad movement layout (NOT JK's WASD) plus droid tool selects;
// the joystick + mouse axis binds are identical to JK's defaults. Installed
// per-mission by dwGuiInGame::StartMission (the reduced DW startup never runs
// jkControl, so nothing else binds movement). The binary's debug-only alternate
// binds (g_debugModeFlags & 0x100 -> WASD + alternate pitch keys) are omitted;
// this is the normal (non-debug) DW control scheme. DIK scancodes kept raw.
void sithControl_FUN_00456da0(void)
{
    stdControlKeyInfoEntry* pEntry;

    sithControl_Reset();               // = sub_4D7C30 (clear binding table + stdControl_Reset)
    sithWeapon_controlOptions = 0x24;  // DAT_00691440: mouse + extended keys enabled

    // --- keyboard (binary FUN_00457000, non-debug layout; flag 4 = reversed dir) ---
    sithControl_BindControl(INPUT_FUNC_TALK,        0x2f, 0); // V
    sithControl_BindControl(INPUT_FUNC_TURN,        0xcb, 0); // Left
    sithControl_BindControl(INPUT_FUNC_TURN,        0xcd, 4); // Right
    sithControl_BindControl(INPUT_FUNC_TURN,        0x4b, 0); // NumPad4
    sithControl_BindControl(INPUT_FUNC_TURN,        0x4d, 4); // NumPad6
    sithControl_BindControl(INPUT_FUNC_FORWARD,     0xc8, 0); // Up
    sithControl_BindControl(INPUT_FUNC_FORWARD,     0xd0, 4); // Down
    sithControl_BindControl(INPUT_FUNC_FORWARD,     0x48, 0); // NumPad8
    sithControl_BindControl(INPUT_FUNC_FORWARD,     0x50, 4); // NumPad2
    sithControl_BindControl(INPUT_FUNC_SLIDE,       0x4f, 4); // NumPad1
    sithControl_BindControl(INPUT_FUNC_SLIDE,       0x51, 0); // NumPad3
    sithControl_BindControl(INPUT_FUNC_JUMP,        0x4e, 0); // NumPad+
    sithControl_BindControl(INPUT_FUNC_JUMP,        0x2d, 0); // X
    sithControl_BindControl(INPUT_FUNC_ACTIVATE,    0x39, 0); // Space
    sithControl_BindControl(INPUT_FUNC_ACTIVATE,    0x52, 0); // NumPad0
    sithControl_BindControl(INPUT_FUNC_SLIDETOGGLE, 0xb8, 0); // RAlt
    sithControl_BindControl(INPUT_FUNC_SLIDETOGGLE, 0x38, 0); // LAlt
    sithControl_BindControl(INPUT_FUNC_SLOW,        0x2a, 0); // LShift
    sithControl_BindControl(INPUT_FUNC_SLOW,        0x36, 0); // RShift
    sithControl_BindControl(INPUT_FUNC_PITCH,       0xc9, 0); // PageUp
    sithControl_BindControl(INPUT_FUNC_PITCH,       0x12, 0); // E
    sithControl_BindControl(INPUT_FUNC_PITCH,       0xd1, 4); // PageDown
    sithControl_BindControl(INPUT_FUNC_PITCH,       0x2e, 4); // C
    sithControl_BindControl(INPUT_FUNC_CENTER,      0xc7, 0); // Home
    sithControl_BindControl(INPUT_FUNC_CENTER,      0x20, 0); // D
    sithControl_BindControl(INPUT_FUNC_CENTER,      0x4c, 0); // NumPad5
    sithControl_BindControl(INPUT_FUNC_DEBUG,       0x0b, 0); // 0
    sithControl_BindControl(INPUT_FUNC_SELECT3,     0x02, 0); // 1
    sithControl_BindControl(INPUT_FUNC_SELECT4,     0x03, 0); // 2
    sithControl_BindControl(INPUT_FUNC_SELECT5,     0x04, 0); // 3
    sithControl_BindControl(INPUT_FUNC_SELECT6,     0x05, 0); // 4
    sithControl_BindControl(INPUT_FUNC_SELECT7,     0x06, 0); // 5
    sithControl_BindControl(INPUT_FUNC_SELECT8,     0x07, 0); // 6
    sithControl_BindControl(INPUT_FUNC_SELECT9,     0x08, 0); // 7
    sithControl_BindControl(INPUT_FUNC_SELECT0,     0x09, 0); // 8
    sithControl_BindControl(INPUT_FUNC_GAMESAVE,    0x0a, 0); // 9
    sithControl_BindControl(INPUT_FUNC_MLOOK,       0x0d, 0); // =
    sithControl_BindControl(INPUT_FUNC_CAMERAMODE,  0x0c, 0); // -
    sithControl_BindControl(INPUT_FUNC_SELECT1,     0x1e, 0); // A
    sithControl_BindControl(INPUT_FUNC_SELECT1,     0x26, 0); // L
    sithControl_BindControl(INPUT_FUNC_SELECT1,     0x47, 0); // NumPad7
    sithControl_BindControl(INPUT_FUNC_SELECT2,     0x1f, 0); // S
    sithControl_BindControl(INPUT_FUNC_SELECT2,     0x13, 0); // R
    sithControl_BindControl(INPUT_FUNC_SELECT2,     0x49, 0); // NumPad9

    // --- mouse buttons (binary FUN_00457330; stdControl extended-key codes) ---
    sithControl_BindControl(INPUT_FUNC_FIRE1,       0x100, 0);
    sithControl_BindControl(INPUT_FUNC_FIRE2,       0x101, 0);
    sithControl_BindControl(INPUT_FUNC_ACTIVATE,    0x102, 0);
    sithControl_BindControl(INPUT_FUNC_JUMP,        0x103, 0);
    sithControl_BindControl(INPUT_FUNC_PITCH,       0x109, 4);
    sithControl_BindControl(INPUT_FUNC_PITCH,       0x10b, 0);
    sithControl_BindControl(INPUT_FUNC_SLIDE,       0x108, 4);
    sithControl_BindControl(INPUT_FUNC_SLIDE,       0x10a, 0);

    // --- axes: joystick (FUN_00457330) + mouse look w/ sensitivity (FUN_00456da0) ---
    sithControl_BindAxis(INPUT_FUNC_FORWARD, AXIS_JOY1_Y, INPUT_MAPPING_FLAG_AXIS_REVERSED);
    sithControl_BindAxis(INPUT_FUNC_TURN,    AXIS_JOY1_X, INPUT_MAPPING_FLAG_AXIS_REVERSED);
    pEntry = sithControl_BindAxis(INPUT_FUNC_TURN,  AXIS_MOUSE_X, INPUT_MAPPING_FLAG_AXIS_REVERSED | INPUT_MAPPING_FLAG_RAW_AXIS);
    if (pEntry) pEntry->binaryAxisVal = 0.4f;
    pEntry = sithControl_BindAxis(INPUT_FUNC_PITCH, AXIS_MOUSE_Y, INPUT_MAPPING_FLAG_RAW_AXIS);
    if (pEntry) pEntry->binaryAxisVal = 0.3f;
    pEntry = sithControl_BindAxis(INPUT_FUNC_PITCH, AXIS_MOUSE_Z, 0);
    if (pEntry) pEntry->binaryAxisVal = 4.0f;
}

void sithControl_RegisterKeyFunction(int functionId)
{
    SITH_ASSERTREL((functionId >= 0) && (functionId < INPUT_FUNC_MAX)); // Added: port from OpenJones3D
    sithControl_inputFuncToControlType[functionId] = 5;
}

stdControlKeyInfo* sithControl_EnumBindings(sithControlEnumFunc_t pfFunc, int a2, int a3, int a4, Darray *a5)
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
    for (int j = 0; j < INPUT_FUNC_MAX; j++)
    {
        int flags = sithControl_inputFuncToControlType[v7];

        v18 = 0;
        v19 = 0;
        v17 = 0;
        v21 = flags & INPUT_MAPPING_FLAG_DXKEY;
        v16 = 0;
        v8 = &result->aEntries[0];

        for ( i = v8; v16 < v20->numEntries; v8 = i )
        {
            v9 = v8->flags;
            v10 = v8->dxKeyNum;
            v11 = v8->flags & INPUT_MAPPING_FLAG_DXKEY;
            if ( (!v11 || v10 >= JK_EXTENDED_KEY_START || a2)
              && (((v9 & 1) == 0 || v10 < AXIS_MOUSE_X) 
              && (!v11 || !KEY_IS_MOUSE(v10)) || a4)
              && (((v9 & 1) == 0 || v10 >= AXIS_MOUSE_X) 
              && (!v11 || v10 < JK_EXTENDED_KEY_START || KEY_IS_MOUSE(v10)) || a3) )
            {
                v6 = pfFunc(v7, sithControl_aFunctionStrs[v7], flags, v16, v10, v9, v8, a5);
                if ( v18 || (v12 = i, (i->flags & INPUT_MAPPING_FLAG_DXKEY) != 0) && (i->flags & 4) == 0 )
                {
                    v12 = i;
                    v18 = 1;
                }
                else
                {
                    v18 = 0;
                }
                v19 = v19 || (v12->flags & INPUT_MAPPING_FLAG_DXKEY) != 0 && (v12->flags & 4) != 0;
                if ( v17 || (v17 = 0, (v12->flags & INPUT_MAPPING_FLAG_AXIS) != 0) )
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
            v6 = pfFunc(v7, sithControl_aFunctionStrs[v7], flags, -1u, 0, 1, 0, a5);
        }
        else
        {
            v13 = a5;
        }
        if ( v6 && !v18 || !v20->numEntries )
            v6 = pfFunc(v7, sithControl_aFunctionStrs[v7], flags, -1u, 0, 2, 0, v13);
        if ( v6 && v21 && !v19 )
            v6 = pfFunc(v7, sithControl_aFunctionStrs[v7], flags, -1u, 0, 6, 0, v13);
        ++v7;
        result = ++v20;
    }
    return result;
}

void sithControl_RegisterMouseBindings()
{
    stdControlKeyInfoEntry *v10;

#ifdef QOL_IMPROVEMENTS
    v10 = sithControl_BindAxis(INPUT_FUNC_TURN, AXIS_MOUSE_X, INPUT_MAPPING_FLAG_AXIS_REVERSED | INPUT_MAPPING_FLAG_RAW_AXIS);
    if ( v10 )
        v10->binaryAxisVal = 0.4;
#else
    v10 = sithControl_BindAxis(INPUT_FUNC_TURN, AXIS_MOUSE_X, INPUT_MAPPING_FLAG_AXIS_REVERSED | INPUT_MAPPING_FLAG_RAW_AXIS);
    if ( v10 )
        v10->binaryAxisVal = 0.4;
#endif

#ifdef QOL_IMPROVEMENTS
    v10 = sithControl_BindAxis(INPUT_FUNC_PITCH, AXIS_MOUSE_Y, INPUT_MAPPING_FLAG_AXIS_REVERSED | INPUT_MAPPING_FLAG_RAW_AXIS); // Non-inverted by default, fight me lol
    if ( v10 ) 
        v10->binaryAxisVal = 0.3;
#else
    v10 = sithControl_BindAxis(INPUT_FUNC_PITCH, AXIS_MOUSE_Y, INPUT_MAPPING_FLAG_RAW_AXIS);
    if ( v10 ) 
        v10->binaryAxisVal = 0.3;
#endif
    
    v10 = sithControl_BindAxis(INPUT_FUNC_PITCH, AXIS_MOUSE_Z, 0);
    if ( v10 )
        v10->binaryAxisVal = 4.0;
    
    sithControl_DefaultHelper(INPUT_FUNC_FIRE1, KEY_MOUSE_B1, 2);
    sithControl_DefaultHelper(INPUT_FUNC_JUMP, KEY_MOUSE_B2, 2);
    sithControl_DefaultHelper(INPUT_FUNC_FIRE2, KEY_MOUSE_B3, 2);
}

void sithControl_RebindMouse()
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
    while ( v3 || ++v0 < &sithControl_aInputFuncToKeyinfo[INPUT_FUNC_MAX] );

    sithControl_RegisterMouseBindings();
}

void sithControl_RebindKeyboard()
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
                if ( (v4->flags & INPUT_MAPPING_FLAG_AXIS) == 0 && v4->dxKeyNum < JK_EXTENDED_KEY_START )
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
    while ( v3 || ++v0 < &sithControl_aInputFuncToKeyinfo[INPUT_FUNC_MAX] );
    sithControl_RegisterKeyboardBindings();
}

void sithControl_RebindJoystick()
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
                if ( (v4->flags & INPUT_MAPPING_FLAG_AXIS) == 0 && KEY_IS_JOY_BUTTON(v5) 
                    || (v4->flags & INPUT_MAPPING_FLAG_AXIS) != 0 && v5 >= AXIS_JOY1_X && v5 <= AXIS_JOY2_V )
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
    while ( v3 || ++v0 < &sithControl_aInputFuncToKeyinfo[INPUT_FUNC_MAX] );

    sithControl_MapDefaultsJoystick();
}

// Added
void sithControl_MapDefaultsJoystick() {
#if !defined(TARGET_RETRO_HOMEBREW) && defined(QOL_IMPROVEMENTS)
    stdControlKeyInfoEntry* mapped;

    mapped = sithControl_BindAxis(INPUT_FUNC_FORWARD, AXIS_JOY1_Y, 4u);
    if (mapped) {
        mapped->binaryAxisVal = 1.0;
    }

    if (Main_bMotsCompat) {
        mapped = sithControl_BindAxis(INPUT_FUNC_SLIDE, AXIS_JOY1_X, 4u);
    }
    else {
        mapped = sithControl_BindAxis(INPUT_FUNC_SLIDE, AXIS_JOY1_X, 0u);
    }
    if (mapped) {
        mapped->binaryAxisVal = 1.0;
    }

    mapped = sithControl_BindAxis(INPUT_FUNC_PITCH, AXIS_JOY1_R, 4u);
    if (mapped) {
        mapped->binaryAxisVal = 1.25;
    }
    mapped = sithControl_BindAxis(INPUT_FUNC_TURN, AXIS_JOY1_Z, 4u);
    if (mapped) {
        mapped->binaryAxisVal = 1.5;
    }

    sithControl_DefaultHelper(INPUT_FUNC_USELASTSELECTED, KEY_JOY1_B1, 2); // a
    sithControl_DefaultHelper(INPUT_FUNC_DUCK, KEY_JOY1_B2, 2); // b
    sithControl_DefaultHelper(INPUT_FUNC_ACTIVATE, KEY_JOY1_B3, 2); // x
    sithControl_BindControl(INPUT_FUNC_JUMP, KEY_JOY1_B4, 0); // y

    sithControl_DefaultHelper(INPUT_FUNC_USEINV, KEY_JOY1_B8, 2); // lstick click
    sithControl_DefaultHelper(INPUT_FUNC_USESKILL, KEY_JOY1_B9, 2); // rstick click

    sithControl_BindControl(INPUT_FUNC_NEXTINV, KEY_JOY1_HUP, 0);
    sithControl_BindControl(INPUT_FUNC_PREVINV, KEY_JOY1_HDOWN, 0);
    sithControl_BindControl(INPUT_FUNC_PREVSKILL, KEY_JOY1_HLEFT, 0);
    sithControl_BindControl(INPUT_FUNC_NEXTSKILL, KEY_JOY1_HRIGHT, 0);

    sithControl_BindControl(INPUT_FUNC_PREVWEAPON, KEY_JOY1_B10, 0); // lbump
    sithControl_BindControl(INPUT_FUNC_NEXTWEAPON, KEY_JOY1_B11, 0); // rbump

    sithControl_DefaultHelper(INPUT_FUNC_FIRE2, KEY_JOY1_B16, 2); // ltrig
    sithControl_DefaultHelper(INPUT_FUNC_FIRE1, KEY_JOY1_B17, 2); // rtrig
#elif defined(TARGET_RETRO_HOMEBREW) // TODO split out analog vs no analog controls
    sithControl_BindControl(INPUT_FUNC_FORWARD, KEY_JOY1_HUP, 0);
    sithControl_BindControl(INPUT_FUNC_NEXTSKILL, KEY_JOY1_HDOWN, 0);
    sithControl_BindControl(INPUT_FUNC_TURN, KEY_JOY1_HLEFT, 0);
    sithControl_BindControl(INPUT_FUNC_TURN, KEY_JOY1_HRIGHT, 4);
    sithControl_DefaultHelper(INPUT_FUNC_FIRE1, KEY_JOY1_B1, 2); // a
    sithControl_DefaultHelper(INPUT_FUNC_DUCK, KEY_JOY1_B2, 0); // b
    sithControl_DefaultHelper(INPUT_FUNC_ACTIVATE, KEY_JOY1_B3, 2); // x
    sithControl_BindControl(INPUT_FUNC_JUMP, KEY_JOY1_B4, 0); // y
    sithControl_BindControl(INPUT_FUNC_NEXTINV, KEY_JOY1_B10, 0); // L
    sithControl_BindControl(INPUT_FUNC_NEXTWEAPON, KEY_JOY1_B11, 0); // R
    sithControl_BindControl(INPUT_FUNC_USELASTSELECTED, KEY_JOY1_B7, 0);
#else
    sithControl_BindAxis(INPUT_FUNC_FORWARD, AXIS_JOY1_Y, 4u);
    sithControl_BindAxis(INPUT_FUNC_TURN, AXIS_JOY1_X, 4u);

    sithControl_DefaultHelper(INPUT_FUNC_FIRE1, KEY_JOY1_B1, 2);
    sithControl_DefaultHelper(INPUT_FUNC_FIRE2, KEY_JOY1_B2, 2);
    sithControl_DefaultHelper(INPUT_FUNC_ACTIVATE, KEY_JOY1_B3, 2);
    sithControl_DefaultHelper(INPUT_FUNC_JUMP, KEY_JOY1_B4, 2);
    sithControl_BindControl(INPUT_FUNC_PITCH, KEY_JOY1_HUP, 4);
    sithControl_BindControl(INPUT_FUNC_PITCH, KEY_JOY1_HDOWN, 0);
    sithControl_BindControl(INPUT_FUNC_SLIDE, KEY_JOY1_HLEFT, 4);
    sithControl_BindControl(INPUT_FUNC_SLIDE, KEY_JOY1_HRIGHT, 0);
    sithControl_BindControl(INPUT_FUNC_NEXTINV, KEY_JOY1_B5, 0);
    sithControl_BindControl(INPUT_FUNC_USEINV, KEY_JOY1_B7, 0);
#endif
}

// Common button for both items and force power usage for controllers
#ifdef QOL_IMPROVEMENTS
void sithControl_SetLastSelected(int which) {
    sithControl_lastSelected = which;
}

int sithControl_GetLastSelected() {
    return sithControl_lastSelected;
}
#endif // QOL_IMPROVEMENTS
