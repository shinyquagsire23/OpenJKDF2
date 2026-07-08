#include "sithCommand.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "General/sithStrTable.h"
#include "General/stdString.h"
#include "Devices/sithConsole.h"
#include "AI/sithAI.h"
#include "Main/jkGame.h"
#include "Cog/sithCog.h"
#include "World/sithThing.h"
#include "Gameplay/sithPlayerActions.h"
#include "Gameplay/sithEvent.h"
#include "Engine/sithIntersect.h"
#include "Dss/sithMulti.h"
#include "Win95/stdComm.h"
#include "World/sithWorld.h"
#include "World/sithMaterial.h"
#include "Gameplay/sithPlayer.h"
#include "World/sithTemplate.h"
#include "Main/jkQuakeConsole.h"
#include "General/stdJSON.h"
#include "jk.h"

typedef struct sithCommandBind sithCommandBind;
typedef struct sithCommandBind
{
    uint16_t key;
    const char* pCmd;
    sithCommandBind* pNext;
} sithCommandBind;

sithCommandBind* sithCommand_pBinds;

static char sithCommand_aIdk[4]; // TODO symbols?

#ifdef QOL_IMPROVEMENTS
int sithCommand_CmdQuit(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    // TODO disconnect clients?
    exit(0);
    return 1;
}
#endif

// MOTS altered
void sithCommand_Startup()
{
    sithConsole_RegisterCommand(sithCommand_Players, "players", 0);
    sithConsole_RegisterCommand(sithCommand_Coords, "coords", 0);
    sithConsole_RegisterCommand(sithCommand_DebugMode, "trackshots", 3);
    sithConsole_RegisterCommand(sithCommand_PingPlayer, "ping", 0);
    sithConsole_RegisterCommand(sithCommand_Kick, "kick", 0);
    sithConsole_RegisterCommand(sithCommand_Kick, "boot", 0); // MOTS added
    sithConsole_RegisterCommand(sithCommand_Tick, "tick", 0);
    sithConsole_RegisterCommand(sithCommand_Session, "session", 0);

    if ( (g_debugmodeFlags & DEBUGFLAG_IN_EDITOR) != 0 )
    {
        sithConsole_RegisterCommand(sithConsole_Help, "help", 0);
        sithConsole_RegisterCommand(sithCommand_DebugMode, "disableai", 0);
        sithConsole_RegisterCommand(sithCommand_DebugMode, "notarget", 6);
        sithConsole_RegisterCommand(sithCommand_DebugMode, "outline", 1);
        sithConsole_RegisterCommand(sithCommand_DebugMode, "disablepuppet", 2);
        sithConsole_RegisterCommand(sithCommand_CogTrace, "cogtrace", 0);
        sithConsole_RegisterCommand(sithCommand_CogList, "coglist", 0);
        sithConsole_RegisterCommand(sithCog_CogStatus, "cogstatus", 0);
        sithConsole_RegisterCommand(sithCommand_DebugMode, "noaishots", 4);
        sithConsole_RegisterCommand(sithAI_AIStatus, "aistatus", 0);
        sithConsole_RegisterCommand(sithAI_AIList, "ailist", 0);
        sithConsole_RegisterCommand(sithCommand_Fly, "fly", 0);
        sithConsole_RegisterCommand(sithCommand_Memory, "mem", 0);
        sithConsole_RegisterCommand(sithCommand_DynamicMemory, "dynamicmem", 0);
        sithConsole_RegisterCommand(sithCommand_MemoryDump, "memdump", 0);
        sithConsole_RegisterCommand(sithCommand_DebugMode, "invul", 5);
        sithConsole_RegisterCommand(sithCommand_CogPause, "cogpause", 0);
#ifndef LINUX_TMP
        sithConsole_RegisterCommand(sithCommand_MatList, "matlist", 0);
#endif
        sithConsole_RegisterCommand(sithCommand_Warp, "warp", 0);
        sithConsole_RegisterCommand(sithCommand_Activate, "activate", 0);
        sithConsole_RegisterCommand(sithCommand_DebugMode, "slowmo", 7);
        sithConsole_RegisterCommand(sithCommand_Jump, "jump", 0);
    }

#ifdef QOL_IMPROVEMENTS
    sithConsole_RegisterCommand(sithCommand_CmdQuit, "quit", 0);
    sithConsole_RegisterCommand(sithCommand_CmdQuit, "q", 0);
    sithConsole_RegisterCommand(sithCommand_CmdThingNpc, "npc", 0);
    sithConsole_RegisterCommand(sithCommand_CmdThingNpc, "thing", 0);
    sithConsole_RegisterCommand(sithCommand_CmdBind, "bind", 0);
    sithConsole_RegisterCommand(sithCommand_CmdUnbind, "unbind", 0);

    sithCommand_StartupBinds();
#endif
}

int sithCommand_DebugMode(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    int *v2; // esi
    int v3; // edi
    SithThing *v4; // eax
    wchar_t *v5; // eax
    wchar_t *v6; // eax
    int result; // eax
    wchar_t *v8; // [esp-4h] [ebp-154h]
    wchar_t v9[32]; // [esp+10h] [ebp-140h] BYREF
    wchar_t a1[128]; // [esp+50h] [ebp-100h] BYREF

    switch ( pCmd->extra )
    {
        case 0u:
            v2 = &g_debugmodeFlags;
            v3 = 1;
            goto LABEL_13;
        case 1u:
            v2 = &sithRender_renderflags;
            v3 = 1;
            goto LABEL_13;
        case 2u:
            v2 = &g_debugmodeFlags;
            v3 = 2;
            goto LABEL_13;
        case 3u:
            v2 = &g_debugmodeFlags;
            v3 = 64;
            goto LABEL_13;
        case 4u:
            v2 = &g_debugmodeFlags;
            v3 = 128;
            goto LABEL_13;
        case 5u:
            if ( !sithWorld_g_pCurrentWorld )
                goto LABEL_24;
            v4 = sithWorld_g_pCurrentWorld->pLocalPlayer;
            if ( !v4 || v4->type != SITH_THING_PLAYER )
                goto LABEL_24;
            v2 = (int*)&v4->actorParams.flags;
            v3 = 8;
LABEL_13:
            if ( pArgStr )
            {
                if ( __strcmpi(pArgStr, "on") && __strcmpi(pArgStr, "1") )
                {
                    if ( !__strcmpi(pArgStr, "off") || !__strcmpi(pArgStr, "0") )
                        *v2 &= ~v3;
                }
                else
                {
                    *v2 |= v3;
                }
            }
            stdString_CharToWchar(v9, pCmd->cmdStr, 31);
            v9[31] = 0;
            if ( (*v2 & v3) != 0 )
                v5 = sithStrTable_GetUniStringWithFallback("ON");
            else
                v5 = sithStrTable_GetUniStringWithFallback("OFF");
            v8 = v5;
            v6 = sithStrTable_GetUniStringWithFallback("%s_IS_%s");
            jk_snwprintf(a1, 0x80u, v6, v9, v8);
            sithConsole_PrintWString(a1);
            result = 1;
            break;
        case 6u:
            v2 = &g_debugmodeFlags;
            v3 = 0x200;
            goto LABEL_13;
        case 7u:
            v2 = &g_debugmodeFlags;
            v3 = 0x400;
            goto LABEL_13;
        default:
LABEL_24:
            result = 0;
            break;
    }
    return result;
}

int sithCommand_Tick(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    signed int result; // eax
    unsigned int newTickrate; // eax

    if ( !sithNet_isMulti )
        return 0;
    if ( pArgStr && (newTickrate = _atoi(pArgStr)) != 0 )
    {
        if ( newTickrate >= 100 && newTickrate <= 300)
        {
            sithNet_tickrate = newTickrate;
            sithEvent_RegisterTask(2, sithMulti_CheckPlayers, newTickrate, 1);
            result = 1;
        }
        else
        {
            sithConsole_PrintString("New tick is out of range");
            result = 0;
        }
    }
    else
    {
        _sprintf(std_g_genBuffer, "Current tick rate is %d msec", sithNet_tickrate);
        sithConsole_PrintString(std_g_genBuffer);
        result = 1;
    }
    return result;
}

int sithCommand_Session(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    uint32_t v3; // edi
    sithDplayPlayer* v4; // esi
    unsigned int v5; // eax

    if ( !sithNet_isMulti )
        return 0;
    DirectPlay_EnumPlayers(0);
    _sprintf(std_g_genBuffer, "%d players in session", DirectPlay_numPlayers);
    sithConsole_PrintString(std_g_genBuffer);
    v3 = 0;
    if ( DirectPlay_numPlayers )
    {
        v4 = &DirectPlay_aPlayers[0];
        do
        {
            v5 = sithMulti_GetPlayerIndexByID(v4->field_80);
            _sprintf(std_g_genBuffer, "Player %x (%S) is in the session", v4->field_80, jkPlayer_playerInfos[v5].player_name);
            sithConsole_PrintString(std_g_genBuffer);
            ++v3;
            ++v4;
        }
        while ( v3 < DirectPlay_numPlayers );
    }
    return 1;
}

int sithCommand_CogTrace(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    signed int result; // eax
    unsigned int v3; // eax
    sithCog *v4; // esi

    if ( sithWorld_g_pCurrentWorld )
    {
        if ( pArgStr )
        {
            v3 = _atoi(pArgStr);
            if ( v3 < sithWorld_g_pCurrentWorld->numCogs )
            {
                v4 = &sithWorld_g_pCurrentWorld->aCogs[v3];
                if ( (v4->flags & SITH_COG_DEBUG) != 0 )
                {
                    sithConsole_PrintString("Cog trace disabled.");
                    v4->flags &= ~SITH_COG_DEBUG;
                }
                else
                {
                    sithConsole_PrintString("Cog trace enabled.");
                    v4->flags |= SITH_COG_DEBUG;
                }
                return 1;
            }
            else
            {
                sithConsole_PrintString("cog id out of range.");
                result = 0;
            }
        }
        else
        {
            sithConsole_PrintString("syntax error.");
            result = 0;
        }
    }
    else
    {
        sithConsole_PrintString("no world open.");
        result = 0;
    }
    return result;
}

int sithCommand_CogPause(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    signed int result; // eax
    unsigned int v3; // eax
    sithCog *v4; // esi
    int v5; // eax

    if ( sithWorld_g_pCurrentWorld )
    {
        if ( pArgStr )
        {
            v3 = _atoi(pArgStr);
            if ( v3 < sithWorld_g_pCurrentWorld->numCogs )
            {
                v4 = &sithWorld_g_pCurrentWorld->aCogs[v3];
                if ( (v4->flags & SITH_COG_DISABLED) != 0 )
                {
                    sithConsole_PrintString("Cog enabled.");
                    v4->flags &= ~SITH_COG_DISABLED;
                }
                else
                {
                    sithConsole_PrintString("Cog disabled.");
                    v4->flags |= SITH_COG_DISABLED;
                }
                result = 1;
            }
            else
            {
                sithConsole_PrintString("cog id out of range.");
                result = 0;
            }
        }
        else
        {
            sithConsole_PrintString("syntax error.");
            result = 0;
        }
    }
    else
    {
        sithConsole_PrintString("No world.");
        result = 0;
    }
    return result;
}

int sithCommand_CogList(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    signed int result; // eax
    unsigned int v3; // ebp
    sithCog *i; // esi

    if ( sithWorld_g_pCurrentWorld )
    {
#ifdef SITH_DEBUG_STRUCT_NAMES
        _sprintf(std_g_genBuffer, "World aCogs = %d.", sithWorld_g_pCurrentWorld->numCogs);
        sithConsole_PrintString(std_g_genBuffer);
        v3 = 0;
        for ( i = sithWorld_g_pCurrentWorld->aCogs; v3 < sithWorld_g_pCurrentWorld->numCogs; ++i )
        {
            _sprintf(std_g_genBuffer, "%d: %-16s %-16s ", v3, i->cogscript_fpath, i->cogscript->cog_fpath);
            if ( (i->flags & SITH_COG_DISABLED) != 0 )
                _sprintf(&std_g_genBuffer[strlen(std_g_genBuffer)], "(paused) ");
            if ( (i->flags & SITH_COG_DEBUG) != 0 )
                _sprintf(&std_g_genBuffer[strlen(std_g_genBuffer)], "(trace)  ");
            _sprintf(&std_g_genBuffer[strlen(std_g_genBuffer)], sithCommand_aIdk);
            sithConsole_PrintString(std_g_genBuffer);
            ++v3;
        }
#endif
        result = 1;
    }
    else
    {
        sithConsole_PrintString("No world.");
        result = 0;
    }
    return result;
}

int sithCommand_Fly(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    SithThing *v0; // ecx
    wchar_t *v3; // eax

    if ( sithWorld_g_pCurrentWorld && (v0 = sithWorld_g_pCurrentWorld->pLocalPlayer) != 0 )
    {
        if ( v0->moveType == SITH_MT_PHYSICS )
        {
            if (v0->physicsParams.flags & SITH_PF_FLY)
            {
                v0->physicsParams.flags &= ~SITH_PF_FLY;
                v0->physicsParams.flags |= SITH_PF_USEGRAVITY;
                v3 = sithStrTable_GetUniStringWithFallback("FLYING_OFF");
            }
            else
            {
                v0->physicsParams.flags &= ~SITH_PF_USEGRAVITY;
                v0->physicsParams.flags |= SITH_PF_FLY;
                v3 = sithStrTable_GetUniStringWithFallback("FLYING_ON");
            }
            sithConsole_PrintWString(v3);
            return 1;
        }
        else
        {
            sithConsole_PrintString("Not physics thing.");
            return 0;
        }
    }
    else
    {
        sithConsole_PrintString("No world.");
        return 0;
    }
    return 0;
}

int sithCommand_Memory(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    int worldAllocatedAmt[17];
    int worldQuantityAmt[17];

    // TODO: verify the exact indices or just rewrite this

    SithWorld* pWorld = sithWorld_g_pCurrentWorld;
    if (pArgStr) {
        pWorld = sithWorld_g_pStaticWorld;
    }
    if (!pWorld)
    {
        sithConsole_PrintString("No world.");
        return 0;
    }
    sithWorld_GetMemoryUsage(pWorld, worldAllocatedAmt, worldQuantityAmt);
    _sprintf(std_g_genBuffer, "%5d Materials        %8d bytes.", worldQuantityAmt[0], worldAllocatedAmt[0]);
    sithConsole_PrintString(std_g_genBuffer);
    _sprintf(std_g_genBuffer, "%5d Models           %8d bytes.", worldQuantityAmt[10], worldAllocatedAmt[10]);
    sithConsole_PrintString(std_g_genBuffer);
    _sprintf(std_g_genBuffer, "%5d Sounds", worldQuantityAmt[6]);
    sithConsole_PrintString(std_g_genBuffer);
    _sprintf(std_g_genBuffer, "%5d Keyframes        %8d bytes.", worldQuantityAmt[11], worldAllocatedAmt[11]);
    sithConsole_PrintString(std_g_genBuffer);
    _sprintf(std_g_genBuffer, "%5d World Vertices   %8d bytes.", worldQuantityAmt[1], worldAllocatedAmt[1]);
    sithConsole_PrintString(std_g_genBuffer);
    _sprintf(std_g_genBuffer, "%5d World TexVerts   %8d bytes.", worldQuantityAmt[2], worldAllocatedAmt[2]);
    sithConsole_PrintString(std_g_genBuffer);
    _sprintf(std_g_genBuffer, "%5d Surfaces         %8d bytes.", worldQuantityAmt[3], worldAllocatedAmt[3]);
    sithConsole_PrintString(std_g_genBuffer);
    _sprintf(std_g_genBuffer, "%5d Sectors          %8d bytes.", worldQuantityAmt[5], worldAllocatedAmt[5]);
    sithConsole_PrintString(std_g_genBuffer);
    _sprintf(std_g_genBuffer, "%5d Cog Scripts\t\t%8d bytes.", worldQuantityAmt[8], worldAllocatedAmt[8]);
    sithConsole_PrintString(std_g_genBuffer);
    _sprintf(std_g_genBuffer, "%5d Cogs             %8d bytes.", worldQuantityAmt[7], worldAllocatedAmt[7]);
    sithConsole_PrintString(std_g_genBuffer);
    _sprintf(std_g_genBuffer, "%5d Adjoins          %8d bytes.", worldQuantityAmt[4], worldAllocatedAmt[4]);
    sithConsole_PrintString(std_g_genBuffer);
    _sprintf(std_g_genBuffer, "Total Memory Used:   %8d bytes.", worldAllocatedAmt[4] + worldAllocatedAmt[5] + worldAllocatedAmt[3] + worldAllocatedAmt[2] + worldAllocatedAmt[1] + worldAllocatedAmt[11] + worldAllocatedAmt[10] + worldAllocatedAmt[0]);
    sithConsole_PrintString(std_g_genBuffer);
    sithConsole_PrintString("(Total does not include sounds & aCogs)"); 
    
    return 1;
}

int sithCommand_DynamicMemory(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    _sprintf(
        std_g_genBuffer,
        "NumAllocs: %d TotalMemAlloc: %d bytes MaxMemAlloc: %d bytes",
        stdMemory_g_curState.nextNum,
        stdMemory_g_curState.allocCur,
        stdMemory_g_curState.allocMax);
    sithConsole_PrintString(std_g_genBuffer);
    return 1;
}

int sithCommand_MemoryDump(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    int result; // eax
    int v3; // edi
    stdMemoryAlloc *i; // esi

    // Added: pSithHS -> pLowLevelHS
    result = pLowLevelHS->fileOpen("memdump.txt", "w+");
    v3 = result;
    if ( result )
    {
        pSithHS->filePrintf(
            result,
            "Total Memory allocated: %d bytes   # Allocations: %d  Max Memory used: %d bytes\n\n",
            stdMemory_g_curState.allocCur,
            stdMemory_g_curState.nextNum,
            stdMemory_g_curState.allocMax);
        for ( i = stdMemory_g_curState.allocTop.prev; i; i = i->prev )
            pSithHS->filePrintf(v3, "%25s:  line %3d   %8d bytes   #%d\n", i->filePath, i->lineNum, i->size, i->num);
        pSithHS->fileClose(v3);
        sithConsole_PrintString("Memory dump file 'memdump.txt' written.");
        result = 1;
    }
    return result;
}

// MatList

int sithCommand_Coords(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    SithThing *player; // esi
    signed int result; // eax
    rdVector3 a2; // [esp+38h] [ebp-Ch] BYREF

    if ( sithWorld_g_pCurrentWorld && (player = sithWorld_g_pCurrentWorld->pLocalPlayer) != 0 )
    {
        if ( player->sector )
        {
            rdMatrix_ExtractAngles34(&player->orient, &a2);
            _sprintf(
                std_g_genBuffer,
                "Pos: (%.2f, %.2f, %.2f) PYR: (%.2f, %.2f, %.2f) Sector: %d.",
                player->position.x,
                player->position.y,
                player->position.z,
                a2.x,
                a2.y,
                a2.z,
                player->sector->id);
            sithConsole_PrintString(std_g_genBuffer);
        }
        else
        {
            sithConsole_PrintString("Thing is not in world");
        }
        result = 1;
    }
    else
    {
        sithConsole_PrintString("No world.");
        result = 0;
    }
    return result;
}

int sithCommand_Warp(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    SithThing *v3; // ebp
    int result; // eax
    int v5; // eax
    SithSector *v6; // edi
    unsigned int i; // esi
    flex32_t fx, fy, fz, f2x, f2y, f2z;
    rdVector3 a1; // [esp+10h] [ebp-48h] BYREF
    rdVector3 a3a; // [esp+1Ch] [ebp-3Ch] BYREF
    rdMatrix34 a; // [esp+28h] [ebp-30h] BYREF

    if ( !sithWorld_g_pCurrentWorld || (v3 = sithWorld_g_pCurrentWorld->pLocalPlayer) == 0 )
    {
        sithConsole_PrintString("No world.");
        return 0;
    }
    if ( !pArgStr )
    {
        sithConsole_PrintString("Format: WARP x y z");
        return 0;
    }
    v5 = _sscanf(pArgStr, "%f %f %f %f %f %f", &fx, &fy, &fz, &f2x, &f2y, &f2z);
    if ( v5 < 3 )
        return 0;
    a1.x = fx; // FLEXTODO
    a1.y = fy; // FLEXTODO
    a1.z = fz; // FLEXTODO
    a3a.x = f2x; // FLEXTODO
    a3a.y = f2y; // FLEXTODO
    a3a.z = f2z; // FLEXTODO

    if ( v5 == 6 )
        rdMatrix_BuildRotate34(&a, &a3a);
    else
        rdMatrix_Identity34(&a);

    v6 = sithWorld_g_pCurrentWorld->aSectors;
    for ( i = 0; i < sithWorld_g_pCurrentWorld->numSectors; ++v6 )
    {
        if ( sithIntersect_IsSphereInSector(&a1, 0.0, v6) )
            break;
        ++i;
    }

    if ( i == sithWorld_g_pCurrentWorld->numSectors )
    {
        sithConsole_PrintString("Position not in world");
        result = 0;
    }
    else
    {
        sithThing_DetachThing(v3);
        sithThing_ExitSector(v3);
        sithThing_SetPositionAndOrient(v3, &a1, &a);
        sithThing_EnterSector(v3, v6, 1, 0);
        result = 1;
    }
    return result;
}

int sithCommand_Activate(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    SithThing *v2; // esi
    int tmp;

    // Added: fixed a nullptr dereference
    if (!pArgStr) return 0;

    if ( sithWorld_g_pCurrentWorld && (v2 = sithWorld_g_pCurrentWorld->pLocalPlayer) != 0 )
    {
        if ( _sscanf(pArgStr, "%d", &tmp) >= 1
          && tmp >= 0
          && sithInventory_g_aTypes[tmp].cog
          && sithInventory_IsInventoryAvailable(v2, tmp) )
        {
            sithCog_SendMessage(
                sithInventory_g_aTypes[tmp].cog,
                SITH_MESSAGE_ACTIVATE,
                SENDERTYPE_0,
                tmp,
                SENDERTYPE_THING,
                v2->idx,
                0);
            return 1;
        }
    }
    else
    {
        sithConsole_PrintString("No world");
    }
    return 0;
}

int sithCommand_Jump(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    int result;
    int idx;

    // MOTS Added: fixed a nullptr dereference
    if (!pArgStr) return 0;

    result = _sscanf(pArgStr, "%d", &idx);
    if ( result )
    {
        sithPlayerActions_MoveToPlayerPosition(sithPlayer_g_pLocalPlayerThing, idx - 1);
        result = 1;
    }
    return result;
}

int sithCommand_Players(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    uint32_t v2; // edi
    SithPlayer* v3; // esi
    int v4; // eax
    int v5; // ecx
    char v7[32]; // [esp+8h] [ebp-20h] BYREF

    _sprintf(std_g_genBuffer, "Maxplayers = %d", jkPlayer_maxPlayers);
    sithConsole_PrintString(std_g_genBuffer);
    v2 = 0;
    if ( jkPlayer_maxPlayers )
    {
        v3 = &jkPlayer_playerInfos[0];
        do
        {
            stdString_WcharToChar(v7, v3->player_name, 31);
            v4 = v3->net_id;
            v5 = v3->flags;
            v7[31] = 0;
            _sprintf(std_g_genBuffer, "Player %d:  Name: %s  Flags: %x  ID: %x", v2, v7, v5, v4);
            sithConsole_PrintString(std_g_genBuffer);
            ++v2;
            ++v3;
        }
        while ( v2 < jkPlayer_maxPlayers );
    }
    return 1;
}

int sithCommand_PingPlayer(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    int v2; // esi
    wchar_t v4[32]; // [esp+4h] [ebp-40h] BYREF

    v2 = 0;
    if ( !sithNet_isMulti )
        return 0;
    if ( pArgStr )
    {
        stdString_CharToWchar(v4, pArgStr, 31);
        v4[31] = 0;
        v2 = sithPlayer_GetPlayerNumByName(v4);
        if ( v2 < 0 )
        {
            _sprintf(std_g_genBuffer, "Player %s not found", (const char *)v4);
            sithConsole_PrintString(std_g_genBuffer);
        }
    }
    sithMulti_Ping(jkPlayer_playerInfos[v2].net_id);
    return 1;
}

int sithCommand_Kick(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    uint32_t v2; // edi
    SithPlayer *v3; // esi
    wchar_t a1[32]; // [esp+Ch] [ebp-40h] BYREF

    v2 = 0;
    if ( !pArgStr || !sithNet_isMulti || !sithNet_isServer )
        return 0;
    stdString_CharToWchar(a1, pArgStr, 31);
    a1[31] = 0;
    if ( jkPlayer_maxPlayers )
    {
        v3 = jkPlayer_playerInfos;
        do
        {
            if ( (v3->flags & 1) != 0 && !__wcsicmp(v3->player_name, a1) )
            {
                _sprintf(std_g_genBuffer, "Kicked %S", v3->player_name);
                sithConsole_PrintString(std_g_genBuffer);
                sithMulti_QuitPlayer(v3->net_id);
            }
            ++v2;
            ++v3;
        }
        while ( v2 < jkPlayer_maxPlayers );
    }
    return 1;
}

int sithCommand_CompareMatInfos(const void *a, const void *b)
{
    return ((const int*)b)[2] - ((const int*)a)[2];
}

int sithCommand_MatList(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    SithWorld *pWorld = sithWorld_g_pCurrentWorld;
    if ( !pWorld )
    {
        sithConsole_PrintString("No world.");
        return 0;
    }

    // Allocate array: [matIdx, numFaces, totalBytes, bytesPerFace] per material
    int (*matInfo)[4] = (int(*)[4])SITH_ALLOC(pWorld->sizeMaterials * sizeof(int[4]));

    // Initialize
    for (int i = 0; i < pWorld->sizeMaterials; i++)
    {
        matInfo[i][0] = i;
        matInfo[i][1] = 0;
    }

    // Count faces per material
    for (int i = 0; i < pWorld->numSurfaces; i++)
    {
        rdMaterial *mat = pWorld->surfaces[i].surfaceInfo.face.material;
        if ( mat )
        {
            int matIdx = (int)(mat - pWorld->aMaterials);
            matInfo[matIdx][1]++;
        }
    }

    // Calculate memory per material
    for (int i = 0; i < pWorld->sizeMaterials; i++)
    {
        if ( matInfo[i][1] == 0 )
        {
            matInfo[i][2] = 0;
            matInfo[i][3] = 0;
        }
        else
        {
            uint32_t memSize = sithMaterial_GetMemorySize(&pWorld->aMaterials[i]);
            matInfo[i][3] = memSize;
            matInfo[i][2] = memSize / matInfo[i][1];
        }
    }

    // Sort by total bytes descending
    _qsort(matInfo, pWorld->sizeMaterials, sizeof(int[4]), sithCommand_CompareMatInfos);

    for (int i = 0; i < pWorld->sizeMaterials; i++)
    {
        if ( matInfo[i][2] != 0 )
        {
            _sprintf(std_g_genBuffer, "%-16s  %d faces, %d bytes, %d bytes/face",
                     pWorld->aMaterials[matInfo[i][0]].mat_fpath,
                     matInfo[i][1], matInfo[i][3], matInfo[i][2]);
            sithConsole_PrintString(std_g_genBuffer);
        }
    }

    SITH_FREE(matInfo);
    return 1;
}

// Added: npc spawn
int sithCommand_CmdThingNpc(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    if (sithNet_isMulti) return 1;

    char* pArgStrMutable = (char*)malloc(strlen(pArgStr)+1);
    strcpy(pArgStrMutable, pArgStr);

    char* pArgIter = _strtok(pArgStrMutable, ", \t\n\r");
    if ( !pArgIter ){
        _sprintf(std_g_genBuffer, "Usage: %s [spawn]\n", pCmd->cmdStr);
        sithConsole_PrintString(std_g_genBuffer);
        free((void*)pArgStrMutable);
        return 1;
    }

    if (!__strcmpi(pArgIter, "spawn")) {
        pArgIter = _strtok(NULL, ", \t\n\r");
        if (!pArgIter) {
            _sprintf(std_g_genBuffer, "Usage: %s spawn <template>\n", pCmd->cmdStr);
            sithConsole_PrintString(std_g_genBuffer);
            free((void*)pArgStrMutable);
            return 1;
        }
        
        SithThing* pCreateThingTemplate = sithTemplate_GetTemplate(pArgIter);
        if (!pCreateThingTemplate) {
            sithConsole_PrintString("No template by that name.");
        }
        else if (pCreateThingTemplate && sithWorld_g_pCurrentWorld && sithPlayer_g_pLocalPlayerThing) {
            //SithThing* pSpawned = sithThing_CreateThing(pCreateThingTemplate, sithPlayer_g_pLocalPlayerThing);
            SithThing* pSpawned = sithPlayerActions_SpawnThingAtLookAt(sithPlayer_g_pLocalPlayerThing, pCreateThingTemplate);
        }
        else {
            sithConsole_PrintString("No world.");
        }
    }
    free((void*)pArgStrMutable);
    return 1;
}

// Added: binds
int sithCommand_CmdBind(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    char tmp[512];
    memset(tmp, 0, sizeof(tmp));

    char* pArgStrMutable = (char*)malloc(strlen(pArgStr)+1);
    strcpy(pArgStrMutable, pArgStr);

    char* pArgIter = _strtok(pArgStrMutable, ", \t\n\r");
    if ( !pArgIter || strlen(pArgIter) > 1) {
        _sprintf(std_g_genBuffer, "Usage: %s <key> <command...args>\n", pCmd->cmdStr);
        sithConsole_PrintString(std_g_genBuffer);
        free((void*)pArgStrMutable);
        return 1;
    }

    uint16_t key = pArgIter[0];

    pArgIter = _strtok(NULL, ", \t\n\r");
    while (pArgIter)
    {
        strncat(tmp, pArgIter, sizeof(tmp)-1);
        strncat(tmp, " ", sizeof(tmp)-1);

        pArgIter = _strtok(NULL, ", \t\n\r");
    }
    tmp[strlen(tmp)] = 0;

    if (strlen(tmp) > 0) {
        sithCommand_AddBind(key, tmp);
    }
    else {
        _sprintf(std_g_genBuffer, "Usage: %s <key> <command...args>\n", pCmd->cmdStr);
        sithConsole_PrintString(std_g_genBuffer);
    }
    free((void*)pArgStrMutable);
    return 1;
}

// Added: unbinds
int sithCommand_CmdUnbind(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    char tmp[512];
    memset(tmp, 0, sizeof(tmp));

    char* pArgStrMutable = (char*)malloc(strlen(pArgStr)+1);
    strcpy(pArgStrMutable, pArgStr);

    char* pArgIter = _strtok(pArgStrMutable, ", \t\n\r");
    if ( !pArgIter || strlen(pArgIter) > 1) {
        _sprintf(std_g_genBuffer, "Usage: %s <key>\n", pCmd->cmdStr);
        sithConsole_PrintString(std_g_genBuffer);
        free((void*)pArgStrMutable);
        return 1;
    }

    uint16_t key = pArgIter[0];

    sithCommand_RemoveBind(key);
    free((void*)pArgStrMutable);
    return 1;
}

void sithCommand_StartupBinds()
{
    if (sithCommand_pBinds) {
        sithCommand_ShutdownBinds();
    }

    // Added: binds
    sithCommand_pBinds = (sithCommandBind*)malloc(sizeof(sithCommandBind));
    sithCommand_pBinds->key = 0;
    sithCommand_pBinds->pCmd = "";
    sithCommand_pBinds->pNext = NULL;

    sithCommand_LoadBinds();
}

void sithCommand_ShutdownBinds()
{
    if (!sithCommand_pBinds) {
        return;
    }

    sithCommand_SaveBinds();

    sithCommandBind* pBindIter = sithCommand_pBinds;
    while (pBindIter)
    {
        if (pBindIter->key && pBindIter->pCmd) {
            free((void*)pBindIter->pCmd);
        }
        sithCommandBind* pBindIterNext = pBindIter->pNext;
        free((void*)pBindIter);
        pBindIter = pBindIterNext;
    }
    sithCommand_pBinds = NULL;
}

void sithCommand_LoadBindCallback(const char* pKey, const char* pVal, void* pCtx)
{
    sithCommand_AddBind(pKey[0], pVal);
}

void sithCommand_SaveBinds()
{
    const char* ext_fpath = SITHBINDS_FNAME;

    stdJSON_EraseAll(ext_fpath);
    
    char tmp[3];
    sithCommandBind* pBindIter = sithCommand_pBinds;
    while (pBindIter = pBindIter->pNext)
    {
        snprintf(tmp, 3, "%c", pBindIter->key);
        stdJSON_SetString(ext_fpath, tmp, pBindIter->pCmd);
    }
}

void sithCommand_LoadBinds()
{
    const char* ext_fpath = SITHBINDS_FNAME;
    stdJSON_IterateKeys(ext_fpath, sithCommand_LoadBindCallback, NULL);
}

// Added
char sithCommand_aTmpCommandExecute[512];
void sithCommand_HandleBinds(uint16_t key)
{
    sithCommandBind* pBindIter = sithCommand_pBinds;
    while (pBindIter = pBindIter->pNext)
    {
        if (key == pBindIter->key) {
            strcpy(sithCommand_aTmpCommandExecute, pBindIter->pCmd);
            jkQuakeConsole_ExecuteCommand(sithCommand_aTmpCommandExecute);
        }
    }
}

// Added
void sithCommand_AddBind(uint16_t key, const char* pCmd)
{
    if (!pCmd || !key) return;

    sithCommandBind* pBindIter = sithCommand_pBinds;
    while (pBindIter)
    {
        // Overwrite existing bind
        if (key == pBindIter->key) {
            if (pBindIter->pCmd) {
                free((void*)pBindIter->pCmd);
            }
            pBindIter->pCmd = (char*)malloc(strlen(pCmd)+1);
            strcpy((char*)pBindIter->pCmd, pCmd);
            break;
        }

        // End of the list, add a bind
        if (!pBindIter->pNext) {
            sithCommandBind* pNewBind = (sithCommandBind*)malloc(sizeof(sithCommandBind));
            pBindIter->pNext = pNewBind;

            pNewBind->key = key;
            pNewBind->pCmd = (char*)malloc(strlen(pCmd)+1);
            strcpy((char*)pNewBind->pCmd, pCmd);
            pNewBind->pNext = NULL;
            break;
        }
        pBindIter = pBindIter->pNext;
    }

    sithCommand_SaveBinds();
}

// Added
void sithCommand_RemoveBind(uint16_t key)
{
    if (!key) return;

    sithCommandBind* pBindIter = sithCommand_pBinds;
    sithCommandBind* pBindIterLast = NULL;
    while (pBindIter)
    {
        // Overwrite existing bind
        if (key == pBindIter->key) {
            if (pBindIter->pCmd) {
                free((void*)pBindIter->pCmd);
            }

            sithCommandBind* pBindIterNext = pBindIter->pNext;
            if (pBindIterLast) {
                pBindIterLast->pNext = pBindIterNext;
            }
            free((void*)pBindIter);
            pBindIter = pBindIterNext;
            continue;
        }
        pBindIterLast = pBindIter;
        pBindIter = pBindIter->pNext;
    }

    sithCommand_SaveBinds();
}
