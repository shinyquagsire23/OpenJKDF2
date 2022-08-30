#include "sithDebugConsole.h"

#include "General/sithStrTable.h"
#include "General/stdString.h"
#include "Win95/DebugConsole.h"
#include "AI/sithAI.h"
#include "Main/jkGame.h"
#include "Cog/sithCog.h"
#include "World/sithThing.h"
#include "Gameplay/sithPlayerActions.h"
#include "Engine/sithIntersect.h"
#include "jk.h"

#define sithDebugConsole_CmdTick ((void*)sithDebugConsole_CmdTick_ADDR)
#define sithDebugConsole_CmdSession ((void*)sithDebugConsole_CmdSession_ADDR)
#define sithDebugConsole_CmdCogTrace ((void*)sithDebugConsole_CmdCogTrace_ADDR)
#define sithDebugConsole_CmdCogPause ((void*)sithDebugConsole_CmdCogPause_ADDR)
#define sithDebugConsole_CmdCogList ((void*)sithDebugConsole_CmdCogList_ADDR)
#define sithDebugConsole_CmdMem ((void*)sithDebugConsole_CmdMem_ADDR)
#define sithDebugConsole_CmdDynamicMem ((void*)sithDebugConsole_CmdDynamicMem_ADDR)
#define sithDebugConsole_CmdMemDump ((void*)sithDebugConsole_CmdMemDump_ADDR)
#define sithDebugConsole_CmdMatList ((void*)sithDebugConsole_CmdMatList_ADDR)
#define sithDebugConsole_CmdCoords ((void*)sithDebugConsole_CmdCoords_ADDR)
#define sithDebugConsole_CmdPlayers ((void*)sithDebugConsole_CmdPlayers_ADDR)
#define sithDebugConsole_CmdPing ((void*)sithDebugConsole_CmdPing_ADDR)
#define sithDebugConsole_CmdKick ((void*)sithDebugConsole_CmdKick_ADDR)
#define sithDebugConsole_matlist_sort ((void*)sithDebugConsole_matlist_sort_ADDR)

void sithDebugConsole_Initialize()
{
    DebugConsole_RegisterDevCmd(sithDebugConsole_CmdPlayers, "players", 0);
    DebugConsole_RegisterDevCmd(sithDebugConsole_CmdCoords, "coords", 0);
    DebugConsole_RegisterDevCmd(sithDebugConsole_CheatSetDebugFlags, "trackshots", 3);
    DebugConsole_RegisterDevCmd(sithDebugConsole_CmdPing, "ping", 0);
    DebugConsole_RegisterDevCmd(sithDebugConsole_CmdKick, "kick", 0);
    DebugConsole_RegisterDevCmd(sithDebugConsole_CmdTick, "tick", 0);
    DebugConsole_RegisterDevCmd(sithDebugConsole_CmdSession, "session", 0);
    if ( (g_debugmodeFlags & 0x100) != 0 )
    {
        DebugConsole_RegisterDevCmd(DebugConsole_PrintHelp, "help", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CheatSetDebugFlags, "disableai", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CheatSetDebugFlags, "notarget", 6);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CheatSetDebugFlags, "outline", 1);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CheatSetDebugFlags, "disablepuppet", 2);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CmdCogTrace, "cogtrace", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CmdCogList, "coglist", 0);
        DebugConsole_RegisterDevCmd(sithCogScript_DevCmdCogStatus, "cogstatus", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CheatSetDebugFlags, "noaishots", 4);
        DebugConsole_RegisterDevCmd(sithAI_PrintThingStatus, "aistatus", 0);
        DebugConsole_RegisterDevCmd(sithAI_PrintThings, "ailist", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CmdFly, "fly", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CmdMem, "mem", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CmdDynamicMem, "dynamicmem", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CmdMemDump, "memdump", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CheatSetDebugFlags, "invul", 5);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CmdCogPause, "cogpause", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CmdMatList, "matlist", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CmdWarp, "warp", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CmdActivate, "activate", 0);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CheatSetDebugFlags, "slowmo", 7);
        DebugConsole_RegisterDevCmd(sithDebugConsole_CmdJump, "jump", 0);
    }
}

int sithDebugConsole_CheatSetDebugFlags(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    int *v2; // esi
    int v3; // edi
    sithThing *v4; // eax
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
            v2 = &sithRender_flag;
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
            if ( !sithWorld_pCurrentWorld )
                goto LABEL_24;
            v4 = sithWorld_pCurrentWorld->playerThing;
            if ( !v4 || v4->type != SITH_THING_PLAYER )
                goto LABEL_24;
            v2 = (int*)&v4->actorParams.typeflags;
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
                v5 = sithStrTable_GetString("ON");
            else
                v5 = sithStrTable_GetString("OFF");
            v8 = v5;
            v6 = sithStrTable_GetString("%s_IS_%s");
            jk_snwprintf(a1, 0x80u, v6, v9, v8);
            DebugConsole_PrintUniStr(a1);
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

int sithDebugConsole_CmdFly()
{
    sithThing *v0; // ecx
    wchar_t *v3; // eax

    if ( sithWorld_pCurrentWorld && (v0 = sithWorld_pCurrentWorld->playerThing) != 0 )
    {
        if ( v0->moveType == SITH_MT_PHYSICS )
        {
            if (v0->physicsParams.physflags & PHYSFLAGS_FLYING)
            {
                v0->physicsParams.physflags &= ~PHYSFLAGS_FLYING;
                v0->physicsParams.physflags |= PHYSFLAGS_GRAVITY;
                v3 = sithStrTable_GetString("FLYING_OFF");
            }
            else
            {
                v0->physicsParams.physflags &= ~PHYSFLAGS_GRAVITY;
                v0->physicsParams.physflags |= PHYSFLAGS_FLYING;
                v3 = sithStrTable_GetString("FLYING_ON");
            }
            DebugConsole_PrintUniStr(v3);
            return 1;
        }
        else
        {
            DebugConsole_Print("Not physics thing.");
            return 0;
        }
    }
    else
    {
        DebugConsole_Print("No world.");
        return 0;
    }
    return 0;
}

//

int sithDebugConsole_CmdWarp(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    sithThing *v3; // ebp
    int result; // eax
    int v5; // eax
    sithSector *v6; // edi
    unsigned int i; // esi
    rdVector3 a1; // [esp+10h] [ebp-48h] BYREF
    rdVector3 a3a; // [esp+1Ch] [ebp-3Ch] BYREF
    rdMatrix34 a; // [esp+28h] [ebp-30h] BYREF

    if ( !sithWorld_pCurrentWorld || (v3 = sithWorld_pCurrentWorld->playerThing) == 0 )
    {
        DebugConsole_Print("No world.");
        return 0;
    }
    if ( !pArgStr )
    {
        DebugConsole_Print("Format: WARP x y z");
        return 0;
    }
    v5 = _sscanf(pArgStr, "%f %f %f %f %f %f", &a1, &a1.y, &a1.z, &a3a, &a3a.y, &a3a.z);
    if ( v5 < 3 )
        return 0;

    if ( v5 == 6 )
        rdMatrix_BuildRotate34(&a, &a3a);
    else
        rdMatrix_Identity34(&a);

    v6 = sithWorld_pCurrentWorld->sectors;
    for ( i = 0; i < sithWorld_pCurrentWorld->numSectors; ++v6 )
    {
        if ( sithIntersect_IsSphereInSector(&a1, 0.0, v6) )
            break;
        ++i;
    }

    if ( i == sithWorld_pCurrentWorld->numSectors )
    {
        DebugConsole_Print("Position not in world");
        result = 0;
    }
    else
    {
        sithThing_DetachThing(v3);
        sithThing_LeaveSector(v3);
        sithThing_SetPosAndRot(v3, &a1, &a);
        sithThing_EnterSector(v3, v6, 1, 0);
        result = 1;
    }
    return result;
}

int sithDebugConsole_CmdActivate(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    sithThing *v2; // esi
    int tmp;

    if ( sithWorld_pCurrentWorld && (v2 = sithWorld_pCurrentWorld->playerThing) != 0 )
    {
        if ( _sscanf(pArgStr, "%d", &tmp) >= 1
          && tmp >= 0
          && sithInventory_aDescriptors[tmp].cog
          && sithInventory_GetAvailable(v2, tmp) )
        {
            sithCog_SendMessage(
                sithInventory_aDescriptors[tmp].cog,
                SITH_MESSAGE_ACTIVATE,
                SENDERTYPE_0,
                tmp,
                SENDERTYPE_THING,
                v2->thingIdx,
                0);
            return 1;
        }
    }
    else
    {
        DebugConsole_Print("No world");
    }
    return 0;
}

int sithDebugConsole_CmdJump(stdDebugConsoleCmd *pCmd, const char *pArgStr)
{
    int result; // eax

    result = _sscanf(pArgStr, "%d", &pArgStr);
    if ( result )
    {
        sithPlayerActions_WarpToCheckpoint(g_localPlayerThing, (int)(pArgStr - 1));
        result = 1;
    }
    return result;
}