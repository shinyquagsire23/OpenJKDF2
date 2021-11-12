#include "sithDebugConsole.h"

#include "Win95/DebugConsole.h"
#include "AI/sithAI.h"
#include "Main/jkGame.h"
#include "Cog/sithCog.h"

#define sithDebugConsole_CmdTick ((void*)sithDebugConsole_CmdTick_ADDR)
#define sithDebugConsole_CmdSession ((void*)sithDebugConsole_CmdSession_ADDR)
#define sithDebugConsole_CheatSetDebugFlags ((void*)sithDebugConsole_CheatSetDebugFlags_ADDR)
#define sithDebugConsole_CmdCogTrace ((void*)sithDebugConsole_CmdCogTrace_ADDR)
#define sithDebugConsole_CmdCogPause ((void*)sithDebugConsole_CmdCogPause_ADDR)
#define sithDebugConsole_CmdCogList ((void*)sithDebugConsole_CmdCogList_ADDR)
#define sithDebugConsole_CmdFly ((void*)sithDebugConsole_CmdFly_ADDR)
#define sithDebugConsole_CmdMem ((void*)sithDebugConsole_CmdMem_ADDR)
#define sithDebugConsole_CmdDynamicMem ((void*)sithDebugConsole_CmdDynamicMem_ADDR)
#define sithDebugConsole_CmdMemDump ((void*)sithDebugConsole_CmdMemDump_ADDR)
#define sithDebugConsole_CmdMatList ((void*)sithDebugConsole_CmdMatList_ADDR)
#define sithDebugConsole_CmdCoords ((void*)sithDebugConsole_CmdCoords_ADDR)
#define sithDebugConsole_CmdWarp ((void*)sithDebugConsole_CmdWarp_ADDR)
#define sithDebugConsole_CmdActivate ((void*)sithDebugConsole_CmdActivate_ADDR)
#define sithDebugConsole_CmdJump ((void*)sithDebugConsole_CmdJump_ADDR)
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
