#include "sithCog.h"

#include "jk.h"
#include "types.h"
#include "Cog/sithCogUtil.h"
#include "Cog/sithCogThing.h"
#include "Cog/sithCogPlayer.h"
#include "Cog/sithCogAI.h"
#include "Cog/sithCogSurface.h"
#include "Cog/sithCogSector.h"
#include "Cog/sithCogSound.h"
#include "Cog/sithCogVm.h"
#include "Cog/sithCogParse.h"
#include "jkCog.h"
#include "Engine/sithTimer.h"

#include "General/stdHashTable.h"

void (*sithDebugConsole_CmdCogList)(void) = (void*)0x004EE2F0;
void (*cog_deinit)(sithCog* ctx) = (void*)0x004DE590;
void (*cog_exec)(sithCog* ctx, int b) = (void*)0x004E2350;
static int (*sithCogScript_TimerTick)() = (void*)0x4E0640;
void (*sithCogScript_RegisterGlobalMessage)(void* ctx, char* name, int id) = (void*)0x004E06C0;
void (*sithCogScript_RegisterMessageSymbol)(void* ctx, int msg, char* name) = (void*)0x004E0600;


int sithCog_Startup()
{
    struct hashmap_entry *v3; // eax
    hashmap_entry *v4; // eax
    hashmap_entry *v5; // eax
    hashmap_entry *v6; // eax
    hashmap_entry *v7; // eax
    struct cogSymbol a2; // [esp+8h] [ebp-10h]

    g_cog_symboltable_hashmap = sithCogParse_NewSymboltable(512);
    if (!g_cog_symboltable_hashmap )
    {
        jk_assert(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 118, "Could not allocate COG symboltable.");
        return 0;
    }
  
    g_cog_hashtable = stdHashTable_New(256);
    if (!g_cog_hashtable)
    {
        jk_assert(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 124, "Could not allocate COG hashtable.");
        return 0;
    }
    g_cog_symboltable_hashmap->bucket_idx = 0x100;
    sithCogUtil_Initialize(g_cog_symboltable_hashmap);
    sithCogThing_Initialize(g_cog_symboltable_hashmap);
    sithCogAI_Initialize(g_cog_symboltable_hashmap);
    sithCogSurface_Initialize(g_cog_symboltable_hashmap);
    sithCogSound_Initialize(g_cog_symboltable_hashmap);
    sithCogSector_Initialize(g_cog_symboltable_hashmap);
    sithCogPlayer_Initialize(g_cog_symboltable_hashmap);
	sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 1, "activate");
	sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 1, "activated");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 3, "startup");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 4, "timer");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 5, "blocked");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 6, "entered");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 7, "exited");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 8, "crossed");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 9, "sighted");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 10, "damaged");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 11, "arrived");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 12, "killed");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 13, "pulse");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 14, "touched");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 15, "created");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 16, "loading");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 17, "selected");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 18, "deselected");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 20, "changed");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 21, "deactivated");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 22, "shutdown");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 23, "respawn");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 2, "removed");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 19, "autoselect");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 24, "aievent");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 25, "skill");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 26, "taken");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 27, "user0");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 28, "user1");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 29, "user2");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 30, "user3");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 31, "user4");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 32, "user5");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 33, "user6");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 34, "user7");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 35, "newplayer");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 36, "fire");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 37, "join");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 38, "leave");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 39, "splash");
    sithCogScript_RegisterMessageSymbol(g_cog_symboltable_hashmap, 40, "trigger");
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global0", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global1", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global2", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global3", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global4", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global5", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global6", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global7", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global8", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global9", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global10", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global11", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global12", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global13", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global14", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symboltable_hashmap, "global15", 0);
    sithTimer_RegisterFunc(4, sithCogScript_TimerTick, 0, 2);
    //cog_initialized = 1;
    return 1;
}

void sithCog_SendMessageFromThing(sithThing *a1, sithThing *a2, int msg)
{
    sithCog_SendMessageFromThingEx(a1, a2, msg, 0.0, 0.0, 0.0, 0.0);
}
