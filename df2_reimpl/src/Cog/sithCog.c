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
#include "Engine/sithSound.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/sithMaterial.h"
#include "Engine/sithModel.h"
#include "Engine/sithTemplate.h"
#include "AI/sithAIClass.h"
#include "General/stdHashTable.h"

#include "jk.h"

void (*sithDebugConsole_CmdCogList)(void) = (void*)0x004EE2F0;
static int (*sithCogScript_TimerTick)() = (void*)0x4E0640;
void (*sithCogScript_RegisterGlobalMessage)(void* ctx, char* name, int id) = (void*)0x004E06C0;
void (*sithCogScript_RegisterMessageSymbol)(void* ctx, int msg, char* name) = (void*)0x004E0600;

static int sithCog_bInitted = 0;

int sithCog_Startup()
{
    struct hashmap_entry *v3; // eax
    hashmap_entry *v4; // eax
    hashmap_entry *v5; // eax
    hashmap_entry *v6; // eax
    hashmap_entry *v7; // eax
    struct cogSymbol a2; // [esp+8h] [ebp-10h]

    g_cog_symbolTable = sithCogParse_NewSymboltable(512);
    if (!g_cog_symbolTable )
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
    g_cog_symbolTable->bucket_idx = 0x100;
    sithCogUtil_Initialize(g_cog_symbolTable);
    sithCogThing_Initialize(g_cog_symbolTable);
    sithCogAI_Initialize(g_cog_symbolTable);
    sithCogSurface_Initialize(g_cog_symbolTable);
    sithCogSound_Initialize(g_cog_symbolTable);
    sithCogSector_Initialize(g_cog_symbolTable);
    sithCogPlayer_Initialize(g_cog_symbolTable);
	sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 1, "activate");
	sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 1, "activated");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 3, "startup");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 4, "timer");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 5, "blocked");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 6, "entered");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 7, "exited");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 8, "crossed");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 9, "sighted");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 10, "damaged");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 11, "arrived");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 12, "killed");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 13, "pulse");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 14, "touched");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 15, "created");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 16, "loading");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 17, "selected");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 18, "deselected");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 20, "changed");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 21, "deactivated");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 22, "shutdown");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 23, "respawn");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 2, "removed");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 19, "autoselect");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 24, "aievent");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 25, "skill");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 26, "taken");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 27, "user0");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 28, "user1");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 29, "user2");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 30, "user3");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 31, "user4");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 32, "user5");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 33, "user6");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 34, "user7");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 35, "newplayer");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 36, "fire");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 37, "join");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 38, "leave");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 39, "splash");
    sithCogScript_RegisterMessageSymbol(g_cog_symbolTable, 40, "trigger");
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global0", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global1", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global2", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global3", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global4", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global5", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global6", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global7", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global8", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global9", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global10", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global11", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global12", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global13", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global14", 0);
    sithCogScript_RegisterGlobalMessage(g_cog_symbolTable, "global15", 0);
    sithTimer_RegisterFunc(4, sithCogScript_TimerTick, 0, 2);
    sithCog_bInitted = 1;
    return 1;
}

void sithCog_Shutdown()
{
    sithCogParse_FreeSymboltable(g_cog_symbolTable);
    if ( g_cog_hashtable )
    {
        stdHashTable_Free((stdHashTable *)g_cog_hashtable);
        g_cog_hashtable = 0;
    }
    sithCogParse_Reset();
    sithCog_bInitted = 0;
}

int sithCog_LoadEntry(sithCogSymbol *cogSymbol, sithCogIdk *cogIdk, char *val)
{
    sithCogSymbol *v5; // esi
    sithCogSymbol *v7; // ecx
    sithCogSymbol *v9; // esi
    rdMaterial *v10; // eax
    sithSound *v12; // eax
    sithThing *v14; // eax
    rdModel3 *v15; // eax
    rdKeyframe *v17; // eax
    sithAIClass *v19; // eax

    switch ( cogIdk->type )
    {
        case COG_TYPE_FLEX:
            cogSymbol->symbol_type = COG_VARTYPE_FLEX;
            cogSymbol->as_flex = _atof(val);
            return 1;

        case COG_TYPE_TEMPLATE:
            cogSymbol->symbol_type = COG_VARTYPE_INT;
            v14 = sithTemplate_GetEntryByName(val);
            if ( !v14 )
            {
                cogSymbol->as_int = -1;
                return 0;
            }
            cogSymbol->symbol_name = (char *)v14->thingIdx;
            return 1;

        case COG_TYPE_KEYFRAME:
            cogSymbol->symbol_type = COG_VARTYPE_INT;
            v17 = sithKeyFrame_LoadEntry(val);
            if ( !v17 )
            {
                cogSymbol->as_int = -1;
                return 0;
            }
            cogSymbol->as_int = v17->id;
            return 1;
        case COG_TYPE_SOUND:
            cogSymbol->symbol_type = COG_VARTYPE_INT;
            v12 = sithSound_LoadEntry(val, 0);
            if ( !v12 )
            {
                cogSymbol->as_int = -1;
                return 0;
            }
            cogSymbol->as_int = v12->id;
            return 1;
        case COG_TYPE_MATERIAL:
            cogSymbol->symbol_type = COG_VARTYPE_INT;
            v10 = sithMaterial_LoadEntry(val, 0, 0);
            if ( !v10 )
            {
                cogSymbol->as_int = -1;
                return 0;
            }
            cogSymbol->as_int = v10->id;
            return 1;
        case COG_TYPE_VECTOR:
            cogSymbol->symbol_type = COG_VARTYPE_VECTOR;
            if (_sscanf(val, "(%f/%f/%f)", &cogSymbol->as_flex, &cogSymbol->field_C, &cogSymbol->field_10) == 3 )
            {
                return 1;
            }
            else
            {
                cogSymbol->as_int = 0;
                cogSymbol->field_C = 0;
                cogSymbol->field_10 = 0;
                return 0;
            }
            break;

        case COG_TYPE_MODEL:
            cogSymbol->symbol_type = COG_VARTYPE_INT;
            v15 = sithModel_LoadEntry(val, 1);
            if ( !v15 )
            {
                cogSymbol->as_int = -1;
                return 0;
            }
            cogSymbol->as_int = v15->id;
            return 1;

        case COG_TYPE_AICLASS:
            cogSymbol->symbol_type = COG_VARTYPE_INT;
            v19 = sithAIClass_Load(val);
            if ( v19 )
            {
                cogSymbol->as_aiclass = v19;
                return 1;
            }
            else
            {
                cogSymbol->as_int = -1;
                return 0;
            }
            break;

        default:
            cogSymbol->symbol_type = COG_VARTYPE_INT;
            cogSymbol->as_int = _atoi(val);
            return 1;
    }
}


void sithCog_SendMessageFromThing(sithThing *a1, sithThing *a2, int msg)
{
    sithCog_SendMessageFromThingEx(a1, a2, msg, 0.0, 0.0, 0.0, 0.0);
}
