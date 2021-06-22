#include "sithCog.h"

#include "jk.h"
#include "types.h"
#include "Win95/DebugConsole.h"
#include "Cog/sithCogUtil.h"
#include "Cog/sithCogThing.h"
#include "Cog/sithCogPlayer.h"
#include "Cog/sithCogAI.h"
#include "Cog/sithCogSurface.h"
#include "Cog/sithCogSector.h"
#include "Cog/sithCogSound.h"
#include "Cog/sithCogVm.h"
#include "Cog/sithCogParse.h"
#include "Cog/jkCog.h"
#include "Engine/sithTimer.h"
#include "Engine/sithSound.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/sithMaterial.h"
#include "Engine/sithModel.h"
#include "Engine/sithTemplate.h"
#include "Engine/sithTime.h"
#include "Engine/sithSurface.h"
#include "Engine/sithNet.h"
#include "AI/sithAIClass.h"
#include "General/stdHashTable.h"
#include "World/sithSector.h"
#include "World/sithThing.h"
#include "World/sithThingPlayer.h"
#include "Main/jkGame.h"
#include "stdPlatform.h"

#include "jk.h"

void (*sithDebugConsole_CmdCogList)(void) = (void*)0x004EE2F0;

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
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 118, "Could not allocate COG symboltable.");
        return 0;
    }
  
    sithCog_pScriptHashtable = stdHashTable_New(256);
    if (!sithCog_pScriptHashtable)
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 124, "Could not allocate COG hashtable.");
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
    if ( sithCog_pScriptHashtable )
    {
        stdHashTable_Free(sithCog_pScriptHashtable);
        sithCog_pScriptHashtable = 0;
    }
    sithCogParse_Reset();
    sithCog_bInitted = 0;
}

int sithCog_Open()
{
    sithWorld *world; // ecx
    signed int result; // eax
    sithCog *v2; // ebx
    sithCogIdk *v3; // ebp
    sithCog *v5; // ebp
    sithCogIdk *v6; // ebx
    char *v7; // esi
    sithCogSymbol *v8; // edx
    uint32_t v10; // [esp+4h] [ebp-14h]
    uint32_t v12; // [esp+8h] [ebp-10h]
    char *v13; // [esp+Ch] [ebp-Ch]
    sithCogSymbol *v14; // [esp+10h] [ebp-8h]
    sithWorld *world_; // [esp+14h] [ebp-4h]

    world = sithWorld_pCurWorld;
    world_ = sithWorld_pCurWorld;
    if ( sithCog_bOpened )
        return 0;
    if ( sithWorld_pStatic )
    {
        v2 = sithWorld_pStatic->cogs;
        for (int i = 0; i < sithWorld_pStatic->numCogsLoaded; i++)
        {
            for (int j = 0; j < v2->cogscript->numIdk; j++)
            {
                v3 = &v2->cogscript->aIdk[j];
                if ( _strlen(v3->value) )
                    sithCog_LoadEntry(&v2->symbolTable->buckets[v3->hash], v3, v3->value);
            }
            sithCog_SendMessage(v2++, SITH_MESSAGE_LOADING, 0, 0, 0, 0, 0);
            world = world_;
        }
    }
    sithCog* cogs = world->cogs;
    v12 = 0;
    if ( world->numCogsLoaded )
    {
        while ( 1 )
        {
            v10 = 0;
            v6 = cogs->cogscript->aIdk;
            if ( cogs->cogscript->numIdk )
                break;
LABEL_25:
            sithCog_SendMessage(cogs++, SITH_MESSAGE_LOADING, 0, 0, 0, 0, 0);
            if (++v12 >= world_->numCogsLoaded )
                goto LABEL_26;
        }

        v13 = cogs->field_4BC;
        while ( 1 )
        {
            sithCogIdk* idk = &cogs->cogscript->aIdk[v10];
            v8 = &cogs->symbolTable->buckets[idk->hash];
            v14 = v8;
            if ( (idk->flags & 1) != 0 )
            {
                if ( _strlen(idk->value) )
                    sithCog_LoadEntry(v8, v6, idk->value);
                goto LABEL_24;
            }
            if ( _strlen(v13) )
                break;
            if ( _strlen(idk->value) )
            {
                sithCog_LoadEntry(v8, v6, idk->value);
                goto LABEL_20;
            }
LABEL_21:
            v13 += 32;
            sithCog_ThingsSectorsRegSymbolIdk(cogs, v6, v8);
LABEL_24:
            ++v6;
            if (++v10 >= cogs->cogscript->numIdk )
                goto LABEL_25;
        }
        sithCog_LoadEntry(v8, v6, v13);
LABEL_20:
        v8 = v14;
        goto LABEL_21;
    }
LABEL_26:
    result = 1;
    sithCog_bOpened = 1;
    return result;
}

void sithCog_Close()
{
    if ( sithCog_bOpened )
    {
        sithCog_SendMessageToAll(COGMSG_SYNCTHINGATTACHMENT, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0);
        sithCog_numSectorLinks = 0;
        sithCog_numSurfaceLinks = 0;
        sithCog_numThingLinks = 0;
        sithCog_masterCog = 0;
        sithCog_bOpened = 0;
    }
}

int sithCog_Load(sithWorld *world, int a2)
{
    int num_cogs; // esi
    signed int result; // eax
    sithCog *cogs; // eax
    unsigned int v7; // eax
    int *v8; // ebx
    sithCog *v9; // eax
    unsigned int v15; // eax
    sithCogSymboltable *cogscript_symboltable; // edx
    int v17; // ecx
    sithCogScript *v18; // ebp
    char **v19; // edi
    void *v20; // ebx
    char *v21; // esi
    unsigned int v22; // [esp+10h] [ebp-88h]
    uint32_t v23; // [esp+14h] [ebp-84h]
    char cog_fpath[32]; // [esp+18h] [ebp-80h] BYREF

    if ( a2 )
        return 0;
    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_entry.args[0].value, "world") || _strcmp(stdConffile_entry.args[1].value, "cogs") )
        return 0;
    num_cogs = _atoi(stdConffile_entry.args[2].value);
    if ( !num_cogs )
        return 1;
    cogs = (sithCog *)pSithHS->alloc(sizeof(sithCog) * num_cogs);
    world->cogs = cogs;
    if ( cogs )
    {
        _memset(cogs, 0, sizeof(sithCog) * num_cogs);
        world->numCogs = num_cogs;
        world->numCogsLoaded = 0;
        while ( stdConffile_ReadArgs() )
        {
            if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
                break;
            if ( stdConffile_entry.numArgs < 2u )
                return 0;
            v9 = sithCog_LoadCogscript(stdConffile_entry.args[1].value);

            if ( v9 )
            {
                v18 = v9->cogscript;
                v23 = 0;
                v21 = &v9->field_4BC[0];
                v22 = 2;
                for (v23 = 0; v23 < v9->cogscript->numIdk; v23++)
                {
                    v20 = &v18->aIdk[v23].flags;
                    if ( (*(uint8_t*)v20 & 1) == 0 && stdConffile_entry.numArgs > v22 )
                    {
                        _strncpy(v21, stdConffile_entry.args[v22].value, 0x1Fu);
                        v21[31] = 0;
                        v21 += 32;
                        ++v22;
                    }
                    v20 = (char *)v20 + sizeof(sithCogIdk);
                }
            }
        }
        result = 1;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 883, "Memory alloc failure initializing COGs.\n", 0, 0, 0, 0);
        result = 0;
    }
    return result;
}

sithCog* sithCog_LoadCogscript(const char *fpath)
{
    unsigned int cogIdx; // eax
    sithCogSymboltable *result; // eax
    sithCog *cog; // ebx
    sithCogScript *v7; // eax
    sithCogScript *v8; // esi
    unsigned int v9; // eax
    char cog_fpath[128]; // [esp+10h] [ebp-80h] BYREF

    cogIdx = sithWorld_pLoading->numCogsLoaded;
    if ( cogIdx >= sithWorld_pLoading->numCogs )
        return 0;

    cog = &sithWorld_pLoading->cogs[cogIdx];
    cog->selfCog = cogIdx;
    if (sithWorld_pLoading->level_type_maybe & 1)
    {
        cog->selfCog |= 0x8000;
    }
    _sprintf(cog_fpath, "%s%c%s", "cog", '\\', fpath);
    v7 = (sithCogScript *)stdHashTable_GetKeyVal(sithCog_pScriptHashtable, fpath);
    if ( v7 )
    {
        v8 = v7;
    }
    else
    {
        v9 = sithWorld_pLoading->numCogScriptsLoaded;
        if ( v9 < sithWorld_pLoading->numCogScripts && (v8 = &sithWorld_pLoading->cogScripts[v9], sithCogParse_Load(cog_fpath, v8, 0)) )
        {
            stdHashTable_SetKeyVal(sithCog_pScriptHashtable, v8->cog_fpath, v8);
            ++sithWorld_pLoading->numCogScriptsLoaded;
        }
        else
        {
            v8 = 0;
        }
    }
    if ( !v8 )
        return 0;
    _strncpy(cog->cogscript_fpath, v8->cog_fpath, 0x1Fu);
    cog->cogscript_fpath[31] = 0;
    cog->cogscript = v8;
    cog->flags = v8->debug_maybe;
    cog->symbolTable = sithCogParse_CopySymboltable(v8->symbolTable);
    if ( cog->symbolTable )
    {
        sithWorld_pLoading->numCogsLoaded++;
        return cog;
    }
    return NULL;
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

int sithCog_ThingsSectorsRegSymbolIdk(sithCog *cog, sithCogIdk *idk, sithCogSymbol *symbol)
{
    int v3; // eax
    int v5; // ebx
    int v6; // edi
    sithSurface *v7; // esi
    int v8; // eax
    int v10; // eax
    int v11; // ebx
    int v12; // edi
    sithSector *v13; // esi
    int v15; // ecx
    int v16; // eax
    int v17; // ebx
    int v18; // edi
    sithThing *v19; // esi
    int v21; // ecx
    int v22; // eax
    int v23; // edx

    v3 = (int)symbol->symbol_name;
    if ( v3 < 0 )
        return 0;
    switch ( idk->type )
    {
        case 3:
            if ( v3 >= sithWorld_pCurWorld->numThingsLoaded )
                return 0;
            v17 = idk->mask;
            v18 = idk->linkid;
            v19 = &sithWorld_pCurWorld->things[v3];
            if ( sithThing_GetIdxFromThing(v19) && v19->thingType && v18 >= 0 )
            {
                v21 = sithCog_numThingLinks;
                v19->thingflags |= SITH_TF_CAPTURED;
                v22 = v21;
                sithCog_aThingLinks[v22].thing = v19;
                sithCog_aThingLinks[v22].cog = cog;
                v23 = v19->signature;
                sithCog_aThingLinks[v22].linkid = v18;
                sithCog_aThingLinks[v22].mask = v17;
                sithCog_aThingLinks[v22].signature = v23;
                sithCog_numThingLinks = v21 + 1;
            }
            break;
        case 5:
            if ( v3 >= sithWorld_pCurWorld->numSectors )
                return 0;
            v11 = idk->mask;
            v12 = idk->linkid;
            v13 = &sithWorld_pCurWorld->sectors[v3];
            if ( sithSector_GetIdxFromPtr(v13) && v12 >= 0 )
            {
                v15 = sithCog_numSectorLinks;
                v13->flags |= SITH_SF_COGLINKED;
                v16 = v15;
                sithCog_aSectorLinks[v16].sector = v13;
                sithCog_aSectorLinks[v16].cog = cog;
                sithCog_aSectorLinks[v16].linkid = v12;
                sithCog_aSectorLinks[v16].mask = v11;
                sithCog_numSectorLinks = v15 + 1;
                return 1;
            }
            break;
        case 6:
            if ( v3 >= sithWorld_pCurWorld->numSurfaces )
                return 0;
            v5 = idk->mask;
            v6 = idk->linkid;
            v7 = &sithWorld_pCurWorld->surfaces[v3];
            if ( sithSurface_GetIdxFromPtr(v7) )
            {
                if ( v6 >= 0 )
                {
                    v7->surfaceFlags |= 0x2;
                    v10 = sithCog_numSurfaceLinks;
                    sithCog_aSurfaceLinks[v10].surface = v7;
                    sithCog_aSurfaceLinks[v10].cog = cog;
                    sithCog_aSurfaceLinks[v10].linkid = v6;
                    sithCog_aSurfaceLinks[v10].mask = v5;
                    sithCog_numSurfaceLinks++;
                    return 1;
                }
            }
            break;
    }
    return 1;
}

void sithCog_SendMessageFromThing(sithThing *a1, sithThing *a2, int msg)
{
    sithCog_SendMessageFromThingEx(a1, a2, msg, 0.0, 0.0, 0.0, 0.0);
}

float sithCog_SendMessageFromThingEx(sithThing *sender, sithThing *receiver, SITH_MESSAGE message, float param0, float param1, float param2, float param3)
{
    //return _sithCog_SendMessageFromThingEx(sender, receiver, message, param0, param1, param2, param3);
    int v7; // ebx
    int v8; // ebp
    sithCog *v9; // eax
    float v10; // st7
    float v11; // st7
    sithCog *v12; // eax
    float v13; // st7
    float v14; // st7
    float v16; // st7
    float v17; // st7
    float v19; // [esp+10h] [ebp-8h]
    int receivera; // [esp+20h] [ebp+8h]

    v19 = 0.0;
    if ( message == SITH_MESSAGE_DAMAGED )
        v19 = param0;
    if ( receiver )
    {
        v7 = receiver->thingIdx;
        v8 = 3;
        receivera = 1 << receiver->thingType;
    }
    else
    {
        v7 = -1;
        v8 = 0;
        receivera = 1;
    }
    v9 = sender->class_cog;
    if ( v9 )
    {
        if ( message == SITH_MESSAGE_DAMAGED )
        {
            v10 = sithCog_SendMessageEx(v9, SITH_MESSAGE_DAMAGED, SENDERTYPE_THING, sender->thingIdx, v8, v7, 0, param0, param1, param2, param3);
            if ( v10 != -9999.9873046875 )
            {
                v19 = v10;
                param0 = v10;
            }
        }
        else
        {
            v11 = sithCog_SendMessageEx(v9, message, SENDERTYPE_THING, sender->thingIdx, v8, v7, 0, param0, param1, param2, param3);
            if ( v11 != -9999.9873046875 )
            {
                v19 = v11 + v19;
            }
        }
    }
    v12 = sender->capture_cog;
    if ( v12 )
    {
        if ( message == SITH_MESSAGE_DAMAGED )
        {
            v13 = sithCog_SendMessageEx(v12, SITH_MESSAGE_DAMAGED, SENDERTYPE_THING, sender->thingIdx, v8, v7, 0, param0, param1, param2, param3);
            if ( v13 != -9999.9873046875 )
            {
                v19 = v13;
                param0 = v13;
            }
        }
        else
        {
            v14 = sithCog_SendMessageEx(v12, message, SENDERTYPE_THING, sender->thingIdx, v8, v7, 0, param0, param1, param2, param3);
            if ( v14 != -9999.9873046875 )
                v19 = v14 + v19;
        }
    }
    for (int i = 0; i < sithCog_numThingLinks; i++)
    {
        sithCogThingLink* v15 = &sithCog_aThingLinks[i];
        if ( v15->thing == sender && v15->signature == sender->signature && (receivera & v15->mask) != 0 )
        {
            if ( message == SITH_MESSAGE_DAMAGED )
            {
                v16 = sithCog_SendMessageEx(
                          v15->cog,
                          SITH_MESSAGE_DAMAGED,
                          SENDERTYPE_THING,
                          sender->thingIdx,
                          v8,
                          v7,
                          0,
                          param0,
                          param1,
                          param2,
                          param3);
                if ( v16 != -9999.9873046875 )
                {
                    v19 = v16;
                    param0 = v16;
                }
            }
            else
            {
                v17 = sithCog_SendMessageEx(
                          v15->cog,
                          message,
                          SENDERTYPE_THING,
                          sender->thingIdx,
                          v8,
                          v7,
                          v15->linkid,
                          param0,
                          param1,
                          param2,
                          param3);
                if ( v17 != -9999.9873046875 )
                    v19 = v17 + v19;
            }
        }
    }
    return v19;
}

void sithCog_SendMessageFromSurface(sithSurface *surface, sithThing *thing, int msg)
{
    sithCog_SendMessageFromSurfaceEx(surface, thing, msg, 0.0, 0.0, 0.0, 0.0);
}

double sithCog_SendMessageFromSurfaceEx(sithSurface *sender, sithThing *thing, SITH_MESSAGE msg, float a4, float a5, float a6, float a7)
{
    int v8; // ebp
    float v9; // ebx
    double v11; // st7
    double v12; // st7
    float v14; // [esp+10h] [ebp-Ch]
    int v15; // [esp+14h] [ebp-8h]
    int sourceType; // [esp+24h] [ebp+8h]

    v14 = 0.0;
    if ( thing )
    {
        v8 = thing->thingIdx;
        sourceType = SENDERTYPE_THING;
        v15 = 1 << thing->thingType;
    }
    else
    {
        v8 = -1;
        sourceType = 0;
        v15 = 1;
    }
    
    v9 = a4;
    for (int i = 0; i < sithCog_numSurfaceLinks; i++)
    {
        sithCogSurfaceLink* surfaceLink = &sithCog_aSurfaceLinks[i];
        if ( surfaceLink->surface == sender && (surfaceLink->mask & v15) != 0 )
        {
            if ( msg == SITH_MESSAGE_DAMAGED )
            {
                v11 = sithCog_SendMessageEx(
                          surfaceLink->cog,
                          SITH_MESSAGE_DAMAGED,
                          SENDERTYPE_SURFACE,
                          sender->field_0,
                          sourceType,
                          v8,
                          surfaceLink->linkid,
                          v9,
                          a5,
                          a6,
                          a7);
                if ( v11 == -9999.9873046875 )
                {
                    v14 = a4;
                }
                else
                {
                    v14 = v11;
                    a4 = v11;
                    v9 = a4;
                }
            }
            else
            {
                v12 = sithCog_SendMessageEx(surfaceLink->cog, msg, SENDERTYPE_SURFACE, sender->field_0, sourceType, v8, surfaceLink->linkid, v9, a5, a6, a7);
                if ( v12 != -9999.9873046875 )
                    v14 = v12 + v14;
            }
        }
    }
    return v14;
}

void sithCog_SendMessageFromSector(sithSector *sector, sithThing *thing, int message)
{
    sithCog_SendMessageFromSectorEx(sector, thing, message, 0.0, 0.0, 0.0, 0.0);
}

float sithCog_SendMessageFromSectorEx(sithSector *a1, sithThing *sourceType, SITH_MESSAGE message, float param0, float param1, float param2, float param3)
{
    int v8; // ebp
    double v11; // st7
    double v12; // st7
    float v13; // [esp+10h] [ebp-Ch]
    int v14; // [esp+14h] [ebp-8h]
    int sourceTypea; // [esp+24h] [ebp+8h]

    v13 = 0.0;
    if ( sourceType )
    {
        v8 = sourceType->thingIdx;
        sourceTypea = SENDERTYPE_THING;
        v14 = 1 << sourceType->thingType;
    }
    else
    {
        v8 = -1;
        sourceTypea = 0;
        v14 = 1;
    }
    if ( &sithCog_aSectorLinks[sithCog_numSectorLinks] > sithCog_aSectorLinks )
    {
        for (int i = 0; i < sithCog_numSectorLinks; i++)
        {
            sithCogSectorLink* link = &sithCog_aSectorLinks[i];
            if ( link->sector == a1 && (link->mask & v14) != 0 )
            {
                if ( message == SITH_MESSAGE_DAMAGED )
                {
                    v11 = sithCog_SendMessageEx(
                              link->cog,
                              SITH_MESSAGE_DAMAGED,
                              SENDERTYPE_SECTOR,
                              a1->id,
                              sourceTypea,
                              v8,
                              link->linkid,
                              param0,
                              param1,
                              param2,
                              param3);
                    if ( v11 == -9999.9873046875 )
                    {
                        v13 = param0;
                    }
                    else
                    {
                        v13 = v11;
                        param0 = v11;
                    }
                }
                else
                {
                    v12 = sithCog_SendMessageEx(link->cog, message, SENDERTYPE_SECTOR, a1->id, sourceTypea, v8, link->linkid, param0, param1, param2, param3);
                    if ( v12 != -9999.9873046875 )
                        v13 = v12 + v13;
                }
            }
        }
    }
    
    return v13;
}

void sithCog_SendSimpleMessageToAll(int a1, int a2, int a3, int a4, int a5)
{
    sithCog_SendMessageToAll(a1, a2, a3, a4, a5, 0.0, 0.0, 0.0, 0.0);
}

void sithCog_SendMessageToAll(int cmdid, int senderType, int senderIdx, int sourceType, int sourceIdx, float arg0, float arg1, float arg2, float arg3)
{
    sithCog *v9; // esi
    unsigned int i; // edi
    sithCog *v11; // esi
    unsigned int j; // edi

    if ( sithWorld_pStatic )
    {
        v9 = sithWorld_pStatic->cogs;
        for ( i = 0; i < sithWorld_pStatic->numCogsLoaded; ++i )
            sithCog_SendMessageEx(v9++, cmdid, senderType, senderIdx, sourceType, sourceIdx, 0, arg0, arg1, arg2, arg3);
    }
    if ( sithWorld_pCurWorld )
    {
        v11 = sithWorld_pCurWorld->cogs;
        for ( j = 0; j < sithWorld_pCurWorld->numCogsLoaded; ++j )
            sithCog_SendMessageEx(v11++, cmdid, senderType, senderIdx, sourceType, sourceIdx, 0, arg0, arg1, arg2, arg3);
    }
}

void sithCog_SendMessage(sithCog *cog, int msgid, int senderType, int senderIndex, int sourceType, int sourceIndex, int linkId)
{
    sithCogScript *v7; // ebp
    unsigned int v10; // edi

    if (!cog)
        return;

    v7 = cog->cogscript;
    if (cog->flags & 1)
    {
        _sprintf(
            std_genBuffer,
            "Cog %s: Message %d delivered, senderType=%d, senderIndex=%d, sourceType=%d, sourceIndex=%d, linkId=%d.\n",
            cog->cogscript_fpath,
            msgid,
            senderType,
            senderIndex,
            sourceType,
            sourceIndex,
            linkId);
        DebugConsole_Print(std_genBuffer);
    }

    if ( (cog->flags & 2) != 0 )
    {
        if ( (cog->flags & 1) != 0 )
        {
            _sprintf(std_genBuffer, "Cog %s: Disabled, message ignored.\n", cog->cogscript_fpath);
            DebugConsole_Print(std_genBuffer);
        }
        return;
    }

    for (v10 = 0; v10 < v7->num_triggers; v10++)
    {
        if ( msgid == v7->triggers[v10].trigId )
            break;
    }

    if ( v10 == v7->num_triggers )
    {
        if (cog->flags & 1)
        {
            _sprintf(std_genBuffer, "--Cog %s: Message %d received but ignored.  No handler.\n", cog->cogscript_fpath, msgid);
            DebugConsole_Print(std_genBuffer);
        }
        return;
    }

    if ( (cog->flags & 0x10) != 0 )
    {
        if (cog->flags & 1)
        {
            _sprintf(std_genBuffer, "--Cog %s: Message %d received but COG is paused.\n", cog->cogscript_fpath, msgid);
            DebugConsole_Print(std_genBuffer);
        }
        return;
    }

    if ( msgid == COGMSG_SYNCSECTORALT || msgid == COGMSG_SYNCTHINGATTACHMENT || !net_isMulti || net_isServer || (cog->flags & 0x40) != 0 )
    {
        cog->params[0] = 0.0;
        cog->senderId = linkId;
        cog->senderRef = senderIndex;
        cog->senderType = senderType;
        cog->sourceRef = sourceIndex;
        cog->sourceType = sourceType;
        cog->params[1] = 0.0;
        cog->params[2] = 0.0;
        cog->params[3] = 0.0;
        if ( (cog->flags & 1) != 0 )
        {
            _sprintf(std_genBuffer, "--Cog %s: Message %d received and accepted for execution.\n", cog->cogscript_fpath, msgid);
            DebugConsole_Print(std_genBuffer);
        }
        sithCogVm_ExecCog(cog, v10);
    }
    else if ( msgid != COGMSG_SYNCCOG && msgid != COGMSG_FIREPROJECTILE )
    {
        sithThingPlayer_cogMsg_SendSendTrigger(cog, msgid, senderType, senderIndex, sourceType, sourceIndex, linkId, 0.0, 0.0, 0.0, 0.0, net_dword_8C4BA4);
    }
}

float sithCog_SendMessageEx(sithCog *cog, int message, int senderType, int senderIndex, int sourceType, int sourceIndex, int linkId, float param0, float param1, float param2, float param3)
{
    double result; // st7
    sithCogScript *v12; // ebp
    int v13; // edx
    unsigned int trigIdxMax; // ecx
    unsigned int trigIdx; // edi
    sithCogTrigger *trig; // eax

    if ( !cog )
        return -9999.9873046875;
    v12 = cog->cogscript;
    if ( (cog->flags & 1) != 0 )
    {
        _sprintf(
            std_genBuffer,
            "Cog %s: MessageEx %d delivered, senderType=%d, senderIndex=%d, sourceType=%d, sourceIndex=%d, linkId=%d, param0=%g, param1=%g, param2=%g, param3=%g.\n",
            cog->cogscript_fpath,
            message,
            senderType,
            senderIndex,
            sourceType,
            sourceIndex,
            linkId,
            param0,
            param1,
            param2,
            param3);
        DebugConsole_Print(std_genBuffer);
    }
    v13 = cog->flags;
    if ( (v13 & 2) != 0 )
    {
        if ( (v13 & 1) != 0 )
        {
            _sprintf(std_genBuffer, "Cog %s: Disabled, MessageEx ignored.\n", cog->cogscript_fpath);
LABEL_18:
            DebugConsole_Print(std_genBuffer);
            return -9999.9873046875;
        }
        return -9999.9873046875;
    }
    trigIdxMax = v12->num_triggers;
    trigIdx = 0;
    if ( trigIdxMax )
    {
        trig = v12->triggers;
        do
        {
            if ( message == trig->trigId )
                break;
            ++trigIdx;
            ++trig;
        }
        while ( trigIdx < trigIdxMax );
    }
    if ( trigIdx == trigIdxMax )
    {
        if ( (v13 & 1) != 0 )
        {
            _sprintf(std_genBuffer, "--Cog %s: MessageEx %d received but ignored.  No handler.\n", cog->cogscript_fpath, message);
            goto LABEL_18;
        }
        return -9999.9873046875;
    }
    if ( (v13 & 0x10) != 0 )
    {
        if ( (v13 & 1) != 0 )
        {
            _sprintf(std_genBuffer, "--Cog %s: MessageEx %d received but COG is paused.\n", cog->cogscript_fpath, message);
            goto LABEL_18;
        }
        return -9999.9873046875;
    }
    if ( message == SITH_MESSAGE_STARTUP || message == SITH_MESSAGE_SHUTDOWN || !net_isMulti || net_isServer || (v13 & 0x40) != 0 )
    {
        cog->senderId = linkId;
        cog->senderRef = senderIndex;
        cog->senderType = senderType;
        cog->sourceRef = sourceIndex;
        cog->sourceType = sourceType;
        cog->params[0] = param0;
        cog->params[1] = param1;
        cog->params[2] = param2;
        cog->params[3] = param3;
        cog->returnEx = -9999.9873046875;
        if ( (v13 & 1) != 0 )
        {
            _sprintf(std_genBuffer, "--Cog %s: MessageEx %d received and accepted for execution.\n", cog->cogscript_fpath, message);
            DebugConsole_Print(std_genBuffer);
        }
        sithCogVm_ExecCog(cog, trigIdx);
        result = cog->returnEx;
    }
    else if ( message == SITH_MESSAGE_PULSE || message == SITH_MESSAGE_TIMER )
    {
        result = 0.0;
    }
    else
    {
        sithThingPlayer_cogMsg_SendSendTrigger(
            cog,
            message,
            senderType,
            senderIndex,
            sourceType,
            sourceIndex,
            linkId,
            param0,
            param1,
            param2,
            param3,
            net_dword_8C4BA4);
        result = 0.0;
    }
    return result;
}

void sithCog_Free(sithWorld *world)
{
    int v2; // edi
    sithCogScript *v4; // esi
    uint32_t v5; // ebx
    unsigned int i; // ebx
    sithCog *v9; // esi

    if ( world->cogScripts )
    {
        for (int i = 0; i < world->numCogScriptsLoaded; i++)
        {
            v4 = &world->cogScripts[i];
            sithCogParse_FreeSymboltable(v4->symbolTable);
            for (v5 = 0; v5 < v4->numIdk; v5++)
            {
                if (v4->aIdk[v5].desc)
                {
                    pSithHS->free(v4->aIdk[v5].desc);
                    v4->aIdk[v5].desc = NULL;
                }
            }
            if ( v4->script_program )
            {
                pSithHS->free(v4->script_program);
                v4->script_program = 0;
            }
            stdHashTable_FreeKey(sithCog_pScriptHashtable, v4->cog_fpath);
        }
        pSithHS->free(world->cogScripts);
        world->cogScripts = 0;
        world->numCogScripts = 0;
        world->numCogScriptsLoaded = 0;
    }
    if ( world->cogs )
    {
        for (int i = 0; i < world->numCogsLoaded; i++ )
        {
            v9 = &world->cogs[i];
            sithCogParse_FreeSymboltable(v9->symbolTable);
            if ( v9->heap )
            {
                pSithHS->free(v9->heap);
                v9->numHeapVars = 0;
            }
        }
        pSithHS->free(world->cogs);
        world->cogs = 0;
        world->numCogs = 0;
        world->numCogsLoaded = 0;
    }
}

int sithCogScript_Load(sithWorld *lvl, int a2)
{
    int numCogScripts; // esi
    signed int result; // eax
    sithCogScript *cogScripts; // edi
    char *v5; // esi
    sithWorld *v6; // edi
    unsigned int v7; // eax
    sithCogScript *v8; // esi
    char cog_fpath[128]; // [esp+10h] [ebp-80h] BYREF

    if ( a2 )
        return 0;
    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_entry.args[0].value, "world") || _strcmp(stdConffile_entry.args[1].value, "scripts") )
        return 0;
    numCogScripts = _atoi(stdConffile_entry.args[2].value);
    if ( !numCogScripts )
        return 1;
    cogScripts = (sithCogScript *)pSithHS->alloc(sizeof(sithCogScript) * numCogScripts);
    lvl->cogScripts = cogScripts;
    if ( cogScripts )
    {
        _memset(cogScripts, 0, sizeof(sithCogScript) * numCogScripts);
        lvl->numCogScripts = numCogScripts;
        lvl->numCogScriptsLoaded = 0;
        while ( stdConffile_ReadArgs() )
        {
            if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
                break;
            if ( lvl->numCogScriptsLoaded < (unsigned int)lvl->numCogScripts )
            {
                if ( !stdConffile_entry.numArgs )
                    return 0;
                v5 = stdConffile_entry.args[1].value;
                v6 = sithWorld_pLoading;
                _sprintf(cog_fpath, "%s%c%s", "cog", '\\', stdConffile_entry.args[1].value);
                if ( !stdHashTable_GetKeyVal(sithCog_pScriptHashtable, v5) )
                {
                    v7 = v6->numCogScriptsLoaded;
                    if ( v7 < v6->numCogScripts )
                    {
                        v8 = &v6->cogScripts[v7];
                        if ( sithCogParse_Load(cog_fpath, v8, 0) )
                        {
                            stdHashTable_SetKeyVal(sithCog_pScriptHashtable, v8->cog_fpath, v8);
                            ++v6->numCogScriptsLoaded;
                        }
                    }
                }
            }
        }
        result = 1;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 843, "Memory alloc failure initializing COG scripts.\n", 0, 0, 0, 0);
        result = 0;
    }
    return result;
}

void sithCogScript_RegisterVerb(sithCogSymboltable *a1, intptr_t a2, char *a3)
{
    sithCogStackvar a2a;

    sithCogSymbol* symbol = sithCogParse_AddSymbol(a1, a3);
    if ( symbol )
    {
        a2a.type = COG_TYPE_VERB;
        a2a.data[0] = a2;
        sithCogParse_SetSymbolVal(symbol, &a2a);
    }
}

void sithCogScript_RegisterMessageSymbol(sithCogSymboltable *a1, int a2, const char *a3)
{
    sithCogStackvar a2a; // [esp+0h] [ebp-10h] BYREF

    sithCogSymbol* v3 = sithCogParse_AddSymbol(a1, a3);
    if ( v3 )
    {
        a2a.type = COG_TYPE_INT;
        a2a.data[0] = a2;
        sithCogParse_SetSymbolVal(v3, &a2a);
    }
}

void sithCogScript_RegisterGlobalMessage(sithCogSymboltable *a1, const char *a2, int a3)
{
    sithCogStackvar a2a; // [esp+0h] [ebp-10h] BYREF

    sithCogSymbol* v3 = sithCogParse_AddSymbol(a1, a2);
    if ( v3 )
    {
        a2a.type = COG_TYPE_FLEX;
        a2a.data[0] = a3;
        sithCogParse_SetSymbolVal(v3, &a2a);
    }
}

void sithCogScript_TickAll()
{
    if (g_sithMode == 2)
        return;

    for (uint32_t i = 0; i < sithWorld_pCurWorld->numCogsLoaded; i++)
    {
        sithCogScript_Tick(&sithWorld_pCurWorld->cogs[i]);
    }

    if ( sithWorld_pStatic )
    {
        for (uint32_t i = 0; i < sithWorld_pStatic->numCogsLoaded; i++)
        {
            sithCogScript_Tick(&sithWorld_pStatic->cogs[i]);
        }
    }
}

void sithCogScript_Tick(sithCog *cog)
{
    if (!(cog->flags & 2))
    {
        //printf("%x %x %x %s\n", cog->flags, sithTime_curMs, cog->nextPulseMs, cog->cogscript_fpath);
        if ( (cog->flags & 4) && sithTime_curMs >= cog->nextPulseMs )
        {
            cog->nextPulseMs = sithTime_curMs + cog->pulsePeriodMs;
            sithCog_SendMessage(cog, SITH_MESSAGE_PULSE, 0, 0, 0, 0, 0);
        }

        if ( (cog->flags & 8) && sithTime_curMs >= cog->field_20 )
        {
            cog->flags &= ~0x8;
            cog->field_20 = 0;
            sithCog_SendMessage(cog, SITH_MESSAGE_TIMER, 0, 0, 0, 0, 0);
        }
        if ( cog->script_running == 2 )
        {
            if ( cog->wakeTimeMs >= sithTime_curMs )
                return;
            if ((cog->flags & 1))
            {
                _sprintf(std_genBuffer, "Cog %s: Waking up due to timer elapse.\n", cog->cogscript_fpath);
                DebugConsole_Print(std_genBuffer);
            }

            sithCogVm_Exec(cog);
            return;
        }
        if ( cog->script_running == 3 && (sithWorld_pCurWorld->things[cog->wakeTimeMs].trackParams.field_C & 3) == 0 )
        {
            if ((cog->flags & 1))
            {
                _sprintf(std_genBuffer, "Cog %s: Waking up due to movement completion.\n", cog->cogscript_fpath);
                DebugConsole_Print(std_genBuffer);
            }

            sithCogVm_Exec(cog);
            return;
        }
    }
}

int sithCogScript_TimerTick(int deltaMs, sithTimerInfo *info)
{
    sithWorld *v2; // ecx
    int v3; // eax
    sithCog *v4; // eax

    v2 = sithWorld_pCurWorld;
    v3 = info->cogIdx;
    if ( (v3 & 0x8000u) != 0 )
    {
        v2 = sithWorld_pStatic;
        v3 &= ~0x8000u;
    }
    if ( v2 && v3 >= 0 && v3 < v2->numCogsLoaded )
        v4 = &v2->cogs[v3];
    else
        v4 = 0;
    if ( v4 )
        sithCog_SendMessageEx(v4, SITH_MESSAGE_TIMER, SENDERTYPE_COG, v4->selfCog, 0, 0, info->timerIdx, info->field_10, info->field_14, 0.0, 0.0);
    return 1;
}
