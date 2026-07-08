#include "sithCogExec.h"

#include "Cog/sithCog.h"
#include "Cog/sithCogParse.h"
#include "jk.h"
#include "stdPlatform.h"
#include "World/sithWorld.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "Gameplay/sithPlayer.h"
#include "World/jkPlayer.h"
#include "Devices/sithConsole.h"
#include "World/sithTemplate.h"
#include "Devices/sithSound.h"
#include "Gameplay/sithTime.h"
#include "Win95/stdComm.h"
#include "Main/jkGame.h"
#include "Dss/sithMulti.h"
#include "AI/sithAIClass.h"

#include <string.h>
#include <stdint.h>
#include <math.h>

// MOTS added
int32_t sithCogExec_009d39b0 = 0;
sithCog* sithCogExec_pIdkMotsCtx = NULL;
sithCog* sithCog_pActionCog = NULL;
int32_t sithCog_actionCogIdk = 0;

void sithCogExec_Execute(sithCog *pCog)
{
    SithCogScript *pScript;
    int32_t op;
    SithCogSymbol *v12; // eax
    cogSymbolFunc_t func; // eax
    int32_t *vec; // ecx
    int32_t v19; // eax
    SithCogSymbolValue val; // [esp+20h] [ebp-80h]
    SithCogSymbolValue var; // [esp+70h] [ebp-30h]
    SithCogSymbolValue outVar; // [esp+90h] [ebp-10h]
    int32_t iTmp;
    SithCogSymbolValue* tmpStackVar;

    // MOTS added
    /*
    if (Main_cogLogFp != 0) {
        fputs(Main_cogLogFp,"Begin: %s (msg=%s)\n",cog_ctx->aName,
              (&PTR_s_invalid_005a1f00)[cog_ctx->trigId]);
        fflush(Main_cogLogFp);
    }
    */
    
    //jk_printf("cog trace %s %x\n", cog_ctx->pScript->aName, cog_ctx->execPos);

    SITH_ASSERTREL(pCog != NULL); // Added: ported J3D assert
    SITH_ASSERTREL(pCog->execPos < pCog->pScript->codeSize); // Added: ported J3D assert
    pCog->script_running = 1;
    while ( 2 )
    {
        pScript = pCog->pScript;
        op = sithCogExec_GetOpCode(pCog);
        //jk_printf("cog trace %s %x op %u stackpos %u\n", cog_ctx->pScript->aName, cog_ctx->execPos, op, cog_ctx->stackPos);
        switch ( op )
        {
            case COG_OPCODE_NOP:
                break;

            case COG_OPCODE_PUSHINT:
                iTmp = sithCogExec_GetOpCode(pCog);
                val.type = SITHCOG_VALUE_INT;
                val.data[0] = iTmp;
                sithCogExec_PushStack(pCog, &val);
                break;

            case COG_OPCODE_PUSHFLOAT:
                iTmp = sithCogExec_GetOpCode(pCog);
                val.type = SITHCOG_VALUE_FLOAT;
                val.dataAsFloat[0] = *(cog_flex_t*)&iTmp;
                sithCogExec_PushStack(pCog, &val);
                break;

            case COG_OPCODE_PUSHSYMBOL:
                iTmp = sithCogExec_GetOpCode(pCog);
                val.type = SITHCOG_VALUE_SYMBOLID;
                val.data[0] = iTmp;
                sithCogExec_PushStack(pCog, &val);
                break;

            case COG_OPCODE_PUSHVECTOR:
#ifndef COG_COMPRESS_VAR_SIZE
                stdPlatform_Memcpy32(val.data, &pScript->pCode[pCog->execPos], sizeof(cog_flex_t) * 3); // Added: word ops (bytecode may be in extram)
                val.type = SITHCOG_VALUE_VECTOR;
                sithCogExec_PushStack(pCog, &val);
#else
                sithCogExec_Push3Floats(pCog, (cog_flex_t*)&pScript->pCode[pCog->execPos]);
#endif
                pCog->execPos += 3;
                break;

            case COG_OPCODE_ARRAYINDEX:
                iTmp = sithCogExec_PopInt(pCog);
                v19 = sithCogExec_PopStack(pCog, &var);

                if ( v19 ) {
                    v19 = var.type == SITHCOG_VALUE_SYMBOLID ? var.data[0] : 0;
#ifdef COG_COMPRESS_VAR_SIZE
                    if (var.type == SITHCOG_VALUE_VECTOR) {
                        if (var.dataAsPtrs[0]){
                            SITH_FREE((void*)var.dataAsPtrs[0]);
                        }
                    }
#endif
                }
                val.type = SITHCOG_VALUE_SYMBOLID;
                val.data[0] = iTmp + v19;
                sithCogExec_PushStack(pCog, &val);
                break;

            case COG_OPCODE_CALLFUNC:
                if (!sithCogExec_PopStack(pCog, &var))
                    break;
                tmpStackVar = &var;

#ifdef COG_COMPRESS_VAR_SIZE
                if (var.type == SITHCOG_VALUE_VECTOR) {
                    if (var.dataAsPtrs[0]){
                        SITH_FREE((void*)var.dataAsPtrs[0]);
                        var.dataAsPtrs[0] = 0;
                    }
                }
#endif

                if ( tmpStackVar->type != SITHCOG_VALUE_SYMBOLID ) {
                    break;
                }

                v12 = sithCogParse_GetSymbolByID(pCog->pSymbolTable, tmpStackVar->data[0]);

                if (!v12 ) {
                    break;
                }
                if (v12->val.type != SITHCOG_VALUE_POINTER) {
#if defined(SITH_DEBUG_STRUCT_NAMES) && !defined(COG_CRC32_SYMBOL_NAMES)
                    stdPlatform_Printf("OpenJKDF2: Script `%s` attempted to call `%s`, which doesn't exist...\n", pCog->pScript->aName, v12->pName);
#endif
                    break;
                }
                if (v12->val.dataAsFunc) {
                    //printf("OpenJKDF2: Script `%s` call `%s`\n", cog_ctx->pScript->aName, v12->pName);
                    v12->val.dataAsFunc(pCog); 
                }
                else {
#if defined(SITH_DEBUG_STRUCT_NAMES) && !defined(COG_CRC32_SYMBOL_NAMES)
                    stdPlatform_Printf("OpenJKDF2: Script `%s` attempted to call `%s`, which doesn't exist...\n", pCog->pScript->aName, v12->pName);
#endif
                }
                //func = sithCogExec_PopSymbolFunc(cog_ctx); // this function is slightly different?
                break;

            case COG_OPCODE_ASSIGN:
                if (!sithCogExec_PopStack(pCog, &val) )
                    break;

                tmpStackVar = sithCogExec_GetSymbolValue(&outVar, pCog, &val);
                val.type = tmpStackVar->type;
                val.dataAsPtrs[0] = tmpStackVar->dataAsPtrs[0];
#ifndef COG_COMPRESS_VAR_SIZE
                val.dataAsPtrs[1] = tmpStackVar->dataAsPtrs[1];
                val.dataAsPtrs[2] = tmpStackVar->dataAsPtrs[2];
#endif

                if (!sithCogExec_PopStack(pCog, &var)) {
#ifdef COG_COMPRESS_VAR_SIZE
                    // Prevent leaks
                    if (val.type == SITHCOG_VALUE_VECTOR) {
                        if (val.dataAsPtrs[0]) {
                            SITH_FREE((void*)val.dataAsPtrs[0]);
                            val.dataAsPtrs[0] = 0;
                        }
                    }
#endif
                    break;
                }

                if (var.type != SITHCOG_VALUE_SYMBOLID) {
#ifdef COG_COMPRESS_VAR_SIZE
                    if (var.type == SITHCOG_VALUE_VECTOR) {
                        if (var.dataAsPtrs[0]){
                            SITH_FREE((void*)var.dataAsPtrs[0]);
                            var.dataAsPtrs[0] = 0;
                        }
                    }

                    // Prevent leaks
                    if (val.type == SITHCOG_VALUE_VECTOR) {
                        if (val.dataAsPtrs[0]){
                            SITH_FREE((void*)val.dataAsPtrs[0]);
                            val.dataAsPtrs[0] = 0;
                        }
                    }
#endif
                    break;
                }
                
                tmpStackVar = &sithCogParse_GetSymbolByID(pCog->pSymbolTable, var.data[0])->val;
                *tmpStackVar = val;
                break;
            case COG_OPCODE_CMPFALSE:
                sithCogExec_PushInt(pCog, sithCogExec_PopInt(pCog) == 0);
                break;
            case COG_OPCODE_NEG:
                sithCogExec_PushFlex(pCog, -sithCogExec_PopFlex(pCog));
                break;
            case COG_OPCODE_CMPAND:
            case COG_OPCODE_CMPOR:
            case COG_OPCODE_CMPNE:
            case COG_OPCODE_ANDI:
            case COG_OPCODE_ORI:
            case COG_OPCODE_XORI:
                sithCogExec_IntererOps(pCog, op);
                break;
            case COG_OPCODE_GOFALSE:
                iTmp = sithCogExec_GetOpCode(pCog);
                if ( !sithCogExec_PopInt(pCog) )
                    pCog->execPos = iTmp;
                break;
            case COG_OPCODE_GOTRUE:
                iTmp = sithCogExec_GetOpCode(pCog);
                if ( sithCogExec_PopInt(pCog) )
                    pCog->execPos = iTmp;
                break;
            case COG_OPCODE_GO:
                pCog->execPos = sithCogExec_GetOpCode(pCog);
                break;
            case COG_OPCODE_RET:
                if ( pCog->flags & SITH_COG_DEBUG )
                {
#ifdef SITH_DEBUG_STRUCT_NAMES
                    _sprintf(std_g_genBuffer, "Cog %s: Returned from depth %d.\n", pCog->aName, pCog->callDepth);
                    sithConsole_PrintString(std_g_genBuffer);
#endif
                }
                sithCogExec_PopCallstack(pCog);
                break;
            case COG_OPCODE_CALL:
                if (pCog->callDepth >= 4)
                    break;
                iTmp = sithCogExec_GetOpCode(pCog);
                if (iTmp < pCog->pScript->codeSize)
                {
                    sithCogExec_PushCallstack(pCog);
                    pCog->execPos = iTmp;
                }
                break;
            case COG_OPCODE_ADD:
            case COG_OPCODE_SUB:
            case COG_OPCODE_MUL:
            case COG_OPCODE_DIV:
            case COG_OPCODE_MOD:
            case COG_OPCODE_CMPGT:
            case COG_OPCODE_CMPLS:
            case COG_OPCODE_CMPEQ:
            case COG_OPCODE_CMPLE:
            case COG_OPCODE_CMPGE:
                sithCogExec_FloatOps(pCog, op);
                break;

            default:
                jk_printf("OpenJKDF2: unk op %u\n", op); // added
                break;
        }
        if ( pCog->script_running == 1 ) {
            continue;
        }
        else {
            // MOTS added
            /*
            if (Main_cogLogFp != 0) {
                fputs(Main_cogLogFp,"  End: %s\n",cog_ctx->aName);
                fflush(Main_cogLogFp);
            }
            */
        }
        return;
    }
}

void sithCogExec_ExecuteMessage(sithCog *pCog, int32_t handlerNum)
{
    int32_t trigPc;

    SITH_ASSERTREL(pCog != NULL); // Added: ported J3D assert
    trigPc = pCog->pScript->aHandlers[handlerNum].trigPc;
    if ( trigPc >= 0 )
    {
        if ( pCog->script_running )
        {
            if ( pCog->script_running == 1 )
                pCog->script_running = 4;
            sithCogExec_PushCallstack(pCog);
        }
        else if ( pCog->stackPos )
        {
            pCog->stackPos = 0;
        }
        pCog->execPos = pCog->pScript->aHandlers[handlerNum].trigPc;
        pCog->trigId = pCog->pScript->aHandlers[handlerNum].trigId;
        if ( pCog->flags & SITH_COG_DEBUG )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: execution started.\n", pCog->aName);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        sithCogExec_Execute(pCog);
        if ( pCog->script_running == 4 )
            pCog->script_running = 1;
    }
}

int32_t sithCogExec_PopSymbol(sithCog *pCog, SithCogSymbolValue *pVal)
{

    SithCogSymbolValue *tmp; // eax
    int32_t *v5; // edx
    int32_t type; // ecx
    intptr_t d0; // edx
#ifndef COG_COMPRESS_VAR_SIZE
    intptr_t d1;
    intptr_t d2;
#endif


    SITH_ASSERTREL(pCog != NULL); // Added: ported J3D assert
    SITH_ASSERTREL(pVal != NULL); // Added: ported J3D assert
    if ( pCog->stackPos < 1 )
        return 0;

    *pVal = pCog->stack[--pCog->stackPos];
    tmp = pVal;

    if ( pVal->type == SITHCOG_VALUE_SYMBOLID ) {
        // Added: nullptr check here
        SithCogSymbol* sym = sithCogParse_GetSymbolByID(pCog->pSymbolTable, pVal->data[0]);
        if (sym) {
            tmp = &sym->val;
        }
        else {
            tmp = NULL;
        }
    }

    // Added
    if (!tmp)
    {
        type = SITHCOG_VALUE_INT;
        d0 = 0;
#ifndef COG_COMPRESS_VAR_SIZE
        d1 = 0;
        d2 = 0;
#endif
    }
    else if ( tmp->type )
    {
        type = tmp->type;
        d0 = tmp->dataAsPtrs[0];
#ifndef COG_COMPRESS_VAR_SIZE
        d1 = tmp->dataAsPtrs[1];
        d2 = tmp->dataAsPtrs[2];
#endif

        // Make a copy of the Vec3 so that it can be freed
#ifdef COG_COMPRESS_VAR_SIZE
        if (pVal->type == SITHCOG_VALUE_SYMBOLID && tmp->type == SITHCOG_VALUE_VECTOR)
        {
            if (d0) {
                cog_flex_t* ptr = (cog_flex_t*)SITH_ALLOC(sizeof(cog_flex_t)*3);
                if (ptr) {
                    stdPlatform_Memcpy32(ptr, (void*)d0, sizeof(cog_flex_t)*3); // Added: word ops (symbol data may be in extram)
                }
                d0 = (intptr_t)ptr;
            }
        }
#endif
    }
    else
    {
        type = SITHCOG_VALUE_INT;
        d0 = tmp->dataAsPtrs[0];
#ifndef COG_COMPRESS_VAR_SIZE
        d1 = tmp->dataAsPtrs[1]; // the original game sets these two to undefined values? Weird compiler optimization fail?
        d2 = tmp->dataAsPtrs[2];
#endif
    }

    pVal->type = type;
    pVal->dataAsPtrs[0] = d0;
#ifndef COG_COMPRESS_VAR_SIZE
    pVal->dataAsPtrs[1] = d1;
    pVal->dataAsPtrs[2] = d2;
#endif
    return 1;
}

cog_flex_t sithCogExec_PopFlex(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    SITH_ASSERTREL(pCog != NULL); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
        return 0.0;
        
    if ( tmp.type == SITHCOG_VALUE_INT )
        return (cog_flex_t)tmp.data[0]; // FLEXTODO
    if ( tmp.type == SITHCOG_VALUE_FLOAT )
        return tmp.dataAsFloat[0]; // FLEXTODO
#ifdef COG_COMPRESS_VAR_SIZE
    if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            cog_flex_t* tmpvec = (cog_flex_t*)tmp.dataAsPtrs[0];
            cog_flex_t tmpf = (cog_flex_t) (*tmpvec);
            SITH_FREE((void*)tmpvec);
            return tmpf;
        }
    }
#endif
    return 0.0;
}

int32_t sithCogExec_PopInt(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    SITH_ASSERTREL(pCog != NULL); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
        return -1;
    
    if ( tmp.type == SITHCOG_VALUE_INT )
        return tmp.data[0];
    if ( tmp.type == SITHCOG_VALUE_FLOAT )
        return (int)tmp.dataAsFloat[0]; // FLEXTODO
#ifdef COG_COMPRESS_VAR_SIZE
    if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            cog_flex_t* tmpvec = (cog_flex_t*)tmp.dataAsPtrs[0];
            int tmpi = (int)(*tmpvec);
            SITH_FREE((void*)tmpvec);
            return tmpi;
        }
    }
#endif

    return -1;
}

int32_t sithCogExec_PopArray(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
        return 0;
    
    if ( tmp.type == SITHCOG_VALUE_SYMBOLID )
        return tmp.data[0];
#ifdef COG_COMPRESS_VAR_SIZE
    if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
    }
#endif

    return 0;
}

int32_t sithCogExec_PopVector(sithCog *pCog, rdVector3* vec)
{
    SithCogSymbolValue tmp;

    SITH_ASSERTREL(pCog != NULL); // Added: ported J3D assert
    SITH_ASSERTREL(vec != NULL); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
    {
        _memset(vec, 0, sizeof(*vec));
        return 0;
    }
    
    if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
#ifndef COG_COMPRESS_VAR_SIZE
        vec->x = (flex_t)tmp.dataAsFloat[0]; // FLEXTODO
        vec->y = (flex_t)tmp.dataAsFloat[1]; // FLEXTODO
        vec->z = (flex_t)tmp.dataAsFloat[2]; // FLEXTODO
#else
        if (tmp.dataAsPtrs[0]) {
            cog_flex_t* tmpvec = (cog_flex_t*)tmp.dataAsPtrs[0];
            vec->x = tmpvec[0];
            vec->y = tmpvec[1];
            vec->z = tmpvec[2];
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
#endif
        return 1;
    }

    _memset(vec, 0, sizeof(*vec));
    return 0;
}

sithCog* sithCogExec_PopCog(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    int32_t idx;
    SithWorld* world = sithWorld_g_pCurrentWorld;

    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
    {
        return NULL;
    }
    
    if ( tmp.type == SITHCOG_VALUE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == SITHCOG_VALUE_FLOAT )
    {
        idx = (int)tmp.dataAsFloat[0]; // FLEXTODO
    }
#ifdef COG_COMPRESS_VAR_SIZE
    else if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            idx = (int)(((cog_flex_t*)tmp.dataAsPtrs[0])[0]);
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
        else {
            idx = -1;
        }
    }
#endif
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( (uint16_t)idx & 0x8000 )
    {
        world = sithWorld_g_pStaticWorld;
        idx &= ~0x8000;
    }
    if ( world && idx >= 0 && (uint32_t )idx < world->numCogs )
        return &world->aCogs[idx];

    return NULL;
} 

SithThing* sithCogExec_PopThing(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    int32_t idx;
    SithWorld* world = sithWorld_g_pCurrentWorld;

    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
    {
        tmp.type = SITHCOG_VALUE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == SITHCOG_VALUE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == SITHCOG_VALUE_FLOAT )
    {
        idx = (int)(flex64_t)tmp.dataAsFloat[0]; // FLEXTODO
    }
#ifdef COG_COMPRESS_VAR_SIZE
    else if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            idx = (int)(((cog_flex_t*)tmp.dataAsPtrs[0])[0]);
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
        else {
            idx = -1;
        }
    }
#endif
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( world && idx >= 0 && idx <= world->numThings ) // TODO is this correct...? vs world->numThingsLoaded
    {
        if (world->aThings[idx].type == SITH_THING_FREE)
            return NULL;

        return &world->aThings[idx];
    }

    return NULL;
}

SithThing* sithCogExec_PopTemplate(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    int32_t idx;

    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
    {
        tmp.type = SITHCOG_VALUE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == SITHCOG_VALUE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == SITHCOG_VALUE_FLOAT )
    {
        idx = (int)(flex64_t)tmp.dataAsFloat[0]; // FLEXTODO
    }
#ifdef COG_COMPRESS_VAR_SIZE
    else if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            idx = (int)(((cog_flex_t*)tmp.dataAsPtrs[0])[0]);
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
        else {
            idx = -1;
        }
    }
#endif
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;

    return sithTemplate_GetTemplateByIndex(idx);
}

sithSound* sithCogExec_PopSound(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    int32_t idx;
    SithWorld* world = sithWorld_g_pCurrentWorld;

    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
    {
        tmp.type = SITHCOG_VALUE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == SITHCOG_VALUE_INT )
    {
        idx = tmp.data[0];

        // Added: wat
        if (Main_bMotsCompat && idx == 0) {
            idx = -1;
        }
    }
    else if ( tmp.type == SITHCOG_VALUE_FLOAT )
    {
        idx = (int)(flex64_t)tmp.dataAsFloat[0]; // FLEXTODO
    }
#ifdef COG_COMPRESS_VAR_SIZE
    else if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            idx = (int)(((cog_flex_t*)tmp.dataAsPtrs[0])[0]);
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
        else {
            idx = -1;
        }
    }
#endif
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_g_pStaticWorld;
        idx &= ~0x8000; // ?
    }
    
    if ( world && idx >= 0 && idx < world->numSoundsLoaded )
    {
        return &world->sounds[idx];
    }

    return NULL;
}

SithSector* sithCogExec_PopSector(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    int32_t idx;
    SithWorld* world = sithWorld_g_pCurrentWorld;

    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
    {
        tmp.type = SITHCOG_VALUE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == SITHCOG_VALUE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == SITHCOG_VALUE_FLOAT )
    {
        idx = (int)(flex64_t)tmp.dataAsFloat[0]; // FLEXTODO
    }
#ifdef COG_COMPRESS_VAR_SIZE
    else if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            idx = (int)(((cog_flex_t*)tmp.dataAsPtrs[0])[0]);
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
        else {
            idx = -1;
        }
    }
#endif
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( world && idx >= 0 && idx < world->numSectors )
    {
        return &world->aSectors[idx];
    }

    return NULL;
}

SithSurface* sithCogExec_PopSurface(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    int32_t idx;
    SithWorld* world = sithWorld_g_pCurrentWorld;

    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
    {
        tmp.type = SITHCOG_VALUE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == SITHCOG_VALUE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == SITHCOG_VALUE_FLOAT )
    {
        idx = (int)(flex64_t)tmp.dataAsFloat[0]; // FLEXTODO
    }
#ifdef COG_COMPRESS_VAR_SIZE
    else if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            idx = (int)(((cog_flex_t*)tmp.dataAsPtrs[0])[0]);
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
        else {
            idx = -1;
        }
    }
#endif
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( world && idx >= 0 && idx < world->numSurfaces )
    {
        return &world->surfaces[idx];
    }

    return NULL;
}


rdMaterial* sithCogExec_PopMaterial(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    int32_t idx;
    SithWorld* world = sithWorld_g_pCurrentWorld;

    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
    {
        tmp.type = SITHCOG_VALUE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == SITHCOG_VALUE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == SITHCOG_VALUE_FLOAT )
    {
        idx = (int)(flex64_t)tmp.dataAsFloat[0]; // FLEXTODO
    }
#ifdef COG_COMPRESS_VAR_SIZE
    else if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            idx = (int)(((cog_flex_t*)tmp.dataAsPtrs[0])[0]);
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
        else {
            idx = -1;
        }
    }
#endif
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_g_pStaticWorld;
        idx &= ~0x8000; // ?
    }
    
    if ( world && idx >= 0 && idx < world->numMaterials )
    {
        return &world->aMaterials[idx];
    }

    return NULL;
}

rdModel3* sithCogExec_PopModel3(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    int32_t idx;
    SithWorld* world = sithWorld_g_pCurrentWorld;

    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
    {
        tmp.type = SITHCOG_VALUE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == SITHCOG_VALUE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == SITHCOG_VALUE_FLOAT )
    {
        idx = (int)(flex64_t)tmp.dataAsFloat[0]; // FLEXTODO
    }
#ifdef COG_COMPRESS_VAR_SIZE
    else if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            idx = (int)(((cog_flex_t*)tmp.dataAsPtrs[0])[0]);
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
        else {
            idx = -1;
        }
    }
#endif
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_g_pStaticWorld;
        idx &= ~0x8000; // ?
    }
    
    if ( world && idx >= 0 && idx < world->numModels )
    {
        return &world->aModels[idx];
    }

    return NULL;
}

rdKeyframe* sithCogExec_PopKeyframe(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    int32_t idx;
    SithWorld* world = sithWorld_g_pCurrentWorld;

    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
    {
        tmp.type = SITHCOG_VALUE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == SITHCOG_VALUE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == SITHCOG_VALUE_FLOAT )
    {
        idx = (int)(flex64_t)tmp.dataAsFloat[0]; // FLEXTODO
    }
#ifdef COG_COMPRESS_VAR_SIZE
    else if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            idx = (int)(((cog_flex_t*)tmp.dataAsPtrs[0])[0]);
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
        else {
            idx = -1;
        }
    }
#endif
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_g_pStaticWorld;
        idx &= ~0x8000; // ?
    }

    if ( world && idx >= 0 && idx < world->numKeyframes )
        return &world->aKeyframes[idx];

    return NULL;
}

SithAIClass* sithCogExec_PopAIClass(sithCog *pCog)
{
    SithCogSymbolValue tmp;
    int32_t idx;
    SithWorld* world = sithWorld_g_pCurrentWorld;

    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if (!sithCogExec_PopSymbol(pCog, &tmp))
    {
        tmp.type = SITHCOG_VALUE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == SITHCOG_VALUE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == SITHCOG_VALUE_FLOAT )
    {
        idx = (int)(flex64_t)tmp.dataAsFloat[0]; // FLEXTODO
    }
#ifdef COG_COMPRESS_VAR_SIZE
    else if ( tmp.type == SITHCOG_VALUE_VECTOR )
    {
        if (tmp.dataAsPtrs[0]) {
            idx = (int)(((cog_flex_t*)tmp.dataAsPtrs[0])[0]);
            SITH_FREE((void*)tmp.dataAsPtrs[0]);
        }
        else {
            idx = -1;
        }
    }
#endif
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( world && idx >= 0 && idx < world->numAIClasses )
        return &world->aAIClasses[idx];

    return NULL;
}

// popsymbolfunc is unused
cogSymbolFunc_t sithCogExec_PopSymbolFunc(sithCog *cog_ctx)
{
    SithCogSymbolValue *v3; // ecx
    SithCogSymbol *sym; // eax
    intptr_t v12; // [esp+10h] [ebp-Ch]

    if ( cog_ctx->stackPos < 1 )
        return 0;
    cog_ctx->stackPos--;
    v3 = &cog_ctx->stack[cog_ctx->stackPos];

    if ( v3->type == SITHCOG_VALUE_SYMBOLID )
    {
        sym = sithCogParse_GetSymbolByID(cog_ctx->pSymbolTable, cog_ctx->stack[cog_ctx->stackPos].data[0]);
        if ( sym->val.type )
            return (cogSymbolFunc_t)sym->val.dataAsFunc; // Added: changed from & to not &?
        else
            return sym->val.dataAsFunc;
    }
    else if ( v3->type )
    {
        v12 = 0;
        return (cogSymbolFunc_t)v12; // aaaaa undefined in original
    }
    else
    {
        return cog_ctx->stack[cog_ctx->stackPos].dataAsFunc;
    }
}

char* sithCogExec_PopString(sithCog *pCog)
{
    uint32_t v1; // eax
    int32_t v2; // eax
    SithCogSymbol *v5; // eax
    char *result; // eax

    SITH_ASSERTREL(pCog != NULL); // Added: ported J3D assert
    v1 = pCog->stackPos;
    if ( v1 < 1
      || (v2 = v1 - 1, pCog->stackPos = v2, pCog->stack[v2].type != SITHCOG_VALUE_SYMBOLID)
      || (v5 = sithCogParse_GetSymbolByID(pCog->pSymbolTable, pCog->stack[v2].data[0]), !v5 || v5->val.type != SITHCOG_VALUE_STRING) ) // Added: v5 nullptr check
    {
        result = 0;
    }
    else
    {
        result = v5->val.dataAsName;
    }
    return result;
}

void sithCogExec_PushStack(sithCog *pCog, SithCogSymbolValue *pValue)
{
    SithCogSymbolValue *pushVar;

    SITH_ASSERTREL(pCog != NULL); // Added: ported J3D assert
    SITH_ASSERTREL(pValue != NULL); // Added: ported J3D assert
#ifdef COG_DYNAMIC_STACKS
    if (pCog->stackPos >= pCog->stackSize) {
        sithCogExec_GrowStack(pCog, pCog->stackSize+COG_DYNAMIC_STACKS_INCREMENT);
        if (pCog->stackPos >= pCog->stackSize)
            return; // Added: grow failed -- drop the push rather than overflow
    }
#endif

    if ( pCog->stackPos == SITHCOGVM_MAX_STACKSIZE )
    {
        // Added: word-safe shift (stack may be word-addressable-only); dst < src,
        // so a forward copy preserves the memmove semantics.
        stdPlatform_Memcpy32(pCog->stack, &pCog->stack[1], sizeof(pCog->stack) * (SITHCOGVM_MAX_STACKSIZE-1));
        --pCog->stackPos;
    }
    
    pushVar = &pCog->stack[pCog->stackPos];
    pushVar->type = pValue->type;
    pushVar->dataAsPtrs[0] = pValue->dataAsPtrs[0];
#ifndef COG_COMPRESS_VAR_SIZE
    pushVar->dataAsPtrs[1] = pValue->dataAsPtrs[1];
    pushVar->dataAsPtrs[2] = pValue->dataAsPtrs[2];
#endif
    ++pCog->stackPos;
}

void sithCogExec_PushInt(sithCog *pCog, int32_t val)
{
    SithCogSymbolValue v;
    v.type = SITHCOG_VALUE_INT;
    v.data[0] = val;
    sithCogExec_PushStack(pCog, &v);
}

void sithCogExec_PushFlex(sithCog *pCog, cog_flex_t value)
{
    SithCogSymbolValue v;
    v.type = SITHCOG_VALUE_FLOAT;
    v.dataAsFloat[0] = value; // FLEXTODO
    sithCogExec_PushStack(pCog, &v);
}

void sithCogExec_PushVector(sithCog *pCog, const rdVector3* vec)
{
    SithCogSymbolValue v;
    v.type = SITHCOG_VALUE_VECTOR;
#ifndef COG_COMPRESS_VAR_SIZE
    v.dataAsFloat[0] = vec->x;
    v.dataAsFloat[1] = vec->y;
    v.dataAsFloat[2] = vec->z;
#else
    cog_flex_t* ptr = (cog_flex_t*)SITH_ALLOC(sizeof(cog_flex_t)*3);
    if (ptr) {
        v.dataAsPtrs[0] = (intptr_t)ptr;
        ptr[0] = (cog_flex_t)vec->x;
        ptr[1] = (cog_flex_t)vec->y;
        ptr[2] = (cog_flex_t)vec->z;
    }
    else {
        v.dataAsPtrs[0] = 0;
    }
#endif
    sithCogExec_PushStack(pCog, &v);
}

// Added
void sithCogExec_Push3Floats(sithCog *ctx, const cog_flex_t* val)
{
    SithCogSymbolValue v;
    v.type = SITHCOG_VALUE_VECTOR;
#ifndef COG_COMPRESS_VAR_SIZE
    v.dataAsFloat[0] = (cog_flex_t)val[0];
    v.dataAsFloat[1] = (cog_flex_t)val[1];
    v.dataAsFloat[2] = (cog_flex_t)val[2];
#else
    cog_flex_t* ptr = (cog_flex_t*)SITH_ALLOC(sizeof(cog_flex_t)*3);
    if (ptr) {
        v.dataAsPtrs[0] = (intptr_t)ptr;
        ptr[0] = (cog_flex_t)val[0];
        ptr[1] = (cog_flex_t)val[1];
        ptr[2] = (cog_flex_t)val[2];
    }
    else {
        v.dataAsPtrs[0] = 0;
    }
#endif
    sithCogExec_PushStack(ctx, &v);
}

int32_t sithCogExec_GetOpCode(sithCog *pCog)
{
    SITH_ASSERTREL(pCog != NULL); // Added: ported J3D assert
    SITH_ASSERTREL(pCog->pScript != NULL); // Added: ported J3D assert
    if ( pCog->execPos >= pCog->pScript->codeSize - 1 )
        return COG_OPCODE_RET;

    return pCog->pScript->pCode[pCog->execPos++];
}

void sithCogExec_ResetStack(sithCog *pCog)
{
    SITH_ASSERTREL(pCog != NULL); // Added: ported J3D assert
    if (pCog->stackPos) {
        pCog->stackPos = 0;
    }
#ifdef COG_DYNAMIC_STACKS
    SITH_FREE(pCog->stack);
    pCog->stack = NULL;
    pCog->stackSize = 0;
#endif
}

void sithCogExec_PushCallstack(sithCog *pCog)
{
    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if ( pCog->callDepth != 4 )
    {
        sithCogExec_009d39b0 = 0;
        pCog->callstack[pCog->callDepth].pc = pCog->execPos;
        pCog->callstack[pCog->callDepth].script_running = pCog->script_running;
        pCog->callstack[pCog->callDepth].waketimeMs = pCog->msecTimerTimeout;
        pCog->callstack[pCog->callDepth++].trigId = pCog->trigId;

        // MOTS added: wakeup
        if (((sithCogExec_009d39b0 != 0) && (pCog->script_running == 2)) && (pCog == sithCogExec_pIdkMotsCtx)) {
            pCog->script_running = 1;
            sithCogExec_009d39b0 = 0;
            sithCogExec_pIdkMotsCtx = NULL;
        }
    }
}

void sithCogExec_PopCallstack(sithCog *pCog)
{
    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    if ( pCog->callDepth )
    {
        pCog->script_running = pCog->callstack[--pCog->callDepth].script_running;
        pCog->execPos = pCog->callstack[pCog->callDepth].pc;
        pCog->msecTimerTimeout = pCog->callstack[pCog->callDepth].waketimeMs;
        pCog->trigId = pCog->callstack[pCog->callDepth].trigId;
    }
    else
    {
        pCog->script_running = 0;
    }
}

int32_t sithCogExec_PopStack(sithCog *pCog, SithCogSymbolValue *pValue)
{
    SithCogSymbolValue *pop; // eax

    SITH_ASSERTREL(pCog != NULL); // Added: ported J3D assert
    SITH_ASSERTREL(pValue != NULL); // Added: ported J3D assert
    if ( pCog->stackPos < 1 )
        return 0;

    pop = &pCog->stack[--pCog->stackPos];
    pValue->type = pop->type;
    pValue->dataAsPtrs[0] = pop->dataAsPtrs[0];
#ifndef COG_COMPRESS_VAR_SIZE
    pValue->dataAsPtrs[1] = pop->dataAsPtrs[1];
    pValue->dataAsPtrs[2] = pop->dataAsPtrs[2];
#endif

    return 1;
}

// MOTS altered?
void sithCogExec_IntererOps(sithCog *pCog, int32_t opcode)
{
    int32_t operand_a = sithCogExec_PopInt(pCog);
    int32_t operand_b = sithCogExec_PopInt(pCog);
    switch ( opcode )
    {
        case COG_OPCODE_CMPAND:
            sithCogExec_PushInt(pCog, (operand_a && operand_b) ? 1 : 0);
            break;
            
        case COG_OPCODE_CMPOR:
            sithCogExec_PushInt(pCog, (operand_a || operand_b) ? 1 : 0);
            break;
        case COG_OPCODE_CMPNE:
            sithCogExec_PushInt(pCog, (operand_a != operand_b) ? 1 : 0);
            break;
        case COG_OPCODE_ANDI:
            sithCogExec_PushInt(pCog, operand_a & operand_b);
            break;
        case COG_OPCODE_ORI:
            sithCogExec_PushInt(pCog, operand_a | operand_b);
            break;
        case COG_OPCODE_XORI:
            sithCogExec_PushInt(pCog, operand_a ^ operand_b);
            break;
        default:
            return;
    }
}

// MOTS altered?
void sithCogExec_FloatOps(sithCog *pCog, int32_t opcode)
{
    cog_flex_t operand_a = sithCogExec_PopFlex(pCog);
    cog_flex_t operand_b = sithCogExec_PopFlex(pCog);
    switch ( opcode )
    {
        case COG_OPCODE_ADD:
            sithCogExec_PushFlex(pCog, operand_a + operand_b);
            break;
        case COG_OPCODE_SUB:
            sithCogExec_PushFlex(pCog, operand_b - operand_a);
            break;
        case COG_OPCODE_MUL:
            sithCogExec_PushFlex(pCog, operand_a * operand_b);
            break;
        case COG_OPCODE_DIV:
            sithCogExec_PushFlex(pCog, (operand_a == 0.0) ? (cog_flex_t)0.0 : operand_b / operand_a);
            break;
        case COG_OPCODE_MOD:
            sithCogExec_PushFlex(pCog, fmod((float)operand_b, (float)operand_a));
            break;
        case COG_OPCODE_CMPGT:
            sithCogExec_PushInt(pCog, (operand_b > operand_a) ? 1 : 0);
            break;
        case COG_OPCODE_CMPLS:
            sithCogExec_PushInt(pCog, (operand_b < operand_a) ? 1 : 0);
            break;
        case COG_OPCODE_CMPEQ:
            sithCogExec_PushInt(pCog, (operand_b == operand_a) ? 1 : 0);
            break;
        case COG_OPCODE_CMPLE:
            sithCogExec_PushInt(pCog, (operand_b <= operand_a) ? 1 : 0);
            break;
        case COG_OPCODE_CMPGE:
            sithCogExec_PushInt(pCog, (operand_b >= operand_a) ? 1 : 0);
            break;
        default:
            return;
    }
}

SithCogSymbolValue* sithCogExec_GetSymbolValue(SithCogSymbolValue *pDest, sithCog *pCog, SithCogSymbolValue *pValue)
{
    SITH_ASSERTREL(pCog && pValue); // Added: ported J3D assert
    if ( pValue->type == SITHCOG_VALUE_SYMBOLID )
        pValue = &sithCogParse_GetSymbolByID(pCog->pSymbolTable, pValue->dataAsPtrs[0])->val;
    if ( pValue->type != SITHCOG_VALUE_POINTER)
    {
        pDest->type = pValue->type;
        pDest->dataAsPtrs[0] = pValue->dataAsPtrs[0];
#ifndef COG_COMPRESS_VAR_SIZE
        pDest->dataAsPtrs[1] = pValue->dataAsPtrs[1];
        pDest->dataAsPtrs[2] = pValue->dataAsPtrs[2];
#endif
        return pDest;
    }
    else
    {
        SITH_ASSERTREL(pValue->dataAsPtrs[0] != 0); // Added: ported J3D assert (non-null before deref)
        pDest->type = SITHCOG_VALUE_INT;
        pDest->dataAsPtrs[0] = *(int32_t*)pValue->dataAsPtrs[0]; // Why is this dereferenced...?
#ifndef COG_COMPRESS_VAR_SIZE
        pDest->dataAsPtrs[1] = pValue->dataAsPtrs[1]; // these are undefined in the original
        pDest->dataAsPtrs[2] = pValue->dataAsPtrs[2];
#endif
        return pDest;
    }    
}

#ifdef COG_DYNAMIC_STACKS
void sithCogExec_GrowStack(sithCog* pCtx, uint32_t sz) {
    if (!pCtx) return;
    if (pCtx->stackSize >= sz) return;

#ifdef TARGET_TWL
    // Added: stacks live in extram on TWL. TWL realloc can't migrate heaps (and
    // dlmalloc's in-mspace move is a byte copy), so grow by alloc+wordcopy+free.
    SithCogSymbolValue* pNew;
    { TWL_EXTRAM_SUGGEST(pSithHS);
    pNew = (SithCogSymbolValue*)SITH_ALLOC(sz * sizeof(*pCtx->stack));
    TWL_EXTRAM_RESTORE(pSithHS); }
    if (!pNew)
        return; // Added: keep the old stack; the push site drops the value instead
    if (pCtx->stack) {
        stdPlatform_Memcpy32(pNew, pCtx->stack, pCtx->stackSize * sizeof(*pCtx->stack));
        SITH_FREE(pCtx->stack);
    }
    pCtx->stack = pNew;
#else
    // Added: a failed grow used to overwrite the stack pointer with NULL,
    // leaking the stack and silently killing the cog. Keep the old stack.
    SithCogSymbolValue* pNew = (SithCogSymbolValue*)SITH_REALLOC(pCtx->stack, sz*sizeof(*pCtx->stack));
    if (!pNew)
        return;
    pCtx->stack = pNew;
#endif
    pCtx->stackSize = sz;
}
#endif