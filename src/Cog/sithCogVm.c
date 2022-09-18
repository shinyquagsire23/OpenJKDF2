#include "sithCogVm.h"

#include "sithCog.h"
#include "jk.h"
#include "stdPlatform.h"
#include "Cog/sithCogScript.h"
#include "World/sithWorld.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "World/sithPlayer.h"
#include "World/jkPlayer.h"
#include "Win95/DebugConsole.h"
#include "Engine/sithTemplate.h"
#include "Engine/sithSound.h"
#include "Engine/sithTime.h"
#include "Win95/sithDplay.h"
#include "Main/jkGame.h"
#include "Engine/sithNet.h"
#include "Engine/sithMulti.h"
#include "AI/sithAIClass.h"

#include <stdint.h>
#include <math.h>

void sithCogVm_Exec(sithCog *cog_ctx)
{
    sithCogScript *cogscript;
    int op;
    sithCogSymbol *v12; // eax
    cogSymbolFunc_t func; // eax
    int *vec; // ecx
    int32_t v19; // eax
    sithCogStackvar val; // [esp+20h] [ebp-80h]
    sithCogStackvar var; // [esp+70h] [ebp-30h]
    sithCogStackvar outVar; // [esp+90h] [ebp-10h]
    float fTmp;
    int iTmp;
    sithCogStackvar* tmpStackVar;
    
    //jk_printf("cog trace %s %x\n", cog_ctx->cogscript->cog_fpath, cog_ctx->execPos);

    cog_ctx->script_running = 1;
    while ( 2 )
    {
        cogscript = cog_ctx->cogscript;
        op = sithCogVm_PopProgramVal(cog_ctx);
        //jk_printf("cog trace %s %x op %u stackpos %u\n", cog_ctx->cogscript->cog_fpath, cog_ctx->execPos, op, cog_ctx->stackPos);
        switch ( op )
        {
            case COG_OPCODE_NOP:
                break;

            case COG_OPCODE_PUSHINT:
                iTmp = sithCogVm_PopProgramVal(cog_ctx);
                val.type = COG_VARTYPE_INT;
                val.data[0] = iTmp;
                sithCogVm_PushVar(cog_ctx, &val);
                break;

            case COG_OPCODE_PUSHFLOAT:
                iTmp = sithCogVm_PopProgramVal(cog_ctx);
                val.type = COG_VARTYPE_FLEX;
                val.dataAsFloat[0] = *(float*)&iTmp;
                sithCogVm_PushVar(cog_ctx, &val);
                break;

            case COG_OPCODE_PUSHSYMBOL:
                iTmp = sithCogVm_PopProgramVal(cog_ctx);
                val.type = COG_VARTYPE_SYMBOL;
                val.data[0] = iTmp;
                sithCogVm_PushVar(cog_ctx, &val);
                break;

            case COG_OPCODE_PUSHVECTOR:
                _memcpy(val.data, &cogscript->script_program[cog_ctx->execPos], sizeof(rdVector3));
                cog_ctx->execPos += 3;
                val.type = COG_VARTYPE_VECTOR;
                sithCogVm_PushVar(cog_ctx, &val);
                break;

            case COG_OPCODE_ARRAYINDEX:
                iTmp = sithCogVm_PopInt(cog_ctx);
                v19 = sithCogVm_PopStackVar(cog_ctx, &var);
                if ( v19 )
                    v19 = var.type == 1 ? var.data[0] : 0;
                val.type = COG_VARTYPE_SYMBOL;
                val.data[0] = iTmp + v19;
                sithCogVm_PushVar(cog_ctx, &val);
                break;

            case COG_OPCODE_CALLFUNC:
                if (!sithCogVm_PopStackVar(cog_ctx, &var))
                    break;
                tmpStackVar = &var;
                if ( tmpStackVar->type != COG_VARTYPE_SYMBOL )
                    break;
                v12 = sithCogParse_GetSymbol(cog_ctx->pSymbolTable, tmpStackVar->data[0]);

                if (!v12 )
                    break;
                if (v12->val.type)
                    break;
                if ( v12->val.dataAsFunc )
                    v12->val.dataAsFunc(cog_ctx); 
                //func = sithCogVm_PopSymbolFunc(cog_ctx); // this function is slightly different?
                break;

            case COG_OPCODE_ASSIGN:
                if (!sithCogVm_PopStackVar(cog_ctx, &val) )
                    break;

                tmpStackVar = sithCogVm_AssignStackVar(&outVar, cog_ctx, &val);
                val.type = tmpStackVar->type;
                val.dataAsPtrs[0] = tmpStackVar->dataAsPtrs[0];
                val.dataAsPtrs[1] = tmpStackVar->dataAsPtrs[1];
                val.dataAsPtrs[2] = tmpStackVar->dataAsPtrs[2];

                if (!sithCogVm_PopStackVar(cog_ctx, &var))
                    break;

                if (var.type != COG_VARTYPE_SYMBOL)
                    break;
                
                tmpStackVar = (sithCogStackvar *)&sithCogParse_GetSymbol(cog_ctx->pSymbolTable, var.data[0])->val.type;
                *tmpStackVar = val;
                break;
            case COG_OPCODE_CMPFALSE:
                sithCogVm_PushInt(cog_ctx, sithCogVm_PopInt(cog_ctx) == 0);
                break;
            case COG_OPCODE_NEG:
                sithCogVm_PushFlex(cog_ctx, -sithCogVm_PopFlex(cog_ctx));
                break;
            case COG_OPCODE_CMPAND:
            case COG_OPCODE_CMPOR:
            case COG_OPCODE_CMPNE:
            case COG_OPCODE_ANDI:
            case COG_OPCODE_ORI:
            case COG_OPCODE_XORI:
                sithCogVm_BitOperation(cog_ctx, op);
                break;
            case COG_OPCODE_GOFALSE:
                iTmp = sithCogVm_PopProgramVal(cog_ctx);
                if ( !sithCogVm_PopInt(cog_ctx) )
                    cog_ctx->execPos = iTmp;
                break;
            case COG_OPCODE_GOTRUE:
                iTmp = sithCogVm_PopProgramVal(cog_ctx);
                if ( sithCogVm_PopInt(cog_ctx) )
                    cog_ctx->execPos = iTmp;
                break;
            case COG_OPCODE_GO:
                cog_ctx->execPos = sithCogVm_PopProgramVal(cog_ctx);
                break;
            case COG_OPCODE_RET:
                if ( cog_ctx->flags & SITH_COG_DEBUG )
                {
                    _sprintf(std_genBuffer, "Cog %s: Returned from depth %d.\n", cog_ctx->cogscript_fpath, cog_ctx->calldepth);
                    DebugConsole_Print(std_genBuffer);
                }
                sithCogVm_Ret(cog_ctx);
                break;
            case COG_OPCODE_CALL:
                if (cog_ctx->calldepth >= 4)
                    break;
                iTmp = sithCogVm_PopProgramVal(cog_ctx);
                if ( iTmp < cog_ctx->cogscript->codeSize )
                {
                    sithCogVm_Call(cog_ctx);
                    cog_ctx->execPos = iTmp;
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
                sithCogVm_MathOperation(cog_ctx, op);
                break;

            default:
                jk_printf("unk op %u\n", op); // added
                break;
        }
        if ( cog_ctx->script_running == 1 )
            continue;
        return;
    }
}

void sithCogVm_ExecCog(sithCog *ctx, int trigIdx)
{
    int trigPc;

    trigPc = ctx->cogscript->triggers[trigIdx].trigPc;
    if ( trigPc >= 0 )
    {
        if ( ctx->script_running )
        {
            if ( ctx->script_running == 1 )
                ctx->script_running = 4;
            sithCogVm_Call(ctx);
        }
        else if ( ctx->stackPos )
        {
            ctx->stackPos = 0;
        }
        ctx->execPos = ctx->cogscript->triggers[trigIdx].trigPc;
        ctx->trigId = ctx->cogscript->triggers[trigIdx].trigId;
        if ( ctx->flags & SITH_COG_DEBUG )
        {
            _sprintf(std_genBuffer, "Cog %s: execution started.\n", ctx->cogscript_fpath);
            DebugConsole_Print(std_genBuffer);
        }
        sithCogVm_Exec(ctx);
        if ( ctx->script_running == 4 )
            ctx->script_running = 1;
    }
}

int sithCogVm_PopValue(sithCog *ctx, sithCogStackvar *stackVar)
{

    sithCogStackvar *tmp; // eax
    int *v5; // edx
    int type; // ecx
    intptr_t d0; // edx
    intptr_t d1;
    intptr_t d2;


    if ( ctx->stackPos < 1 )
        return 0;

    *stackVar = ctx->stack[--ctx->stackPos];
    tmp = stackVar;

    if ( stackVar->type == COG_VARTYPE_SYMBOL ) {
        // Added: nullptr check here
        sithCogSymbol* sym = sithCogParse_GetSymbol(ctx->pSymbolTable, stackVar->data[0]);
        if (sym)
            tmp = (sithCogStackvar *)&sym->val.type;
        else
            tmp = NULL;
    }

    // Added
    if (!tmp)
    {
        type = COG_VARTYPE_INT;
        d0 = 0;
        d1 = 0;
        d2 = 0;
    }
    else if ( tmp->type )
    {
        type = tmp->type;
        d0 = tmp->dataAsPtrs[0];
        d1 = tmp->dataAsPtrs[1];
        d2 = tmp->dataAsPtrs[2];
    }
    else
    {
        type = COG_VARTYPE_INT;
        d0 = tmp->dataAsPtrs[0];
        d1 = tmp->dataAsPtrs[1]; // the original game sets these two to undefined values? Weird compiler optimization fail?
        d2 = tmp->dataAsPtrs[2];
    }

    stackVar->type = type;
    stackVar->dataAsPtrs[0] = d0;
    stackVar->dataAsPtrs[1] = d1;
    stackVar->dataAsPtrs[2] = d2;
    return 1;
}

float sithCogVm_PopFlex(sithCog *ctx)
{
    sithCogStackvar tmp;
    if (!sithCogVm_PopValue(ctx, &tmp))
        return 0.0;
        
    if ( tmp.type == COG_VARTYPE_INT )
        return (float)tmp.data[0];
    if ( tmp.type == COG_VARTYPE_FLEX )
        return tmp.dataAsFloat[0];
    return 0.0;
}

int sithCogVm_PopInt(sithCog *ctx)
{
    sithCogStackvar tmp;
    if (!sithCogVm_PopValue(ctx, &tmp))
        return -1;
    
    if ( tmp.type == COG_VARTYPE_INT )
        return tmp.data[0];
    if ( tmp.type == COG_VARTYPE_FLEX )
        return (int)tmp.dataAsFloat[0];

    return -1;
}

int sithCogVm_PopSymbolIdx(sithCog *ctx)
{
    sithCogStackvar tmp;
    if (!sithCogVm_PopValue(ctx, &tmp))
        return 0;
    
    if ( tmp.type == COG_VARTYPE_SYMBOL )
        return tmp.data[0];

    return 0;
}

int sithCogVm_PopVector3(sithCog *ctx, rdVector3* out)
{
    sithCogStackvar tmp;
    if (!sithCogVm_PopValue(ctx, &tmp))
    {
        _memset(out, 0, sizeof(*out));
        return 0;
    }
    
    if ( tmp.type == COG_VARTYPE_VECTOR )
    {
        _memcpy(out, &tmp.data[0], sizeof(*out));
        return 1;
    }

    _memset(out, 0, sizeof(*out));
    return 0;
}

sithCog* sithCogVm_PopCog(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t cogIdx;
    sithWorld* world = sithWorld_pCurrentWorld;

    if (!sithCogVm_PopValue(ctx, &tmp))
    {
        return NULL;
    }
    
    if ( tmp.type == COG_VARTYPE_INT )
    {
        cogIdx = tmp.data[0];
    }
    else if ( tmp.type == COG_VARTYPE_FLEX )
    {
        cogIdx = (int)tmp.dataAsFloat[0];
    }
    else
    {
        cogIdx = -1;
    }

    if (cogIdx == -1)
        return NULL;
    
    if ( (uint16_t)cogIdx & 0x8000 )
    {
        world = sithWorld_pStatic;
        cogIdx &= ~0x8000;
    }
    if ( world && cogIdx >= 0 && (unsigned int)cogIdx < world->numCogsLoaded )
        return &world->cogs[cogIdx];

    return NULL;
} 

sithThing* sithCogVm_PopThing(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t idx;
    sithWorld* world = sithWorld_pCurrentWorld;

    if (!sithCogVm_PopValue(ctx, &tmp))
    {
        tmp.type = COG_VARTYPE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == COG_VARTYPE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == COG_VARTYPE_FLEX )
    {
        idx = (int)(double)tmp.dataAsFloat[0];
    }
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( world && idx >= 0 && idx <= world->numThings ) // TODO is this correct...? vs world->numThingsLoaded
    {
        if (world->things[idx].type == SITH_THING_FREE)
            return NULL;

        return &world->things[idx];
    }

    return NULL;
}

sithThing* sithCogVm_PopTemplate(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t idx;

    if (!sithCogVm_PopValue(ctx, &tmp))
    {
        tmp.type = COG_VARTYPE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == COG_VARTYPE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == COG_VARTYPE_FLEX )
    {
        idx = (int)(double)tmp.dataAsFloat[0];
    }
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;

    return sithTemplate_GetEntryByIdx(idx);
}

sithSound* sithCogVm_PopSound(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t idx;
    sithWorld* world = sithWorld_pCurrentWorld;

    if (!sithCogVm_PopValue(ctx, &tmp))
    {
        tmp.type = COG_VARTYPE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == COG_VARTYPE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == COG_VARTYPE_FLEX )
    {
        idx = (int)(double)tmp.dataAsFloat[0];
    }
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_pStatic;
        idx &= ~0x8000; // ?
    }
    
    if ( world && idx >= 0 && idx < world->numSoundsLoaded )
    {
        return &world->sounds[idx];
    }

    return NULL;
}

sithSector* sithCogVm_PopSector(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t idx;
    sithWorld* world = sithWorld_pCurrentWorld;

    if (!sithCogVm_PopValue(ctx, &tmp))
    {
        tmp.type = COG_VARTYPE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == COG_VARTYPE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == COG_VARTYPE_FLEX )
    {
        idx = (int)(double)tmp.dataAsFloat[0];
    }
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( world && idx >= 0 && idx < world->numSectors )
    {
        return &world->sectors[idx];
    }

    return NULL;
}

sithSurface* sithCogVm_PopSurface(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t idx;
    sithWorld* world = sithWorld_pCurrentWorld;

    if (!sithCogVm_PopValue(ctx, &tmp))
    {
        tmp.type = COG_VARTYPE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == COG_VARTYPE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == COG_VARTYPE_FLEX )
    {
        idx = (int)(double)tmp.dataAsFloat[0];
    }
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


rdMaterial* sithCogVm_PopMaterial(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t idx;
    sithWorld* world = sithWorld_pCurrentWorld;

    if (!sithCogVm_PopValue(ctx, &tmp))
    {
        tmp.type = COG_VARTYPE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == COG_VARTYPE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == COG_VARTYPE_FLEX )
    {
        idx = (int)(double)tmp.dataAsFloat[0];
    }
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_pStatic;
        idx &= ~0x8000; // ?
    }
    
    if ( world && idx >= 0 && idx < world->numMaterialsLoaded )
    {
        return &world->materials[idx];
    }

    return NULL;
}

rdModel3* sithCogVm_PopModel3(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t idx;
    sithWorld* world = sithWorld_pCurrentWorld;

    if (!sithCogVm_PopValue(ctx, &tmp))
    {
        tmp.type = COG_VARTYPE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == COG_VARTYPE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == COG_VARTYPE_FLEX )
    {
        idx = (int)(double)tmp.dataAsFloat[0];
    }
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_pStatic;
        idx &= ~0x8000; // ?
    }
    
    if ( world && idx >= 0 && idx < world->numModelsLoaded )
    {
        return &world->models[idx];
    }

    return NULL;
}

rdKeyframe* sithCogVm_PopKeyframe(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t idx;
    sithWorld* world = sithWorld_pCurrentWorld;

    if (!sithCogVm_PopValue(ctx, &tmp))
    {
        tmp.type = COG_VARTYPE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == COG_VARTYPE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == COG_VARTYPE_FLEX )
    {
        idx = (int)(double)tmp.dataAsFloat[0];
    }
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_pStatic;
        idx &= ~0x8000; // ?
    }

    if ( world && idx >= 0 && idx < world->numKeyframesLoaded )
        return &world->keyframes[idx];

    return NULL;
}

sithAIClass* sithCogVm_PopAIClass(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t idx;
    sithWorld* world = sithWorld_pCurrentWorld;

    if (!sithCogVm_PopValue(ctx, &tmp))
    {
        tmp.type = COG_VARTYPE_INT;
        tmp.data[0] = -1;
    }
    
    if ( tmp.type == COG_VARTYPE_INT )
    {
        idx = tmp.data[0];
    }
    else if ( tmp.type == COG_VARTYPE_FLEX )
    {
        idx = (int)(double)tmp.dataAsFloat[0];
    }
    else
    {
        idx = -1;
    }

    if (idx == -1)
        return NULL;
    
    if ( world && idx >= 0 && idx < world->numAIClassesLoaded )
        return &world->aiclasses[idx];

    return NULL;
}

// popsymbolfunc is unused
cogSymbolFunc_t sithCogVm_PopSymbolFunc(sithCog *cog_ctx)
{
    sithCogStackvar *v3; // ecx
    sithCogSymbol *sym; // eax
    intptr_t v12; // [esp+10h] [ebp-Ch]

    if ( cog_ctx->stackPos < 1 )
        return 0;
    cog_ctx->stackPos--;
    v3 = &cog_ctx->stack[cog_ctx->stackPos];

    if ( v3->type == COG_VARTYPE_SYMBOL )
    {
        sym = sithCogParse_GetSymbol(cog_ctx->pSymbolTable, cog_ctx->stack[cog_ctx->stackPos].data[0]);
        if ( sym->val.type )
            return (cogSymbolFunc_t)&sym->val.dataAsFunc;
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
        return (cogSymbolFunc_t)cog_ctx->stack[cog_ctx->stackPos].dataAsPtrs[0];
    }
}

char* sithCogVm_PopString(sithCog *ctx)
{
    unsigned int v1; // eax
    int v2; // eax
    sithCogSymbol *v5; // eax
    char *result; // eax

    v1 = ctx->stackPos;
    if ( v1 < 1
      || (v2 = v1 - 1, ctx->stackPos = v2, ctx->stack[v2].type != COG_VARTYPE_SYMBOL)
      || (v5 = sithCogParse_GetSymbol(ctx->pSymbolTable, ctx->stack[v2].data[0]), !v5 || v5->val.type != COG_VARTYPE_STR) ) // Added: v5 nullptr check
    {
        result = 0;
    }
    else
    {
        result = v5->val.dataAsName;
    }
    return result;
}

void sithCogVm_PushVar(sithCog *ctx, sithCogStackvar *val)
{
    sithCogStackvar *pushVar;

    if ( ctx->stackPos == SITHCOGVM_MAX_STACKSIZE )
    {
        memmove(ctx->stack, &ctx->stack[1], sizeof(ctx->stack) * (SITHCOGVM_MAX_STACKSIZE-1));
        --ctx->stackPos;
    }
    
    pushVar = &ctx->stack[ctx->stackPos];
    pushVar->type = val->type;
    pushVar->dataAsPtrs[0] = val->dataAsPtrs[0];
    pushVar->dataAsPtrs[1] = val->dataAsPtrs[1];
    pushVar->dataAsPtrs[2] = val->dataAsPtrs[2];
    ++ctx->stackPos;
}

void sithCogVm_PushInt(sithCog *ctx, int val)
{
    sithCogStackvar v;
    v.type = COG_VARTYPE_INT;
    v.data[0] = val;
    sithCogVm_PushVar(ctx, &v);
}

void sithCogVm_PushFlex(sithCog *ctx, float val)
{
    sithCogStackvar v;
    v.type = COG_VARTYPE_FLEX;
    v.dataAsFloat[0] = val;
    sithCogVm_PushVar(ctx, &v);
}

void sithCogVm_PushVector3(sithCog *ctx, const rdVector3* val)
{
    sithCogStackvar v;
    v.type = COG_VARTYPE_VECTOR;
    v.dataAsFloat[0] = val->x;
    v.dataAsFloat[1] = val->y;
    v.dataAsFloat[2] = val->z;
    sithCogVm_PushVar(ctx, &v);
}

int sithCogVm_PopProgramVal(sithCog *ctx)
{
    if ( ctx->execPos >= ctx->cogscript->codeSize - 1 )
        return COG_OPCODE_RET;

    return ctx->cogscript->script_program[ctx->execPos++];
}

void sithCogVm_ResetStack(sithCog *ctx)
{
    if ( ctx->stackPos )
        ctx->stackPos = 0;
}

void sithCogVm_Call(sithCog *ctx)
{
    if ( ctx->calldepth != 4 )
    {
        ctx->callstack[ctx->calldepth].pc = ctx->execPos;
        ctx->callstack[ctx->calldepth].script_running = ctx->script_running;
        ctx->callstack[ctx->calldepth].waketimeMs = ctx->wakeTimeMs;
        ctx->callstack[ctx->calldepth++].trigId = ctx->trigId;
    }
}

void sithCogVm_Ret(sithCog *ctx)
{
    if ( ctx->calldepth )
    {
        ctx->script_running = ctx->callstack[--ctx->calldepth].script_running;
        ctx->execPos = ctx->callstack[ctx->calldepth].pc;
        ctx->wakeTimeMs = ctx->callstack[ctx->calldepth].waketimeMs;
        ctx->trigId = ctx->callstack[ctx->calldepth].trigId;
    }
    else
    {
        ctx->script_running = 0;
    }
}

int sithCogVm_PopStackVar(sithCog *cog, sithCogStackvar *out)
{
    sithCogStackvar *pop; // eax

    if ( cog->stackPos < 1 )
        return 0;

    pop = &cog->stack[--cog->stackPos];
    out->type = pop->type;
    out->dataAsPtrs[0] = pop->dataAsPtrs[0];
    out->dataAsPtrs[1] = pop->dataAsPtrs[1];
    out->dataAsPtrs[2] = pop->dataAsPtrs[2];

    return 1;
}

void sithCogVm_BitOperation(sithCog *cog_ctx, int op)
{
    int operand_a = sithCogVm_PopInt(cog_ctx);
    int operand_b = sithCogVm_PopInt(cog_ctx);
    switch ( op )
    {
        case COG_OPCODE_CMPAND:
            sithCogVm_PushInt(cog_ctx, (operand_a && operand_b) ? 1 : 0);
            break;
            
        case COG_OPCODE_CMPOR:
            sithCogVm_PushInt(cog_ctx, (operand_a || operand_b) ? 1 : 0);
            break;
        case COG_OPCODE_CMPNE:
            sithCogVm_PushInt(cog_ctx, (operand_a != operand_b) ? 1 : 0);
            break;
        case COG_OPCODE_ANDI:
            sithCogVm_PushInt(cog_ctx, operand_a & operand_b);
            break;
        case COG_OPCODE_ORI:
            sithCogVm_PushInt(cog_ctx, operand_a | operand_b);
            break;
        case COG_OPCODE_XORI:
            sithCogVm_PushInt(cog_ctx, operand_a ^ operand_b);
            break;
        default:
            return;
    }
}

void sithCogVm_MathOperation(sithCog *cog_ctx, int op)
{
    float operand_a = sithCogVm_PopFlex(cog_ctx);
    float operand_b = sithCogVm_PopFlex(cog_ctx);
    switch ( op )
    {
        case COG_OPCODE_ADD:
            sithCogVm_PushFlex(cog_ctx, operand_a + operand_b);
            break;
        case COG_OPCODE_SUB:
            sithCogVm_PushFlex(cog_ctx, operand_b - operand_a);
            break;
        case COG_OPCODE_MUL:
            sithCogVm_PushFlex(cog_ctx, operand_a * operand_b);
            break;
        case COG_OPCODE_DIV:
            sithCogVm_PushFlex(cog_ctx, (operand_a == 0.0) ? 0.0 : operand_b / operand_a);
            break;
        case COG_OPCODE_MOD:
            sithCogVm_PushFlex(cog_ctx, fmod(operand_b, operand_a));
            break;
        case COG_OPCODE_CMPGT:
            sithCogVm_PushInt(cog_ctx, (operand_b > operand_a) ? 1 : 0);
            break;
        case COG_OPCODE_CMPLS:
            sithCogVm_PushInt(cog_ctx, (operand_b < operand_a) ? 1 : 0);
            break;
        case COG_OPCODE_CMPEQ:
            sithCogVm_PushInt(cog_ctx, (operand_b == operand_a) ? 1 : 0);
            break;
        case COG_OPCODE_CMPLE:
            sithCogVm_PushInt(cog_ctx, (operand_b <= operand_a) ? 1 : 0);
            break;
        case COG_OPCODE_CMPGE:
            sithCogVm_PushInt(cog_ctx, (operand_b >= operand_a) ? 1 : 0);
            break;
        default:
            return;
    }
}

sithCogStackvar* sithCogVm_AssignStackVar(sithCogStackvar *out, sithCog *ctx, sithCogStackvar *in)
{
    if ( in->type == COG_VARTYPE_SYMBOL )
        in = (sithCogStackvar *)&sithCogParse_GetSymbol(ctx->pSymbolTable, in->dataAsPtrs[0])->val.type;
    if ( in->type != COG_VARTYPE_VERB)
    {
        out->type = in->type;
        out->dataAsPtrs[0] = in->dataAsPtrs[0];
        out->dataAsPtrs[1] = in->dataAsPtrs[1];
        out->dataAsPtrs[2] = in->dataAsPtrs[2];
        return out;
    }
    else
    {
        out->type = COG_VARTYPE_INT;
        out->dataAsPtrs[0] = *(int32_t*)in->dataAsPtrs[0];
        out->dataAsPtrs[1] = in->dataAsPtrs[1]; // these are undefined in the original
        out->dataAsPtrs[2] = in->dataAsPtrs[2];
        return out;
    }

    
}
