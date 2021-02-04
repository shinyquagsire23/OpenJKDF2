#include "sithCogVm.h"

#include "sithCog.h"
#include "jk.h"
#include "stdPlatform.h"
#include "Cog/sithCogScript.h"
#include "World/sithWorld.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "Win95/DebugConsole.h"
#include "Engine/sithTemplate.h"
#include "Engine/sithSound.h"

#include <stdint.h>
#include <math.h>

#define sithMulti_HandleJoinLeave ((void*)0x004CA780)
#define sithMulti_HandleJoin_unused ((void*)0x004CA910)
#define sithMulti_HandleLeaveJoin ((void*)0x004CAAF0)
#define sithMulti_HandleRequestConnect ((void*)0x004CAE50)
#define sithMulti_HandleChat ((void*)0x004CB2E0)
#define sithMulti_HandlePing ((void*)0x004CB3E0)
#define sithMulti_HandlePingResponse ((void*)0x004CB410)
#define sithMulti_HandleKickPlayer ((void*)0x004CB4F0)
#define sithMulti_HandleTimeLimit ((void*)0x004CB690)
#define sithMulti_HandleDeath ((void*)0x004CBC50)
#define sithMulti_HandleScore ((void*)0x004CBDE0)
#define cogMsg_HandleTeleportThing ((void*)0x004F3270)
#define cogMsg_HandleSyncThing ((void*)0x004F35E0)
#define cogMsg_HandlePlaySoundPos ((void*)0x004F3870)
#define cogMsg_HandleSoundClassPlay ((void*)0x004F39C0)
#define cogMsg_HandlePlayKey ((void*)0x004F3AA0)
#define cogMsg_HandleOpenDoor ((void*)0x004F3B90)
#define cogMsg_HandleSetThingModel ((void*)0x004F3C80)
#define cogMsg_HandleStopKey ((void*)0x004F3D50)
#define cogMsg_HandleStopSound ((void*)0x004F3E10)
#define cogMsg_HandleFireProjectile ((void*)0x004F3F60)
#define cogMsg_HandleDeath ((void*)0x004F40B0)
#define cogMsg_HandleDamage ((void*)0x004F41A0)
#define cogMsg_HandleSyncThingFull ((void*)0x004F46F0)
#define cogmsg_HandleSyncThingFrame ((void*)0x004F4D60)
#define cogMsg_HandleSyncThingAttachment ((void*)0x004F4F50)
#define cogMsg_HandleTakeItem ((void*)0x004F5150)
#define cogMsg_HandleCreateThing ((void*)0x004F52E0)
#define cogMsg_HandleDestroyThing ((void*)0x004F5410)
#define cogMsg_HandleSyncSurface ((void*)0x004F9050)
#define cogMsg_HandleSyncSector ((void*)0x004F91F0)
#define cogMsg_HandleSyncSectorAlt ((void*)0x004F9350)
#define cogMsg_HandleSyncAI ((void*)0x004F9640)
#define cogMsg_HandleSyncItemDesc ((void*)0x004F99C0)
#define cogMsg_HandleStopAnim ((void*)0x004F9BA0)
#define cogMsg_HandleSyncPuppet ((void*)0x004F9E10)
#define cogMsg_HandleSyncTimers ((void*)0x004F9FA0)
#define cogMsg_HandleSyncCameras ((void*)0x004FA130)
#define cogMsg_HandleSyncPalEffects ((void*)0x004FA350)
#define cogMsg_HandleSendTrigger ((void*)0x004FC630)
#define cogMsg_HandleSyncCog ((void*)0x004FC8A0)
#define cogmsg_31 ((void*)0x4FA5D0)
#define sithDplay_cogMsg_HandleEnumPlayers ((void*)0x004C9A40)
#define sithCogVm_ClearTmpBuf2_cogmsg_40 ((void*)0x004E1EE0)


int sithCogVm_Startup()
{
    if (sithCogVm_bInit)
        return 0;
    _memset(&sithCogVm_globals, 0, sizeof(sithCogVm_globals));
    _memset(&sithCogVm_jkl_map_idk, 0, sizeof(sithCogVm_jkl_map_idk));
    sithCogVm_dword_847E84 = 0;
    jkl_map_idk_set_one = 1;
    sithCogVm_globals.msgFuncs[COGMSG_TELEPORTTHING] = cogMsg_HandleTeleportThing;
    sithCogVm_globals.msgFuncs[COGMSG_FIREPROJECTILE] = cogMsg_HandleFireProjectile;
    sithCogVm_globals.msgFuncs[COGMSG_REQUESTCONNECT] = sithMulti_HandleRequestConnect;
    sithCogVm_globals.msgFuncs[COGMSG_JOINLEAVE] = sithMulti_HandleJoinLeave;
    sithCogVm_globals.msgFuncs[COGMSG_DEATH] = cogMsg_HandleDeath;
    sithCogVm_globals.msgFuncs[COGMSG_DAMAGE] = cogMsg_HandleDamage;
    sithCogVm_globals.msgFuncs[COGMSG_SENDTRIGGER] = cogMsg_HandleSendTrigger;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCTHING] = cogMsg_HandleSyncThing;
    sithCogVm_globals.msgFuncs[COGMSG_PLAYSOUNDPOS] = cogMsg_HandlePlaySoundPos;
    sithCogVm_globals.msgFuncs[COGMSG_PLAYKEY] = cogMsg_HandlePlayKey;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCTHINGFULL] = cogMsg_HandleSyncThingFull;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCCOG] = cogMsg_HandleSyncCog;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCSURFACE] = cogMsg_HandleSyncSurface;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCAI] = cogMsg_HandleSyncAI;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCITEMDESC] = cogMsg_HandleSyncItemDesc;
    sithCogVm_globals.msgFuncs[COGMSG_STOPANIM] = cogMsg_HandleStopAnim;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCSECTOR] = cogMsg_HandleSyncSector;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCTHINGFRAME] = cogmsg_HandleSyncThingFrame;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCPUPPET] = cogMsg_HandleSyncPuppet;
    sithCogVm_globals.msgFuncs[COGMSG_LEAVEJOIN] = sithMulti_HandleLeaveJoin;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCTHINGATTACHMENT] = cogMsg_HandleSyncThingAttachment;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCTIMERS] = cogMsg_HandleSyncTimers;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCCAMERAS] = cogMsg_HandleSyncCameras;
    sithCogVm_globals.msgFuncs[COGMSG_TAKEITEM1] = cogMsg_HandleTakeItem;
    sithCogVm_globals.msgFuncs[COGMSG_TAKEITEM2] = cogMsg_HandleTakeItem;
    sithCogVm_globals.msgFuncs[COGMSG_STOPKEY] = cogMsg_HandleStopKey;
    sithCogVm_globals.msgFuncs[COGMSG_STOPSOUND] = cogMsg_HandleStopSound;
    sithCogVm_globals.msgFuncs[COGMSG_CREATETHING] = cogMsg_HandleCreateThing;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCPALEFFECTS] = cogMsg_HandleSyncPalEffects;
    sithCogVm_globals.msgFuncs[COGMSG_ID_1F] = cogmsg_31;
    sithCogVm_globals.msgFuncs[COGMSG_CHAT] = sithMulti_HandleChat;
    sithCogVm_globals.msgFuncs[COGMSG_DESTROYTHING] = cogMsg_HandleDestroyThing;
    sithCogVm_globals.msgFuncs[COGMSG_SYNCSECTORALT] = cogMsg_HandleSyncSectorAlt;
    sithCogVm_globals.msgFuncs[COGMSG_SOUNDCLASSPLAY] = cogMsg_HandleSoundClassPlay;
    sithCogVm_globals.msgFuncs[COGMSG_OPENDOOR] = cogMsg_HandleOpenDoor;
    sithCogVm_globals.msgFuncs[COGMSG_SETTHINGMODEL] = cogMsg_HandleSetThingModel;
    sithCogVm_globals.msgFuncs[COGMSG_PING] = sithMulti_HandlePing;
    sithCogVm_globals.msgFuncs[COGMSG_PINGREPLY] = sithMulti_HandlePingResponse;
    sithCogVm_globals.msgFuncs[COGMSG_ENUMPLAYERS] = sithDplay_cogMsg_HandleEnumPlayers;
    sithCogVm_globals.msgFuncs[COGMSG_RESET] = sithCogVm_ClearTmpBuf2_cogmsg_40;
    sithCogVm_globals.msgFuncs[COGMSG_KICK] = sithMulti_HandleKickPlayer;
    sithCogVm_bInit = 1;
    return 1;
}

void sithCogVm_Shutdown()
{
    if ( sithCogVm_bInit )
        sithCogVm_bInit = 0;
}

void sithCogVm_SetMsgFunc(int msgid, void *func)
{
    sithCogVm_globals.msgFuncs[msgid] = func;
}

//sendmsgtoplayer
//filewrite
//sub

void sithCogVm_Set104()
{
    sithCogVm_idk = 1;
}

int sithCogVm_InvokeMsgByIdx(net_msg *a1)
{
    int v1; // eax
    int (__cdecl *v2)(net_msg *); // eax
    int result; // eax

    v1 = a1->msg_id;
    if ( (signed int)(unsigned __int16)v1 < 65 && (v2 = (int (__cdecl *)(net_msg *))sithCogVm_globals.msgFuncs[v1]) != 0 )
        result = v2(a1);
    else
        result = 1;
    return result;
}

// syncwithplayers

void sithCogVm_ClearMsgTmpBuf()
{
    _memset(sithCogVm_MsgTmpBuf, 0, sizeof(sithCogVm_MsgTmpBuf));
    sithCogVm_idk2 = 0;
}

//sithCogVm_ClearTmpBuf2_cogmsg_40

void sithCogVm_Exec(sithCog *cog_ctx)
{
    sithCogScript *cogscript;
    int op;
    struct cogSymbol *v12; // eax
    cogSymbolFunc_t func; // eax
    int *vec; // ecx
    int v19; // eax
    sithCogStackvar val; // [esp+20h] [ebp-80h]
    sithCogStackvar var; // [esp+70h] [ebp-30h]
    sithCogStackvar outVar; // [esp+90h] [ebp-10h]
    float fTmp;
    int iTmp;
    sithCogStackvar* tmpStackVar;

    cog_ctx->script_running = 1;
    while ( 2 )
    {
        cogscript = cog_ctx->cogscript;
        op = sithCogVm_PopProgramVal(cog_ctx);
        //jk_printf("cog trace %s %x op %u\n", cog_ctx->cogscript->cog_fpath, cog_ctx->cogscript_pc, op);
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
                val.data[0] = iTmp;
                sithCogVm_PushVar(cog_ctx, &val);
                break;

            case COG_OPCODE_PUSHSYMBOL:
                iTmp = sithCogVm_PopProgramVal(cog_ctx);
                val.type = COG_VARTYPE_SYMBOL;
                val.data[0] = iTmp;
                sithCogVm_PushVar(cog_ctx, &val);
                break;

            case COG_OPCODE_PUSHVECTOR:
                _memcpy(val.data, &cogscript->script_program[cog_ctx->cogscript_pc], sizeof(rdVector3));
                cog_ctx->cogscript_pc += 3;
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
                if ( cog_ctx->stackPos < 1 )
                    break;
                tmpStackVar = &cog_ctx->stack[--cog_ctx->stackPos];
                if ( tmpStackVar->type != COG_VARTYPE_SYMBOL )
                    break;
                v12 = sithCogParse_GetSymbol(cog_ctx->symbolTable, tmpStackVar->data[0]);
                if (!v12 )
                    break;
                if (v12->val)
                    break;
                if ( v12->func )
                    v12->func(cog_ctx); 
                //func = sithCogVm_PopSymbolFunc(cog_ctx); // this function is slightly different?
                break;

            case COG_OPCODE_ASSIGN:
                if (!sithCogVm_PopStackVar(cog_ctx, &val) )
                    break;

                tmpStackVar = sithCogVm_AssignStackVar(&outVar, cog_ctx, &val);
                val.type = tmpStackVar->type;
                val.data[0] = tmpStackVar->data[0];
                val.data[1] = tmpStackVar->data[1];
                val.data[2] = tmpStackVar->data[2];

                if (!sithCogVm_PopStackVar(cog_ctx, &var))
                    break;

                if (var.type != COG_VARTYPE_SYMBOL)
                    break;
                        
                tmpStackVar = (sithCogStackvar *)&sithCogParse_GetSymbol(cog_ctx->symbolTable, var.data[0])->val;
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
                    cog_ctx->cogscript_pc = iTmp;
                break;
            case COG_OPCODE_GOTRUE:
                iTmp = sithCogVm_PopProgramVal(cog_ctx);
                if ( sithCogVm_PopInt(cog_ctx) )
                    cog_ctx->cogscript_pc = iTmp;
                break;
            case COG_OPCODE_GO:
                cog_ctx->cogscript_pc = sithCogVm_PopProgramVal(cog_ctx);
                break;
            case COG_OPCODE_RET:
                if ( cog_ctx->flags & COGVM_FLAG_TRACE )
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
                if ( iTmp < cog_ctx->cogscript->program_pc_max )
                {
                    sithCogVm_Call(cog_ctx);
                    cog_ctx->cogscript_pc = iTmp;
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
        ctx->cogscript_pc = ctx->cogscript->triggers[trigIdx].trigPc;
        ctx->trigId = ctx->cogscript->triggers[trigIdx].trigId;
        if ( ctx->flags & COGFLAGS_TRACE )
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
    int v6; // eax
    int v7; // edi
    int type; // ecx
    int v9; // edx

    if ( ctx->stackPos < 1 )
        return 0;
    *stackVar = ctx->stack[--ctx->stackPos];
    tmp = stackVar;
    if ( stackVar->type == COG_VARTYPE_SYMBOL )
        tmp = (sithCogStackvar *)&sithCogParse_GetSymbol(ctx->symbolTable, stackVar->data[0])->val;
    if ( tmp->type )
    {
        type = tmp->type;
        v9 = tmp->data[0];
        v7 = tmp->data[1];
        v6 = tmp->data[2];
    }
    else
    {
        type = COG_VARTYPE_INT;
        v9 = tmp->data[0];
        v6 = tmp->data[1]; // the original game sets these two to undefined values? Weird compiler optimization fail?
        v7 = tmp->data[2];
    }
    stackVar->type = type;
    stackVar->data[0] = v9;
    stackVar->data[1] = v7;
    stackVar->data[2] = v6;
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
        return *(float*)&tmp.data[0];
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
        return (int)*(float*)&tmp.data[0];

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
    sithWorld* world = sithWorld_pCurWorld;

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
        if (cogIdx == -1)
            return NULL;
    }
    else
    {
        cogIdx = -1;
    }
    
    if ( (uint16_t)cogIdx & 0x8000 )
    {
        world = sithWorld_pStatic;
        cogIdx &= 0xFFFF7FFF;
    }
    if ( world && cogIdx >= 0 && (unsigned int)cogIdx < world->numCogsLoaded )
        return &world->cogs[cogIdx];

    return NULL;
} 

sithThing* sithCogVm_PopThing(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t idx;
    sithWorld* world = sithWorld_pCurWorld;

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
        if (idx == -1)
            return NULL;
    }
    else
    {
        idx = -1;
    }
    
    if ( world && idx >= 0 && idx < world->numThings )
    {
        if (world->things[idx].thingType == THINGTYPE_FREE)
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
        if (idx == -1)
            return NULL;
    }
    else
    {
        idx = -1;
    }

    return sithTemplate_GetEntryByIdx(idx);
}

sithSound* sithCogVm_PopSound(sithCog *ctx)
{
    sithCogStackvar tmp;
    int32_t idx;
    sithWorld* world = sithWorld_pCurWorld;

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
        if (idx == -1)
            return NULL;
    }
    else
    {
        idx = -1;
    }
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_pStatic;
        idx &= 0xFFFF7FFF; // ?
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
    sithWorld* world = sithWorld_pCurWorld;

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
        if (idx == -1)
            return NULL;
    }
    else
    {
        idx = -1;
    }
    
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
    sithWorld* world = sithWorld_pCurWorld;

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
        if (idx == -1)
            return NULL;
    }
    else
    {
        idx = -1;
    }
    
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
    sithWorld* world = sithWorld_pCurWorld;

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
        if (idx == -1)
            return NULL;
    }
    else
    {
        idx = -1;
    }
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_pStatic;
        idx &= 0xFFFF7FFF; // ?
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
    sithWorld* world = sithWorld_pCurWorld;

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
        if (idx == -1)
            return NULL;
    }
    else
    {
        idx = -1;
    }
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_pStatic;
        idx &= 0xFFFF7FFF; // ?
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
    sithWorld* world = sithWorld_pCurWorld;

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
        if (idx == -1)
            return NULL;
    }
    else
    {
        idx = -1;
    }
    
    if ( idx & 0x8000 )
    {
        world = sithWorld_pStatic;
        idx &= 0xFFFF7FFF; // ?
    }
    
    if ( world && idx >= 0 && idx < world->numKeyframesLoaded )
        return &world->keyframes[idx];

    return NULL;
}

// aiclass
// popsymbolfunc is unused

cogSymbolFunc_t sithCogVm_PopSymbolFunc(sithCog *cog_ctx)
{
    sithCogStackvar *v3; // ecx
    struct cogSymbol *v7; // eax
    int v12; // [esp+10h] [ebp-Ch]

    if ( cog_ctx->stackPos < 1 )
        return 0;
    cog_ctx->stackPos--;
    v3 = &cog_ctx->stack[cog_ctx->stackPos];

    if ( v3->type == COG_VARTYPE_SYMBOL )
    {
        v7 = sithCogParse_GetSymbol(cog_ctx->symbolTable, cog_ctx->stack[cog_ctx->stackPos].data[0]);
        if ( v7->val )
            return (cogSymbolFunc_t)&v7->func;
        else
            return v7->func;
    }
    else if ( v3->type )
    {
        return (cogSymbolFunc_t)v12; // aaaaa
    }
    else
    {
        return cog_ctx->stack[cog_ctx->stackPos].data[0];
    }
}

char* sithCogVm_PopString(sithCog *ctx)
{
    unsigned int v1; // eax
    int v2; // eax
    int v3; // ST18_4
    int v4; // ST1C_4
    struct cogSymbol *v5; // eax
    char *result; // eax

    v1 = ctx->stackPos;
    if ( v1 < 1
      || (v2 = v1 - 1, ctx->stackPos = v2, v3 = ctx->stack[v2].data[1], v4 = ctx->stack[v2].data[2], ctx->stack[v2].type != 1)
      || (v5 = sithCogParse_GetSymbol(ctx->symbolTable, ctx->stack[v2].data[0]), v5->val != COG_VARTYPE_STR) )
    {
        result = 0;
    }
    else
    {
        result = (char *)v5->func;
    }
    return result;
}

void sithCogVm_PushVar(sithCog *ctx, sithCogStackvar *val)
{
    sithCogStackvar *pushVar;

    if ( ctx->stackPos == 64 )
    {
        _memcpy(ctx->stack, &ctx->stack[1], 0x3F0u);
        --ctx->stackPos;
    }
    
    pushVar = &ctx->stack[ctx->stackPos];
    pushVar->type = val->type;
    pushVar->data[0] = val->data[0];
    pushVar->data[1] = val->data[1];
    pushVar->data[2] = val->data[2];
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

void sithCogVm_PushVector3(sithCog *ctx, rdVector3* val)
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
    if ( ctx->cogscript_pc >= ctx->cogscript->program_pc_max - 1 )
        return COG_OPCODE_RET;

    return ctx->cogscript->script_program[ctx->cogscript_pc++];
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
        ctx->callstack[ctx->calldepth].pc = ctx->cogscript_pc;
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
        ctx->cogscript_pc = ctx->callstack[ctx->calldepth].pc;
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
    out->data[0] = pop->data[0];
    out->data[1] = pop->data[1];
    out->data[2] = pop->data[2];

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
        in = (sithCogStackvar *)&sithCogParse_GetSymbol(ctx->symbolTable, in->data[0])->val;
    if ( in->type != COG_VARTYPE_VERB)
    {
        out->type = in->type;
        out->data[0] = in->data[0];
        out->data[1] = in->data[1];
        out->data[2] = in->data[2];
        return out;
    }
    else
    {
        out->type = COG_VARTYPE_INT;
        out->data[0] = *(int*)in->data[0];
        out->data[1] = in->data[1]; // these are undefined in the original
        out->data[2] = in->data[2];
        return out;
    }

    
}
