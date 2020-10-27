#include "sithCogVm.h"

#include "sithCog.h"
#include "jk.h"
#include "stdPlatform.h"
#include "Cog/sithCogScript.h"

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

void sithCogVm_Exec(sithCog *cog_ctx)
{
    sithCogScript *cogscript; // ecx
    unsigned int pc; // eax
    int pc_1; // eax
    int op; // edi
    sithCogStackvar *v5; // eax
    sithCogStackvar *v6; // eax
    unsigned int v7; // eax
    int v8; // eax
    sithCogStackvar *v9; // edx
    int v10; // eax
    unsigned int v11; // ecx
    struct cogSymbol *v12; // eax
    void (__cdecl *v13)(sithCog *); // eax
    int v14; // edi
    int v15; // edi
    int v16; // eax
    int *vec; // ecx
    signed int v18; // edi
    int v19; // eax
    int v20; // edi
    int v21; // edi
    unsigned int v22; // edi
    __int32 v23; // edi
    signed int v24; // eax
    sithCogStackvar a3; // [esp+10h] [ebp-90h]
    sithCogStackvar val; // [esp+20h] [ebp-80h]
    sithCogStackvar v27; // [esp+30h] [ebp-70h]
    sithCogStackvar v28; // [esp+40h] [ebp-60h]
    sithCogStackvar a2; // [esp+50h] [ebp-50h]
    sithCogStackvar v30; // [esp+60h] [ebp-40h]
    sithCogStackvar v31; // [esp+70h] [ebp-30h]
    int v32; // [esp+88h] [ebp-18h]
    int v33; // [esp+8Ch] [ebp-14h]
    sithCogStackvar v34; // [esp+90h] [ebp-10h]
    float fTmp;
    int iTmp;

    cog_ctx->script_running = 1;
    while ( 2 )
    {
        cogscript = cog_ctx->cogscript;
        pc = cog_ctx->cogscript_pc;
        if ( pc >= cog_ctx->cogscript->program_pc_max - 1 )
        {
            op = COG_OPCODE_RET;
        }
        else
        {
            pc_1 = pc + 1;
            op = cogscript->script_program[pc_1 - 1];
            cog_ctx->cogscript_pc = pc_1;
        }
        jk_printf("cog trace %s %x op %u\n", cog_ctx->cogscript->cog_fpath, cog_ctx->cogscript_pc, op);
        switch ( op )
        {
            case COG_OPCODE_NOP:
                break;

            case COG_OPCODE_PUSHINT:
                iTmp = sithCogVm_StackPopVal(cog_ctx);
                val.type = COG_VARTYPE_INT;
                val.data[0] = iTmp;
                sithCogVm_PushVar(cog_ctx, &val);
                break;

            case COG_OPCODE_PUSHFLOAT:
                iTmp = sithCogVm_StackPopVal(cog_ctx);
                val.type = COG_VARTYPE_FLEX;
                val.data[0] = iTmp;
                sithCogVm_PushVar(cog_ctx, &val);
                break;

            case COG_OPCODE_PUSHSYMBOL:
                iTmp = sithCogVm_StackPopVal(cog_ctx);
                val.type = COG_VARTYPE_SYMBOL;
                val.data[0] = iTmp;
                sithCogVm_PushVar(cog_ctx, &val);
                break;

            case COG_OPCODE_ARRAYINDEX:
                v18 = sithCogVm_PopInt(cog_ctx);
                v19 = sithCogVm_PopStackVar(cog_ctx, &v31);
                if ( v19 )
                    v19 = v31.type == 1 ? v31.data[0] : 0;
                v30.type = COG_VARTYPE_SYMBOL;
                v30.data[0] = v18 + v19;
                sithCogVm_PushVar(cog_ctx, &v30);
                break;

            case COG_OPCODE_CALLFUNC:
                if ( cog_ctx->callDepthDecrement < 1 )
                    break;
                v9 = &cog_ctx->variable_array[--cog_ctx->callDepthDecrement];
                if ( v9->type != COG_VARTYPE_SYMBOL )
                    break;
                v12 = sithCogParse_GetSymbol(cog_ctx->variable_hashmap_maybe, v9->data[0]);
                if (!v12 )
                    break;
                if (v12->val)
                    break;
                v13 = (void (__cdecl *)(sithCog *))v12->func;
                if ( v13 )
                    v13(cog_ctx);
                break;
            case COG_OPCODE_ASSIGN:
                if (!sithCogVm_PopStackVar(cog_ctx, &a3) )
                    break;

                v5 = sithCogVm_GetSymbolIdk(&v34, (int)cog_ctx, &a3);
                a3.type = v5->type;
                a3.data[0] = v5->data[0];
                a3.data[1] = v5->data[1];
                a3.data[2] = v5->data[2];

                if (!sithCogVm_PopStackVar(cog_ctx, &a2))
                    break;

                if (a2.type != COG_VARTYPE_SYMBOL)
                    break;
                        
                v6 = (sithCogStackvar *)&sithCogParse_GetSymbol(cog_ctx->variable_hashmap_maybe, a2.data[0])->val;
                *v6 = a3;
                break;
            case COG_OPCODE_PUSHVECTOR:
                _memcpy(v27.data, &cogscript->script_program[cog_ctx->cogscript_pc], sizeof(rdVector3));
                cog_ctx->cogscript_pc++;
                v27.type = COG_VARTYPE_VECTOR;
                sithCogVm_PushVar(cog_ctx, &v27);
                break;
            case COG_OPCODE_CMPFALSE:
                v24 = sithCogVm_PopInt(cog_ctx);
                v28.type = COG_VARTYPE_INT;
                v28.data[0] = v24 == 0;
                sithCogVm_PushVar(cog_ctx, &v28);
                break;
            case COG_OPCODE_NEG:
                *(float *)v28.data = -sithCogVm_PopFlex(cog_ctx);
                v28.type = COG_VARTYPE_FLEX;
                sithCogVm_PushVar(cog_ctx, &v28);
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
                v21 = sithCogVm_StackPopVal(cog_ctx);
                if ( !sithCogVm_PopInt(cog_ctx) )
                    cog_ctx->cogscript_pc = v21;
                break;
            case COG_OPCODE_GOTRUE:
                v20 = sithCogVm_StackPopVal(cog_ctx);
                if ( sithCogVm_PopInt(cog_ctx) )
                    cog_ctx->cogscript_pc = v20;
                break;
            case COG_OPCODE_GO:
                cog_ctx->cogscript_pc = sithCogVm_StackPopVal(cog_ctx);
                break;
            case COG_OPCODE_RET:
                if ( cog_ctx->flags & 1 )
                {
                    _sprintf(std_genBuffer, "Cog %s: Returned from depth %d.\n", cog_ctx->cogscript_fpath, cog_ctx->calldepth);
                    DebugConsole_Print(std_genBuffer);
                }
                sithCogVm_Ret(cog_ctx);
                break;
            case COG_OPCODE_CALL:
                if ( cog_ctx->calldepth < 4u )
                {
                    v22 = sithCogVm_StackPopVal(cog_ctx);
                    if ( v22 < cog_ctx->cogscript->program_pc_max )
                    {
                        sithCogVm_Call(cog_ctx);
                        cog_ctx->cogscript_pc = v22;
                    }
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
