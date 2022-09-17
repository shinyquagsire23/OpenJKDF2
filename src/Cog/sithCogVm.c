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
#include "Dss/sithDSSThing.h"
#include "Dss/sithDSS.h"
#include "Dss/sithDSSCog.h"

#include <stdint.h>
#include <math.h>

int sithCogVm_Startup()
{
    if (sithCogVm_bInit)
        return 0;
    _memset(sithCogVm_msgFuncs, 0, sizeof(cogMsg_Handler) * 65);  // TODO define
    _memset(sithCogVm_aMsgPairs, 0, sizeof(sithCogMsg_Pair) * 0x80); // TODO define
    sithCogVm_dword_847E84 = 0;
    sithCogVm_msgId = 1;
    sithCogVm_msgFuncs[DSS_THINGPOS] = sithDSSThing_ProcessPos;
    sithCogVm_msgFuncs[DSS_FIREPROJECTILE] = sithDSSThing_ProcessFireProjectile;
    sithCogVm_msgFuncs[DSS_JOINREQUEST] = sithMulti_ProcessJoinRequest;
    sithCogVm_msgFuncs[DSS_WELCOME] = sithMulti_ProcessJoinLeave;
    sithCogVm_msgFuncs[DSS_DEATH] = sithDSSThing_ProcessDeath;
    sithCogVm_msgFuncs[DSS_DAMAGE] = sithDSSThing_ProcessDamage;
    sithCogVm_msgFuncs[DSS_SENDTRIGGER] = sithDSSCog_ProcessSendTrigger;
    sithCogVm_msgFuncs[DSS_SYNCTHING] = sithDSSThing_ProcessSyncThing;
    sithCogVm_msgFuncs[DSS_PLAYSOUNDPOS] = sithDSSThing_ProcessPlaySoundPos;
    sithCogVm_msgFuncs[DSS_PLAYKEY] = sithDSSThing_ProcessPlayKey;
    sithCogVm_msgFuncs[DSS_THINGFULLDESC] = sithDSSThing_ProcessFullDesc;
    sithCogVm_msgFuncs[DSS_SYNCCOG] = sithDSSCog_ProcessSyncCog;
    sithCogVm_msgFuncs[DSS_SURFACESTATUS] = sithDSS_ProcessSurfaceStatus;
    sithCogVm_msgFuncs[DSS_AISTATUS] = sithDSS_ProcessAIStatus;
    sithCogVm_msgFuncs[DSS_INVENTORY] = sithDSS_ProcessInventory;
    sithCogVm_msgFuncs[DSS_SURFACE] = sithDSS_ProcessSurface;
    sithCogVm_msgFuncs[DSS_SECTORSTATUS] = sithDSS_ProcessSectorStatus;
    sithCogVm_msgFuncs[DSS_SYNCTHINGFRAME] = sithDSSThing_ProcessSyncThingFrame;
    sithCogVm_msgFuncs[DSS_SYNCPUPPET] = sithDSS_ProcessSyncPuppet;
    sithCogVm_msgFuncs[DSS_LEAVEJOIN] = sithMulti_ProcessLeaveJoin;
    sithCogVm_msgFuncs[DSS_SYNCTHINGATTACHMENT] = sithDSSThing_ProcessSyncThingAttachment;
    sithCogVm_msgFuncs[DSS_SYNCEVENTS] = sithDSS_ProcessSyncEvents;
    sithCogVm_msgFuncs[DSS_SYNCCAMERAS] = sithDSS_ProcessSyncCameras;
    sithCogVm_msgFuncs[DSS_TAKEITEM1] = sithDSSThing_ProcessTakeItem;
    sithCogVm_msgFuncs[DSS_TAKEITEM2] = sithDSSThing_ProcessTakeItem;
    sithCogVm_msgFuncs[DSS_STOPKEY] = sithDSSThing_ProcessStopKey;
    sithCogVm_msgFuncs[DSS_STOPSOUND] = sithDSSThing_ProcessStopSound;
    sithCogVm_msgFuncs[DSS_CREATETHING] = sithDSSThing_ProcessCreateThing;
    sithCogVm_msgFuncs[DSS_SYNCPALEFFECTS] = sithDSS_ProcessSyncPalEffects;
    sithCogVm_msgFuncs[DSS_ID_1F] = sithDSS_ProcessMisc;
    sithCogVm_msgFuncs[DSS_CHAT] = sithMulti_ProcessChat;
    sithCogVm_msgFuncs[DSS_DESTROYTHING] = sithDSSThing_ProcessDestroyThing;
    sithCogVm_msgFuncs[DSS_SYNCSECTORALT] = sithDSS_ProcessSyncSectorAlt;
    sithCogVm_msgFuncs[DSS_SOUNDCLASSPLAY] = sithDSSThing_ProcessSoundClassPlay;
    sithCogVm_msgFuncs[DSS_OPENDOOR] = sithDSSThing_ProcessOpenDoor;
    sithCogVm_msgFuncs[DSS_SETTHINGMODEL] = sithDSSThing_ProcessSetThingModel;
    sithCogVm_msgFuncs[DSS_PING] = sithMulti_ProcessPing;
    sithCogVm_msgFuncs[DSS_PINGREPLY] = sithMulti_ProcessPingResponse;
    sithCogVm_msgFuncs[DSS_ENUMPLAYERS] = sithDplay_cogMsg_HandleEnumPlayers;
    sithCogVm_msgFuncs[DSS_RESET] = sithCogVm_cogMsg_Reset;
    sithCogVm_msgFuncs[DSS_KICK] = sithMulti_ProcessKickPlayer;
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
    sithCogVm_msgFuncs[msgid] = func;
}

int sithCogVm_SendMsgToPlayer(sithCogMsg *msg, int a2, int mpFlags, int a4)
{
    char multiplayerFlags; // bl
    unsigned int curMs; // esi
    __int16 v9; // ax
    unsigned int v10; // ebx
    int v11; // edi
    int idx; // ecx
    sithCogMsg *v14; // eax
    int v16; // eax
    sithCogMsg *v17; // edi
    int v19; // ecx
    int v20; // eax
    int idx_; // [esp+18h] [ebp+Ch]

    //printf("sithCogVm_SendMsgToPlayer %x %x %x %x\n", msg->netMsg.cogMsgId, a2, mpFlags, a4);

    int ret = 1;
    multiplayerFlags = sithCogVm_multiplayerFlags & mpFlags;
    if (!multiplayerFlags)
        return 1;
    curMs = sithTime_curMs;
    msg->netMsg.thingIdx = playerThingIdx;
    msg->netMsg.timeMs = curMs;
    if ( (multiplayerFlags & 1) != 0 )
    {
        if ( a4 )
        {
            v9 = sithCogVm_msgId;
            if ( !sithCogVm_msgId )
                v9 = 1;
            v10 = jkPlayer_maxPlayers;
            v11 = a2;
            msg->netMsg.msgId = v9;
            sithCogVm_msgId = v9 + 1;
            msg->netMsg.field_C = a2;
            idx_ = 0;
            msg->netMsg.timeMs2 = curMs;
            msg->netMsg.field_14 = 0;
            for (int i = 0; i < v10; i++)
            {
                if ( i != playerThingIdx && (jkPlayer_playerInfos[i].net_id == a2 || (a2 == -1 || !a2) && (jkPlayer_playerInfos[i].flags & 1) != 0) )
                    msg->netMsg.field_14 |= 1 << i;
                if (!i && i != playerThingIdx) {
                    msg->netMsg.field_14 |= 1 << i; // Added: Dedicated server hax
                }
            }
            if ( !msg->netMsg.field_14 )
                goto LABEL_35;
            
            for (idx = 0; idx < 32; idx++)
            {
                v14 = &sithCogVm_MsgTmpBuf[idx];
                if ( !v14->netMsg.msgId )
                    break;
                if ( v14->netMsg.timeMs < curMs )
                {
                    curMs = v14->netMsg.timeMs;
                    idx_ = idx;
                }
                ++v14;
            }

            if ( idx == 32 )
            {
                v16 = sithTime_curMs;
                v17 = &sithCogVm_MsgTmpBuf[idx_];
                v17->netMsg.field_18 = sithCogVm_MsgTmpBuf[idx_].netMsg.field_18 + 1;
                v17->netMsg.timeMs2 = v16;
                if ( v10 )
                {
                    for (unsigned int v15 = 0; v15 < jkPlayer_maxPlayers; v15++)
                    {
                        v19 = sithCogVm_MsgTmpBuf[idx_].netMsg.field_14;
                        if ( (v19 & (1 << v15)) != 0 )
                        {
                            if (jkPlayer_playerInfos[v15].net_id)
                                sithDplay_SendToPlayer(v17, jkPlayer_playerInfos[v15].net_id);
                            else
                                sithCogVm_MsgTmpBuf[idx_].netMsg.field_14 = ~(1 << v15) & v19;
                        }
                    }
                }
                if ( !sithCogVm_MsgTmpBuf[idx_].netMsg.field_14 || sithCogVm_MsgTmpBuf[idx_].netMsg.field_18 >= 6u )
                {
                    _memset(v17, 0, sizeof(sithCogMsg));
                    --sithCogVm_idk2;
                }
                idx = idx_;
                --sithCogVm_idk2;
            }
            ++sithCogVm_idk2;
            v20 = msg->netMsg.field_14;
            _memcpy(&sithCogVm_MsgTmpBuf[idx_], msg, sizeof(sithCogMsg));
            v11 = a2;
            if ( !v20 )
LABEL_35:
                msg->netMsg.msgId = 0;
        }
        else
        {
            v11 = a2;
            msg->netMsg.msgId = 0;
        }
        ret = sithDplay_SendToPlayer(msg, v11);
    }
    if ( (multiplayerFlags & 4) != 0 )
    {
        sithCogVm_FileWrite(msg);
    }
    return ret;
}

void sithCogVm_FileWrite(sithCogMsg *ctx)
{
    stdConffile_Write((const char*)&ctx->netMsg.cogMsgId, sizeof(int));
    stdConffile_Write((const char*)&ctx->netMsg.msg_size, sizeof(int));
    stdConffile_Write((const char*)&ctx->pktData[0], ctx->netMsg.msg_size);
}

int sithCogVm_Sync()
{
    int v1; // eax
    uint16_t v2; // dx
    uint32_t *v3; // ecx
    int v4; // eax
    int v12; // ecx
    int v13; // [esp+4h] [ebp-4h]

    v13 = 0;
    sithCogVm_needsSync = 0;
    if ( !sithCogVm_bSyncMultiplayer )
        return 0;
    while ( sithDplay_Recv(&sithCogVm_netMsgTmp) == 1 )
    {
        ++v13;
        if ( sithCogVm_netMsgTmp.netMsg.thingIdx )
        {
            v1 = sithPlayer_ThingIdxToPlayerIdx(sithCogVm_netMsgTmp.netMsg.thingIdx);
            v2 = sithCogVm_netMsgTmp.netMsg.cogMsgId;
            if ( v1 >= 0 )
            {
                jkPlayer_playerInfos[v1].lastUpdateMs = sithTime_curMs;
LABEL_14:
                if ( sithCogVm_netMsgTmp.netMsg.msgId )
                {
                    sithCogVm_MsgTmpBuf2.netMsg.msgId = 0;
                    *(uint16_t*)sithCogVm_MsgTmpBuf2.pktData = sithCogVm_netMsgTmp.netMsg.msgId;
                    sithCogVm_MsgTmpBuf2.netMsg.field_C = sithCogVm_netMsgTmp.netMsg.thingIdx;
                    sithCogVm_MsgTmpBuf2.netMsg.cogMsgId = DSS_RESET;
                    sithCogVm_MsgTmpBuf2.netMsg.msg_size = 2;
                    sithDplay_SendToPlayer(&sithCogVm_MsgTmpBuf2, sithCogVm_netMsgTmp.netMsg.thingIdx);
                    
                    int i = 0;
                    v4 = (uint16_t)sithCogVm_netMsgTmp.netMsg.msgId;
                    while ( sithCogVm_netMsgTmp.netMsg.thingIdx != sithCogVm_aMsgPairs[i].thingIdx || (uint16_t)sithCogVm_netMsgTmp.netMsg.msgId != sithCogVm_aMsgPairs[i].msgId )
                    {
                        i++;
                        if ( i >= 128 )
                        {
                            sithCogVm_aMsgPairs[sithCogVm_dword_847E84].thingIdx = sithCogVm_netMsgTmp.netMsg.thingIdx;
                            sithCogVm_aMsgPairs[sithCogVm_dword_847E84].msgId = v4;
                            sithCogVm_dword_847E84++;
                            if ( sithCogVm_dword_847E84 >= 0x80 )
                                sithCogVm_dword_847E84 = 0;
                            v2 = sithCogVm_netMsgTmp.netMsg.cogMsgId;
                            goto LABEL_22;
                        }
                    }
                }
                else
                {
LABEL_22:
                    if ( v2 < (unsigned int)DSS_MAX )
                    {
                        if ( sithCogVm_msgFuncs[v2] )
                            sithCogVm_msgFuncs[v2](&sithCogVm_netMsgTmp);
                    }
                }
                goto LABEL_25;
            }
            if ( sithCogVm_netMsgTmp.netMsg.cogMsgId == DSS_WELCOME
              || sithCogVm_netMsgTmp.netMsg.cogMsgId == DSS_JOINREQUEST
              || sithCogVm_netMsgTmp.netMsg.cogMsgId == DSS_RESET
              || sithCogVm_netMsgTmp.netMsg.cogMsgId == DSS_LEAVEJOIN
              || (g_submodeFlags & 8) != 0 )
            {
                goto LABEL_14;
            }
            if ( sithNet_isServer )
                sithMulti_SendKickPlayer(sithCogVm_netMsgTmp.netMsg.thingIdx);
        }
LABEL_25:
        if ( sithCogVm_needsSync )
            break;
    }
    sithCogVm_SyncWithPlayers();
    return v13;
}

void sithCogVm_SetNeedsSync()
{
    sithCogVm_needsSync = 1;
}

int sithCogVm_InvokeMsgByIdx(sithCogMsg *a1)
{
    int result; // eax

    int msgId = a1->netMsg.cogMsgId;

    if ( (signed int)(uint16_t)msgId < 65 && sithCogVm_msgFuncs[msgId])
        result = sithCogVm_msgFuncs[msgId](a1);
    else
        result = 1;
    return result;
}

void sithCogVm_SyncWithPlayers()
{
    if ( sithCogVm_idk2 )
    {
        
        for (int i = 0; i < 32; i++)
        {
            if (!sithCogVm_MsgTmpBuf[i].netMsg.msgId)
                continue;

            if ( sithCogVm_MsgTmpBuf[i].netMsg.timeMs2 + 1700 <= sithTime_curMs )
            {
                sithCogVm_MsgTmpBuf[i].netMsg.field_18++;
                sithCogVm_MsgTmpBuf[i].netMsg.timeMs2 = sithTime_curMs;

                for (int v9 = 0; v9 < jkPlayer_maxPlayers; v9++)
                {
                    if (sithCogVm_MsgTmpBuf[i].netMsg.field_14 & (1 << v9))
                    {
                        if (jkPlayer_playerInfos[v9].net_id)
                            sithDplay_SendToPlayer(&sithCogVm_MsgTmpBuf[i], jkPlayer_playerInfos[v9].net_id);
                        else
                            sithCogVm_MsgTmpBuf[i].netMsg.field_14 &= ~(1 << v9);
                    }
                }

                if ( !sithCogVm_MsgTmpBuf[i].netMsg.field_14 || sithCogVm_MsgTmpBuf[i].netMsg.field_18 >= 6 )
                {
                    _memset(&sithCogVm_MsgTmpBuf[i], 0, sizeof(sithCogMsg));
                    --sithCogVm_idk2;
                }
            }
        }
    }
}

void sithCogVm_ClearMsgTmpBuf()
{
    _memset(sithCogVm_MsgTmpBuf, 0, sizeof(sithCogVm_MsgTmpBuf));
    sithCogVm_idk2 = 0;
}

int sithCogVm_cogMsg_Reset(sithCogMsg *msg)
{
    int v1; // edi
    char playerIdx; // al
    
    int foundIdx;

    NETMSG_IN_START(msg);

    v1 = NETMSG_POPS16();
    playerIdx = sithPlayer_ThingIdxToPlayerIdx(msg->netMsg.thingIdx);
    foundIdx = 0;
    
    for (foundIdx = 0; foundIdx < 32; foundIdx++)
    {
        if (sithCogVm_MsgTmpBuf[foundIdx].netMsg.msgId == v1 )
            break;
    }

    if ( foundIdx != 32 )
    {
        sithCogVm_MsgTmpBuf[foundIdx].netMsg.field_14 &= ~(1 << playerIdx);
        if (!sithCogVm_MsgTmpBuf[foundIdx].netMsg.field_14)
        {
            _memset(&sithCogVm_MsgTmpBuf[foundIdx], 0, sizeof(sithCogMsg));
            --sithCogVm_idk2;
        }
    }

    return 1;
}

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
