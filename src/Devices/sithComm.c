#include "sithComm.h"

#include "Dss/sithMulti.h"
#include "Dss/sithDSSThing.h"
#include "Dss/sithDSS.h"
#include "Dss/sithDSSCog.h"
#include "Win95/stdComm.h"
#include "jk.h"

int sithComm_009a1160 = 0;
int sithComm_version = 6;

// MOTS altered
int sithComm_Startup()
{
    if (sithComm_bInit)
        return 0;
    _memset(sithComm_msgFuncs, 0, sizeof(cogMsg_Handler) * 65);  // TODO define
    _memset(sithComm_aMsgPairs, 0, sizeof(sithCogMsg_Pair) * 0x80); // TODO define
    sithComm_dword_847E84 = 0;
    sithComm_msgId = 1;
    sithComm_msgFuncs[DSS_THINGPOS] = sithDSSThing_ProcessPos;
    sithComm_msgFuncs[DSS_FIREPROJECTILE] = sithDSSThing_ProcessFireProjectile;
    sithComm_msgFuncs[DSS_JOINREQUEST] = sithMulti_ProcessJoinRequest;
    sithComm_msgFuncs[DSS_WELCOME] = sithMulti_ProcessJoinLeave;
    sithComm_msgFuncs[DSS_DEATH] = sithDSSThing_ProcessDeath;
    sithComm_msgFuncs[DSS_DAMAGE] = sithDSSThing_ProcessDamage;
    sithComm_msgFuncs[DSS_SENDTRIGGER] = sithDSSCog_ProcessSendTrigger;
    sithComm_msgFuncs[DSS_SYNCTHING] = sithDSSThing_ProcessSyncThing;
    sithComm_msgFuncs[DSS_PLAYSOUND] = sithDSSThing_ProcessPlaySound;
    sithComm_msgFuncs[DSS_PLAYKEY] = sithDSSThing_ProcessPlayKey;
    sithComm_msgFuncs[DSS_THINGFULLDESC] = sithDSSThing_ProcessFullDesc;
    sithComm_msgFuncs[DSS_SYNCCOG] = sithDSSCog_ProcessSyncCog;
    sithComm_msgFuncs[DSS_SURFACESTATUS] = sithDSS_ProcessSurfaceStatus;
    sithComm_msgFuncs[DSS_AISTATUS] = sithDSS_ProcessAIStatus;
    sithComm_msgFuncs[DSS_INVENTORY] = sithDSS_ProcessInventory;
    sithComm_msgFuncs[DSS_SURFACE] = sithDSS_ProcessSurface;
    sithComm_msgFuncs[DSS_SECTORSTATUS] = sithDSS_ProcessSectorStatus;
    sithComm_msgFuncs[DSS_PATHMOVE] = sithDSSThing_ProcessPathMove;
    sithComm_msgFuncs[DSS_SYNCPUPPET] = sithDSS_ProcessSyncPuppet;
    sithComm_msgFuncs[DSS_LEAVEJOIN] = sithMulti_ProcessLeaveJoin;
    sithComm_msgFuncs[DSS_SYNCTHINGATTACHMENT] = sithDSSThing_ProcessSyncThingAttachment;
    sithComm_msgFuncs[DSS_SYNCEVENTS] = sithDSS_ProcessSyncEvents;
    sithComm_msgFuncs[DSS_SYNCCAMERAS] = sithDSS_ProcessSyncCameras;
    sithComm_msgFuncs[DSS_TAKEITEM1] = sithDSSThing_ProcessTakeItem;
    sithComm_msgFuncs[DSS_TAKEITEM2] = sithDSSThing_ProcessTakeItem;
    sithComm_msgFuncs[DSS_STOPKEY] = sithDSSThing_ProcessStopKey;
    sithComm_msgFuncs[DSS_STOPSOUND] = sithDSSThing_ProcessStopSound;
    sithComm_msgFuncs[DSS_CREATETHING] = sithDSSThing_ProcessCreateThing;
    sithComm_msgFuncs[DSS_SYNCPALEFFECTS] = sithDSS_ProcessSyncPalEffects;
    sithComm_msgFuncs[DSS_ID_1F] = sithDSS_ProcessMisc;
    sithComm_msgFuncs[DSS_CHAT] = sithMulti_ProcessChat;
    sithComm_msgFuncs[DSS_DESTROYTHING] = sithDSSThing_ProcessDestroyThing;
    sithComm_msgFuncs[DSS_SECTORFLAGS] = sithDSS_ProcessSectorFlags;
    sithComm_msgFuncs[DSS_PLAYSOUNDMODE] = sithDSSThing_ProcessPlaySoundMode;
    sithComm_msgFuncs[DSS_PLAYKEYMODE] = sithDSSThing_ProcessPlayKeyMode;
    sithComm_msgFuncs[DSS_SETTHINGMODEL] = sithDSSThing_ProcessSetThingModel;
    sithComm_msgFuncs[DSS_PING] = sithMulti_ProcessPing;
    sithComm_msgFuncs[DSS_PINGREPLY] = sithMulti_ProcessPingResponse;
    sithComm_msgFuncs[DSS_ENUMPLAYERS] = stdComm_cogMsg_HandleEnumPlayers;
    sithComm_msgFuncs[DSS_RESET] = sithComm_cogMsg_Reset;
    sithComm_msgFuncs[DSS_QUIT] = sithMulti_ProcessQuit;

    if (Main_bMotsCompat) {
        sithComm_msgFuncs[DSS_MOTS_NEW_1] = sithDSSThing_ProcessMOTSNew1;
        sithComm_msgFuncs[DSS_MOTS_NEW_2] = sithDSSThing_ProcessMOTSNew2;
    }

    // Added: clean reset
    sithComm_009a1160 = 0;
    sithComm_version = 6;

    sithComm_bInit = 1;
    return 1;
}

void sithComm_Shutdown()
{
    if ( sithComm_bInit )
        sithComm_bInit = 0;

    // Added: clean reset
    sithComm_009a1160 = 0;
    sithComm_version = 6;
}

void sithComm_SetMsgFunc(int msgid, void *func)
{
    sithComm_msgFuncs[msgid] = func;
}

// MOTS altered
int sithComm_SendMsgToPlayer(sithCogMsg *msg, int a2, int mpFlags, int a4)
{
    char multiplayerFlags; // bl
    unsigned int curMs; // esi
    __int16 v9; // ax
    int idx; // ecx
    sithCogMsg *v14; // eax
    sithCogMsg *v17; // edi
    int v19; // ecx
    int v20; // eax
    int idx_; // [esp+18h] [ebp+Ch]

    //printf("sithComm_SendMsgToPlayer %x %x %x %x\n", msg->netMsg.cogMsgId, a2, mpFlags, a4);

    int ret = 1;
    multiplayerFlags = sithComm_multiplayerFlags & mpFlags;
    if (!multiplayerFlags)
        return 1;
    curMs = sithTime_curMs;
    msg->netMsg.thingIdx = playerThingIdx;
    msg->netMsg.timeMs = curMs;
    if ( (multiplayerFlags & 1) != 0 )
    {
        if ( a4 )
        {
            v9 = sithComm_msgId;
            if ( !sithComm_msgId )
                v9 = 1;
            msg->netMsg.msgId = v9;
            sithComm_msgId = v9 + 1;
            msg->netMsg.field_C = a2;
            idx_ = 0;
            msg->netMsg.timeMs2 = curMs;
            msg->netMsg.field_14 = 0;
            for (int i = 0; i < jkPlayer_maxPlayers; i++)
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
                v14 = &sithComm_MsgTmpBuf[idx];
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
                v17 = &sithComm_MsgTmpBuf[idx_];
                v17->netMsg.field_18++;
                v17->netMsg.timeMs2 = sithTime_curMs;
                for (unsigned int v15 = 0; v15 < jkPlayer_maxPlayers; v15++)
                {
                    v19 = sithComm_MsgTmpBuf[idx_].netMsg.field_14;
                    if ( (v19 & (1 << v15)) != 0 )
                    {
                        if (jkPlayer_playerInfos[v15].net_id)
                            stdComm_SendToPlayer(v17, jkPlayer_playerInfos[v15].net_id);
                        else
                            sithComm_MsgTmpBuf[idx_].netMsg.field_14 = ~(1 << v15) & v19;
                    }
                }
                if ( !sithComm_MsgTmpBuf[idx_].netMsg.field_14 || sithComm_MsgTmpBuf[idx_].netMsg.field_18 >= 6u )
                {
                    _memset(v17, 0, sizeof(sithCogMsg));
                    --sithComm_idk2;
                }
                idx = idx_;
                --sithComm_idk2;
            }
            ++sithComm_idk2;
            v20 = msg->netMsg.field_14;
            _memcpy(&sithComm_MsgTmpBuf[idx_], msg, sizeof(sithCogMsg));
            if ( !v20 )
LABEL_35:
                msg->netMsg.msgId = 0;
        }
        else
        {
            msg->netMsg.msgId = 0;
        }
        ret = stdComm_SendToPlayer(msg, a2);
    }
    if ( (multiplayerFlags & 4) != 0 )
    {
        sithComm_FileWrite(msg);
    }
    return ret;
}

// MOTS altered
void sithComm_FileWrite(sithCogMsg* ctx)
{
    // Added: multiple version handling
    if (sithComm_version == 0x7D6) {
        stdConffile_Write((const char*)&sithComm_009a1160, sizeof(sithComm_009a1160));
    }
    stdConffile_Write((const char*)&ctx->netMsg.cogMsgId, sizeof(int));
    stdConffile_Write((const char*)&ctx->netMsg.msg_size, sizeof(int));
    stdConffile_Write((const char*)&ctx->pktData[0], ctx->netMsg.msg_size);
}

// MOTS altered
int sithComm_Sync()
{
    int v1; // eax
    uint16_t v2; // dx
    uint32_t *v3; // ecx
    int v4; // eax
    int v12; // ecx
    int v13; // [esp+4h] [ebp-4h]

    v13 = 0;
    sithComm_needsSync = 0;
    if ( !sithComm_bSyncMultiplayer )
        return 0;
    while ( stdComm_Recv(&sithComm_netMsgTmp) == 1 )
    {
        ++v13;
        if ( sithComm_netMsgTmp.netMsg.thingIdx )
        {
            v1 = sithPlayer_ThingIdxToPlayerIdx(sithComm_netMsgTmp.netMsg.thingIdx);
            v2 = sithComm_netMsgTmp.netMsg.cogMsgId;
            if ( v1 >= 0 )
            {
                jkPlayer_playerInfos[v1].lastUpdateMs = sithTime_curMs;
LABEL_14:
                if ( sithComm_netMsgTmp.netMsg.msgId )
                {
                    sithComm_MsgTmpBuf2.netMsg.msgId = 0;
                    *(uint16_t*)sithComm_MsgTmpBuf2.pktData = sithComm_netMsgTmp.netMsg.msgId;
                    sithComm_MsgTmpBuf2.netMsg.field_C = sithComm_netMsgTmp.netMsg.thingIdx;
                    sithComm_MsgTmpBuf2.netMsg.cogMsgId = DSS_RESET;
                    sithComm_MsgTmpBuf2.netMsg.msg_size = 2;
                    stdComm_SendToPlayer(&sithComm_MsgTmpBuf2, sithComm_netMsgTmp.netMsg.thingIdx);
                    
                    int i = 0;
                    v4 = (uint16_t)sithComm_netMsgTmp.netMsg.msgId;
                    while ( sithComm_netMsgTmp.netMsg.thingIdx != sithComm_aMsgPairs[i].thingIdx || (uint16_t)sithComm_netMsgTmp.netMsg.msgId != sithComm_aMsgPairs[i].msgId )
                    {
                        i++;
                        if ( i >= 128 )
                        {
                            sithComm_aMsgPairs[sithComm_dword_847E84].thingIdx = sithComm_netMsgTmp.netMsg.thingIdx;
                            sithComm_aMsgPairs[sithComm_dword_847E84].msgId = v4;
                            sithComm_dword_847E84++;
                            if ( sithComm_dword_847E84 >= 0x80 )
                                sithComm_dword_847E84 = 0;
                            v2 = sithComm_netMsgTmp.netMsg.cogMsgId;
                            goto LABEL_22;
                        }
                    }
                }
                else
                {
LABEL_22:
                    if ( v2 < (unsigned int)DSS_MAX )
                    {
                        if ( sithComm_msgFuncs[v2] )
                            sithComm_msgFuncs[v2](&sithComm_netMsgTmp);
                    }
                }
                goto LABEL_25;
            }
            if ( sithComm_netMsgTmp.netMsg.cogMsgId == DSS_WELCOME
              || sithComm_netMsgTmp.netMsg.cogMsgId == DSS_JOINREQUEST
              || sithComm_netMsgTmp.netMsg.cogMsgId == DSS_RESET
              || sithComm_netMsgTmp.netMsg.cogMsgId == DSS_LEAVEJOIN
              || (g_submodeFlags & 8) != 0 )
            {
                goto LABEL_14;
            }
            if ( sithNet_isServer )
                sithMulti_SendQuit(sithComm_netMsgTmp.netMsg.thingIdx);
        }
LABEL_25:
        if ( sithComm_needsSync )
            break;
    }
    sithComm_SyncWithPlayers();
    return v13;
}

void sithComm_SetNeedsSync()
{
    sithComm_needsSync = 1;
}

int sithComm_InvokeMsgByIdx(sithCogMsg *a1)
{
    int result; // eax

    int msgId = a1->netMsg.cogMsgId;

    if ( (signed int)(uint16_t)msgId < 65 && sithComm_msgFuncs[msgId])
        result = sithComm_msgFuncs[msgId](a1);
    else
        result = 1;
    return result;
}

void sithComm_SyncWithPlayers()
{
    if ( sithComm_idk2 )
    {
        
        for (int i = 0; i < 32; i++)
        {
            if (!sithComm_MsgTmpBuf[i].netMsg.msgId)
                continue;

            if ( sithComm_MsgTmpBuf[i].netMsg.timeMs2 + 1700 <= sithTime_curMs )
            {
                sithComm_MsgTmpBuf[i].netMsg.field_18++;
                sithComm_MsgTmpBuf[i].netMsg.timeMs2 = sithTime_curMs;

                for (int v9 = 0; v9 < jkPlayer_maxPlayers; v9++)
                {
                    if (sithComm_MsgTmpBuf[i].netMsg.field_14 & (1 << v9))
                    {
                        if (jkPlayer_playerInfos[v9].net_id)
                            stdComm_SendToPlayer(&sithComm_MsgTmpBuf[i], jkPlayer_playerInfos[v9].net_id);
                        else
                            sithComm_MsgTmpBuf[i].netMsg.field_14 &= ~(1 << v9);
                    }
                }

                if ( !sithComm_MsgTmpBuf[i].netMsg.field_14 || sithComm_MsgTmpBuf[i].netMsg.field_18 >= 6 )
                {
                    _memset(&sithComm_MsgTmpBuf[i], 0, sizeof(sithCogMsg));
                    --sithComm_idk2;
                }
            }
        }
    }
}

void sithComm_ClearMsgTmpBuf()
{
    _memset(sithComm_MsgTmpBuf, 0, sizeof(sithComm_MsgTmpBuf));
    sithComm_idk2 = 0;
}

int sithComm_cogMsg_Reset(sithCogMsg *msg)
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
        if (sithComm_MsgTmpBuf[foundIdx].netMsg.msgId == v1 )
            break;
    }

    if ( foundIdx != 32 )
    {
        sithComm_MsgTmpBuf[foundIdx].netMsg.field_14 &= ~(1 << playerIdx);
        if (!sithComm_MsgTmpBuf[foundIdx].netMsg.field_14)
        {
            _memset(&sithComm_MsgTmpBuf[foundIdx], 0, sizeof(sithCogMsg));
            --sithComm_idk2;
        }
    }

    return 1;
}