#include "sithDplay.h"

#include "Engine/sithMulti.h"
#include "jk.h"

int sithDplay_Startup()
{
    if ( sithDplay_bInitted )
        return 0;

#ifdef TARGET_HAS_DPLAY
    DirectPlay_Initialize();
#endif

#ifndef WIN32_BLOBS
    jkGuiMultiplayer_numConnections = 1;
    jk_snwprintf(jkGuiMultiplayer_aConnections[0].name, 0x80, L"OpenJKDF2 TCP");
    sithDplay_dword_8321E0 = 1;
#endif
    sithDplay_bInitted = 1;

    return 1;
}

HRESULT sithDplay_EnumSessions2(void)
{
    return DirectPlay_EnumSessions2();
}

int sithDplay_Recv(sithCogMsg *msg)
{
    sithCogMsg *pMsg; // esi
    signed int v2; // eax
    int v6; // eax
    int msgBytes; // [esp+4h] [ebp-4h] BYREF

    pMsg = msg;
    msgBytes = 2052;
    int playerId = 0;
    v2 = DirectPlay_Receive(&playerId, &msg->netMsg.cogMsgId, &msgBytes);
    if ( v2 != -1 )
    {
        if ( !v2 )
        {
            pMsg->netMsg.thingIdx = playerId;
            pMsg->netMsg.msg_size = msgBytes - 4;
            pMsg->netMsg.timeMs = sithTime_curMs;
            return 1;
        }
        if ( (g_submodeFlags & 8) == 0 )
        {
            v6 = v2 - 2;
            if ( v6 )
            {
                if ( v6 == 3 && sithNet_isServer )
                {
                    sithMulti_SendLeaveJoin(playerId, 1);
                    return 0;
                }
            }
            else
            {
                sithMulti_sub_4CA470(playerId);
            }
        }
    }
    return 0;
}

#ifndef WIN32_BLOBS
int DirectPlay_Receive(int *pIdOut, int *pMsgIdOut, int *pLenOut)
{
    *pIdOut = 0;
    *pMsgIdOut = 0;
    *pLenOut = 0;
    return 1;
}

int sithDplay_EarlyInit()
{
    return 0;
}

int sithDplay_OpenConnection(void* a)
{
    return 0;
}

void sithDplay_CloseConnection()
{
}

int sithDplay_Open(int a, void* b)
{
    return 0;
}

int sithDplay_seed_idk(void* a)
{
    return 0;
}

int sithDplay_CreatePlayer(void* a)
{
    return 0;
}

int sithDplay_DoReceive()
{
    return 1;
}

void sithDplay_Close()
{

}

BOOL sithDplay_SendToPlayer(void *a1, int sendto_id)
{
    return 1;
}

int DirectPlay_SendLobbyMessage(void* pPkt, uint32_t pktLen)
{
    return 1;
}

int DirectPlay_EnumSessions2()
{
    return 0;
}
#endif
