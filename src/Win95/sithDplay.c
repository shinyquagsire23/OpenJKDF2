#include "sithDplay.h"

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

#ifndef WIN32_BLOBS
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

int sithDplay_Recv(void *a1)
{
    return 0;
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
