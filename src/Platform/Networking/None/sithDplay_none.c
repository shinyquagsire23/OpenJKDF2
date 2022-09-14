#include "sithDplay_none.h"

#include "Win95/sithDplay.h"
#include "Engine/sithMulti.h"
#include "General/stdString.h"
#include "jk.h"

void Hack_ResetClients()
{
    DirectPlay_numPlayers = 2;
    DirectPlay_aPlayers[0].dpId = 1;
    jk_snwprintf(DirectPlay_aPlayers[0].waName, 32, L"asdf1");

    DirectPlay_aPlayers[1].dpId = 2;
    jk_snwprintf(DirectPlay_aPlayers[1].waName, 32, L"asdf2");

    int id_self = 1;
    int id_other = 2;
    if (!sithDplay_bIsServer)
    {
        id_self = 2;
        id_other = 1;
    }
    //jkPlayer_playerInfos[0].net_id = id_self;
    //jkPlayer_playerInfos[1].net_id = id_other;
    //jk_snwprintf(jkPlayer_playerInfos[0].player_name, 32, "asdf1");
    //jk_snwprintf(jkPlayer_playerInfos[1].player_name, 32, "asdf2");

    jkPlayer_maxPlayers = 2;
}

void sithDplay_None_Startup()
{
    jkGuiMultiplayer_numConnections = 1;
    jk_snwprintf(jkGuiMultiplayer_aConnections[0].name, 0x80, L"Screaming Into The Void");
    sithDplay_dword_8321E0 = 0;

    memset(jkGuiMultiplayer_aEntries, 0, sizeof(jkMultiEntry) * 32);
    dplay_dword_55D618 = 1;
    jk_snwprintf(jkGuiMultiplayer_aEntries[0].serverName, 0x20, L"OpenJKDF2 Loopback");
    stdString_snprintf(jkGuiMultiplayer_aEntries[0].episodeGobName, 0x20, "JK1MP");
    stdString_snprintf(jkGuiMultiplayer_aEntries[0].mapJklFname, 0x20, "m2.jkl");
    jkGuiMultiplayer_aEntries[0].field_E0 = 10;

    Hack_ResetClients();
}

int DirectPlay_Receive(int *pIdOut, int *pMsgIdOut, int *pLenOut)
{
    return -1;
}

BOOL DirectPlay_Send(DPID idFrom, DPID idTo, void *lpData, DWORD dwDataSize)
{
    return 0;
}

int sithDplay_OpenConnection(void* a)
{
    sithDplay_dword_8321DC = 1;
    return 0;
}

void sithDplay_CloseConnection()
{

}

int sithDplay_Open(int idx, wchar_t* pwPassword)
{
    return 1;
}

void sithDplay_Close()
{

}

int DirectPlay_SendLobbyMessage(void* pPkt, uint32_t pktLen)
{
    return 1;
}

int DirectPlay_EnumSessions2()
{
    return 0;
}

void DirectPlay_SetSessionDesc(const char* a1, DWORD maxPlayers)
{

}

BOOL DirectPlay_SetSessionFlagidk(int a1)
{
    return 1;
}

BOOL DirectPlay_Initialize()
{
    //IDirectPlay3Vtbl *v0; // esi
    //uint32_t *v1; // eax

    //CoInitialize(0);
    //CoCreateInstance(&rclsid, 0, 1u, &riid, (LPVOID *)&idirectplay);
    jkGuiMultiplayer_numConnections = 0;
    memset(&jkGuiMultiplayer_aConnections, 0, 0x1180u);
    //v0 = idirectplay->lpVtbl;
    //v1 = WinIdk_GetDplayGuid();
    //return v0->EnumConnections(idirectplay, (LPCGUID)v1, (LPDPENUMCONNECTIONSCALLBACK)DirectPlay_EnumConnectionsCallback, 0, 0) >= 0;
    return 1;
}

int DirectPlay_EarlyInit(wchar_t* pwIdk, wchar_t* pwPlayerName)
{
    // This can launch straight into a game? Gaming Zone stuff. 1 and 2 autolaunch an MP game.
    return 0;
}

DPID DirectPlay_CreatePlayer(wchar_t* pwIdk, int idk2)
{
    return 1;
}

void DirectPlay_Close()
{
    
}

int DirectPlay_OpenHost(jkMultiEntry* a)
{
    
    return 0;
}

int DirectPlay_GetSession_passwordidk(jkMultiEntry* a)
{
    return 1;
}

int sithDplay_EnumSessions(int a, void* b)
{
    return 0;
}

void DirectPlay_EnumPlayers(int a)
{
}

int DirectPlay_StartSession(void* a, void* b)
{
    return 1;
}

void DirectPlay_Destroy()
{
    
}

int DirectPlay_IdkSessionDesc(jkMultiEntry* pEntry)
{
    //TODO
    return 1;
}