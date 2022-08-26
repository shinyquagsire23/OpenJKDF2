#include "sithDplay_basic.h"

#include "Win95/sithDplay.h"
#include "Engine/sithMulti.h"
#include "General/stdString.h"
#include "jk.h"

#if defined(WIN64_MINGW)
typedef size_t socklen_t;
//#include <arpa/inet.h>
//#include <netinet/in.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
//#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#elif defined(WIN32_BLOBS)

#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#define SITHDPLAY_ADDRESS "127.0.0.1"
#define SITHDPLAY_PORT 3500
#define BUFSIZE 4096

int DirectPlay_sock = -1;
int DirectPlay_clientSocks[32];

typedef struct DPlayPktWrap
{
    DPID idFrom;
    DPID idTo;
    void* data;
    uint32_t dataSize;
} DPlayPktWrap;

enum MyDplayState
{
    STATE_FINDMAGIC = 0,
    STATE_READLEN = 1,
    STATE_READING = 2,
};

#define MYDPLAY_MAGIC (0xAA55F00F)
#define DPLAY_OUTQUEUE_LEN (256)
DPlayPktWrap aDplayOutgoing[DPLAY_OUTQUEUE_LEN] = {0};
int MyDplay_hasClient = 0;
struct sockaddr_in MyDplay_addr = {0};
int MyDplay_curState = STATE_FINDMAGIC;

uint8_t MyDplay_sendBuffer[4096];
uint32_t MyDplay_amtSent = 0;

uint8_t MyDplay_readBuffer[4096];
uint32_t MyDplay_amtRead = 0;

void Hack_ResetClients()
{
    DirectPlay_numPlayers = 2;
    DirectPlay_aPlayers[0].dpId = 1;
    jk_snwprintf(DirectPlay_aPlayers[0].waName, 32, L"asdf1");

    DirectPlay_aPlayers[1].dpId = 2;
    jk_snwprintf(DirectPlay_aPlayers[1].waName, 32, L"asdf2");

    int id_self = 1;
    int id_other = 2;
    if (!sithDplay_dword_8321E4)
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

void sithDplay_Basic_Startup()
{
    jkGuiMultiplayer_numConnections = 1;
    jk_snwprintf(jkGuiMultiplayer_aConnections[0].name, 0x80, L"OpenJKDF2 TCP");
    sithDplay_dword_8321E0 = 0;

    memset(jkGuiMultiplayer_aEntries, 0, sizeof(jkMultiEntry) * 32);
    dplay_dword_55D618 = 1;
    jk_snwprintf(jkGuiMultiplayer_aEntries[0].field_18, 0x20, L"OpenJKDF2 Loopback");
    stdString_snprintf(jkGuiMultiplayer_aEntries[0].field_58, 0x20, "JK1MP");
    stdString_snprintf(jkGuiMultiplayer_aEntries[0].field_78, 0x20, "m2.jkl");
    jkGuiMultiplayer_aEntries[0].field_E0 = 10;

    for (int i = 0; i < 32; i++)
    {
        DirectPlay_clientSocks[i] = -1;
    }

    Hack_ResetClients();
}

void MyDplay_CheckIncoming()
{
    if (!sithDplay_dword_8321E4) return;
    if (MyDplay_hasClient) return;

    socklen_t socklen = sizeof MyDplay_addr;
    int client_sock = accept(DirectPlay_sock, &MyDplay_addr, &socklen); /* 2nd and 3rd argument may be NULL. */
    if (client_sock < 0) {
        //TODO: specific error checks
        return;
    }

#ifdef WIN64_MINGW
    u_long iMode = 0;
    ioctlsocket(client_sock, FIONBIO, &iMode);
#else
    fcntl(client_sock, F_SETFL, O_NONBLOCK);
#endif

    printf("Client with IP %s connected\n", inet_ntoa(MyDplay_addr.sin_addr));

    for (int i = 0; i < 32; i++)
    {
        DirectPlay_clientSocks[i] = client_sock;
    }
    MyDplay_hasClient = 1;
}

int DirectPlay_ReceiveLoopback(int *pIdOut, int *pMsgIdOut, int *pLenOut)
{
    int pMsgIdOut_size = *pLenOut;

    // Loopback
    DPlayPktWrap* pPkt = NULL;
    for (int i = 0; i < DPLAY_OUTQUEUE_LEN; i++)
    {
        if (aDplayOutgoing[i].data)
        {
            pPkt = &aDplayOutgoing[i];
            break;
        }
    }
    if (!pPkt) return -1;

    if (pMsgIdOut_size > pPkt->dataSize)
        pMsgIdOut_size = pPkt->dataSize;

    *pIdOut = pPkt->idFrom;
    memcpy((void*)pMsgIdOut, pPkt->data, pMsgIdOut_size);
    *pLenOut = pMsgIdOut_size;

    // Clear the packet
    pPkt->idFrom = 0;
    pPkt->idTo = 0;
    free(pPkt->data);
    pPkt->data = NULL;
    pPkt->dataSize = 0;

    printf("[L] Recv %x bytes from %x (%x)\n", pMsgIdOut_size, pPkt->idFrom, *pMsgIdOut);

    return 0;
}

int DirectPlay_Receive(int *pIdOut, int *pMsgIdOut, int *pLenOut)
{
    int idRecv = sithDplay_dword_8321E4 ? 2 : 1;
    int pMsgIdOut_size = *pLenOut;

    Hack_ResetClients();
    MyDplay_CheckIncoming();
    
    if (!DirectPlay_ReceiveLoopback(pIdOut, pMsgIdOut, pLenOut))
        return 0;

    if (!MyDplay_hasClient) return -1;

    *pIdOut = 0;
    *pMsgIdOut = 0;
    *pLenOut = 0;

    MyDplay_curState = STATE_FINDMAGIC;

    uint8_t magicBytes[4] = {0};
    uint32_t magicAmt = 0;
    uint8_t lenBytes[4] = {0};
    uint32_t lenAmt = 0;
    uint32_t readingLen = 0;

    MyDplay_amtRead = 0;

    int magicAttempts = 100;
    while (1)
    {
        //if (MyDplay_curState)
        //    printf("Reading... %x\n", MyDplay_curState);
        if (MyDplay_curState == STATE_FINDMAGIC)
        {
            if (magicAmt == 4)
            {
                if (*(uint32_t*)magicBytes == MYDPLAY_MAGIC) {
                    MyDplay_curState = STATE_READLEN;
                    continue;
                }
                else {
                    printf("%x\n", *(uint32_t*)magicBytes);
                    uint8_t magicBytesShift[4];
                    memcpy(magicBytesShift, &magicBytes[1], 3);
                    memcpy(magicBytes, magicBytesShift, 3);
                    magicAmt = 3;
                }
            }

            int n = read(DirectPlay_clientSocks[0], (void*)&magicBytes[magicAmt], sizeof(uint32_t) - magicAmt);
            if (n <= 0) {
                //return -1;
                if (magicAmt == 0)
                {
                    magicAttempts -= 1;
                    if (magicAttempts <= 0)
                        return -1;
                }
                continue;
            }

            magicAmt += n;
        }
        else if (MyDplay_curState == STATE_READLEN)
        {
            if (lenAmt == 4)
            {
                readingLen = *(uint32_t*)lenBytes;
                MyDplay_curState = STATE_READING;
                continue;
            }

            int n = read(DirectPlay_clientSocks[0], (void*)&lenBytes[lenAmt], sizeof(uint32_t) - lenAmt);
            if (n <= 0) {
                //return -1;
                continue;
            }

            lenAmt += n;
        }
        else if (MyDplay_curState == STATE_READING)
        {
            if (MyDplay_amtRead == readingLen)
            {
                break;
            }

            //printf("%x %x\n", MyDplay_amtRead, readingLen);
            int n = read(DirectPlay_clientSocks[0], (void*)&MyDplay_readBuffer[MyDplay_amtRead], readingLen - MyDplay_amtRead);
            if (n <= 0) {
                //return -1;
                continue;
            }

            MyDplay_amtRead += n;
        }
    }

    if (MyDplay_amtRead < 8) {
        return -1;
    }

    int idFrom = *(uint32_t*)&MyDplay_readBuffer[0];
    int idTo = *(uint32_t*)&MyDplay_readBuffer[4];

    if (pMsgIdOut_size > MyDplay_amtRead-8)
        pMsgIdOut_size = MyDplay_amtRead-8;

    // Info request packet
    if (idFrom == 0xFFFFFFFF) {
        printf("[I] Recv %x bytes from %x/%x (%x)\n", pMsgIdOut_size, idRecv, idFrom, *pMsgIdOut);

        int type = *(uint32_t*)&MyDplay_readBuffer[8];
        if (type == 0) {
            memcpy(pMsgIdOut, &MyDplay_readBuffer[8], pMsgIdOut_size);

            *pIdOut = idFrom;
            *pLenOut = pMsgIdOut_size;
            return 0;
        }
        else if (type == 1) {
            struct
            {
                int type;
                jkMultiEntry3 entry;
            } outPkt;

            memset(&outPkt, 0, sizeof(outPkt));

            outPkt.type = 0;
            __wcsncpy(outPkt.entry.field_E8, L"OpenJKDF2 Loopback", 0x20);
            _strncpy(outPkt.entry.episodeGobName, sithWorld_episodeName, 0x20);
            _strncpy(outPkt.entry.mapJklFname, jkMain_aLevelJklFname, 0x80);

            DirectPlay_Send(0xFFFFFFFF, idRecv, &outPkt, sizeof(outPkt));

            close(DirectPlay_clientSocks[0]);
            MyDplay_hasClient = 0;
            return -1;
        }

        return -1;
    }

    memcpy(pMsgIdOut, &MyDplay_readBuffer[8], pMsgIdOut_size);

    *pIdOut = idFrom;
    *pLenOut = pMsgIdOut_size;

    printf("Recv %x bytes from %x/%x %x (%x)\n", pMsgIdOut_size, idFrom, idRecv, idTo, *pMsgIdOut);
    MyDplay_amtRead = 0;

    //
    //

    return 0;
}

BOOL DirectPlay_SendLoopback(DPID idFrom, DPID idTo, void *lpData, DWORD dwDataSize)
{
    if (!lpData || dwDataSize > 2052 || dwDataSize <= 0) return 0;
    //dwDataSize = 2052;

    DPlayPktWrap* pPkt = NULL;
    for (int i = 0; i < DPLAY_OUTQUEUE_LEN; i++)
    {
        if (!aDplayOutgoing[i].data)
        {
            pPkt = &aDplayOutgoing[i];
            break;
        }
    }

    if (!pPkt) return 0;

    pPkt->idFrom = idFrom;
    pPkt->idTo = idTo;
    pPkt->data = malloc(dwDataSize);
    pPkt->dataSize = dwDataSize;

    printf("[L] Sent %x bytes to %x (%x)\n", dwDataSize, idTo, *(int*)lpData);

    memcpy(pPkt->data, lpData, dwDataSize);

    return 1;
}

BOOL DirectPlay_Send(DPID idFrom, DPID idTo, void *lpData, DWORD dwDataSize)
{
    Hack_ResetClients();
    MyDplay_CheckIncoming();
    if (!lpData || dwDataSize > 2052 || dwDataSize <= 0) return 0;
    //dwDataSize = 2052;

    if (idFrom == idTo)
    {
        return DirectPlay_SendLoopback(idFrom, idTo, lpData, dwDataSize);
    }

    if (!MyDplay_hasClient) return 0;

    uint32_t amtToSend = dwDataSize + (sizeof(uint32_t) * 4);
    *(uint32_t*)&MyDplay_sendBuffer[0] = MYDPLAY_MAGIC;
    *(uint32_t*)&MyDplay_sendBuffer[4] = dwDataSize + (sizeof(uint32_t) * 2);
    *(uint32_t*)&MyDplay_sendBuffer[8] = idFrom;
    *(uint32_t*)&MyDplay_sendBuffer[0xC] = idTo;
    memcpy(&MyDplay_sendBuffer[0x10], lpData, dwDataSize);

    MyDplay_amtSent = 0;
    while (MyDplay_amtSent < amtToSend)
    {
        int n = write(DirectPlay_clientSocks[0], &MyDplay_sendBuffer[MyDplay_amtSent], amtToSend - MyDplay_amtSent);
        if (n < 0)
        {
            return 0;
        }

        MyDplay_amtSent += n;
    }

    printf("Sent %x bytes to %x (%x) %x %x\n", MyDplay_amtSent, idTo, *(int*)lpData, *(uint32_t*)&MyDplay_sendBuffer[0], *(uint32_t*)&MyDplay_sendBuffer[4]);
    
    MyDplay_amtSent = 0;
    return 1;
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
    sithDplay_dword_8321E8 = 0;
    sithDplay_dword_8321E0 = 1;
    sithDplay_dplayIdSelf = DirectPlay_CreatePlayer(jkPlayer_playerShortName, 0);
    sithDplay_dword_8321E4 = 0;
    sithDplay_dplayIdSelf = 2; // HACK
    jkGuiNet_checksumSeed = jkGuiMultiplayer_aEntries[idx].checksumSeed;

    // Client socket connect
    MyDplay_addr.sin_family = AF_INET;
    MyDplay_addr.sin_port = htons(SITHDPLAY_PORT); /*converts short to
                                           short with network byte order*/
    MyDplay_addr.sin_addr.s_addr = inet_addr(SITHDPLAY_ADDRESS);

    DirectPlay_sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (DirectPlay_sock == -1) {
        perror("Socket creation error");
        return EXIT_FAILURE;
    }
    if (connect(DirectPlay_sock, (struct sockaddr*) &MyDplay_addr, sizeof(MyDplay_addr)) == -1) {
        perror("Connection error");
        close(DirectPlay_sock);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < 32; i++)
    {
        DirectPlay_clientSocks[i] = DirectPlay_sock;
    }
    MyDplay_hasClient = 1;

#ifdef WIN64_MINGW
    u_long iMode = 0;
    ioctlsocket(DirectPlay_sock, FIONBIO, &iMode);
#else
    fcntl(DirectPlay_sock, F_SETFL, O_NONBLOCK);
#endif

#if 0
    char buf[BUFSIZE];
    if (send(sock, "hello", 5, 0); /*write may be also used*/ == -1) {
        perror("Send error");
        close(client_sock);
        close(sock);
        return EXIT_FAILURE;
    }

    ssize_t readden = recv(sock, buf, BUFSIZE, 0); /*read may be also used*/
    if (readden < 0) {
        perror("Receive error");
        close(client_sock);
        close(sock);
        return EXIT_FAILURE;
    }
    else if (readden == 0)
    {
        fprintf(stderr, "Client orderly shut down the connection.\n");
    }
    else /* if (readden > 0) */ {
        if (readden < BUFSIZE)
        {
          fprintf(stderr, "Received less bytes (%zd) then requested (%d).\n", 
            readden, BUFSIZE);
        }

        write (STDOUT_FILENO, buf, readden);
    }  
#endif
    return 0;
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

void DirectPlay_SetSessionDesc(int a1, DWORD maxPlayers)
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
    close(DirectPlay_sock);
}

int DirectPlay_OpenIdk(void* a)
{
    MyDplay_addr.sin_family = AF_INET;
    MyDplay_addr.sin_port = htons(SITHDPLAY_PORT); /*converts short to
                                           short with network byte order*/
    MyDplay_addr.sin_addr.s_addr = inet_addr(SITHDPLAY_ADDRESS);

    DirectPlay_sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (DirectPlay_sock == -1) {
        perror("Socket creation error");
        return EXIT_FAILURE;
    }

    if (bind(DirectPlay_sock, (struct sockaddr*) &MyDplay_addr, sizeof(MyDplay_addr)) == -1) {
        perror("Bind error");
        close(DirectPlay_sock);
        return EXIT_FAILURE;
    }

    if (listen(DirectPlay_sock, 1/*length of connections queue*/) == -1) {
        perror("Listen error");
        close(DirectPlay_sock);
        return EXIT_FAILURE;
    }

#ifdef WIN64_MINGW
    u_long iMode = 0;
    ioctlsocket(DirectPlay_sock, FIONBIO, &iMode);
#else
    fcntl(DirectPlay_sock, F_SETFL, O_NONBLOCK);
#endif

    //DirectPlay_clientSocks[sithDplay_dplayIdSelf] = DirectPlay_sock;

#if 0
    char buf[BUFSIZE];
    if (send(DirectPlay_sock, "hello", 5, 0) == -1) {
        perror("Send error");
        close(client_sock);
        close(DirectPlay_sock);
        return EXIT_FAILURE;
    }

    ssize_t readden = recv(DirectPlay_sock, buf, BUFSIZE, 0);
    if (readden < 0) {
        perror("Receive error");
        close(client_sock);
        close(DirectPlay_sock);
        return EXIT_FAILURE;
    }
    else if (readden == 0) {
      fprintf(stderr, "Client orderly shut down the connection.\n");
    }
    else {readden > 0) {
        if (readden < BUFSIZE)
        {
          fprintf(stderr, "Received less bytes (%zd) then requested (%d).\n", 
            readden, BUFSIZE);
        }

        write (STDOUT_FILENO, buf, readden);
    }
#endif
    return 0;
}

int DirectPlay_GetSession_passwordidk(void* a)
{
    return 1;
}

int sithDplay_EnumSessions(int a, void* b)
{
    struct
    {
        int type;
        jkMultiEntry3 entry;
    } inPkt;

    Hack_ResetClients();
    sithDplay_Open(0, NULL);

    uint32_t aAskForInfo[1] = {1};
    DirectPlay_Send(0xFFFFFFFF, 1, aAskForInfo, sizeof(aAskForInfo));

    while (1)
    {
        int id_from = 0;
        uint32_t len_recv = sizeof(inPkt);

        memset(&inPkt, 0, sizeof(inPkt));
        DirectPlay_Receive(&id_from, &inPkt, &len_recv);

        if (len_recv == sizeof(inPkt) && id_from == 0xFFFFFFFF) {
            break;
        }
    }

    __wcsncpy(jkGuiMultiplayer_aEntries[0].field_18, inPkt.entry.field_E8, 0x20);
    _strncpy(jkGuiMultiplayer_aEntries[0].field_58, inPkt.entry.episodeGobName, 0x20);
    _strncpy(jkGuiMultiplayer_aEntries[0].field_78, inPkt.entry.mapJklFname, 0x20);

    sithDplay_Close();

    return 0;
}

void DirectPlay_EnumPlayers(int a)
{
    Hack_ResetClients();
}

int DirectPlay_StartSession(void* a, void* b)
{
    return 1;
}

void DirectPlay_Destroy()
{
    
}