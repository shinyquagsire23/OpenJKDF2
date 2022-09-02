#include "sithDplay_GNS.h"

#include "Win95/sithDplay.h"
#include "Engine/sithMulti.h"
#include "General/stdString.h"
#include "jk.h"

#ifdef MACOS
#define GL_SILENCE_DEPRECATION
#include <SDL.h>
#elif defined(ARCH_WASM)
#include <emscripten.h>
#include <SDL.h>
#else
#include <SDL.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <algorithm>
#include <string>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>
#include <queue>
#include <map>
#include <cctype>

#include <steam/steamnetworkingsockets.h>
#include <steam/isteamnetworkingmessages.h>
#include <steam/steamnetworkingtypes.h>
#include <steam/isteamnetworkingutils.h>
#ifndef STEAMNETWORKINGSOCKETS_OPENSOURCE
#include <steam/steam_api.h>
#endif

#ifdef _WIN32
    #include <windows.h> // Ug, for NukeProcess -- see below
#else
    #include <unistd.h>
    #include <signal.h>
#endif
extern "C"
{
void Hack_ResetClients();

#pragma pack(push, 4)
typedef struct GNSInfoPacket
{
    int id;
    jkMultiEntry entry;
} GNSInfoPacket;
#pragma pack(pop)

static jkMultiEntry sithDplayGNS_storedEntryEnum;
static jkMultiEntry sithDplayGNS_storedEntry;
extern wchar_t jkGuiMultiplayer_ipText[256];
char jkGuiMultiplayer_ipText_conv[256];
static int sithDplayGNS_numEnumd = 0;
}
/////////////////////////////////////////////////////////////////////////////
//
// Common stuff
//
/////////////////////////////////////////////////////////////////////////////

bool g_bQuit = false;

SteamNetworkingMicroseconds g_logTimeZero;

#ifdef WIN32
#elif _POSIX_C_SOURCE >= 199309L
#include <time.h>   // for nanosleep
#endif

void sleep_ms(int milliseconds){ // cross-platform sleep function
    SDL_Delay(milliseconds);
}

// We do this because I won't want to figure out how to cleanly shut
// down the thread that is reading from stdin.
static void NukeProcess( int rc )
{
    #ifdef _WIN32
        ExitProcess( rc );
    #else
        (void)rc; // Unused formal parameter
        kill( getpid(), SIGKILL );
    #endif
}

static void DebugOutput( ESteamNetworkingSocketsDebugOutputType eType, const char *pszMsg )
{
    SteamNetworkingMicroseconds time = SteamNetworkingUtils()->GetLocalTimestamp() - g_logTimeZero;
    printf( "%10.6f %s\n", time*1e-6, pszMsg );
    fflush(stdout);
    if ( eType == k_ESteamNetworkingSocketsDebugOutputType_Bug )
    {
        fflush(stdout);
        fflush(stderr);
        //NukeProcess(1);
    }
}

static void FatalError( const char *fmt, ... )
{
    char text[ 2048 ];
    va_list ap;
    va_start( ap, fmt );
    vsprintf( text, fmt, ap );
    va_end(ap);
    char *nl = strchr( text, '\0' ) - 1;
    if ( nl >= text && *nl == '\n' )
        *nl = '\0';
    DebugOutput( k_ESteamNetworkingSocketsDebugOutputType_Bug, text );
}

static void Printf( const char *fmt, ... )
{
    char text[ 2048 ];
    va_list ap;
    va_start( ap, fmt );
    vsprintf( text, fmt, ap );
    va_end(ap);
    char *nl = strchr( text, '\0' ) - 1;
    if ( nl >= text && *nl == '\n' )
        *nl = '\0';
    DebugOutput( k_ESteamNetworkingSocketsDebugOutputType_Msg, text );
}

static void InitSteamDatagramConnectionSockets()
{
    #ifdef STEAMNETWORKINGSOCKETS_OPENSOURCE
        SteamDatagramErrMsg errMsg;
        if ( !GameNetworkingSockets_Init( nullptr, errMsg ) )
            FatalError( "GameNetworkingSockets_Init failed.  %s", errMsg );
    #else
        SteamDatagram_SetAppID( 570 ); // Just set something, doesn't matter what
        SteamDatagram_SetUniverse( false, k_EUniverseDev );

        SteamDatagramErrMsg errMsg;
        if ( !SteamDatagramClient_Init( errMsg ) )
            FatalError( "SteamDatagramClient_Init failed.  %s", errMsg );

        // Disable authentication when running with Steam, for this
        // example, since we're not a real app.
        //
        // Authentication is disabled automatically in the open-source
        // version since we don't have a trusted third party to issue
        // certs.
        SteamNetworkingUtils()->SetGlobalConfigValueInt32( k_ESteamNetworkingConfig_IP_AllowWithoutAuth, 1 );
    #endif

    g_logTimeZero = SteamNetworkingUtils()->GetLocalTimestamp();

    SteamNetworkingUtils()->SetDebugOutputFunction( k_ESteamNetworkingSocketsDebugOutputType_Msg, DebugOutput );
}

static void ShutdownSteamDatagramConnectionSockets()
{
    // Give connections time to finish up.  This is an application layer protocol
    // here, it's not TCP.  Note that if you have an application and you need to be
    // more sure about cleanup, you won't be able to do this.  You will need to send
    // a message and then either wait for the peer to close the connection, or
    // you can pool the connection to see if any reliable data is pending.
    sleep_ms( 500 );

    #ifdef STEAMNETWORKINGSOCKETS_OPENSOURCE
        GameNetworkingSockets_Kill();
    #else
        SteamDatagramClient_Kill();
    #endif
}


/////////////////////////////////////////////////////////////////////////////
//
// GNSServer
//
/////////////////////////////////////////////////////////////////////////////

class GNSServer
{
public:
    void Init( uint16 nPort )
    {
        // Select instance to use.  For now we'll always use the default.
        // But we could use SteamGameServerNetworkingSockets() on Steam.
        m_pInterface = SteamNetworkingSockets();

        // Start listening
        SteamNetworkingIPAddr serverLocalAddr;
        serverLocalAddr.Clear();
        serverLocalAddr.m_port = nPort;
        SteamNetworkingConfigValue_t opt;
        opt.SetPtr( k_ESteamNetworkingConfig_Callback_ConnectionStatusChanged, (void*)SteamNetConnectionStatusChangedCallback );
        //opt.SetPtr( k_ESteamNetworkingConfig_Callback_CreateConnectionSignaling, (void*)SteamNetCreateConnectionSignalingCallback);
        m_hListenSock = m_pInterface->CreateListenSocketIP( serverLocalAddr, 1, &opt );
        if ( m_hListenSock == k_HSteamListenSocket_Invalid )
            Printf( "[1] Failed to listen on port %d", nPort );
        m_hPollGroup = m_pInterface->CreatePollGroup();
        if ( m_hPollGroup == k_HSteamNetPollGroup_Invalid )
            Printf( "[2] Failed to listen on port %d", nPort );
        Printf( "Server listening on port %d\n", nPort );

        m_pBcastInterface = SteamNetworkingMessages();

        m_identity.Clear();
        m_identity.SetGenericString("OpenJKDF2");

        id = 1;
        availableIds = 0x1;
    }

    void Shutdown()
    {
        // Close all the connections
        Printf( "Closing connections...\n" );
        for ( auto it: m_mapClients )
        {
            // TODO: Send a proper shutdown message

            // Close the connection.  We use "linger mode" to ask SteamNetworkingSockets
            // to flush this out and close gracefully.
            m_pInterface->CloseConnection( it.first, 0, "Server Shutdown", true );
        }
        m_mapClients.clear();

        m_pInterface->CloseListenSocket( m_hListenSock );
        m_hListenSock = k_HSteamListenSocket_Invalid;

        m_pInterface->DestroyPollGroup( m_hPollGroup );
        m_hPollGroup = k_HSteamNetPollGroup_Invalid;

        availableIds = 0x1;
    }

    void RunStep()
    {
        //printf("Server runstep\n");
        //PollIncomingMessages();
        PollConnectionStateChanges();
        //TickBroadcastOut();
    }

    void Run()
    {
        while ( !g_bQuit )
        {
            RunStep();
            sleep_ms(10);
        }

        Shutdown();
    }

    int Receive(int *pIdOut, void *pMsg, int *pLenInOut)
    {
        int maxLen = *pLenInOut;
        *pIdOut = 0;
        *pLenInOut = 0;

        if (m_DisconnectedPeers.size())
        {
            int dis_id = m_DisconnectedPeers.front();
            m_DisconnectedPeers.pop();

            *pIdOut = dis_id;

            return 2;
        }

        ISteamNetworkingMessage *pIncomingMsg = nullptr;
        int numMsgs = m_pInterface->ReceiveMessagesOnPollGroup( m_hPollGroup, &pIncomingMsg, 1 );
        if ( numMsgs == 0 )
            return -1;
        if ( numMsgs < 0 ) {
            printf( "Error checking for messages (%d)\n", numMsgs);
            return -1;
        }
        assert( numMsgs == 1 && pIncomingMsg );
        auto itClient = m_mapClients.find( pIncomingMsg->m_conn );
        assert( itClient != m_mapClients.end() );

        if (pIncomingMsg->m_cbSize < 8) {
            printf("Bad packet size %x\n", pIncomingMsg->m_cbSize);
            pIncomingMsg->Release();
            return -1;
        }

        uint8_t* dataBuf = (uint8_t*)pIncomingMsg->m_pData;
        int idFrom = *(uint32_t*)&dataBuf[0];//itClient->second.m_id;
        int idTo = *(uint32_t*)&dataBuf[4];
        *pIdOut = idFrom;

        // If we get a packet intended for another client, forward it to them.
        if (idTo && idTo != id)
        {
            Send(idFrom, idTo, &dataBuf[8], pIncomingMsg->m_cbSize-8);
            pIncomingMsg->Release();

            *pLenInOut = maxLen;
            return Receive(pIdOut, pMsg, pLenInOut);
        }

        //printf("Received %x bytes from %x\n", pIncomingMsg->m_cbSize, itClient->second.m_id);

        int outsize = maxLen;
        if (outsize > pIncomingMsg->m_cbSize-8)
            outsize = pIncomingMsg->m_cbSize-8;

        memcpy(pMsg, &dataBuf[8], outsize);
        *pLenInOut = outsize;

        printf("Recv %x bytes from %x %x (%x)\n", outsize, idFrom, idTo, *(uint32_t*)pMsg);

        // We don't need this anymore.
        pIncomingMsg->Release();

        return 0;
    }

    int Send(uint32_t idFrom, uint32_t idTo, void *lpData, uint32_t dwDataSize)
    {
        if (dwDataSize > 4096-8) dwDataSize = 4096-8;
        *(uint32_t*)&sendBuffer[0] = idFrom;
        *(uint32_t*)&sendBuffer[4] = idTo;

        memcpy(&sendBuffer[8], lpData, dwDataSize);

        HSteamNetConnection except = k_HSteamNetConnection_Invalid;
        for ( auto &c: m_mapClients )
        {
            if ( c.first != except && c.second.m_id == idTo ) {
                printf("Sent %x bytes to %x (%x)\n", dwDataSize+8, idTo, *(uint32_t*)lpData);
                SendBytesToClient( c.first, sendBuffer, dwDataSize+8 );
            }
        }

        return 1;
    }

    uint32_t id;
private:

    HSteamListenSocket m_hListenSock;
    HSteamNetPollGroup m_hPollGroup;
    ISteamNetworkingSockets *m_pInterface;
    ISteamNetworkingMessages *m_pBcastInterface;
    uint64_t availableIds = 0x1;
    uint8_t sendBuffer[4096];
    SteamNetworkingIdentity m_identity;

    struct Client_t
    {
        uint32_t m_id;
        std::string m_sNick;
    };

    std::map< HSteamNetConnection, Client_t > m_mapClients;
    std::queue<int> m_DisconnectedPeers;

    void SendStringToClient( HSteamNetConnection conn, const char *str )
    {
        SendBytesToClient( conn, (void*)str, (uint32)strlen(str));
    }

    void SendBytesToClient( HSteamNetConnection conn, void *pData, uint32_t len)
    {
        m_pInterface->SendMessageToConnection( conn, pData, len, k_nSteamNetworkingSend_Reliable, nullptr );
    }

    void SendStringToAllClients( const char *str, HSteamNetConnection except = k_HSteamNetConnection_Invalid )
    {
        for ( auto &c: m_mapClients )
        {
            if ( c.first != except )
                SendStringToClient( c.first, str );
        }
    }

    void SendBytesToAllClients( void *pData, uint32_t len, HSteamNetConnection except = k_HSteamNetConnection_Invalid )
    {
        for ( auto &c: m_mapClients )
        {
            if ( c.first != except )
                SendBytesToClient( c.first, pData, len );
        }
    }

    void SetClientNick( HSteamNetConnection hConn, const char *nick )
    {

        // Remember their nick
        m_mapClients[hConn].m_sNick = nick;

        // Set the connection name, too, which is useful for debugging
        m_pInterface->SetConnectionName( hConn, nick );
    }

    void SetClientId( HSteamNetConnection hConn, int id )
    {
        m_mapClients[hConn].m_id = id;
    }

    void TickBroadcastOut()
    {
        uint8_t tmp[8] = {0};
        m_pBcastInterface->SendMessageToUser(m_identity, tmp, 8, k_nSteamNetworkingSend_Unreliable, 1337);
    }

    void OnSteamNetConnectionStatusChanged( SteamNetConnectionStatusChangedCallback_t *pInfo )
    {
        char temp[1024];

        // What's the state of the connection?
        switch ( pInfo->m_info.m_eState )
        {
            case k_ESteamNetworkingConnectionState_None:
                // NOTE: We will get callbacks here when we destroy connections.  You can ignore these.
                break;

            case k_ESteamNetworkingConnectionState_ClosedByPeer:
            case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
            {
                // Ignore if they were not previously connected.  (If they disconnected
                // before we accepted the connection.)
                if ( pInfo->m_eOldState == k_ESteamNetworkingConnectionState_Connected )
                {

                    // Locate the client.  Note that it should have been found, because this
                    // is the only codepath where we remove clients (except on shutdown),
                    // and connection change callbacks are dispatched in queue order.
                    auto itClient = m_mapClients.find( pInfo->m_hConn );
                    assert( itClient != m_mapClients.end() );

                    // Select appropriate log messages
                    const char *pszDebugLogAction;
                    if ( pInfo->m_info.m_eState == k_ESteamNetworkingConnectionState_ProblemDetectedLocally )
                    {
                        pszDebugLogAction = "problem detected locally";
                        sprintf( temp, "Problem detected with client %x (%s)", itClient->second.m_id, pInfo->m_info.m_szEndDebug );
                    }
                    else
                    {
                        // Note that here we could check the reason code to see if
                        // it was a "usual" connection or an "unusual" one.
                        pszDebugLogAction = "closed by peer";
                        sprintf( temp, "Client id %x has left.", itClient->second.m_id );
                    }

                    // Spew something to our own log.  Note that because we put their nick
                    // as the connection description, it will show up, along with their
                    // transport-specific data (e.g. their IP address)
                    Printf( "Connection %s %s, reason %d: %s\n",
                        pInfo->m_info.m_szConnectionDescription,
                        pszDebugLogAction,
                        pInfo->m_info.m_eEndReason,
                        pInfo->m_info.m_szEndDebug
                    );

                    m_DisconnectedPeers.push(itClient->second.m_id);

                    availableIds &= ~(1 << (itClient->second.m_id-1));

                    m_mapClients.erase( itClient );

                    // Send a message so everybody else knows what happened
                    SendStringToAllClients( temp );
                }
                else
                {
                    assert( pInfo->m_eOldState == k_ESteamNetworkingConnectionState_Connecting );
                }

                // Clean up the connection.  This is important!
                // The connection is "closed" in the network sense, but
                // it has not been destroyed.  We must close it on our end, too
                // to finish up.  The reason information do not matter in this case,
                // and we cannot linger because it's already closed on the other end,
                // so we just pass 0's.
                m_pInterface->CloseConnection( pInfo->m_hConn, 0, nullptr, false );
                break;
            }

            case k_ESteamNetworkingConnectionState_Connecting:
            {
                // This must be a new connection
                assert( m_mapClients.find( pInfo->m_hConn ) == m_mapClients.end() );

                Printf( "Connection request from %s", pInfo->m_info.m_szConnectionDescription );

                // Don't accept if we can't allocate an ID
                if (ConnectedPlayers() >= 64) {
                    printf("Rejecting request.\n");
                    break;
                }

                // A client is attempting to connect
                // Try to accept the connection.
                if ( m_pInterface->AcceptConnection( pInfo->m_hConn ) != k_EResultOK )
                {
                    // This could fail.  If the remote host tried to connect, but then
                    // disconnected, the connection may already be half closed.  Just
                    // destroy whatever we have on our side.
                    m_pInterface->CloseConnection( pInfo->m_hConn, 0, nullptr, false );
                    Printf( "Can't accept connection.  (It was already closed?)" );
                    break;
                }

                // Assign the poll group
                if ( !m_pInterface->SetConnectionPollGroup( pInfo->m_hConn, m_hPollGroup ) )
                {
                    m_pInterface->CloseConnection( pInfo->m_hConn, 0, nullptr, false );
                    Printf( "Failed to set poll group?" );
                    break;
                }

                int nextId = 0;
                for (int i = 0; i < 64; i++)
                {
                    if (!(availableIds & (1 << i))) {
                        availableIds |= (1 << i);
                        nextId = i+1;
                        break;
                    }
                }

                printf("Assigning ID: %x\n", nextId);

                GNSInfoPacket infoPkt = {0};
                infoPkt.id = nextId;
                infoPkt.entry = sithDplayGNS_storedEntry;
                infoPkt.entry.numPlayers = RealConnectedPlayers();
                infoPkt.entry.maxPlayers = sithDplayGNS_storedEntry.maxPlayers;

                jkPlayer_maxPlayers = sithDplayGNS_storedEntry.maxPlayers; // Hack?

                SendBytesToClient( pInfo->m_hConn, &infoPkt, sizeof(infoPkt)); 

                // Add them to the client list, using std::map wacky syntax
                m_mapClients[ pInfo->m_hConn ];
                SetClientNick( pInfo->m_hConn, "asdf" );
                SetClientId( pInfo->m_hConn, nextId);

                nextId++;
                break;
            }

            case k_ESteamNetworkingConnectionState_Connected:
                // We will get a callback immediately after accepting the connection.
                // Since we are the server, we can ignore this, it's not news to us.
                break;

            default:
                // Silences -Wswitch
                break;
        }
    }

    static GNSServer *s_pCallbackInstance;
    static void SteamNetConnectionStatusChangedCallback( SteamNetConnectionStatusChangedCallback_t *pInfo )
    {
        s_pCallbackInstance->OnSteamNetConnectionStatusChanged( pInfo );
    }

    static ISteamNetworkingConnectionSignaling* SteamNetCreateConnectionSignalingCallback( ISteamNetworkingSockets *pLocalInterface, const SteamNetworkingIdentity &identityPeer, int nLocalVirtualPort, int nRemoteVirtualPort )
    {
        //s_pCallbackInstance->OnSteamNetConnectionStatusChanged( pInfo );
        printf("incoming!\n");
        return nullptr;
    }

    void PollConnectionStateChanges()
    {
        s_pCallbackInstance = this;
        m_pInterface->RunCallbacks();
    }

    int ConnectedPlayers()
    {
        int ret = 0;
        for (int i = 0; i < 64; i++)
        {
            if (availableIds & (1 << i)) {
                ret++;
            }
        }
        return ret;
    }

    int RealConnectedPlayers()
    {
        int amt = 0;
        for (int i = 0; i < jkPlayer_maxPlayers; i++)
        {
            if (!i && jkGuiNetHost_bIsDedicated) continue;

            if ( (jkPlayer_playerInfos[i].flags & 2) != 0 && !jkPlayer_playerInfos[i].net_id ){

            }
            else {
                amt++;
            }
        }
        return amt;
    }
};

GNSServer *GNSServer::s_pCallbackInstance = nullptr;

/////////////////////////////////////////////////////////////////////////////
//
// GNSClient
//
/////////////////////////////////////////////////////////////////////////////

class GNSClient
{
public:
    void Init( const SteamNetworkingIPAddr &serverAddr )
    {
        id = 0xFFFFFFFF;
        m_closed = 0;

        // Select instance to use.  For now we'll always use the default.
        m_pInterface = SteamNetworkingSockets();

        // Start connecting
        char szAddr[ SteamNetworkingIPAddr::k_cchMaxString ];
        serverAddr.ToString( szAddr, sizeof(szAddr), true );
        Printf( "Connecting to server at %s", szAddr );
        SteamNetworkingConfigValue_t opt;
        opt.SetPtr( k_ESteamNetworkingConfig_Callback_ConnectionStatusChanged, (void*)SteamNetConnectionStatusChangedCallback );
        //opt.SetPtr( k_ESteamNetworkingConfig_Callback_CreateConnectionSignaling, (void*)SteamNetCreateConnectionSignalingCallback);
        m_hConnection = m_pInterface->ConnectByIPAddress( serverAddr, 1, &opt );
        if ( m_hConnection == k_HSteamNetConnection_Invalid ) {
            Printf( "Failed to create connection" );
            m_closed = 1;
        }

        m_pBcastInterface = SteamNetworkingMessages();

        m_identity.Clear();
        m_identity.SetGenericString("OpenJKDF2");

        m_hostDisconnected = 0;
    }

    void Shutdown()
    {
        m_pInterface->CloseConnection( m_hConnection, 0, nullptr, false );
        m_hConnection = k_HSteamNetConnection_Invalid;
        id = 0xFFFFFFFF;
        m_closed = 1;

        m_hostDisconnected = 0;
    }

    void RunStep()
    {
        //printf("Client runstep\n");
        //PollIncomingMessages();
        PollConnectionStateChanges();
        //TickBroadcastIn();
    }

    void Run()
    {
        while ( !g_bQuit )
        {
            RunStep();
            sleep_ms(10);
        }
    }

    int Receive(int *pIdOut, void *pMsg, int *pLenInOut)
    {
        int maxLen = *pLenInOut;
        *pIdOut = 0;
        *pLenInOut = 0;

        if ( m_hostDisconnected ) {
            printf( "Host is disconnected, forcing exit...\n");
            Shutdown();
            m_closed = 1;
            *pIdOut = 1;
            return 2;
        }

        ISteamNetworkingMessage *pIncomingMsg = nullptr;
        int numMsgs = m_pInterface->ReceiveMessagesOnConnection( m_hConnection, &pIncomingMsg, 1 );
        if ( numMsgs == 0 )
            return -1;
        if ( numMsgs < 0 ) {
            printf( "Error checking for messages (%d)\n", numMsgs);
            Shutdown();
            m_closed = 1;
            *pIdOut = 1;
            m_hackFallback = !m_hackFallback;
            return m_hackFallback ? 2 : -1;
        }

        if (pIncomingMsg->m_cbSize < 8) {
            printf("Bad packet size %x\n", pIncomingMsg->m_cbSize);
            Shutdown();
            m_closed = 1;
            return -1;
        }

        uint8_t* dataBuf = (uint8_t*)pIncomingMsg->m_pData;
        int idFrom = *(uint32_t*)&dataBuf[0];//itClient->second.m_id;
        int idTo = *(uint32_t*)&dataBuf[4];
        *pIdOut = idFrom;

        // Not intended for us
        if (idTo && idTo != id) {
            return -1;
        }
        
        int outsize = maxLen;
        if (outsize > pIncomingMsg->m_cbSize-8)
            outsize = pIncomingMsg->m_cbSize-8;

        memcpy(pMsg, &dataBuf[8], outsize);
        *pLenInOut = outsize;

        printf("Recv %x bytes from %x %x (%x)\n", pIncomingMsg->m_cbSize, idFrom, idTo, *(uint32_t*)pMsg);

        // We don't need this anymore.
        pIncomingMsg->Release();

        return 0;
    }

    int Send(uint32_t idFrom, uint32_t idTo, void *lpData, uint32_t dwDataSize)
    {
        if (dwDataSize > 4096-8) dwDataSize = 4096-8;
        *(uint32_t*)&sendBuffer[0] = idFrom;
        *(uint32_t*)&sendBuffer[4] = idTo;

        memcpy(&sendBuffer[8], lpData, dwDataSize);

        printf("Sent %x bytes to %x (%x)\n", dwDataSize+8, idTo, *(uint32_t*)lpData);

        EResult ret = m_pInterface->SendMessageToConnection( m_hConnection, sendBuffer, dwDataSize+8, k_nSteamNetworkingSend_Reliable, nullptr );
        if (ret < 0) {
            printf( "Error sending message (%d)\n", ret);
        }
        if (ret == k_EResultNoConnection || ret == k_EResultInvalidParam) {
            return 0;
        }

        return 1;
    }

    void GetServerInfo( const SteamNetworkingIPAddr &serverAddr )
    {
        int attempts = 1;
        int id_real = 0xFFFFFFFF;
        id = 0xFFFFFFFF;
        m_closed = 0;
        
        while (id == 0xFFFFFFFF && !m_closed && attempts) {
            Init(serverAddr);
            for (int i = 0; i < 100; i++)
            {
                RunStep();
                sleep_ms(10);
                if (id != 0xFFFFFFFF) break;
            }
            id_real = id;
            Shutdown();
            attempts--;
        }
        
        if (id_real == 0xFFFFFFFF) {
            sithDplayGNS_numEnumd = 0;
        }

        // Hack: Force the UI to update
        jkGuiNet_dword_5564E8 -= 10000;
    }

    uint32_t id = 0xFFFFFFFF;
private:

    HSteamNetConnection m_hConnection;
    ISteamNetworkingSockets *m_pInterface;
    ISteamNetworkingMessages *m_pBcastInterface;
    SteamNetworkingIdentity m_identity;
    uint8_t sendBuffer[4096];
    int m_closed = 0;
    int m_hostDisconnected = 0;
    int m_hackFallback = 0;

    void PollIncomingMessages()
    {
        ISteamNetworkingMessage *pIncomingMsg = nullptr;
        int numMsgs = m_pInterface->ReceiveMessagesOnConnection( m_hConnection, &pIncomingMsg, 1 );
        if ( numMsgs == 0 )
            return;
        if ( numMsgs < 0 ) {
            printf( "Error checking for messages (%d)\n", numMsgs);
            return;
        }

        // Just echo anything we get from the server
        printf("Received %x bytes (%x)\n", pIncomingMsg->m_cbSize, sizeof(GNSInfoPacket));

        if (id == 0xFFFFFFFF && pIncomingMsg->m_cbSize == sizeof(GNSInfoPacket)) {
            GNSInfoPacket* pPkt = (GNSInfoPacket*)pIncomingMsg->m_pData;
            id = pPkt->id;
            printf("We are ID %x\n", id);

            sithDplayGNS_storedEntryEnum = pPkt->entry;
            sithDplayGNS_storedEntryEnum.field_E0 = 10;
            sithDplayGNS_numEnumd = 1;
        }

        // We don't need this anymore.
        pIncomingMsg->Release();
    }

    int TickBroadcastIn()
    {
        SteamNetworkingMessage_t *pMsg = nullptr;
        int numMsgs = m_pBcastInterface->ReceiveMessagesOnChannel(1337, &pMsg, 1);
        if ( numMsgs == 0 )
            return -1;
        if ( numMsgs < 0 ) {
            printf( "Error checking for messages (%d)\n", numMsgs);
            Shutdown();
            m_closed = 1;
            return 2;
        }

        if (pMsg->m_cbSize < 8) {
            printf("Bad packet size %x\n", pMsg->m_cbSize);
            Shutdown();
            m_closed = 1;
            return -1;
        }

        printf("Got broadcast %x\n", pMsg->m_cbSize);
        return 0;
    }

    void OnSteamNetConnectionStatusChanged( SteamNetConnectionStatusChangedCallback_t *pInfo )
    {
        if (m_hConnection == k_HSteamNetConnection_Invalid )
            return;

        // What's the state of the connection?
        switch ( pInfo->m_info.m_eState )
        {
            case k_ESteamNetworkingConnectionState_None:
                // NOTE: We will get callbacks here when we destroy connections.  You can ignore these.
                break;

            case k_ESteamNetworkingConnectionState_ClosedByPeer:
            case k_ESteamNetworkingConnectionState_ProblemDetectedLocally:
            {
                g_bQuit = true;

                // Print an appropriate message
                if ( pInfo->m_eOldState == k_ESteamNetworkingConnectionState_Connecting )
                {
                    // Note: we could distinguish between a timeout, a rejected connection,
                    // or some other transport problem.
                    Printf( "Couldn't connect to host. (%s)", pInfo->m_info.m_szEndDebug );
                }
                else if ( pInfo->m_info.m_eState == k_ESteamNetworkingConnectionState_ProblemDetectedLocally )
                {
                    Printf( "Lost contact with the host. (%s)", pInfo->m_info.m_szEndDebug );
                }
                else
                {
                    // NOTE: We could check the reason code for a normal disconnection
                    Printf( "Host has disconnected. (%s)", pInfo->m_info.m_szEndDebug );
                    m_hostDisconnected = 1;
                }

                // Clean up the connection.  This is important!
                // The connection is "closed" in the network sense, but
                // it has not been destroyed.  We must close it on our end, too
                // to finish up.  The reason information do not matter in this case,
                // and we cannot linger because it's already closed on the other end,
                // so we just pass 0's.
                m_pInterface->CloseConnection( pInfo->m_hConn, 0, nullptr, false );
                m_hConnection = k_HSteamNetConnection_Invalid;
                break;
            }

            case k_ESteamNetworkingConnectionState_Connecting:
                // We will get this callback when we start connecting.
                // We can ignore this.
                break;

            case k_ESteamNetworkingConnectionState_Connected:
                Printf( "Connected to server OK" );
                while (id == 0xFFFFFFFF) {
                    PollIncomingMessages();
                }
                Hack_ResetClients();
                break;

            default:
                // Silences -Wswitch
                break;
        }
    }

    static GNSClient *s_pCallbackInstance;
    static void SteamNetConnectionStatusChangedCallback( SteamNetConnectionStatusChangedCallback_t *pInfo )
    {
        s_pCallbackInstance->OnSteamNetConnectionStatusChanged( pInfo );
    }

    static ISteamNetworkingConnectionSignaling* SteamNetCreateConnectionSignalingCallback( ISteamNetworkingSockets *pLocalInterface, const SteamNetworkingIdentity &identityPeer, int nLocalVirtualPort, int nRemoteVirtualPort )
    {
        //s_pCallbackInstance->OnSteamNetConnectionStatusChanged( pInfo );
        printf("incoming!\n");
        return nullptr;
    }

    void PollConnectionStateChanges()
    {
        s_pCallbackInstance = this;
        m_pInterface->RunCallbacks();
    }
};

GNSClient *GNSClient::s_pCallbackInstance = nullptr;

const uint16 DEFAULT_SERVER_PORT = 27020;

extern "C"
{

extern int jkGuiNetHost_portNum;
SteamNetworkingIPAddr addrServer;
int addrServerPortLast = -1;
char addrServerLast[256];
GNSClient client;
GNSServer server;

void Hack_ResetClients()
{
    DirectPlay_numPlayers = 32;
    for (int i = 0; i < 32; i++)
    {
        DirectPlay_aPlayers[i].dpId = i+1;
        jk_snwprintf(DirectPlay_aPlayers[i].waName, 32, L"asdf");
    }

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

    //jkPlayer_maxPlayers = 2;

    if (sithDplay_bIsServer)
        sithDplay_dplayIdSelf = server.id;
    else
        sithDplay_dplayIdSelf = client.id;
}

void sithDplay_GNS_Startup()
{
    jkGuiMultiplayer_numConnections = 1;
    jk_snwprintf(jkGuiMultiplayer_aConnections[0].name, 0x80, L"Valve GNS");
    sithDplay_dword_8321E0 = 0;

    memset(jkGuiMultiplayer_aEntries, 0, sizeof(jkMultiEntry) * 32);
    dplay_dword_55D618 = 0;
    /*jk_snwprintf(jkGuiMultiplayer_aEntries[0].serverName, 0x20, L"OpenJKDF2 Loopback");
    stdString_snprintf(jkGuiMultiplayer_aEntries[0].episodeGobName, 0x20, "JK1MP");
    stdString_snprintf(jkGuiMultiplayer_aEntries[0].mapJklFname, 0x20, "m2.jkl");
    jkGuiMultiplayer_aEntries[0].field_E0 = 10;*/

    Hack_ResetClients();

    addrServer.Clear();
    addrServer.ParseString("127.0.0.1");
    addrServer.m_port = DEFAULT_SERVER_PORT;

    // Create client and server sockets
    InitSteamDatagramConnectionSockets();
}

void sithDplay_GNS_Shutdown()
{
    ShutdownSteamDatagramConnectionSockets();
}

int DirectPlay_Receive(int *pIdOut, int *pMsgIdOut, int *pLenOut)
{
    Hack_ResetClients();

    if (sithDplay_bIsServer)
    {
        server.RunStep();
        return server.Receive(pIdOut, (void*)pMsgIdOut, pLenOut);
    }
    else 
    {
        client.RunStep();
        return client.Receive(pIdOut, (void*)pMsgIdOut, pLenOut);
    }

    return -1;
}

BOOL DirectPlay_Send(DPID idFrom, DPID idTo, void *lpData, DWORD dwDataSize)
{
    Hack_ResetClients();

    if (sithDplay_bIsServer)
    {
        server.RunStep();
        return server.Send(idFrom, idTo, lpData, dwDataSize);
    }
    else 
    {
        client.RunStep();
        return client.Send(idFrom, idTo, lpData, dwDataSize);
    }

    return 1;
}

int sithDplay_OpenConnection(void* a)
{
    sithDplay_dword_8321DC = 1;
    return 0;
}

void sithDplay_CloseConnection()
{
    if ( sithDplay_dword_8321DC )
    {
        if ( sithDplay_dword_8321E0 )
        {
            //DirectPlay_DestroyPlayer(sithDplay_dplayIdSelf);
            DirectPlay_Close();
            sithDplay_dword_8321E0 = 0;
            sithDplay_bIsServer = 0;
            sithDplay_dplayIdSelf = 0;
        }
        //DirectPlay_CloseConnection();
        sithDplay_dword_8321DC = 0;
    }
}

int sithDplay_Open(int idx, wchar_t* pwPassword)
{
    DirectPlay_EnumSessions2();

    sithDplay_dword_8321E8 = 0;
    sithDplay_dword_8321E0 = 1;
    sithDplay_dplayIdSelf = DirectPlay_CreatePlayer(jkPlayer_playerShortName, 0);
    sithDplay_bIsServer = 0;
    sithDplay_dplayIdSelf = 2; // HACK
    jkGuiNet_checksumSeed = jkGuiMultiplayer_aEntries[idx].checksumSeed;

    client.Init(addrServer);
    return 0;
}

void sithDplay_Close()
{
    if (sithDplay_bIsServer)
    {
        server.Shutdown();
    }
    else 
    {
        client.Shutdown();
    }
}

int DirectPlay_SendLobbyMessage(void* pPkt, uint32_t pktLen)
{
    return 1;
}

void DirectPlay_SetSessionDesc(const char* a1, DWORD maxPlayers)
{
    _strncpy(sithDplayGNS_storedEntry.mapJklFname, jkMain_aLevelJklFname, 0x20);
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

int DirectPlay_OpenHost(jkMultiEntry* pEntry)
{
    sithDplayGNS_storedEntry = *pEntry;

    jkPlayer_maxPlayers = pEntry->maxPlayers; // Hack?

    sithDplay_bIsServer = 1;
    server.Init(jkGuiNetHost_portNum);
    return 0;
}

int DirectPlay_GetSession_passwordidk(jkMultiEntry* pEntry)
{
    sithDplayGNS_storedEntry = *pEntry;

    jkPlayer_maxPlayers = pEntry->maxPlayers; // Hack?

    return 1;
}

static int sithDplay_EnumThread_bInit = 0;
static SDL_Thread *sithDplay_EnumThread_thread = NULL;
static SDL_mutex* sithDplay_EnumThread_mutex = NULL;

static int sithDplay_EnumThread(void *ptr)
{
    while (sithDplay_EnumThread_bInit)
    {
        SDL_LockMutex(sithDplay_EnumThread_mutex);
        stdString_WcharToChar(jkGuiMultiplayer_ipText_conv, jkGuiMultiplayer_ipText, 255);
        addrServer.ParseString(jkGuiMultiplayer_ipText_conv);
        if (!addrServer.m_port) {
            addrServer.m_port = DEFAULT_SERVER_PORT;
        }

        if (strncmp(jkGuiMultiplayer_ipText_conv, addrServerLast, 256) || addrServerPortLast != addrServer.m_port)
            client.GetServerInfo(addrServer);
        strncpy(addrServerLast, jkGuiMultiplayer_ipText_conv, 256);
        addrServerPortLast = addrServer.m_port;

        SDL_UnlockMutex(sithDplay_EnumThread_mutex);

        SDL_Delay(100);
    }

    return 0;
}

int DirectPlay_EnumSessions2()
{
    printf("sithDplay_EnumSessions2\n");
    if (!sithDplay_EnumThread_bInit)
        return 0;

    sithDplay_EnumThread_bInit = 0;

    int threadReturnValue;
    SDL_WaitThread(sithDplay_EnumThread_thread, &threadReturnValue);
    sithDplay_EnumThread_thread = NULL;

    printf("Enum thread done\n");

    return 0;
}

int sithDplay_EnumSessions(int a, void* b)
{
    printf("sithDplay_EnumSessions\n");
    if (!sithDplay_EnumThread_mutex)
        sithDplay_EnumThread_mutex = SDL_CreateMutex();

    SDL_LockMutex(sithDplay_EnumThread_mutex);
    jkGuiMultiplayer_aEntries[0] = sithDplayGNS_storedEntryEnum;
    dplay_dword_55D618 = sithDplayGNS_numEnumd;
    SDL_UnlockMutex(sithDplay_EnumThread_mutex);

    if (sithDplay_EnumThread_bInit)
        return 0;

    Hack_ResetClients();

    dplay_dword_55D618 = 0;
    sithDplayGNS_numEnumd = 0;
    memset(&sithDplayGNS_storedEntryEnum, 0, sizeof(sithDplayGNS_storedEntryEnum));
    memset(&jkGuiMultiplayer_aEntries[0], 0, sizeof(jkGuiMultiplayer_aEntries[0]));
    memset(addrServerLast, 0, sizeof(addrServerLast));
    addrServerPortLast = -1;

    sithDplay_EnumThread_bInit = 1;

    sithDplay_EnumThread_thread = SDL_CreateThread(sithDplay_EnumThread, "sithDplay_EnumThread", (void *)NULL);
    printf("Enum thread start\n");

    //DirectPlay_EnumSessions2();

    //client.GetServerInfo(addrServer);

    SDL_LockMutex(sithDplay_EnumThread_mutex);
    jkGuiMultiplayer_aEntries[0] = sithDplayGNS_storedEntryEnum;
    dplay_dword_55D618 = sithDplayGNS_numEnumd;
    SDL_UnlockMutex(sithDplay_EnumThread_mutex);
    

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

}
