#include "stdComm_GNS.h"

#include "Win95/stdComm.h"
#include "Dss/sithMulti.h"
#include "General/stdString.h"
#include "stdPlatform.h"
#include "jk.h"

#include "SDL2_helper.h"

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
    #include <winsock2.h>
    #include <windows.h> // Ug, for NukeProcess -- see below
    #include <ws2tcpip.h>
    typedef int socklen_t;
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <sys/ioctl.h>
    typedef int SOCKET;
    constexpr SOCKET INVALID_SOCKET = -1;
    #include <signal.h>
    #include <dlfcn.h>
#endif

#define sithDplayGNS_infoPrintf(fmt, ...) stdPlatform_Printf(fmt, ##__VA_ARGS__)
#define sithDplayGNS_verbosePrintf(fmt, ...) if (Main_bVerboseNetworking) \
    { \
        stdPlatform_Printf(fmt, ##__VA_ARGS__);  \
    } \
    ;

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
extern int Main_bVerboseNetworking;

typedef bool (*GameNetworkingSockets_Init_t)( const SteamNetworkingIdentity *pIdentity, SteamNetworkingErrMsg &errMsg );
typedef ISteamNetworkingUtils* (*SteamNetworkingUtils_t)(void);
typedef void (*GameNetworkingSockets_Kill_t)(void);
typedef ISteamNetworkingSockets* (*SteamNetworkingSockets_t)(void);
typedef void (*SteamNetworkingIPAddr_ToString_t)( const SteamNetworkingIPAddr *pAddr, char *buf, size_t cbBuf, bool bWithPort );
typedef bool (*SteamNetworkingIPAddr_ParseString_t)( SteamNetworkingIPAddr *pAddr, const char *pszStr );

GameNetworkingSockets_Init_t g_GameNetworkingSockets_Init = NULL;
SteamNetworkingUtils_t g_SteamNetworkingUtils = NULL;
GameNetworkingSockets_Kill_t g_GameNetworkingSockets_Kill = NULL;
SteamNetworkingSockets_t g_SteamNetworkingSockets = NULL;
SteamNetworkingIPAddr_ToString_t g_SteamNetworkingIPAddr_ToString = NULL;
SteamNetworkingIPAddr_ParseString_t g_SteamNetworkingIPAddr_ParseString = NULL;

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
    //SteamNetworkingMicroseconds time = g_SteamNetworkingUtils()->GetLocalTimestamp() - g_logTimeZero;
    //sithDplayGNS_verbosePrintf( "%10.6f %s\n", time*1e-6, pszMsg );
    sithDplayGNS_verbosePrintf( "%s\n", pszMsg );
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
    vsnprintf( text, sizeof(text), fmt, ap );
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
    vsnprintf( text, sizeof(text), fmt, ap );
    va_end(ap);
    char *nl = strchr( text, '\0' ) - 1;
    if ( nl >= text && *nl == '\n' )
        *nl = '\0';
    DebugOutput( k_ESteamNetworkingSocketsDebugOutputType_Msg, text );
}

static int stdComm_GNS_bInitted = 0;
static int stdComm_GNS_bForceStubs = 0;
static int stdComm_GNS_bSymbolsLoaded = 0;

static void stdComm_GNS_LoadSymbols()
{
    if (stdComm_GNS_bSymbolsLoaded) return;

    static const char pszExportFunc[] = "GameNetworkingSockets_Init";

    #if defined( WIN32 )
        static const char pszModule[] = "libGameNetworkingSockets.dll";
        HMODULE h = ::LoadLibraryA( pszModule );
        if ( h == NULL )
        {
            stdPlatform_Printf("Failed to load %s.\n", pszModule );
            stdComm_GNS_bForceStubs = 1;
            
            return;
        }
        g_GameNetworkingSockets_Init = (GameNetworkingSockets_Init_t)::GetProcAddress(h, "GameNetworkingSockets_Init");
        g_SteamNetworkingUtils = (SteamNetworkingUtils_t)::GetProcAddress(h, "SteamNetworkingUtils_LibV4");
        g_GameNetworkingSockets_Kill = (GameNetworkingSockets_Kill_t)::GetProcAddress(h, "GameNetworkingSockets_Kill");
        g_SteamNetworkingSockets = (SteamNetworkingSockets_t)::GetProcAddress(h, "SteamNetworkingSockets_LibV12");
        g_SteamNetworkingIPAddr_ToString = (SteamNetworkingIPAddr_ToString_t)::GetProcAddress(h, "SteamNetworkingIPAddr_ToString");
        g_SteamNetworkingIPAddr_ParseString = (SteamNetworkingIPAddr_ParseString_t)::GetProcAddress(h, "SteamNetworkingIPAddr_ParseString");
    #elif defined(LINUX) | defined(MACOS)
        #if defined(MACOS)
            static const char pszModule[] = "libGameNetworkingSockets.dylib";
        #else
            static const char pszModule[] = "libGameNetworkingSockets.so";
        #endif
        void* h = dlopen(pszModule, RTLD_LAZY);
        if ( h == NULL )
        {
            stdPlatform_Printf("Failed to dlopen %s.  %s\n", pszModule, dlerror() );
            stdComm_GNS_bForceStubs = 1;
            return;
        }
        g_GameNetworkingSockets_Init = (GameNetworkingSockets_Init_t)dlsym(h, "GameNetworkingSockets_Init");
        g_SteamNetworkingUtils = (SteamNetworkingUtils_t)dlsym(h, "SteamNetworkingUtils_LibV4");
        g_GameNetworkingSockets_Kill = (GameNetworkingSockets_Kill_t)dlsym(h, "GameNetworkingSockets_Kill");
        g_SteamNetworkingSockets = (SteamNetworkingSockets_t)dlsym(h, "SteamNetworkingSockets_LibV12");
        g_SteamNetworkingIPAddr_ToString = (SteamNetworkingIPAddr_ToString_t)dlsym(h, "SteamNetworkingIPAddr_ToString");
        g_SteamNetworkingIPAddr_ParseString = (SteamNetworkingIPAddr_ParseString_t)dlsym(h, "SteamNetworkingIPAddr_ParseString");
    #else
        
    #endif

    if (!g_SteamNetworkingIPAddr_ToString || !g_GameNetworkingSockets_Init 
        || !g_GameNetworkingSockets_Kill || !g_SteamNetworkingSockets 
        || !g_SteamNetworkingIPAddr_ToString || !g_SteamNetworkingIPAddr_ParseString)
    {
        stdPlatform_Printf("Failed to load %s, reverting to stubs.\n");
        stdComm_GNS_bForceStubs = 1;
        return;
    }
    stdPlatform_Printf("Loaded %s successfully.\n", pszModule);

    stdComm_GNS_bSymbolsLoaded = 1;
}

static void InitSteamDatagramConnectionSockets()
{
    if (stdComm_GNS_bInitted) return;

    stdComm_GNS_LoadSymbols();

    #ifdef STEAMNETWORKINGSOCKETS_OPENSOURCE
        SteamDatagramErrMsg errMsg;
        if ( !g_GameNetworkingSockets_Init( nullptr, errMsg ) )
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
        g_SteamNetworkingUtils()->SetGlobalConfigValueInt32( k_ESteamNetworkingConfig_IP_AllowWithoutAuth, 1 );
    #endif

    g_logTimeZero = g_SteamNetworkingUtils()->GetLocalTimestamp();

    g_SteamNetworkingUtils()->SetDebugOutputFunction( k_ESteamNetworkingSocketsDebugOutputType_Msg, DebugOutput );
    stdComm_GNS_bInitted = 1;
}

static void ShutdownSteamDatagramConnectionSockets()
{
    if (!stdComm_GNS_bInitted) return;

    // Give connections time to finish up.  This is an application layer protocol
    // here, it's not TCP.  Note that if you have an application and you need to be
    // more sure about cleanup, you won't be able to do this.  You will need to send
    // a message and then either wait for the peer to close the connection, or
    // you can pool the connection to see if any reliable data is pending.
    sleep_ms( 500 );

    #ifdef STEAMNETWORKINGSOCKETS_OPENSOURCE
        g_GameNetworkingSockets_Kill();
    #else
        SteamDatagramClient_Kill();
    #endif

    stdComm_GNS_bInitted = 0;
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
        m_pInterface = g_SteamNetworkingSockets();

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

        //m_pBcastInterface = SteamNetworkingMessages();

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
            sithDplayGNS_infoPrintf( "Error checking for messages (%d)\n", numMsgs);
            return -1;
        }
        assert( numMsgs == 1 && pIncomingMsg );
        auto itClient = m_mapClients.find( pIncomingMsg->m_conn );
        assert( itClient != m_mapClients.end() );

        if (pIncomingMsg->m_cbSize < 8) {
            sithDplayGNS_infoPrintf("Bad packet size %x\n", pIncomingMsg->m_cbSize);
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

        int outsize = maxLen;
        if (outsize > pIncomingMsg->m_cbSize-8)
            outsize = pIncomingMsg->m_cbSize-8;

        memcpy(pMsg, &dataBuf[8], outsize);
        *pLenInOut = outsize;

        sithDplayGNS_verbosePrintf("Recv %x bytes from %x %x (%x)\n", outsize, idFrom, idTo, *(uint32_t*)pMsg);

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
                sithDplayGNS_verbosePrintf("Sent %x bytes to %x (%x)\n", dwDataSize+8, idTo, *(uint32_t*)lpData);
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
    //ISteamNetworkingMessages *m_pBcastInterface;
    uint64_t availableIds = 0x1;
    uint8_t sendBuffer[4096];
    uint8_t sendBuffer2[4096];
    SteamNetworkingIdentity m_identity;

    struct Client_t
    {
        uint32_t m_id;
        std::string m_sNick;
    };

    std::map< HSteamNetConnection, Client_t > m_mapClients;
    std::queue<int> m_DisconnectedPeers;

    void SendBytesToClient( HSteamNetConnection conn, void *pData, uint32_t len)
    {
        m_pInterface->SendMessageToConnection( conn, pData, len, k_nSteamNetworkingSend_Reliable, nullptr );
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

#if 0
    void TickBroadcastOut()
    {
        uint8_t tmp[8] = {0};
        m_pBcastInterface->SendMessageToUser(m_identity, tmp, 8, k_nSteamNetworkingSend_Unreliable, 1337);
    }
#endif

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
                        snprintf( temp, sizeof(temp), "Problem detected with client %x (%s)", itClient->second.m_id, pInfo->m_info.m_szEndDebug );
                    }
                    else
                    {
                        // Note that here we could check the reason code to see if
                        // it was a "usual" connection or an "unusual" one.
                        pszDebugLogAction = "closed by peer";
                        snprintf( temp, sizeof(temp), "Client id %x has left.", itClient->second.m_id );
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

                    // Only send disconnect messages to fully connected clients.
                    for (int i = 0; i < jkPlayer_maxPlayers; i++)
                    {
                        if (!i && jkGuiNetHost_bIsDedicated) continue;

                        if ( (jkPlayer_playerInfos[i].flags & 2) != 0 && jkPlayer_playerInfos[i].net_id == itClient->second.m_id) {
                            m_DisconnectedPeers.push(itClient->second.m_id);
                            break;
                        }
                    }

                    availableIds &= ~(1 << (itClient->second.m_id-1));
                    m_mapClients.erase( itClient );
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
                    stdPlatform_Printf("Rejecting request.\n");
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

                sithDplayGNS_verbosePrintf("Assigning ID: %x\n", nextId);

                sithDplayGNS_storedEntry.multiModeFlags = sithMulti_multiModeFlags;

                GNSInfoPacket infoPkt = {0};
                infoPkt.id = nextId;
                infoPkt.entry = sithDplayGNS_storedEntry;
                infoPkt.entry.numPlayers = RealConnectedPlayers();
                infoPkt.entry.maxPlayers = sithDplayGNS_storedEntry.maxPlayers;

                jkPlayer_maxPlayers = sithDplayGNS_storedEntry.maxPlayers; // Hack?

                memcpy(sendBuffer2, &infoPkt, sizeof(infoPkt));
                SendBytesToClient( pInfo->m_hConn, sendBuffer2, sizeof(infoPkt)); 

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
        sithDplayGNS_verbosePrintf("incoming!\n");
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
        //RealConnectedPlayers();
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
        //availableIds = 3;
        for (int i = 0; i < jkPlayer_maxPlayers; i++)
        {
            if (!i && jkGuiNetHost_bIsDedicated) continue;


            if ( (jkPlayer_playerInfos[i].flags & 2) != 0 && !jkPlayer_playerInfos[i].net_id ){
                
            }
            else {
                //availableIds |= (1 << (jkPlayer_playerInfos[i].net_id-1));
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
        m_pInterface = g_SteamNetworkingSockets();

        // Start connecting
        char szAddr[ SteamNetworkingIPAddr::k_cchMaxString ];
        g_SteamNetworkingIPAddr_ToString(&serverAddr, szAddr, sizeof(szAddr), true );
        Printf( "Connecting to server at %s", szAddr );
        SteamNetworkingConfigValue_t opt;
        opt.SetPtr( k_ESteamNetworkingConfig_Callback_ConnectionStatusChanged, (void*)SteamNetConnectionStatusChangedCallback );
        //opt.SetPtr( k_ESteamNetworkingConfig_Callback_CreateConnectionSignaling, (void*)SteamNetCreateConnectionSignalingCallback);
        m_hConnection = m_pInterface->ConnectByIPAddress( serverAddr, 1, &opt );
        if ( m_hConnection == k_HSteamNetConnection_Invalid ) {
            Printf( "Failed to create connection" );
            m_closed = 1;
        }

        //m_pBcastInterface = SteamNetworkingMessages();

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
            sithDplayGNS_infoPrintf( "Host is disconnected, forcing exit...\n");
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
            sithDplayGNS_infoPrintf( "Error checking for messages (%d)\n", numMsgs);
            Shutdown();
            m_closed = 1;
            *pIdOut = 1;
            m_hackFallback = !m_hackFallback;
            return m_hackFallback ? 2 : -1;
        }

        if (pIncomingMsg->m_cbSize < 8) {
            sithDplayGNS_infoPrintf("Bad packet size %x\n", pIncomingMsg->m_cbSize);
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

        sithDplayGNS_verbosePrintf("Recv %x bytes from %x %x (%x)\n", pIncomingMsg->m_cbSize, idFrom, idTo, *(uint32_t*)pMsg);

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

        sithDplayGNS_verbosePrintf("Sent %x bytes to %x (%x)\n", dwDataSize+8, idTo, *(uint32_t*)lpData);

        EResult ret = m_pInterface->SendMessageToConnection( m_hConnection, sendBuffer, dwDataSize+8, k_nSteamNetworkingSend_Reliable, nullptr );
        if (ret < 0) {
            sithDplayGNS_infoPrintf( "Error sending message (%d)\n", ret);
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
        jkGuiMultiplayer_dword_5564E8 -= 10000;
    }

    uint32_t id = 0xFFFFFFFF;
private:

    HSteamNetConnection m_hConnection;
    ISteamNetworkingSockets *m_pInterface;
    //ISteamNetworkingMessages *m_pBcastInterface;
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
            sithDplayGNS_infoPrintf( "Error checking for messages (%d)\n", numMsgs);
            return;
        }

        // Just echo anything we get from the server
        sithDplayGNS_verbosePrintf("Received %x bytes (%x)\n", pIncomingMsg->m_cbSize, sizeof(GNSInfoPacket));

        if (id == 0xFFFFFFFF && pIncomingMsg->m_cbSize == sizeof(GNSInfoPacket)) {
            GNSInfoPacket* pPkt = (GNSInfoPacket*)pIncomingMsg->m_pData;
            id = pPkt->id;
            sithDplayGNS_verbosePrintf("We are ID %x\n", id);

            sithDplayGNS_storedEntryEnum = pPkt->entry;
            sithDplayGNS_storedEntryEnum.field_E0 = 10;

            // Hack?
            sithMulti_multiModeFlags = sithDplayGNS_storedEntryEnum.multiModeFlags;
            sithNet_MultiModeFlags = sithDplayGNS_storedEntryEnum.multiModeFlags;
            sithDplayGNS_numEnumd = 1;
        }

        // We don't need this anymore.
        pIncomingMsg->Release();
    }

#if 0
    int TickBroadcastIn()
    {
        SteamNetworkingMessage_t *pMsg = nullptr;
        int numMsgs = m_pBcastInterface->ReceiveMessagesOnChannel(1337, &pMsg, 1);
        if ( numMsgs == 0 )
            return -1;
        if ( numMsgs < 0 ) {
            sithDplayGNS_infoPrintf( "Error checking for messages (%d)\n", numMsgs);
            Shutdown();
            m_closed = 1;
            return 2;
        }

        if (pMsg->m_cbSize < 8) {
            sithDplayGNS_infoPrintf("Bad packet size %x\n", pMsg->m_cbSize);
            Shutdown();
            m_closed = 1;
            return -1;
        }

        sithDplayGNS_infoPrintf("Got broadcast %x\n", pMsg->m_cbSize);
        return 0;
    }
#endif

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
        sithDplayGNS_infoPrintf("incoming!\n");
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
    if (!stdComm_bIsServer)
    {
        id_self = 2;
        id_other = 1;
    }
    //jkPlayer_playerInfos[0].net_id = id_self;
    //jkPlayer_playerInfos[1].net_id = id_other;
    //jk_snwprintf(jkPlayer_playerInfos[0].player_name, 32, "asdf1");
    //jk_snwprintf(jkPlayer_playerInfos[1].player_name, 32, "asdf2");

    //jkPlayer_maxPlayers = 2;

    if (stdComm_bIsServer)
        stdComm_dplayIdSelf = server.id;
    else
        stdComm_dplayIdSelf = client.id;
}

void stdComm_GNS_Startup()
{
    stdComm_GNS_LoadSymbols();

    if (stdComm_GNS_bForceStubs)
    {
        jkGuiMultiplayer_numConnections = 1;
        jk_snwprintf(jkGuiMultiplayer_aConnections[0].name, 0x80, L"Screaming Into The Void (GNS Failed)");
        stdComm_dword_8321E0 = 0;

        memset(jkGuiMultiplayer_aEntries, 0, sizeof(jkMultiEntry) * 32);
        dplay_dword_55D618 = 0;
        return;
    }

    jkGuiMultiplayer_numConnections = 1;
    jk_snwprintf(jkGuiMultiplayer_aConnections[0].name, 0x80, L"Valve GNS");
    stdComm_dword_8321E0 = 0;

    memset(jkGuiMultiplayer_aEntries, 0, sizeof(jkMultiEntry) * 32);
    dplay_dword_55D618 = 0;
    /*jk_snwprintf(jkGuiMultiplayer_aEntries[0].serverName, 0x20, L"OpenJKDF2 Loopback");
    stdString_snprintf(jkGuiMultiplayer_aEntries[0].episodeGobName, 0x20, "JK1MP");
    stdString_snprintf(jkGuiMultiplayer_aEntries[0].mapJklFname, 0x20, "m2.jkl");
    jkGuiMultiplayer_aEntries[0].field_E0 = 10;*/

    Hack_ResetClients();

    addrServer.Clear();
    g_SteamNetworkingIPAddr_ParseString(&addrServer, "127.0.0.1");
    addrServer.m_port = DEFAULT_SERVER_PORT;

    // Create client and server sockets
    InitSteamDatagramConnectionSockets();
}

void stdComm_GNS_Shutdown()
{
    if (stdComm_GNS_bForceStubs)
        return;

    ShutdownSteamDatagramConnectionSockets();
}

int DirectPlay_Receive(int *pIdOut, int *pMsgIdOut, int *pLenOut)
{
    if (stdComm_GNS_bForceStubs)
        return -1;

    Hack_ResetClients();

    if (stdComm_bIsServer)
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
    if (stdComm_GNS_bForceStubs)
        return 0;

    Hack_ResetClients();

    if (stdComm_bIsServer)
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

int stdComm_OpenConnection(void* a)
{
    stdComm_dword_8321DC = 1;
    return 0;
}

void stdComm_CloseConnection()
{
    if ( stdComm_dword_8321DC )
    {
        if ( stdComm_dword_8321E0 )
        {
            //DirectPlay_DestroyPlayer(stdComm_dplayIdSelf);
            DirectPlay_Close();
            stdComm_dword_8321E0 = 0;
            stdComm_bIsServer = 0;
            stdComm_dplayIdSelf = 0;
        }
        //DirectPlay_CloseConnection();
        stdComm_dword_8321DC = 0;
    }
}

int stdComm_Open(int idx, wchar_t* pwPassword)
{
    DirectPlay_EnumSessions2();

    stdComm_dword_8321E8 = 0;
    stdComm_dword_8321E0 = 1;
    stdComm_dplayIdSelf = DirectPlay_CreatePlayer(jkPlayer_playerShortName, 0);
    stdComm_bIsServer = 0;
    stdComm_dplayIdSelf = 2; // HACK
    jkGuiMultiplayer_checksumSeed = jkGuiMultiplayer_aEntries[idx].checksumSeed;

    if (stdComm_GNS_bForceStubs)
        return 0;

    client.Init(addrServer);
    return 0;
}

void stdComm_Close()
{
    if (stdComm_GNS_bForceStubs)
        return;

    if (stdComm_bIsServer)
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

BOOL DirectPlay_Startup()
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

    stdComm_bIsServer = 1;

    if (stdComm_GNS_bForceStubs)
        return 0;
    server.Init(jkGuiNetHost_portNum);

    return 0;
}

int DirectPlay_GetSession_passwordidk(jkMultiEntry* pEntry)
{
    sithDplayGNS_storedEntry = *pEntry;

    jkPlayer_maxPlayers = pEntry->maxPlayers; // Hack?

    return 1;
}

static int stdComm_EnumThread_bForce = 0;
static int stdComm_EnumThread_bInit = 0;
static SDL_Thread *stdComm_EnumThread_thread = NULL;
static SDL_mutex* stdComm_EnumThread_mutex = NULL;

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    s, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, maxlen);
            break;

        default:
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
    }

    return s;
}

static int stdComm_EnumThread(void *ptr)
{
    while (stdComm_EnumThread_bInit)
    {
        SDL_LockMutex(stdComm_EnumThread_mutex);
        stdString_WcharToChar(jkGuiMultiplayer_ipText_conv, jkGuiMultiplayer_ipText, 255);

        std::string sAddress( jkGuiMultiplayer_ipText_conv );
        std::string sService;
        size_t colon = sAddress.find( ':' );
        if ( colon == std::string::npos )
        {
            sService = ""; // Default port
        }
        else
        {
            sService = sAddress.substr( colon+1 );
            sAddress.erase( colon );
        }

        // Resolve name synchronously
        addrinfo *pAddrInfo = nullptr;
        std::string finalStr = "";
        int r = getaddrinfo( sAddress.c_str(), sService.c_str(), nullptr, &pAddrInfo );
        if ( r != 0 || pAddrInfo == nullptr )
        {
            //snprintf( errMsg, sizeof(errMsg), "Invalid/unknown server address.  getaddrinfo returned %d", r );
            //return nullptr;

        }
        else {
            get_ip_str(pAddrInfo->ai_addr, jkGuiMultiplayer_ipText_conv, 255);
            finalStr += std::string(jkGuiMultiplayer_ipText_conv);
            if (sService != "") {
                finalStr += ":";
            finalStr += sService;
            }
        }

        g_SteamNetworkingIPAddr_ParseString(&addrServer, finalStr.c_str());
        if (!addrServer.m_port) {
            addrServer.m_port = DEFAULT_SERVER_PORT;
        }

        if (stdComm_EnumThread_bForce || strncmp(jkGuiMultiplayer_ipText_conv, addrServerLast, 256) || addrServerPortLast != addrServer.m_port)
            client.GetServerInfo(addrServer);
        strncpy(addrServerLast, jkGuiMultiplayer_ipText_conv, 256);
        addrServerPortLast = addrServer.m_port;
        stdComm_EnumThread_bForce = 0;

        SDL_UnlockMutex(stdComm_EnumThread_mutex);

        SDL_Delay(100);
    }

    return 0;
}

int DirectPlay_EnumSessions2()
{
    if (stdComm_GNS_bForceStubs)
        return 0;

    if (!stdComm_EnumThread_bInit)
        return 0;

    stdComm_EnumThread_bInit = 0;

    int threadReturnValue;
    SDL_WaitThread(stdComm_EnumThread_thread, &threadReturnValue);
    stdComm_EnumThread_thread = NULL;

    sithDplayGNS_verbosePrintf("Enum thread done\n");

    return 0;
}

int stdComm_EnumSessions(int a, void* b)
{
    if (stdComm_GNS_bForceStubs)
        return 0;

    if (!stdComm_EnumThread_mutex)
        stdComm_EnumThread_mutex = SDL_CreateMutex();

    SDL_LockMutex(stdComm_EnumThread_mutex);
    stdComm_EnumThread_bForce = 1;
    jkGuiMultiplayer_aEntries[0] = sithDplayGNS_storedEntryEnum;
    dplay_dword_55D618 = sithDplayGNS_numEnumd;
    SDL_UnlockMutex(stdComm_EnumThread_mutex);

    if (stdComm_EnumThread_bInit)
        return 0;

    Hack_ResetClients();

    dplay_dword_55D618 = 0;
    sithDplayGNS_numEnumd = 0;
    memset(&sithDplayGNS_storedEntryEnum, 0, sizeof(sithDplayGNS_storedEntryEnum));
    memset(&jkGuiMultiplayer_aEntries[0], 0, sizeof(jkGuiMultiplayer_aEntries[0]));
    memset(addrServerLast, 0, sizeof(addrServerLast));
    addrServerPortLast = -1;

    stdComm_EnumThread_bInit = 1;

    stdComm_EnumThread_thread = SDL_CreateThread(stdComm_EnumThread, "stdComm_EnumThread", (void *)NULL);
    sithDplayGNS_verbosePrintf("Enum thread start\n");

    //DirectPlay_EnumSessions2();

    //client.GetServerInfo(addrServer);

    SDL_LockMutex(stdComm_EnumThread_mutex);
    jkGuiMultiplayer_aEntries[0] = sithDplayGNS_storedEntryEnum;
    dplay_dword_55D618 = sithDplayGNS_numEnumd;
    SDL_UnlockMutex(stdComm_EnumThread_mutex);
    

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

int DirectPlay_IdkSessionDesc(jkMultiEntry* pEntry)
{
    //TODO
    return 1;
}

}
