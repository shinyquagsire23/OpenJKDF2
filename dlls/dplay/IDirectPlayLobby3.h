
#ifndef IDIRECTPLAYLOBBY3_H
#define IDIRECTPLAYLOBBY3_H

#include <QObject>
#include "vm.h"
#include "dlls/winutils.h"

typedef uint32_t DWORD;
typedef uint16_t* LPWSTR;
typedef char* LPSTR;
typedef void** LPVOID;
typedef struct GUID
{
    uint32_t a[4];
} GUID;

typedef struct tagDPNAME
{
    DWORD   dwSize;
    DWORD   dwFlags;            /* Not used must be 0 */

    union /*playerShortName */      /* Player's Handle? */
    {
        LPWSTR  lpszShortName;
        LPSTR   lpszShortNameA;
    } DUMMYUNIONNAME1;

    union /*playerLongName */       /* Player's formal/real name */
    {
        LPWSTR  lpszLongName;
        LPSTR   lpszLongNameA;
    } DUMMYUNIONNAME2;

} DPNAME, *LPDPNAME;

typedef struct tagDPSESSIONDESC2
{
    DWORD   dwSize;
    DWORD   dwFlags;
    GUID    guidInstance;
    GUID    guidApplication;   /* GUID of the DP application, GUID_NULL if
                                * all applications! */

    DWORD   dwMaxPlayers;
    DWORD   dwCurrentPlayers;   /* (read only value) */

    union  /* Session name */
    {
        LPWSTR  lpszSessionName;
        LPSTR   lpszSessionNameA;
    } DUMMYUNIONNAME1;

    union  /* Optional password */
    {
        LPWSTR  lpszPassword;
        LPSTR   lpszPasswordA;
    } DUMMYUNIONNAME2;

    DWORD   dwReserved1;
    DWORD   dwReserved2;

    DWORD   dwUser1;        /* For use by the application */
    DWORD   dwUser2;
    DWORD   dwUser3;
    DWORD   dwUser4;
} DPSESSIONDESC2, *LPDPSESSIONDESC2;

typedef struct tagDPLCONNECTION
{
    DWORD               dwSize;
    DWORD               dwFlags;
    LPDPSESSIONDESC2    lpSessionDesc;  /* Ptr to session desc to use for connect */
    LPDPNAME            lpPlayerName;   /* Ptr to player name structure */
    GUID                guidSP;         /* GUID of Service Provider to use */
    LPVOID              lpAddress;      /* Ptr to Address of Service Provider to use */
    DWORD               dwAddressSize;  /* Size of address data */
} DPLCONNECTION, *LPDPLCONNECTION;

class IDirectPlayLobby3 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectPlayLobby3() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirectPlayLobby3::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirectPlayLobby3::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirectPlayLobby3::Release\n");
        
        GlobalRelease(this_ptr);
    }
    
    /*** IDirectPlayLobby ***/
    Q_INVOKABLE uint32_t Connect(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectPlayLobby3::Connect(%x %x %x)\n", a, b, c);
        
        return 0;
    }
    
    Q_INVOKABLE void CreateAddress(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f)
    {
        printf("STUB: IDirectPlayLobby3::CreateAddress\n");
    }
    
    Q_INVOKABLE void EnumAddress(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectPlayLobby3::EnumAddress\n");
    }
    
    Q_INVOKABLE uint32_t EnumAddressTypes(void* this_ptr, uint32_t lpEnumAddressTypeCallback, uint32_t guidSP, uint32_t lpContext, uint32_t dwFlags)
    {
        printf("STUB: IDirectPlayLobby3::EnumAddressTypes(%x, %x, %x, %x)\n", lpEnumAddressTypeCallback, guidSP, lpContext, dwFlags);
        
        //uint32_t ret = vm_call_func(lpEnumAddressTypeCallback, iid_ptr, lpContext, dwFlags);
        
        return 0;
    }
    
    Q_INVOKABLE void EnumLocalApplications(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectPlayLobby3::EnumLocalApplications\n");
    }
    
    Q_INVOKABLE uint32_t GetConnectionSettings(void* this_ptr, uint32_t a, uint32_t outSettings, uint32_t* lpdwSize)
    {
        printf("STUB: IDirectPlayLobby3::GetConnectionSettings(%x ...)\n", a);
        
        return 0;  
#if 0
        if (lpdwSize)
            *lpdwSize = 0x28; //TODO sizeof
        
        if (!outSettings)
        {
            return 0x8877001E;
        }
#endif
        
        return 0;
    }
    
    Q_INVOKABLE void ReceiveLobbyMessage(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectPlayLobby3::ReceiveLobbyMessage\n");
    }
    
    Q_INVOKABLE void RunApplication(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectPlayLobby3::RunApplication\n");
    }
    
    Q_INVOKABLE void SendLobbyMessage(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectPlayLobby3::SendLobbyMessage\n");
    }
    
    Q_INVOKABLE uint32_t SetConnectionSettings(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectPlayLobby3::SetConnectionSettings(%x %x %x)\n", a, b, c);
        
        return 0;
    }
    
    Q_INVOKABLE void SetLobbyMessageEvent(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectPlayLobby3::SetLobbyMessageEvent\n");
    }
    
    /*** IDirectPlayLobby2 ***/
    
    Q_INVOKABLE void CreateCompoundAddress(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectPlayLobby3::CreateCompoundAddress\n");
    }
    
    /*** IDirectPlayLobby3 ***/

//    Q_INVOKABLE uint32_t ();
};

extern IDirectPlayLobby3* idirectplaylobby3;

#endif // IDIRECTPLAYLOBBY3_H
