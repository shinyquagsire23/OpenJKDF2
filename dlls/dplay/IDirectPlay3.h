
#ifndef IDIRECTPLAY3_H
#define IDIRECTPLAY3_H

#include <QObject>
#include "vm.h"
#include "dlls/winutils.h"

class IDirectPlay3 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectPlay3() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirectPlay3::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }
    
    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirectPlay3::AddRef\n");
    }
    
    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirectPlay3::Release\n");
        
        GlobalRelease(this_ptr);
    }
    
    /*** IDirectPlay2 ***/
    Q_INVOKABLE void AddPlayerToGroup(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectPlay3::AddPlayerToGroup\n");
    }
    
    Q_INVOKABLE void Close(void* this_ptr)
    {
        printf("STUB: IDirectPlay3::Close\n");
    }
    
    Q_INVOKABLE void CreateGroup(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectPlay3::CreateGroup\n");
    }
    
    Q_INVOKABLE void CreatePlayer(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f)
    {
        printf("STUB: IDirectPlay3::CreatePlayer\n");
    }
    
    Q_INVOKABLE void DeletePlayerFromGroup(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectPlay3::DeletePlayerFromGroup\n");
    }
    
    Q_INVOKABLE void DestroyGroup(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectPlay3::DestroyGroup\n");
    }
    
    Q_INVOKABLE void DestroyPlayer(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectPlay3::DestroyPlayer\n");
    }
    
    Q_INVOKABLE void EnumGroupPlayers(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectPlay3::EnumGroupPlayers\n");
    }
    
    Q_INVOKABLE void EnumGroups(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectPlay3::EnumGroups\n");
    }
    
    Q_INVOKABLE void EnumPlayers(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectPlay3::EnumPlayers\n");
    }
    
    Q_INVOKABLE void EnumSessions(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectPlay3::EnumSessions\n");
    }
    
    Q_INVOKABLE void GetCaps(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectPlay3::GetCaps\n");
    }
    
    Q_INVOKABLE void GetGroupData(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectPlay3::GetGroupData\n");
    }
    
    Q_INVOKABLE void GetGroupName(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectPlay3::GetGroupName\n");
    }
    
    Q_INVOKABLE void GetMessageCount(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectPlay3::GetMessageCount\n");
    }
    
    Q_INVOKABLE void GetPlayerAddress(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectPlay3::GetPlayerAddress\n");
    }
    
    Q_INVOKABLE void GetPlayerCaps(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectPlay3::GetPlayerCaps\n");
    }
    
    Q_INVOKABLE void GetPlayerData(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectPlay3::GetPlayerData\n");
    }
    
    Q_INVOKABLE void GetPlayerName(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectPlay3::GetPlayerName\n");
    }
    
    Q_INVOKABLE void GetSessionDesc(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectPlay3::GetSessionDesc\n");
    }
    
    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectPlay3::Initialize\n");
    }
    
    Q_INVOKABLE void Open(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectPlay3::Open\n");
    }
    
    Q_INVOKABLE void Receive(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectPlay3::Receive\n");
    }
    
    Q_INVOKABLE void Send(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectPlay3::Send\n");
    }
    
    Q_INVOKABLE void SetGroupData(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectPlay3::SetGroupData\n");
    }
    
    Q_INVOKABLE void SetGroupName(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectPlay3::SetGroupName\n");
    }
    
    Q_INVOKABLE void SetPlayerData(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectPlay3::SetPlayerData\n");
    }
    
    Q_INVOKABLE void SetPlayerName(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectPlay3::SetPlayerName\n");
    }
    
    Q_INVOKABLE void SetSessionDesc(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectPlay3::SetSessionDesc\n");
    }


    /*** IDirectPlay3 ***/
    Q_INVOKABLE void AddGroupToGroup(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void CreateGroupInGroup(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f){}
    Q_INVOKABLE void DeleteGroupFromGroup(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE uint32_t EnumConnections(void* this_ptr, uint32_t lpGuid, uint32_t callback, uint32_t unk1, uint32_t unk2)
    {
        printf("STUB: IDirectPlay3::EnumConnections(%x %x %x %x)\n", lpGuid, callback, unk1, unk2);
        
        // call callback(connectionGUID, lpConnection, dwConnectionSize, lpName, dwFlags, lpContext)
        
        return 0;
    }
    Q_INVOKABLE void EnumGroupsInGroup(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e){}
    Q_INVOKABLE void GetGroupConnectionSettings(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void InitializeConnection(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void SecureOpen(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void SendChatMessage(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void SetGroupConnectionSettings(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void StartSession(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void GetGroupFlags(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void GetGroupParent(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void GetPlayerAccount(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void GetPlayerFlags(void* this_ptr, uint32_t a, uint32_t b){}

//    Q_INVOKABLE uint32_t ();
};

extern IDirectPlay3 *idirectplay3;

#endif // IDIRECTPLAY3_H
