
#ifndef IDIRECTPLAY3_H
#define IDIRECTPLAY3_H

#include <QObject>
#include <unicorn/unicorn.h>

class IDirectPlay3 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectPlay3() {}

    /*** Base ***/
    Q_INVOKABLE void QueryInterface(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void AddRef(void* this_ptr){}
    Q_INVOKABLE void Release(void* this_ptr){}
    
    /*** IDirectPlay2 ***/
    Q_INVOKABLE void AddPlayerToGroup(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void Close(void* this_ptr){}
    Q_INVOKABLE void CreateGroup(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e){}
    Q_INVOKABLE void CreatePlayer(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f){}
    Q_INVOKABLE void DeletePlayerFromGroup(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void DestroyGroup(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void DestroyPlayer(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void EnumGroupPlayers(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e){}
    Q_INVOKABLE void EnumGroups(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void EnumPlayers(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void EnumSessions(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e){}
    Q_INVOKABLE void GetCaps(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void GetGroupData(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void GetGroupName(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void GetMessageCount(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void GetPlayerAddress(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void GetPlayerCaps(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void GetPlayerData(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void GetPlayerName(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void GetSessionDesc(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void Open(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void Receive(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e){}
    Q_INVOKABLE void Send(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e){}
    Q_INVOKABLE void SetGroupData(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void SetGroupName(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void SetPlayerData(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void SetPlayerName(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void SetSessionDesc(void* this_ptr, uint32_t a, uint32_t b){}


    /*** IDirectPlay3 ***/
    Q_INVOKABLE void AddGroupToGroup(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void CreateGroupInGroup(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f){}
    Q_INVOKABLE void DeleteGroupFromGroup(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void EnumConnections(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
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

#endif // IDIRECTPLAY3_H
