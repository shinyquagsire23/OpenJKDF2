
#ifndef IDIRECTPLAYLOBBY3_H
#define IDIRECTPLAYLOBBY3_H

#include <QObject>
#include <unicorn/unicorn.h>

class IDirectPlayLobby3 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectPlayLobby3() {}

    /*** Base ***/
    Q_INVOKABLE void QueryInterface(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void AddRef(void* this_ptr){}
    Q_INVOKABLE void Release(void* this_ptr){}
    
    /*** IDirectPlayLobby ***/
    Q_INVOKABLE void Connect(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void ConnectEx(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void CreateAddress(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f){}
    Q_INVOKABLE void CreateCompoundAddress(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void EnumAddress(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void EnumAddressTypes(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void EnumLocalApplications(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void GetConnectionSettings(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void ReceiveLobbyMessage(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e){}
    Q_INVOKABLE void RegisterApplication(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void RunApplication(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void SendLobbyMessage(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void SetConnectionSettings(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void SetLobbyMessageEvent(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    
    /*** IDirectPlayLobby2 ***/
    
    /*** IDirectPlayLobby3 ***/

//    Q_INVOKABLE uint32_t ();
};

extern IDirectPlayLobby3* idirectplaylobby3;

#endif // IDIRECTPLAYLOBBY3_H
