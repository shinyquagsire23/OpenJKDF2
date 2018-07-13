#ifndef DPLAY_H
#define DPLAY_H

#include <QObject>
#include <unicorn/unicorn.h>
#include "dlls/winutils.h"

class DPlay : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE DPlay() {}
    
    Q_INVOKABLE void DirectPlayLobbyCreateA(uint8_t* lpGUID, uint32_t* lplpDPL, void* lpUnk, void* lpData, uint32_t dwDatasize)
    {
        //printf("GUID: %s\n", guid_to_string(lpGUID).c_str());
        *lplpDPL = CreateInterfaceInstance("IDirectPlayLobby3", 200);
    }

//    Q_INVOKABLE uint32_t ();
};

extern DPlay *dplay;

#endif // DPLAY_H
