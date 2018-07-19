#ifndef DSOUND_H
#define DSOUND_H

#include <QObject>
#include <unicorn/unicorn.h>
#include "dlls/winutils.h"

class DSound : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE DSound() {}
    
    Q_INVOKABLE void DirectSoundCreate(uint8_t* lpGuid, uint32_t* ppDS, void* pUnkOuter)
    {
        *ppDS = CreateInterfaceInstance("IDirectSound", 200);
    }

//    Q_INVOKABLE uint32_t ();
};

extern DSound* dsound;

#endif // DSOUND_H
