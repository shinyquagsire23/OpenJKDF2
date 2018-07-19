
#ifndef IDIRECTSOUND_H
#define IDIRECTSOUND_H

#include <QObject>
#include <unicorn/unicorn.h>

#include "dlls/winutils.h"

class IDirectSound : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectSound() {}

    /*** Base ***/
    Q_INVOKABLE void QueryInterface(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void AddRef(void* this_ptr){}
    Q_INVOKABLE void Release(void* this_ptr){}
    
    /*** IDirectSound ***/
    Q_INVOKABLE void CreateSoundBuffer(void* this_ptr, uint32_t a, uint32_t *ppDSBuffer, void* pUnkOuter)
    {
        *ppDSBuffer = CreateInterfaceInstance("IDirectSoundBuffer", 200);
    }
    Q_INVOKABLE void GetCaps(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void DuplicateSoundBuffer(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void SetCooperativeLevel(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void Compact(void* this_ptr){}
    Q_INVOKABLE void GetSpeakerConfig(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void SetSpeakerConfig(void* this_ptr, uint32_t b){}
    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t a){}

//    Q_INVOKABLE uint32_t ();
};

extern IDirectSound* idirectsound;

#endif // IDIRECTSOUND_H
