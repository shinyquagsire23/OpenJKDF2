
#ifndef IDIRECTSOUNDBUFFER_H
#define IDIRECTSOUNDBUFFER_H

#include <QObject>
#include <unicorn/unicorn.h>

#include "dlls/winutils.h"

class IDirectSoundBuffer : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectSoundBuffer() {}

    /*** Base ***/
    Q_INVOKABLE void QueryInterface(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void AddRef(void* this_ptr){}
    Q_INVOKABLE void Release(void* this_ptr){}
    
    /*** IDirectSoundBuffer methods ***/
    Q_INVOKABLE void GetCaps(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void GetCurrentPosition(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void GetFormat(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void GetVolume(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void GetPan(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void GetFrequency(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void GetStatus(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void Lock(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g){}
    Q_INVOKABLE void Play(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectSoundBuffer::Play\n");
    }
    Q_INVOKABLE void SetCurrentPosition(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectSoundBuffer::SetCurrentPosition\n");
    }
    Q_INVOKABLE void SetFormat(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void SetVolume(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void SetPan(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void SetFrequency(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void Stop(void* this_ptr)
    {
        printf("STUB: IDirectSoundBuffer::Stop\n");
    }
    Q_INVOKABLE void Unlock(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void Restore(void* this_ptr){}

//    Q_INVOKABLE uint32_t ();
};

extern IDirectSoundBuffer *idirectsoundbuffer;

#endif // IDIRECTSOUNDBUFFER_H
