
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
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirectSoundBuffer::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirectSoundBuffer::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirectSoundBuffer::Release\n");
        
        GlobalRelease(this_ptr);
    }
    
    /*** IDirectSoundBuffer methods ***/
    Q_INVOKABLE uint32_t GetCaps(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::GetCaps\n");
        
        return 0;
    }

    Q_INVOKABLE void GetCurrentPosition(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirectSoundBuffer::GetCurrentPosition\n");
    }

    Q_INVOKABLE void GetFormat(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB:: IDirectSoundBuffer::GetFormat\n");
    }

    Q_INVOKABLE void GetVolume(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::GetVolume\n");
    }

    Q_INVOKABLE void GetPan(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::GetPan\n");
    }

    Q_INVOKABLE void GetFrequency(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::GetFrequency\n");
    }

    Q_INVOKABLE void GetStatus(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::GetStatus\n");
    }

    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirectSoundBuffer::Initialize\n");
    }

    Q_INVOKABLE uint32_t Lock(void* this_ptr, uint32_t dwWriteCursor, uint32_t dwWriteBytes, uint32_t* lplpvAudioPtr1, uint32_t* lpdwAudioBytes1, uint32_t* lplpvAudioPtr2, uint32_t* lpdwAudioBytes2, uint32_t dwFlags )
    {
        printf("STUB:: IDirectSoundBuffer::Lock\n");
        
        return 1;
    }

    Q_INVOKABLE void Play(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectSoundBuffer::Play\n");
    }

    Q_INVOKABLE void SetCurrentPosition(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectSoundBuffer::SetCurrentPosition\n");
    }

    Q_INVOKABLE void SetFormat(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::SetFormat\n");
    }

    Q_INVOKABLE void SetVolume(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::SetVolume\n");
    }

    Q_INVOKABLE void SetPan(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::SetPan\n");
    }

    Q_INVOKABLE void SetFrequency(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::SetFrequency\n");
    }

    Q_INVOKABLE void Stop(void* this_ptr)
    {
        printf("STUB: IDirectSoundBuffer::Stop\n");
    }

    Q_INVOKABLE void Unlock(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB:: IDirectSoundBuffer::Unlock\n");
    }

    Q_INVOKABLE void Restore(void* this_ptr)
    {
        printf("STUB:: IDirectSoundBuffer::Restore\n");
    }

//    Q_INVOKABLE uint32_t ();
};

extern IDirectSoundBuffer *idirectsoundbuffer;

#endif // IDIRECTSOUNDBUFFER_H
