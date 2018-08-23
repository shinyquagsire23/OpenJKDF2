
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
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirectSound::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirectSound::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirectSound::Release\n");
        
        GlobalRelease(this_ptr);
    }
    
    /*** IDirectSound ***/
    Q_INVOKABLE uint32_t CreateSoundBuffer(void* this_ptr, uint32_t a, uint32_t *ppDSBuffer, void* pUnkOuter)
    {
        printf("STUB: IDirectSound::CreateSoundBuffer\n");
        *ppDSBuffer = CreateInterfaceInstance("IDirectSoundBuffer", 200);

        return 0;
    }

    Q_INVOKABLE uint32_t GetCaps(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectSound::GetCaps\n");
    }
    
    Q_INVOKABLE uint32_t DuplicateSoundBuffer(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectSound::DuplicateSoundBuffer\n");
    }

    Q_INVOKABLE uint32_t SetCooperativeLevel(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectSound::SetCooperativeLevel\n");
    }

    Q_INVOKABLE uint32_t Compact(void* this_ptr)
    {
        printf("STUB: IDirectSound::Compact\n");
    }

    Q_INVOKABLE uint32_t GetSpeakerConfig(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectSound::GetSpeakerConfig\n");
    }

    Q_INVOKABLE uint32_t SetSpeakerConfig(void* this_ptr, uint32_t b)
    {
        printf("STUB: IDirectSound::SetSpeakerConfig\n");
    }

    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectSound::Initialize\n");
    }

//    Q_INVOKABLE uint32_t ();
};

extern IDirectSound* idirectsound;

#endif // IDIRECTSOUND_H
