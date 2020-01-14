
#ifndef IDIRECTSOUND_H
#define IDIRECTSOUND_H

#include <stdint.h>
#include <QObject>
#include <unicorn/unicorn.h>

#include "vm.h"
#include "dlls/kernel32.h"
#include "dlls/winutils.h"
#include <SDL2/SDL.h>
#include <SDL2/SDL_mixer.h>

typedef struct WAVEFORMATEX 
{
    uint16_t wFormatTag;
    uint16_t nChannels;
    uint32_t nSamplesPerSec;
    uint32_t nAvgBytesPerSec;
    uint16_t nBlockAlign;
    uint16_t wBitsPerSample;
    uint16_t cbSize;
} WAVEFORMATEX;

typedef struct DSBUFFERDESC 
{
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwBufferBytes;
    uint32_t dwReserved;
    vm_ptr<WAVEFORMATEX*> lpwfxFormat;
    uint8_t guid3DAlgorithm[0x20];
} DSBUFFERDESC;

struct dsndbuffer_ext
{
    uint32_t lpVtbl;
    uint8_t padding[0x200];
    vm_ptr<uint8_t *> buffer;
    uint32_t size;
    int channel;
    int volume;
    
    WAVEFORMATEX format;
    void* raw_buffer;
};

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
    Q_INVOKABLE uint32_t CreateSoundBuffer(void* this_ptr, DSBUFFERDESC* pcDSBufferDesc, uint32_t *ppDSBuffer, void* pUnkOuter)
    {
        printf("STUB: IDirectSound::CreateSoundBuffer desc(%x %x)", pcDSBufferDesc->dwFlags, pcDSBufferDesc->dwBufferBytes);
        
        *ppDSBuffer = CreateInterfaceInstance("IDirectSoundBuffer", 21);
        struct dsndbuffer_ext* new_obj = (struct dsndbuffer_ext*)vm_ptr_to_real_ptr(*ppDSBuffer);
        
        if (pcDSBufferDesc->lpwfxFormat.translated())
        {
            WAVEFORMATEX* format = pcDSBufferDesc->lpwfxFormat.translated();
            new_obj->format = *format;
            
            printf(" format(tag %x, channels %u, samples/sec %u, avg bytes/sec 0x%x, block align %x, bits/sample %u, cbSize %x)",
                   format->wFormatTag, format->nChannels, format->nSamplesPerSec, format->nAvgBytesPerSec, format->nBlockAlign,
                   format->wBitsPerSample, format->cbSize);
        }
        printf("\n");

        new_obj->buffer = 0;
        new_obj->raw_buffer = NULL;
        new_obj->volume = 0;
        new_obj->channel = -1;
        new_obj->size = 0;

        return 0;
    }

    Q_INVOKABLE uint32_t GetCaps(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectSound::GetCaps\n");
        return 0;
    }
    
    Q_INVOKABLE uint32_t DuplicateSoundBuffer(void* this_ptr, struct dsndbuffer_ext* orig, uint32_t* duplicate)
    {
        printf("STUB: IDirectSound::DuplicateSoundBuffer\n");
        
        *duplicate = CreateInterfaceInstance("IDirectSoundBuffer", 21);
        
        struct dsndbuffer_ext* dup = (struct dsndbuffer_ext*)vm_ptr_to_real_ptr(*duplicate);
        dup->buffer = 0;
        dup->size = orig->size;
        dup->channel = -1;
        dup->volume = orig->volume;
        dup->format = orig->format;
        
        //TODO: refcnt this stuff instead?
        if (orig->raw_buffer)
        {
            dup->raw_buffer = malloc(dup->size);
            memcpy(dup->raw_buffer, orig->raw_buffer, dup->size);
        }

        return 0;
    }

    Q_INVOKABLE uint32_t SetCooperativeLevel(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectSound::SetCooperativeLevel\n");
        return 0;
    }

    Q_INVOKABLE uint32_t Compact(void* this_ptr)
    {
        printf("STUB: IDirectSound::Compact\n");
        return 0;
    }

    Q_INVOKABLE uint32_t GetSpeakerConfig(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectSound::GetSpeakerConfig\n");
        return 0;
    }

    Q_INVOKABLE uint32_t SetSpeakerConfig(void* this_ptr, uint32_t b)
    {
        printf("STUB: IDirectSound::SetSpeakerConfig\n");
        return 0;
    }

    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectSound::Initialize\n");
        return 0;
    }

//    Q_INVOKABLE uint32_t ();
};

extern IDirectSound* idirectsound;

#endif // IDIRECTSOUND_H
