
#ifndef IDIRECTSOUNDBUFFER_H
#define IDIRECTSOUNDBUFFER_H

#include <QObject>

#include "vm.h"
#include "dlls/winutils.h"
#include "dlls/kernel32.h"

#include "main.h"
#include "dlls/dsound/IDirectSound.h"

class IDirectSoundBuffer : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectSoundBuffer() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(struct dsndbuffer_ext* obj, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirectSoundBuffer::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(struct dsndbuffer_ext* obj)
    {
        printf("STUB: IDirectSoundBuffer::AddRef\n");
    }

    Q_INVOKABLE void Release(struct dsndbuffer_ext* obj)
    {
        //printf("STUB: IDirectSoundBuffer::Release\n");
        
        if (obj->buffer.raw_vm_ptr)
            kernel32->VirtualFree(obj->buffer.raw_vm_ptr, 0, 0);
        
        GlobalRelease(obj);
    }
    
    /*** IDirectSoundBuffer methods ***/
    Q_INVOKABLE uint32_t GetCaps(struct dsndbuffer_ext* obj, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::GetCaps\n");
        
        return 0;
    }

    Q_INVOKABLE uint32_t GetCurrentPosition(struct dsndbuffer_ext* obj, uint32_t* lpdwCurrentPlayCursor, uint32_t* lpdwCurrentWriteCursor)
    {
        printf("STUB:: IDirectSoundBuffer::GetCurrentPosition\n");
        
        //TODO
        *lpdwCurrentPlayCursor = 0;
        *lpdwCurrentWriteCursor = 0;
        
        return 0;
    }

    Q_INVOKABLE void GetFormat(struct dsndbuffer_ext* obj, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB:: IDirectSoundBuffer::GetFormat\n");
    }

    Q_INVOKABLE uint32_t GetVolume(struct dsndbuffer_ext* obj, uint32_t* lplVolume)
    {
        *lplVolume = obj->volume;
        
        return 0;
    }

    Q_INVOKABLE uint32_t GetPan(struct dsndbuffer_ext* obj, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::GetPan %x\n", a);
        
        return 0;
    }

    Q_INVOKABLE uint32_t GetFrequency(struct dsndbuffer_ext* obj, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::GetFrequency %x\n", a);
        
        return 0;
    }

    Q_INVOKABLE uint32_t GetStatus(struct dsndbuffer_ext* obj, uint32_t a)
    {
        //printf("STUB:: IDirectSoundBuffer::GetStatus %x\n", a);
        
        return 0;
    }

    Q_INVOKABLE void Initialize(struct dsndbuffer_ext* obj, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirectSoundBuffer::Initialize\n");
    }

    Q_INVOKABLE uint32_t Lock(struct dsndbuffer_ext* obj, uint32_t dwWriteCursor, uint32_t dwWriteBytes, uint32_t* lplpvAudioPtr1, uint32_t* lpdwAudioBytes1, uint32_t* lplpvAudioPtr2, uint32_t* lpdwAudioBytes2, uint32_t dwFlags)
    {
        printf("STUB:: IDirectSoundBuffer::Lock %x %x %p %p %p %p %x\n", dwWriteCursor, dwWriteBytes, lplpvAudioPtr1, lpdwAudioBytes1, lplpvAudioPtr2,  lpdwAudioBytes2, dwFlags);
        
        uint32_t alloc = kernel32->VirtualAlloc(0, dwWriteBytes, 0, 0);
        
        //TODO flags?
        *lplpvAudioPtr1 = alloc;
        *lpdwAudioBytes1 = dwWriteBytes;
        
        if (lplpvAudioPtr2)
            *lplpvAudioPtr2 = 0;
        if (lpdwAudioBytes2)
            *lpdwAudioBytes2 = 0;
        
        obj->buffer = alloc;

        return 0;
    }

    Q_INVOKABLE uint32_t Play(struct dsndbuffer_ext* obj, uint32_t res, uint32_t res2, uint32_t c)
    {
        //printf("STUB: IDirectSoundBuffer::Play %x\n", c);

        if (obj->buffer.raw_vm_ptr)
        {
            obj->channel = sdl_audio_mix(obj->buffer.translated(), obj->size, obj->volume);
            
            /*FILE* test = fopen("sound_dump2.bin", "wb");
            fwrite(obj->buffer.translated(), obj->size, 1, test);
            fclose(test);
            
            uint8_t* audio = obj->buffer.translated();
            for (int i = 0; i < 0x100; i++)
            {
                printf("%s%02x ", (i && i % 16 == 0 ? "\n" : ""), audio[i]);
            }
            printf("\n");*/
        }

        return 0;
    }

    Q_INVOKABLE uint32_t SetCurrentPosition(struct dsndbuffer_ext* obj, uint32_t a)
    {
        //printf("STUB: IDirectSoundBuffer::SetCurrentPosition %x\n", a);

        return 0;
    }

    Q_INVOKABLE uint32_t SetFormat(struct dsndbuffer_ext* obj, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::SetFormat\n");
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetVolume(struct dsndbuffer_ext* obj, int32_t lVolume)
    {
        //printf("STUB:: IDirectSoundBuffer::SetVolume %i\n", lVolume);
        
        obj->volume = lVolume;
        //Mix_Volume
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetPan(struct dsndbuffer_ext* obj, uint32_t a)
    {
        //printf("STUB:: IDirectSoundBuffer::SetPan %x\n", a);
        
        //Mix_SetPanning
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetFrequency(struct dsndbuffer_ext* obj, uint32_t a)
    {
        printf("STUB:: IDirectSoundBuffer::SetFrequency %x\n", a);
        
        return 0;
    }

    Q_INVOKABLE uint32_t Stop(struct dsndbuffer_ext* obj)
    {
        //printf("STUB: IDirectSoundBuffer::Stop\n");

        if (obj->channel > 0)
            sdl_audio_halt(obj->channel);
        obj->channel = -1;

        return 0;
    }

    Q_INVOKABLE uint32_t Unlock(struct dsndbuffer_ext* obj, uint32_t lpvAudioPtr1, uint32_t dwAudioBytes1, uint32_t lpvAudioPtr2, uint32_t dwAudioBytes2)
    {
        printf("STUB:: IDirectSoundBuffer::Unlock %x %x %x %x\n", lpvAudioPtr1, dwAudioBytes1, lpvAudioPtr2, dwAudioBytes2);

        obj->size = dwAudioBytes1;
        obj->channel = -1;
        
        /*FILE* test = fopen("sound_dump.bin", "wb");
        fwrite(obj->buffer.translated(), dwAudioBytes1, 1, test);
        fclose(test);
        
        uint8_t* audio = obj->buffer.translated();
        for (int i = 0; i < 0x100; i++)
        {
            printf("%s%02x ", (i && i % 16 == 0 ? "\n" : ""), audio[i]);
        }
        printf("\n");*/

        return 0;
    }

    Q_INVOKABLE uint32_t Restore(struct dsndbuffer_ext* obj)
    {
        printf("STUB:: IDirectSoundBuffer::Restore\n");
        
        return 0;
    }

//    Q_INVOKABLE uint32_t ();
};

extern IDirectSoundBuffer *idirectsoundbuffer;

#endif // IDIRECTSOUNDBUFFER_H
