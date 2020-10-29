
#ifndef IDIRECTSOUNDBUFFER_H
#define IDIRECTSOUNDBUFFER_H

#include <QObject>

#include "vm.h"
#include "dlls/winutils.h"
#include "dlls/kernel32.h"

#include "main.h"
#include "dlls/dsound/IDirectSound.h"

#define NUM_CHANNELS 32
#define DSBPLAY_LOOPING 1

extern std::array<Mix_Chunk*, NUM_CHANNELS> active_channels;
extern void channel_done(int channel);

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
        
        if (obj->raw_buffer)
            free(obj->raw_buffer);

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

    Q_INVOKABLE uint32_t Play(struct dsndbuffer_ext* obj, uint32_t res, uint32_t res2, uint32_t flags)
    {
        //printf("STUB: IDirectSoundBuffer::Play %x\n", flags);
        
        if (obj->raw_buffer)
        {
            SDL_AudioStream *stream = SDL_NewAudioStream(AUDIO_S16, obj->format.nChannels, obj->format.nSamplesPerSec, AUDIO_S16, 2, 48000);

            SDL_AudioStreamPut(stream, obj->raw_buffer, obj->size);
            SDL_AudioStreamFlush(stream);
            size_t avail = SDL_AudioStreamAvailable(stream);

            void* converted = malloc(avail);

            size_t converted_size = avail;
            SDL_AudioStreamGet(stream, converted, avail);
            SDL_AudioStreamClear(stream);
            SDL_FreeAudioStream(stream);
            
            /*char tmp[0x100];
            snprintf(tmp, 0x100, "auddump/%p.bin", converted);
            FILE* dump = fopen(tmp, "wb");
            fwrite(converted, converted_size, 1, dump);
            fclose(dump);*/
            
            Mix_ChannelFinished(channel_done);
            Mix_Chunk* chunk = Mix_QuickLoad_RAW((uint8_t*)converted, converted_size);
            obj->channel = Mix_PlayChannel(-1, chunk, flags & DSBPLAY_LOOPING ? -1 : 0);
            Mix_Volume(obj->channel, (uint8_t)(128.0 - ((float)obj->volume * 128.0f/-10000.0f)));
            
            active_channels[obj->channel] = chunk;
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

        //TODO: This can currently interfere if a channel gets reassigned...
        if (obj->channel >= 0)
            Mix_Volume(obj->channel, (uint8_t)(128.0 - ((float)obj->volume * 128.0f/-10000.0f)));
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetPan(struct dsndbuffer_ext* obj, uint32_t a)
    {
        //printf("STUB:: IDirectSoundBuffer::SetPan %x\n", a);
        
        //Mix_SetPanning
        
        return 0;
    }

    Q_INVOKABLE uint32_t SetFrequency(struct dsndbuffer_ext* obj, uint32_t freq)
    {
        printf("STUB:: IDirectSoundBuffer::SetFrequency %u\n", freq);
        
        obj->format.nSamplesPerSec = freq;

        return 0;
    }

    Q_INVOKABLE uint32_t Stop(struct dsndbuffer_ext* obj)
    {
        //printf("STUB: IDirectSoundBuffer::Stop\n");

        if (obj->channel >= 0)
            Mix_ExpireChannel(obj->channel, 2000);

        obj->channel = -1;

        return 0;
    }

    Q_INVOKABLE uint32_t Unlock(struct dsndbuffer_ext* obj, uint32_t lpvAudioPtr1, uint32_t dwAudioBytes1, uint32_t lpvAudioPtr2, uint32_t dwAudioBytes2)
    {
        printf("STUB:: IDirectSoundBuffer::Unlock %x %x %x %x\n", lpvAudioPtr1, dwAudioBytes1, lpvAudioPtr2, dwAudioBytes2);

        obj->size = dwAudioBytes1;
        obj->channel = -1;
        
        if (obj->raw_buffer)
            free(obj->raw_buffer);
        obj->raw_buffer = malloc(obj->size);
        memcpy(obj->raw_buffer, obj->buffer.translated(), obj->size);

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
