#include "stdSound.h"

#include "Gui/jkGUISound.h"
#include "Main/Main.h"
#include "stdPlatform.h"
#include "Platform/wuRegistry.h"

#include <stdio.h>

#include "jk.h"

float stdSound_fMenuVolume = 1.0f;

uint32_t stdSound_ParseWav(stdFile_t sound_file, uint32_t *nSamplesPerSec, int *bitsPerSample, int *bStereo, int *seekOffset)
{
    unsigned int result; // eax
    char v9[4]; // [esp+Ch] [ebp-14h] BYREF
    stdWaveFormat v10; // [esp+10h] [ebp-10h] BYREF
    uint32_t seekPos;

    std_pHS->fseek(sound_file, 8, 0);
    std_pHS->fileRead(sound_file, v9, 4);
    result = 0;
    if ( !_memcmp(v9, "WAVE", 4) )
    {
        std_pHS->fseek(sound_file, 4, SEEK_CUR);
        std_pHS->fileRead(sound_file, &seekPos, 4);
        std_pHS->fileRead(sound_file, &v10, sizeof(stdWaveFormat));
        *nSamplesPerSec = v10.nSamplesPerSec;
        *bitsPerSample = 8 * (v10.nBlockAlign / (int)v10.nChannels);
        *bStereo = v10.nChannels == 2;

        if (seekPos > 0x10 )
            std_pHS->fseek(sound_file, seekPos - 16, 1);

        // MoTS removed
        //std_pHS->fseek(sound_file, 4, SEEK_CUR);
        //std_pHS->fileRead(sound_file, &seekPos, 4);

        // MoTS added
        while (!std_pHS->feof(sound_file))
        {
            std_pHS->fileRead(sound_file, v9, 4);
            std_pHS->fileRead(sound_file, &seekPos, 4);

            if (!_memcmp(v9, "data", 4)) break;
            std_pHS->fseek(sound_file, seekPos, SEEK_CUR);
        }

        *seekOffset = std_pHS->ftell(sound_file);
        result = seekPos;
#ifdef AL_FORMAT_WAVE_EXT
        //*seekOffset = 0;
        //result += v8;
#endif
    }
    return result;
}

#ifdef STDSOUND_OPENAL

#define AL_FORMAT_MONO24 (0xFFFF0000)
#define AL_FORMAT_STEREO24 (0xFFFF0001)

ALCdevice *device;
ALCcontext *context;
static rdVector3 stdSound_listenerPos;
static ALfloat stdSound_listenerOri[6] = { 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f };

void stdSound_DS3DToAL(rdVector3* pOut, rdVector3* pIn)
{
    pOut->x = pIn->x * 0.1;
    pOut->y = pIn->y * 0.1;
    pOut->z = pIn->z * 0.1;
}

int stdSound_Startup()
{
    jkGuiSound_b3DSound_3 = 1;

    if (Main_bHeadless) return 1;

	ALboolean enumeration;
	const ALCchar *defaultDeviceName = NULL;
	int ret;
	char *bufferData;
	ALvoid *data;
	ALsizei size, freq;
	ALenum format;
	ALboolean loop = AL_FALSE;
	ALCenum error;
	ALint source_state;

	printf("Using OpenAL+ALUT as audio backend\n");

	enumeration = alcIsExtensionPresent(NULL, "ALC_ENUMERATION_EXT");
	if (enumeration == AL_FALSE)
		fprintf(stderr, "enumeration extension not available\n");

	if (!defaultDeviceName)
		defaultDeviceName = alcGetString(NULL, ALC_DEFAULT_DEVICE_SPECIFIER);

	device = alcOpenDevice(defaultDeviceName);
	if (!device) {
		fprintf(stderr, "unable to open default device\n");
		return 0;
	}

	alGetError();

	context = alcCreateContext(device, NULL);
	if (!alcMakeContextCurrent(context)) {
		fprintf(stderr, "failed to make default context\n");
		return 0;
	}

	/* set orientation */
	alListener3f(AL_POSITION, 0, 0, 1.0f);
    alListener3f(AL_VELOCITY, 0, 0, 0);
	alListenerfv(AL_ORIENTATION, stdSound_listenerOri);
    alListenerf(AL_ROLLOFF_FACTOR, 0.0f);
    alListenerf(AL_REFERENCE_DISTANCE, 5.0f);
    alListenerf(AL_MAX_GAIN, 1.0f);
    alListenerf(AL_MIN_GAIN, 0.0f);

    jkGuiSound_musicVolume = wuRegistry_GetFloat("musicVolume", jkGuiSound_musicVolume);
    jkGuiSound_sfxVolume = wuRegistry_GetFloat("sfxVolume", jkGuiSound_sfxVolume);
    jkGuiSound_numChannels = 256;
    jkGuiSound_bLowResSound = wuRegistry_GetBool("bLowRes", jkGuiSound_bLowResSound);
    jkGuiSound_b3DSound = wuRegistry_GetBool("b3DSound", jkGuiSound_b3DSound);
    jkGuiSound_b3DSound_2 = jkGuiSound_b3DSound;

    return 1;
}

void stdSound_Shutdown()
{
    if (Main_bHeadless) return;

	device = alcGetContextsDevice(context);
	alcMakeContextCurrent(NULL);
	alcDestroyContext(context);
	alcCloseDevice(device);
}

void stdSound_SetMenuVolume(float a1)
{
    stdSound_fMenuVolume = a1;
}

stdSound_buffer_t* stdSound_BufferCreate(int bStereo, uint32_t nSamplesPerSec, uint16_t bitsPerSample, int bufferLen)
{
    stdSound_buffer_t* out = std_pHS->alloc(sizeof(stdSound_buffer_t));
    if (!out)
        return NULL;
    
    _memset(out, 0, sizeof(*out));
    
    out->data = NULL;
    out->bStereo = bStereo;
    out->bufferLen = bufferLen;
    out->nSamplesPerSec = nSamplesPerSec;
    out->bitsPerSample = bitsPerSample;
    out->refcnt = 1;
    out->vol = 1.0;

    rdVector_Zero3(&out->pos);
    rdVector_Zero3(&out->vel);
    
    if (!Main_bHeadless)
        alGenBuffers(1, &out->buffer);
    
    int format = 0;
    if (bStereo)
    {
        switch (bitsPerSample) {
            case 8:
                format = AL_FORMAT_STEREO8;
                break;
            case 16:
                format = AL_FORMAT_STEREO16;
                break;
            case 24:
                format = AL_FORMAT_STEREO24;
                break;
        }
    }
    else
    {
        switch (bitsPerSample) {
            case 8:
                format = AL_FORMAT_MONO8;
                break;
            case 16:
                format = AL_FORMAT_MONO16;
                break;
            case 24:
                format = AL_FORMAT_MONO24;
                break;
        }
    }
    
#ifdef AL_FORMAT_WAVE_EXT
    //format = AL_FORMAT_WAVE_EXT;
#endif

    out->format = format;
    
    return out;
}

void* stdSound_BufferSetData(stdSound_buffer_t* sound, int bufferBytes, int* bufferMaxSize)
{
    sound->bufferBytes = bufferBytes;
    
    if (bufferMaxSize)
        *bufferMaxSize = bufferBytes;
    
    if (sound->data && !sound->bIsCopy)
        std_pHS->free(sound->data);

    sound->data = std_pHS->alloc(bufferBytes);
    sound->bufferBytes = bufferBytes;
    
    _memset(sound->data, 0, sound->bufferBytes);
    
    if (!Main_bHeadless)
        alBufferData(sound->buffer, sound->format, sound->data, sound->bufferBytes, sound->nSamplesPerSec);
    
    
    return sound->data;
}

int stdSound_BufferUnlock(stdSound_buffer_t* sound, void* buffer, int bufferRead)
{
    if (Main_bHeadless) return 1;
    
    if (sound->format == AL_FORMAT_STEREO24 || sound->format == AL_FORMAT_MONO24)
    {
        void* tmp = std_pHS->alloc(sound->bufferBytes);
        memcpy(tmp, sound->data, sound->bufferBytes);
        memset(sound->data, 0, sound->bufferBytes);

        uint8_t* tmp_8 = tmp;
        int16_t* out_16 = sound->data;
        for (size_t i = 0; i < sound->bufferBytes / 3; i += 1)
        {
            uint32_t val = 0;

            val = val | *(tmp_8++);
            val = val | (*(tmp_8++) << 8);
            val = val | (*(tmp_8++) << 16);

            int32_t val_int = *(int32_t*)&val;

            val_int = val_int >> 8;
            *(out_16++) = val_int;
        }

        sound->bufferBytes = (sound->bufferBytes / 3) * 2;
        sound->format = AL_FORMAT_STEREO16;
        free(tmp);
    }

    alBufferData(sound->buffer, sound->format, sound->data, sound->bufferBytes, sound->nSamplesPerSec);

#if 0
    if (!sound->bIsCopy) {
        float tmp = sound->vol;
        sound->vol = 0.0;
        stdSound_BufferPlay(sound, 0);
        sound->vol = tmp;
    }
#endif

    if (!sound->source)
    {
        alGenSources((ALuint)1, &sound->source);

        alSourcef(sound->source, AL_PITCH, 1.0);
        alSourcefv(sound->source, AL_POSITION, (ALfloat*)&sound->pos);
        alSourcefv(sound->source, AL_VELOCITY, (ALfloat*)&sound->vel);
        alSourcei(sound->source, AL_SOURCE_RELATIVE, AL_TRUE); // No 3D until we're given a position
        
        //printf("%u %u\n", buf->source, buf->buffer);
    }
    alSourcei(sound->source, AL_BUFFER, sound->buffer);

    return 1;
}

int stdSound_BufferPlay(stdSound_buffer_t* buf, int loop)
{
    if (Main_bHeadless) return 1;

    //alSourceStop(buf->source);
    
    if (!buf->source)
    {
        alGenSources((ALuint)1, &buf->source);

	    alSourcef(buf->source, AL_PITCH, 1.0);
        alSourcefv(buf->source, AL_POSITION, (ALfloat*)&buf->pos);
        alSourcefv(buf->source, AL_VELOCITY, (ALfloat*)&buf->vel);
        alSourcei(buf->source, AL_SOURCE_RELATIVE, AL_TRUE); // No 3D until we're given a position
	    
	    //printf("%u %u\n", buf->source, buf->buffer);
	}

    alSourcei(buf->source, AL_BUFFER, buf->buffer);
    alSourcei(buf->source, AL_LOOPING, loop ? AL_TRUE : AL_FALSE);
    alSourcef(buf->source, AL_GAIN, buf->vol);

	alSourcePlay(buf->source);
    return 1;
}

void stdSound_BufferRelease(stdSound_buffer_t* sound)
{
    ALint source_state;
    
    if (Main_bHeadless)
        goto end;

    //sound->refcnt--;
    //if (sound->refcnt > 0)
    //    return;
    
    if (sound->source)
        alSourcei(sound->source, AL_LOOPING, AL_FALSE);
    //alSourceStop(sound->source);
    
    /*alGetSourcei(sound->source, AL_SOURCE_STATE, &source_state);
    while (source_state == AL_PLAYING) {
		alGetSourcei(sound->source, AL_SOURCE_STATE, &source_state);
	}*/
	
	if (sound->source)
	{
	    //printf("del %u\n", sound->source);
    	alDeleteSources(1, &sound->source);
    }
	
	if (!sound->bIsCopy && sound->buffer)
	    alDeleteBuffers(1, &sound->buffer);

end:
	sound->source = 0;
	sound->buffer = 0;
	
	if (sound->data && !sound->bIsCopy)
	    std_pHS->free(sound->data);

    memset(sound, 0, sizeof(*sound));
	std_pHS->free(sound);
}

int stdSound_BufferReset(stdSound_buffer_t* sound)
{
    if (Main_bHeadless) return 1;

    //alSourcef(sound->source, AL_PITCH, 1.0);
	//alSourcef(sound->source, AL_GAIN, 1.0);
	//alSource3f(sound->source, AL_POSITION, 0, 0, 0);
	//alSource3f(sound->source, AL_VELOCITY, 0, 0, 0);
	
	if (sound->source)
	{
	    alSourcei(sound->source, AL_LOOPING, AL_FALSE);
	
	    alSourceStop(sound->source);
	    
	    //printf("del %u\n", sound->source);
	    alDeleteSources(1, &sound->source);
	    sound->source = 0;
	}
	
    return 1;
}

void stdSound_BufferSetPan(stdSound_buffer_t* a1, float a2)
{
    
}

void stdSound_BufferSetFrequency(stdSound_buffer_t* sound, int freq)
{
    if (Main_bHeadless) return;

    float pitch = (double)freq / (double)sound->nSamplesPerSec;
    
    if (sound->source)
        alSourcef(sound->source, AL_PITCH, pitch);
}

stdSound_buffer_t* stdSound_BufferDuplicate(stdSound_buffer_t* sound)
{
#if 1
    stdSound_buffer_t* out = std_pHS->alloc(sizeof(stdSound_buffer_t));
    if (!out)
        return NULL;
    
    _memset(out, 0, sizeof(*out));
    
    out->data = sound->data;
    out->bStereo = sound->bStereo;
    out->bufferLen = sound->bufferLen;
    out->nSamplesPerSec = sound->nSamplesPerSec;
    out->bitsPerSample = sound->bitsPerSample;
    out->refcnt = 1;
    out->vol = sound->vol;
    out->format = sound->format;
    out->bufferBytes = sound->bufferBytes;
    out->bIsCopy = 1;
    out->buffer = sound->buffer;

    out->pos = sound->pos;
    out->vel = sound->vel;
    
    //stdSound_BufferSetData(out, sound->bufferBytes, NULL);
    
    //_memcpy(out->data, sound->data, out->bufferBytes);
    
    //stdSound_BufferUnlock(out, out->data, out->bufferBytes);
    
    //printf("%u %u\n", out->source, out->buffer);
    
    return out;
#endif
#if 0
    sound->refcnt++;
    return sound;
#endif
}

void stdSound_IA3D_idk(float a)
{
}

int stdSound_BufferStop(stdSound_buffer_t* buf)
{
    if (Main_bHeadless) return 1;

    if (buf->source)
    {
        alSourcei(buf->source, AL_LOOPING, AL_FALSE);
        alSourcePause(buf->source);
    }
    return 1;
}

void stdSound_BufferSetVolume(stdSound_buffer_t* sound, float vol)
{
    if (Main_bHeadless) return;
    if (!sound) return;
    
    sound->vol = vol * stdSound_fMenuVolume;
    if (!sound->source)
        return;

    alSourcef(sound->source, AL_GAIN, sound->vol);
    
    if (vol == 0.0)
    {
        alSourcei(sound->source, AL_LOOPING, AL_FALSE);
        alSourceStop(sound->source);
    }
}

int stdSound_3DSetMode(stdSound_buffer_t* a1, int a2)
{
    return 1;
}

stdSound_3dBuffer_t* stdSound_BufferQueryInterface(stdSound_buffer_t* pSoundBuffer)
{
    return pSoundBuffer;
}

void stdSound_CommitDeferredSettings()
{
}

void stdSound_SetPositionOrientation(rdVector3 *pos, rdVector3 *lvec, rdVector3 *uvec)
{
    if (!pos || !lvec || !uvec) return;

    stdSound_DS3DToAL(&stdSound_listenerPos, pos);

    stdSound_DS3DToAL((rdVector3*)&stdSound_listenerOri[0], lvec);
    stdSound_DS3DToAL((rdVector3*)&stdSound_listenerOri[3], uvec);

    if (Main_bHeadless) return;

    alListenerfv(AL_POSITION, (ALfloat*)&stdSound_listenerPos);
    alListenerfv(AL_ORIENTATION, stdSound_listenerOri);
}

void stdSound_SetPosition(stdSound_buffer_t* pSoundBuf, rdVector3 *pos)
{
    if (!pSoundBuf || !pos) return;

    stdSound_DS3DToAL(&pSoundBuf->pos, pos);

    if (!pSoundBuf->source)
        return;

    if (Main_bHeadless) return;

    alSourcei(pSoundBuf->source, AL_SOURCE_RELATIVE, AL_FALSE);
    alSourcefv(pSoundBuf->source, AL_POSITION, (ALfloat*)&pSoundBuf->pos);    
}

void stdSound_SetVelocity(stdSound_buffer_t* pSoundBuf, rdVector3 *vel)
{
    if (!pSoundBuf || !vel) return;

    stdSound_DS3DToAL(&pSoundBuf->vel, vel);

    if (!pSoundBuf->source)
        return;

    if (Main_bHeadless) return;

    alSourcei(pSoundBuf->source, AL_SOURCE_RELATIVE, AL_FALSE);
    alSourcefv(pSoundBuf->source, AL_VELOCITY, (ALfloat*)&pSoundBuf->pos);
}

int stdSound_IsPlaying(stdSound_buffer_t* pSoundBuf, rdVector3 *pos)
{
    if (!pSoundBuf) return 0;

    if (pos)
        rdVector_Copy3(pos, &pSoundBuf->pos);
    
    if (!pSoundBuf->source)
        return 0;
    
    // Added
    if (pSoundBuf->vol == 0.0)
        return 0;

    if (Main_bHeadless) return 0;

    ALint source_state;
    alGetSourcei(pSoundBuf->source, AL_SOURCE_STATE, &source_state);
    
    return (source_state == AL_PLAYING);
}

void stdSound_3DBufferRelease(stdSound_3dBuffer_t* p3DBuffer)
{
    
}
#endif

#ifdef STDSOUND_NULL
int stdSound_Startup()
{
    jkGuiSound_b3DSound = 0;

    return 1;
}

void stdSound_Shutdown()
{
}

void stdSound_SetMenuVolume(float a1)
{
}

stdSound_buffer_t* stdSound_BufferCreate(int bStereo, uint32_t nSamplesPerSec, uint16_t bitsPerSample, int bufferLen)
{
    stdSound_buffer_t* out = std_pHS->alloc(sizeof(stdSound_buffer_t));
    if (!out)
        return NULL;
    
    _memset(out, 0, sizeof(*out));
    
    out->data = NULL;
    out->bStereo = bStereo;
    out->bufferLen = bufferLen;
    out->nSamplesPerSec = nSamplesPerSec;
    out->bitsPerSample = bitsPerSample;
    out->refcnt = 1;
    out->vol = 1.0 * stdSound_fMenuVolume;
    
    out->format = 0;
    
    return out;
}

void* stdSound_BufferSetData(stdSound_buffer_t* sound, int bufferBytes, int* bufferMaxSize)
{
    sound->bufferBytes = bufferBytes;
    
    if (bufferMaxSize)
        *bufferMaxSize = bufferBytes;
    
    if (sound->data && !sound->bIsCopy)
        std_pHS->free(sound->data);

    sound->data = std_pHS->alloc(bufferBytes);
    sound->bufferBytes = bufferBytes;
    
    _memset(sound->data, 0, sound->bufferBytes);

    return sound->data;
}

int stdSound_BufferUnlock(stdSound_buffer_t* sound, void* buffer, int bufferRead)
{
    return 1;
}

int stdSound_BufferPlay(stdSound_buffer_t* buf, int loop)
{
    return 1;
}

void stdSound_BufferRelease(stdSound_buffer_t* sound)
{	
	if (sound->data && !sound->bIsCopy)
	    std_pHS->free(sound->data);

    memset(sound, 0, sizeof(*sound));
    std_pHS->free(sound);
}

int stdSound_BufferReset(stdSound_buffer_t* sound)
{
    return 1;
}

void stdSound_BufferSetPan(stdSound_buffer_t* a1, float a2)
{
    
}

void stdSound_BufferSetFrequency(stdSound_buffer_t* sound, int freq)
{
    float pitch = (double)freq / (double)sound->nSamplesPerSec;
}

stdSound_buffer_t* stdSound_BufferDuplicate(stdSound_buffer_t* sound)
{
    stdSound_buffer_t* out = std_pHS->alloc(sizeof(stdSound_buffer_t));
    if (!out)
        return NULL;
    
    _memset(out, 0, sizeof(*out));
    
    out->data = sound->data;
    out->bStereo = sound->bStereo;
    out->bufferLen = sound->bufferLen;
    out->nSamplesPerSec = sound->nSamplesPerSec;
    out->bitsPerSample = sound->bitsPerSample;
    out->refcnt = 1;
    out->vol = sound->vol;
    out->format = sound->format;
    out->bufferBytes = sound->bufferBytes;
    out->bIsCopy = 1;

    stdSound_BufferUnlock(out, out->data, out->bufferBytes);

    return out;
}

void stdSound_IA3D_idk(float a)
{
}

int stdSound_BufferStop(stdSound_buffer_t* buf)
{
    return 1;
}

void stdSound_BufferSetVolume(stdSound_buffer_t* sound, float vol)
{
    if (!sound) return;
    
    sound->vol = vol;
}

int stdSound_3DSetMode(stdSound_buffer_t* a1, int a2)
{
    return 1;
}

stdSound_3dBuffer_t* stdSound_BufferQueryInterface(stdSound_buffer_t* pSoundBuffer)
{
    return pSoundBuffer;
}

void stdSound_CommitDeferredSettings()
{
}

void stdSound_SetPositionOrientation(rdVector3 *pos, rdVector3 *lvec, rdVector3 *uvec)
{
}

void stdSound_SetPosition(stdSound_buffer_t* sound, rdVector3 *pos)
{

}

void stdSound_SetVelocity(stdSound_buffer_t* sound, rdVector3 *vel)
{
    
}

int stdSound_IsPlaying(stdSound_buffer_t* sound, rdVector3 *pos)
{
    return 0;
}

void stdSound_3DBufferRelease(stdSound_3dBuffer_t* p3DBuffer)
{

}
#endif
