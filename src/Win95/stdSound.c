#include "stdSound.h"

#include "Gui/jkGUISound.h"
#include "Main/Main.h"
#include "stdPlatform.h"

#include "jk.h"

float stdSound_fMenuVolume = 1.0f;

uint32_t stdSound_ParseWav(int sound_file, uint32_t *nSamplesPerSec, int *bitsPerSample, int *bStereo, int *seekOffset)
{
    unsigned int result; // eax
    int v8; // eax
    char v9[4]; // [esp+Ch] [ebp-14h] BYREF
    stdWaveFormat v10; // [esp+10h] [ebp-10h] BYREF
    uint32_t seekPos;

    std_pHS->fseek(sound_file, 8, 0);
    std_pHS->fileRead(sound_file, v9, 4);
    result = 0;
    if ( !_memcmp(v9, "WAVE", 4) )
    {
        std_pHS->fseek(sound_file, 4, 1);
        std_pHS->fileRead(sound_file, &seekPos, 4);
        std_pHS->fileRead(sound_file, &v10, sizeof(stdWaveFormat));
        *nSamplesPerSec = v10.nSamplesPerSec;
        *bitsPerSample = 8 * (v10.nBlockAlign / (int)v10.nChannels);
        *bStereo = v10.nChannels == 2;
        if (seekPos > 0x10 )
            std_pHS->fseek(sound_file, seekPos - 16, 1);
        std_pHS->fseek(sound_file, 4, 1);
        std_pHS->fileRead(sound_file, &seekPos, 4);
        v8 = std_pHS->ftell(sound_file);
        *seekOffset = v8;
        result = seekPos;
    }
    return result;
}

#ifdef OPENAL_SOUND

ALCdevice *device;
ALCcontext *context;

int stdSound_Initialize()
{
    if (Main_bHeadless) return 1;

	ALboolean enumeration;
	const ALCchar *defaultDeviceName = NULL;
	int ret;
	char *bufferData;
	ALvoid *data;
	ALsizei size, freq;
	ALenum format;
	ALfloat listenerOri[] = { 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f };
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
	alListenerfv(AL_ORIENTATION, listenerOri);

    jkGuiSound_b3DSound = 0;

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

stdSound_buffer_t* stdSound_BufferCreate(int bStereo, int nSamplesPerSec, uint16_t bitsPerSample, int bufferLen)
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
    
    if (!Main_bHeadless)
        alGenBuffers(1, &out->buffer);
    
    int format = 0;
    if (bStereo)
    {
        format = (bitsPerSample == 16 ? AL_FORMAT_STEREO16 : AL_FORMAT_STEREO8);
    }
    else
    {
        format = (bitsPerSample == 16 ? AL_FORMAT_MONO16 : AL_FORMAT_MONO8);
    }
    
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
    if (!Main_bHeadless)
        alBufferData(sound->buffer, sound->format, sound->data, sound->bufferBytes, sound->nSamplesPerSec);

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
	    alSource3f(buf->source, AL_POSITION, 0, 0, 0);
	    alSource3f(buf->source, AL_VELOCITY, 0, 0, 0);
	    
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
	//std_pHS->free(sound);
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

int stdSound_3DBufferIdk(stdSound_buffer_t* a1, int a2)
{
    return 1;
}

void* stdSound_BufferQueryInterface(stdSound_buffer_t* a1)
{
    return NULL;
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
    if (Main_bHeadless) return 0;

    if (pos)
        rdVector_Zero3(pos);
    
    if (!sound->source)
        return 0;
    
    // Added
    if (sound->vol == 0.0)
        return 0;

    ALint source_state;
    
    alGetSourcei(sound->source, AL_SOURCE_STATE, &source_state);
    
    return (source_state == AL_PLAYING);
}
#endif

#ifdef NULL_SOUND
int stdSound_Initialize()
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

stdSound_buffer_t* stdSound_BufferCreate(int bStereo, int nSamplesPerSec, uint16_t bitsPerSample, int bufferLen)
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

int stdSound_3DBufferIdk(stdSound_buffer_t* a1, int a2)
{
    return 1;
}

void* stdSound_BufferQueryInterface(stdSound_buffer_t* a1)
{
    return NULL;
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
#endif
