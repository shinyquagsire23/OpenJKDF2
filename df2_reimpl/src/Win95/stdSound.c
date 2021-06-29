#include "stdSound.h"

#include "Gui/jkGUISound.h"
#include "stdPlatform.h"

#include "jk.h"


uint32_t stdSound_ParseWav(int sound_file, int *nSamplesPerSec, int *bitsPerSample, int *bStereo, int *seekOffset)
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

#ifdef LINUX
#include <AL/al.h>
#include <AL/alc.h>
#include <AL/alut.h>

ALCdevice *device;
ALCcontext *context;

int stdSound_Initialize()
{
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
	device = alcGetContextsDevice(context);
	alcMakeContextCurrent(NULL);
	alcDestroyContext(context);
	alcCloseDevice(device);
}

void stdSound_SetMenuVolume(float a1)
{
}

stdSound_buffer_t* stdSound_BufferCreate(int bStereo, int nSamplesPerSec, uint16_t bitsPerSample, int bufferLen)
{
    stdSound_buffer_t* out = std_pHS->alloc(sizeof(stdSound_buffer_t));
    
    _memset(out, 0, sizeof(*out));
    
    alGenSources((ALuint)1, &out->source);

	alSourcef(out->source, AL_PITCH, 1);
	alSourcef(out->source, AL_GAIN, 1);
	alSource3f(out->source, AL_POSITION, 0, 0, 0);
	alSource3f(out->source, AL_VELOCITY, 0, 0, 0);
	alSourcei(out->source, AL_LOOPING, AL_FALSE);
    
    out->data = NULL;
    out->bufferLen = bufferLen;
    out->nSamplesPerSec = nSamplesPerSec;
    out->bitsPerSample = bitsPerSample;
    
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
    
    if (sound->data)
        std_pHS->free(sound->data);

    sound->data = std_pHS->alloc(bufferBytes);
    sound->bufferBytes = bufferBytes;
    
    _memset(sound->data, 0, sound->bufferBytes);
    
    alBufferData(sound->buffer, sound->format, sound->data, sound->bufferBytes, sound->nSamplesPerSec);
    
    return sound->data;
}

int stdSound_BufferUnlock(stdSound_buffer_t* sound, void* buffer, int bufferRead)
{
    alBufferData(sound->buffer, sound->format, sound->data, sound->bufferBytes, sound->nSamplesPerSec);
    return 1;
}

int stdSound_BufferPlay(stdSound_buffer_t* buf, int loop)
{
    alSourcei(buf->source, AL_BUFFER, buf->buffer);

	alSourcePlay(buf->source);
    return 1;
}

void stdSound_BufferRelease(stdSound_buffer_t* sound)
{
    ALint source_state;
    
    alGetSourcei(sound->source, AL_SOURCE_STATE, &source_state);
    while (source_state == AL_PLAYING) {
		alGetSourcei(sound->source, AL_SOURCE_STATE, &source_state);
	}
	
	alDeleteSources(1, &sound->source);
	alDeleteBuffers(1, &sound->buffer);
	
	if (sound->data)
	    std_pHS->free(sound->data);
	std_pHS->free(sound);
}

int stdSound_BufferReset(stdSound_buffer_t* sound)
{
    return 1;
}

void stdSound_BufferSetPan(stdSound_buffer_t* a1, float a2)
{
    
}

void stdSound_BufferSetFrequency(stdSound_buffer_t* a1, int a2)
{
    
}

void stdSound_IA3D_idk(float a)
{
}

int stdSound_BufferStop(stdSound_buffer_t* a1)
{
    return 1;
}

void stdSound_BufferSetVolume(stdSound_buffer_t* a1, float a2)
{
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
#endif
