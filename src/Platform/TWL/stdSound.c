#include "Win95/stdSound.h"

#include "Gui/jkGUISound.h"
#include "Main/Main.h"
#include "stdPlatform.h"
#include "Platform/wuRegistry.h"
#include "General/stdMath.h"

#include <stdio.h>

#include "jk.h"

#include <filesystem.h>
#include <maxmod9.h>
#include <nds.h>

uint32_t stdSound_ParseWav(stdFile_t sound_file, uint32_t *nSamplesPerSec, int32_t *bitsPerSample, int32_t *bStereo, int32_t *seekOffset)
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
        while (!std_pHS->fileEof(sound_file))
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

#ifdef STDSOUND_MAXMOD

static mm_stream stdSound_mmstream;
static stdSound_buffer_t* stdSound_aPlayingSounds[SITH_MIXER_NUMPLAYINGSOUNDS];

#define BUFFER_LENGTH 0x400
#define STDSOUND_SAMPLE_RATE (22050)
#define STDSOUND_NUM_CHANNELS (1)

//char stream_buffer[BUFFER_LENGTH];
//int stream_buffer_in;
//int stream_buffer_out;

mm_stream_formats getMMStreamType(uint16_t numChannels, uint16_t bitsPerSample)
{
    if (numChannels == 1)
    {
        if (bitsPerSample == 8)
            return MM_STREAM_8BIT_MONO;
        else
            return MM_STREAM_16BIT_MONO;
    }
    else if (numChannels == 2)
    {
        if (bitsPerSample == 8)
            return MM_STREAM_8BIT_STEREO;
        else
            return MM_STREAM_16BIT_STEREO;
    }
    return MM_STREAM_8BIT_MONO;
}

size_t getMMFormatBytesPerSample(mm_stream_formats format) {
    size_t multiplier = 0;

    if (format == MM_STREAM_8BIT_MONO)
        multiplier = 1;
    else if (format == MM_STREAM_8BIT_STEREO)
        multiplier = 2;
    else if (format == MM_STREAM_16BIT_MONO)
        multiplier = 2;
    else if (format == MM_STREAM_16BIT_STEREO)
        multiplier = 4;
    return multiplier;
}

MATH_FUNC mm_word streamingCallback(mm_word length,
                          mm_addr dest,
                          mm_stream_formats format)
{
    

    size_t size = length * getMMFormatBytesPerSample(format);
    //size_t bytes_until_end = BUFFER_LENGTH - stream_buffer_out;

    memset((s16*)dest, 0, size);

    mm_word largestLength = length;

    for (int i = 0; i < SITH_MIXER_NUMPLAYINGSOUNDS; i++) {
        stdSound_buffer_t* buf = stdSound_aPlayingSounds[i];
        if (!buf || !buf->data || buf->vol <= 0.0) continue;

        s16 *dst = (s16*)dest;
        int neededRepeats = STDSOUND_SAMPLE_RATE / buf->nSamplesPerSec;
        int shift = (buf->format == MM_STREAM_8BIT_MONO || buf->format == MM_STREAM_8BIT_STEREO) ? 8 : 0;

        for (int j = 0; j < length; j++) {
            if (buf->format == MM_STREAM_16BIT_MONO || buf->format == MM_STREAM_8BIT_MONO) {
                s32 val = *((s16*)buf->data + buf->currentSample) << shift;
                val = (s16)((flex_t)val * buf->vol);
                s32 mergeL = ((s32)val + (s32)*dst);
                *dst = stdMath_ClampInt(mergeL, -0x8000, 0x7FFF);
                dst++;
                //s32 mergeR = ((s32)val + (s32)*dst);
                //*dst = stdMath_ClampInt(mergeR, -0x8000, 0x7FFF);
                //dst++;
            } 
            else if (buf->format == MM_STREAM_16BIT_STEREO || buf->format == MM_STREAM_8BIT_STEREO) {
                s16 valL = *((s16*)buf->data + (buf->currentSample * 2)) << shift;
                //s16 valR = *((s16*)buf->data + (buf->currentSample * 2) + 1) << shift;

                valL = (s16)((flex_t)valL * buf->vol);
                //valR = (s16)((flex_t)valR * buf->vol);

                s32 mergeL = ((s32)valL + (s32)*dst);
                *dst = stdMath_ClampInt(mergeL, -0x8000, 0x7FFF);
                dst++;
                //s32 mergeR = ((s32)valR + (s32)*dst);
                //*dst = stdMath_ClampInt(mergeR, -0x8000, 0x7FFF);
                //dst++;
            }
            else {
                dst++;
                //dst++;
            }

            buf->sampleRepeats++;
            if (buf->sampleRepeats >= neededRepeats) {
                buf->currentSample++;
                buf->sampleRepeats = 0;
            }

            if (buf->currentSample * getMMFormatBytesPerSample((mm_stream_formats)buf->format) > buf->bufferBytes) {
                if (buf->isLooping) {
                    buf->currentSample = 0;
                }
                else {
                    stdSound_BufferStop(buf);
                    if (j > largestLength) {
                        largestLength = j;
                    }
                    break;
                }
            }
        }
    }

    //printf("playing! %x\n", rand());
    /*for (int j = 0; j < length; j++) {
        *dst++ = rand();
        *dst++ = rand();
    }*/

#if 0
    if (bytes_until_end > size)
    {
        char *src_ = &stream_buffer[stream_buffer_out];

        memcpy(dest, src_, size);
        stream_buffer_out += size;
    }
    else
    {
        char *src_ = &stream_buffer[stream_buffer_out];
        char *dst_ = dest;

        memcpy(dst_, src_, bytes_until_end);
        dst_ += bytes_until_end;
        size -= bytes_until_end;

        src_ = &stream_buffer[0];
        memcpy(dst_, src_, size);
        stream_buffer_out = size;
    }
#endif

    return largestLength;
}

int stdSound_Startup()
{
    jkGuiSound_b3DSound = 0;

    printf("Using STDSOUND_MAXMOD as audio backend\n");

    //soundEnable();

    memset(stdSound_aPlayingSounds, 0, sizeof(stdSound_aPlayingSounds));

    static int bInitted = 0;
    if (bInitted) {
        return 1;
    }

#ifdef STDPLATFORM_HEAP_SUGGESTIONS
    int prevSuggest = pSithHS->suggestHeap(HEAP_AUDIO);
#endif

    // We are not using a soundbank so we need to manually initialize
    // mm_ds_system.
    mm_ds_system mmSys =
    {
        .mod_count    = 0,
        .samp_count   = 0,
        .mem_bank     = 0,
        .fifo_channel = FIFO_MAXMOD
    };
    mmInit(&mmSys);

    // Open the stream
    stdSound_mmstream =
    {
        .sampling_rate = STDSOUND_SAMPLE_RATE, // 22050
        .buffer_length = BUFFER_LENGTH, // BUFFER_LENGTH
        .callback      = streamingCallback,
        .format        = MM_STREAM_16BIT_MONO,//getMMStreamType(2, 16),
        .timer         = MM_TIMER2,
        .manual        = false,
    };
    mmStreamOpen(&stdSound_mmstream);

#ifdef STDPLATFORM_HEAP_SUGGESTIONS
    pSithHS->suggestHeap(prevSuggest);
#endif
    bInitted = 1;

    return 1;
}

void stdSound_Shutdown()
{
    //mmStreamClose();
    //soundDisable();
}

void stdSound_SetMenuVolume(flex_t a1)
{
    stdSound_fMenuVolume = a1;
}

stdSound_buffer_t* stdSound_BufferCreate(int bStereo, uint32_t nSamplesPerSec, uint16_t bitsPerSample, int bufferLen)
{
    stdSound_buffer_t* out = (stdSound_buffer_t*)std_pHS->alloc(sizeof(stdSound_buffer_t));
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
    
    out->format = getMMStreamType(bStereo ? 2 : 1, bitsPerSample);
    
    return out;
}

void* stdSound_BufferSetData(stdSound_buffer_t* sound, int bufferBytes, int32_t* bufferMaxSize)
{
    sound->bufferBytes = bufferBytes;
    
    if (bufferMaxSize)
        *bufferMaxSize = bufferBytes;
    
    if (sound->data && !sound->bIsCopy)
        std_pHS->free(sound->data);

    sound->bufferBytes = 0;
    sound->data = std_pHS->alloc(bufferBytes);
    if (!sound->data) {
        return NULL;
    }
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
    if (!buf || !buf->data) return 0;
    buf->isLooping = loop;
    if (stdSound_IsPlaying(buf, NULL)) {
        return 1;
    }

    // TODO: critical section?
    for (int i = 0; i < SITH_MIXER_NUMPLAYINGSOUNDS; i++) {
        if (!stdSound_aPlayingSounds[i]) {
            buf->currentSample = 0;
            buf->isPlaying = 1;
            stdSound_aPlayingSounds[i] = buf;
            return 1;
        }
    }
    return 0;
}

void stdSound_BufferRelease(stdSound_buffer_t* sound)
{   
    stdSound_BufferStop(sound);
    if (sound->data && !sound->bIsCopy) {
        std_pHS->free(sound->data);
        sound->data = NULL;
    }

    memset(sound, 0, sizeof(*sound));
    std_pHS->free(sound);
}

int stdSound_BufferReset(stdSound_buffer_t* sound)
{
    if (!sound) return 0;

    sound->isPlaying = 0;
    sound->currentSample = 0;
    sound->isLooping = 0;
    return 1;
}

void stdSound_BufferSetPan(stdSound_buffer_t* a1, flex_t a2)
{
    
}

void stdSound_BufferSetFrequency(stdSound_buffer_t* sound, int freq)
{
    flex_t pitch = (flex_d_t)freq / (flex_d_t)sound->nSamplesPerSec;
}

stdSound_buffer_t* stdSound_BufferDuplicate(stdSound_buffer_t* sound)
{
    stdSound_buffer_t* out = (stdSound_buffer_t*)std_pHS->alloc(sizeof(stdSound_buffer_t));
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
    out->isPlaying = 0;
    out->currentSample = 0;
    out->isLooping = 0;

    stdSound_BufferUnlock(out, out->data, out->bufferBytes);

    return out;
}

void stdSound_IA3D_idk(flex_t a)
{
}

int stdSound_BufferStop(stdSound_buffer_t* buf)
{
    if (!buf) return 1;

    buf->isPlaying = 0;
    buf->currentSample = 0;
    buf->isLooping = 0;

    // TODO: critical section?
    for (int i = 0; i < SITH_MIXER_NUMPLAYINGSOUNDS; i++) {
        if (stdSound_aPlayingSounds[i] == buf) {
            stdSound_aPlayingSounds[i] = NULL;
            return 1;
        }
    }
    return 1;
}

void stdSound_BufferSetVolume(stdSound_buffer_t* sound, flex_t vol)
{
    if (!sound) return;
    
    sound->vol = vol * stdSound_fMenuVolume;
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
    if (sound) return sound->isPlaying;
    return 0;
}

void stdSound_3DBufferRelease(stdSound_3dBuffer_t* p3DBuffer)
{

}
#endif // STDSOUND_MAXMOD