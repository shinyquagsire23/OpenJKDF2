#ifndef _SITHSOUND_H
#define _SITHSOUND_H

typedef struct sithSound
{
    char sound_fname[32];
    int id;
    int isLoaded;
    int bufferBytes;
    int sampleRateHz;
    int bitsPerSample;
    void* dsoundBuffer; // LPDIRECTSOUNDBUFFER
    int sound_len;
    int seekOffset;
    int field_40;
    int infoLoaded;
    void* dsoundBuffer2; // LPDIRECTSOUNDBUFFER
} sithSound;

#endif // _SITHSOUND_H
