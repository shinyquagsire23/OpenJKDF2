#ifndef _SITHSOUND_H
#define _SITHSOUND_H

#define sithSound_Startup_ADDR (0x004EEE90)
#define sithSound_Shutdown_ADDR (0x004EEEC0)
#define sithSound_Load_ADDR (0x004EEF00)
#define sithSound_Free_ADDR (0x004EF0C0)
#define sithSound_New_ADDR (0x004EF170)
#define sithSound_LoadEntry_ADDR (0x004EF1D0)
#define sithSound_GetFromIdx_ADDR (0x004EF3F0)
#define sithSound_LoadFileData_ADDR (0x004EF430)
#define sithSound_UnloadData_ADDR (0x004EF5D0)
#define sithSound_LoadData_ADDR (0x004EF620)
#define sithSound_ReadDataFromFd_ADDR (0x004EF660)
#define sithSound_StopAll_ADDR (0x004EF6C0)
#define sithSound_InitFromPath_ADDR (0x004EF7E0)

typedef struct sithSound
{
    char sound_fname[32];
    int id;
    int isLoaded;
    int bufferBytes;
    int sampleRateHz;
    int bitsPerSample;
    void* dsoundBuffer; // LPDIRECTSOUNDBUFFER
    uint32_t sound_len;
    int seekOffset;
    int field_40;
    int infoLoaded;
    void* dsoundBuffer2; // LPDIRECTSOUNDBUFFER
} sithSound;

static sithSound* (*sithSound_LoadEntry)(char *sound_fname, int a2) = (void*)sithSound_LoadEntry_ADDR;

#endif // _SITHSOUND_H
