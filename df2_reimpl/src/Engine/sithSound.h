#ifndef _SITHSOUND_H
#define _SITHSOUND_H

#include "types.h"

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
    uint32_t bufferBytes;
    uint32_t sampleRateHz;
    int bitsPerSample;
    int bStereo; // LPDIRECTSOUNDBUFFER
    uint32_t sound_len;
    int seekOffset;
    int field_40;
    int infoLoaded;
    void* dsoundBuffer2; // LPDIRECTSOUNDBUFFER
} sithSound;

int sithSound_Startup();
int sithSound_Shutdown();
int sithSound_Load(sithWorld *world, int a2);
void sithSound_Free(sithWorld *world);
int sithSound_New(sithWorld *world, int num);
sithSound* sithSound_LoadEntry(char *sound_fname, int a2);
sithSound* sithSound_GetFromIdx(int idx);
int sithSound_LoadFileData(sithSound *sound);
int sithSound_UnloadData(sithSound *sound);
LPDIRECTSOUND sithSound_LoadData(sithSound *sound);
int sithSound_StopAll(uint32_t idk);
LPDIRECTSOUNDBUFFER sithSound_InitFromPath(char *path);

//static int (*sithSound_Load)(sithWorld *world, int a2) = (void*)sithSound_Load_ADDR;
//static sithSound* (*sithSound_LoadEntry)(char *sound_fname, int a2) = (void*)sithSound_LoadEntry_ADDR;
//static int (*sithSound_LoadFileData)(sithSound *sound) = (void*)sithSound_LoadFileData_ADDR;
//static unsigned int (*sithSound_StopAll)(sithSound *sound) = (void*)sithSound_StopAll_ADDR;

#define sithSound_hashtable (*(stdHashTable**)0x0084DF38)
#define sithSound_curDataLoaded (*(int*)0x0084DF30)

#define sithSound_maxDataLoaded (*(int*)0x0054C390)
#define sithSound_var3 (*(int*)0x0054C394)
#define sithSound_var4 (*(int*)0x0084DF40)
#define sithSound_var5 (*(int*)0x0084DF44)
#define sithSound_bInit (*(int*)0x0084DF34)

#endif // _SITHSOUND_H
