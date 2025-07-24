#ifndef _SITHSOUND_H
#define _SITHSOUND_H

#include "types.h"
#include "globals.h"

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
#define sithSound_FreeUpMemory_ADDR (0x004EF6C0)
#define sithSound_InitFromPath_ADDR (0x004EF7E0)

int sithSound_Startup();
int sithSound_Shutdown();
int sithSound_Load(sithWorld *world, int a2);
void sithSound_Free(sithWorld *world);
int sithSound_New(sithWorld *world, int num);
sithSound* sithSound_LoadEntry(char *sound_fname, int a2);
sithSound* sithSound_GetFromIdx(int idx);
int sithSound_LoadFileData(sithSound *sound);
int sithSound_UnloadData(sithSound *sound);
stdSound_buffer_t* sithSound_LoadData(sithSound *sound);
int sithSound_FreeUpMemory(uint32_t idk);
stdSound_buffer_t* sithSound_InitFromPath(char *path);
int sithSound_ReadDataFromFd(int fd, sithSound *sound);

//static int (*sithSound_Load)(sithWorld *world, int a2) = (void*)sithSound_Load_ADDR;
//static sithSound* (*sithSound_LoadEntry)(char *sound_fname, int a2) = (void*)sithSound_LoadEntry_ADDR;
//static int (*sithSound_LoadFileData)(sithSound *sound) = (void*)sithSound_LoadFileData_ADDR;
//static unsigned int (*sithSound_FreeUpMemory)(sithSound *sound) = (void*)sithSound_FreeUpMemory_ADDR;

#endif // _SITHSOUND_H
