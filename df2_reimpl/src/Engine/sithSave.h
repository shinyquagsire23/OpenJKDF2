#ifndef _SITHSAVE_H
#define _SITHSAVE_H

#include "types.h"

#define sithSave_GetProfilePath_ADDR (0x004DA400)
#define sithSave_Setidk_ADDR (0x004DA450)
#define sithSave_Write_ADDR (0x004DA490)
#define sithSave_Load_ADDR (0x004DA6A0)
#define sithSave_SerializeAllThings_ADDR (0x004DA770)
#define sithSave_WriteEntry_ADDR (0x004DA9C0)
#define sithSave_LoadEntry_ADDR (0x004DAB70)

typedef int (*sithSaveHandler_t)();

#define sithSave_func1 (*(sithSaveHandler_t*)0x00835910)
#define sithSave_func2 (*(sithSaveHandler_t*)0x00835908)
#define sithSave_func3 (*(sithSaveHandler_t*)0x00835904)
#define sithSave_funcWrite (*(sithSaveHandler_t*)0x00835F44)
#define sithSave_funcRead (*(sithSaveHandler_t*)0x0083590C)
#define sithSave_autosave_fname ((char*)0x008BBC80)
#define sithSave_dword_835900 (*(int*)0x00835900)
#define sithSave_dword_835914 (*(int*)0x00835914)
#define sithSave_fpath ((char*)0x00835F48)
#define sithSave_wsaveName ((wchar_t*)0x008BBD00)
#define sithSave_saveName ((char*)0x008BBF00)
#define sithSave_headerTmp (*(sithSave_Header*)0x00835918)

typedef struct sithSave_Header
{
    int version;
    char episodeName[128];
    char jklName[128];
    float playerHealth;
    float playerMaxHealth;
    float binAmts[200];
    wchar_t saveName[256];
} sithSave_Header;

void sithSave_Setidk(sithSaveHandler_t a1, sithSaveHandler_t a2, sithSaveHandler_t a3, sithSaveHandler_t a4, sithSaveHandler_t a5);
int sithSave_GetProfilePath(char *out, int outSize, char *a3);
int sithSave_Load(char *saveFname, int a2, int a3);
int sithSave_LoadEntry(char *fpath);

//static int (*sithSave_Load)(char *a1, int a2, int a3) = (void*)sithSave_Load_ADDR;
//static int (*sithSave_LoadEntry)(char *fpath) = (void*)sithSave_LoadEntry_ADDR;
static int (*sithSave_Write)(char *a1, int a2, int a3, wchar_t *a4) = (void*)sithSave_Write_ADDR;
static int (*sithSave_WriteEntry)() = (void*)sithSave_WriteEntry_ADDR;

#endif // _SITHSAVE_H
