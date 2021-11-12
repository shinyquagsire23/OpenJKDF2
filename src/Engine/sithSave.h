#ifndef _SITHSAVE_H
#define _SITHSAVE_H

#include "types.h"
#include "globals.h"

#define sithSave_GetProfilePath_ADDR (0x004DA400)
#define sithSave_Setidk_ADDR (0x004DA450)
#define sithSave_Write_ADDR (0x004DA490)
#define sithSave_Load_ADDR (0x004DA6A0)
#define sithSave_SerializeAllThings_ADDR (0x004DA770)
#define sithSave_WriteEntry_ADDR (0x004DA9C0)
#define sithSave_LoadEntry_ADDR (0x004DAB70)

void sithSave_Setidk(sithSaveHandler_t a1, sithSaveHandler_t a2, sithSaveHandler_t a3, sithSaveHandler_t a4, sithSaveHandler_t a5);
int sithSave_GetProfilePath(char *out, int outSize, char *a3);
int sithSave_Load(char *saveFname, int a2, int a3);
int sithSave_LoadEntry(char *fpath);
int sithSave_Write(char *saveFname, int a2, int a3, wchar_t *saveName);
int sithSave_WriteEntry();

//static int (*sithSave_Load)(char *a1, int a2, int a3) = (void*)sithSave_Load_ADDR;
//static int (*sithSave_LoadEntry)(char *fpath) = (void*)sithSave_LoadEntry_ADDR;
//static int (*sithSave_Write)(char *a1, int a2, int a3, wchar_t *a4) = (void*)sithSave_Write_ADDR;
//static int (*sithSave_WriteEntry)() = (void*)sithSave_WriteEntry_ADDR;

#endif // _SITHSAVE_H
