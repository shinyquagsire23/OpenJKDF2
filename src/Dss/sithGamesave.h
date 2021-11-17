#ifndef _SITHGAMESAVE_H
#define _SITHGAMESAVE_H

#include "types.h"
#include "globals.h"

#define sithGamesave_GetProfilePath_ADDR (0x004DA400)
#define sithGamesave_Setidk_ADDR (0x004DA450)
#define sithGamesave_Write_ADDR (0x004DA490)
#define sithGamesave_Load_ADDR (0x004DA6A0)
#define sithGamesave_SerializeAllThings_ADDR (0x004DA770)
#define sithGamesave_WriteEntry_ADDR (0x004DA9C0)
#define sithGamesave_LoadEntry_ADDR (0x004DAB70)

void sithGamesave_Setidk(sithSaveHandler_t a1, sithSaveHandler_t a2, sithSaveHandler_t a3, sithSaveHandler_t a4, sithSaveHandler_t a5);
int sithGamesave_GetProfilePath(char *out, int outSize, char *a3);
int sithGamesave_Load(char *saveFname, int a2, int a3);
int sithGamesave_LoadEntry(char *fpath);
int sithGamesave_Write(char *saveFname, int a2, int a3, wchar_t *saveName);
int sithGamesave_WriteEntry();

//static int (*sithGamesave_Load)(char *a1, int a2, int a3) = (void*)sithGamesave_Load_ADDR;
//static int (*sithGamesave_LoadEntry)(char *fpath) = (void*)sithGamesave_LoadEntry_ADDR;
//static int (*sithGamesave_Write)(char *a1, int a2, int a3, wchar_t *a4) = (void*)sithGamesave_Write_ADDR;
//static int (*sithGamesave_WriteEntry)() = (void*)sithGamesave_WriteEntry_ADDR;

#endif // _SITHGAMESAVE_H
