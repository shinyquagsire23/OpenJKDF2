#ifndef _SITHGAMESAVE_H
#define _SITHGAMESAVE_H

#include "types.h"
#include "globals.h"

#define sithGamesave_GetProfilePath_ADDR (0x004DA400)
#define sithGamesave_Setidk_ADDR (0x004DA450)
#define sithGamesave_Save_ADDR (0x004DA490)
#define sithGamesave_Restore_ADDR (0x004DA6A0)
#define sithGamesave_SaveCurrentWorld_ADDR (0x004DA770)
#define sithGamesave_Process_ADDR (0x004DA9C0)
#define sithGamesave_RestoreFile_ADDR (0x004DAB70)

void sithGamesave_Setidk(sithSaveHandler_t a1, sithSaveHandler_t a2, sithSaveHandler_t a3, sithSaveHandler_t a4, sithSaveHandler_t a5);
int sithGamesave_GetProfilePath(char *out, int outSize, char *a3);
int sithGamesave_Restore(char *saveFname, int a2, int a3);
int sithGamesave_RestoreFile(char *fpath);
int sithGamesave_Save(char *saveFname, int a2, int a3, char16_t *saveName);
int sithGamesave_Process();
const char* sithGamesave_AutosaveMapName(void); // Added: single autosave slot on DC VMU/RAM
#ifdef TARGET_DREAMCAST
extern int sithGamesave_bForceSlim;             // Added: force a slim (inventory-only) save
void sithGamesave_DcFlushSlimToVmu(void);       // Added: write the slim VMU copy alongside SD
#endif

//static int (*sithGamesave_Restore)(char *a1, int a2, int a3) = (void*)sithGamesave_Restore_ADDR;
//static int (*sithGamesave_RestoreFile)(char *fpath) = (void*)sithGamesave_RestoreFile_ADDR;
//static int (*sithGamesave_Save)(char *a1, int a2, int a3, char16_t *a4) = (void*)sithGamesave_Save_ADDR;
//static int (*sithGamesave_Process)() = (void*)sithGamesave_Process_ADDR;

#endif // _SITHGAMESAVE_H
