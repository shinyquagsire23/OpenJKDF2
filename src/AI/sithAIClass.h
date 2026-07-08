#ifndef _SITHAICLASS_H
#define _SITHAICLASS_H

#include "types.h"
#include "globals.h"

#define sithAIClass_Startup_ADDR (0x004F11F0)
#define sithAIClass_Shutdown_ADDR (0x004F1210)
#define sithAIClass_ReadStaticAIClassesListText_ADDR (0x004F1230)
#define sithAIClass_AllocWorldAIClasses_ADDR (0x004F13A0)
#define sithAIClass_FreeWorldAIClasses_ADDR (0x004F1410)
#define sithAIClass_Load_ADDR (0x004F14A0)
#define sithAIClass_LoadEntry_ADDR (0x004F15C0)

int sithAIClass_Startup();
void sithAIClass_Shutdown();
int sithAIClass_AllocWorldAIClasses(SithWorld *pWorld, int numClasses);
int sithAIClass_ReadStaticAIClassesListText(SithWorld *pWorld, int bSkip);
SithAIClass* sithAIClass_Load(char *fpath);
int sithAIClass_LoadEntry(char *pPath, SithAIClass *pClass);
void sithAIClass_FreeWorldAIClasses(SithWorld *pWorld);

//static int (*sithAIClass_Startup)() = (void*)sithAIClass_Startup_ADDR;
//static int (*sithAIClass_ReadStaticAIClassesListText)(SithWorld *world, int a2) = (void*)sithAIClass_ReadStaticAIClassesListText_ADDR;
//static SithAIClass* (*sithAIClass_Load)(char *a1) = (void*)sithAIClass_Load_ADDR;
//static void (*sithAIClass_FreeWorldAIClasses)(SithWorld *a1) = (void*)sithAIClass_FreeWorldAIClasses_ADDR;

#endif // _SITHAICLASS_H
