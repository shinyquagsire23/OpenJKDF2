#ifndef _SITHAICLASS_H
#define _SITHAICLASS_H

#include "types.h"
#include "globals.h"

#define sithAIClass_Startup_ADDR (0x004F11F0)
#define sithAIClass_Shutdown_ADDR (0x004F1210)
#define sithAIClass_ParseSection_ADDR (0x004F1230)
#define sithAIClass_New_ADDR (0x004F13A0)
#define sithAIClass_Free_ADDR (0x004F1410)
#define sithAIClass_Load_ADDR (0x004F14A0)
#define sithAIClass_LoadEntry_ADDR (0x004F15C0)

typedef struct sithAIClassEntry
{
  int param1;
  int param2;
  int param3;
  float argsAsFloat[16];
  int argsAsInt[16];
  sithAICommandFunc_t func;
} sithAIClassEntry;

typedef struct sithAIClass
{
  int index;
  int field_4;
  float alignment;
  float rank;
  float maxStep;
  float sightDist;
  float hearDist;
  float fov;
  float wakeupDist;
  float accuracy;
  int numEntries;
  sithAIClassEntry entries[16];
  char fpath[32];
} sithAIClass;

int sithAIClass_Startup();
void sithAIClass_Shutdown();
int sithAIClass_New(sithWorld *world, int a2);
int sithAIClass_ParseSection(sithWorld *world, int a2);
sithAIClass* sithAIClass_Load(char *fpath);
int sithAIClass_LoadEntry(char *fpath, sithAIClass *aiclass);
void sithAIClass_Free(sithWorld *world);

//static int (*sithAIClass_Startup)() = (void*)sithAIClass_Startup_ADDR;
//static int (*sithAIClass_ParseSection)(sithWorld *world, int a2) = (void*)sithAIClass_ParseSection_ADDR;
//static sithAIClass* (*sithAIClass_Load)(char *a1) = (void*)sithAIClass_Load_ADDR;
//static void (*sithAIClass_Free)(sithWorld *a1) = (void*)sithAIClass_Free_ADDR;

#endif // _SITHAICLASS_H
