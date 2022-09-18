#ifndef _SITHTEMPLATE_H
#define _SITHTEMPLATE_H

#include "types.h"
#include "globals.h"

#define sithTemplate_Startup_ADDR (0x004DD880)
#define sithTemplate_Shutdown_ADDR (0x004DD8A0)
#define sithTemplate_New_ADDR (0x004DD8C0)
#define sithTemplate_GetEntryByIdx_ADDR (0x004DD970)
#define sithTemplate_Load_ADDR (0x004DD9B0)
#define sithTemplate_OldNew_ADDR (0x004DDB00)
#define sithTemplate_OldFree_ADDR (0x004DDCE0)
#define sithTemplate_FreeWorld_ADDR (0x004DDDB0)
#define sithTemplate_GetEntryByName_ADDR (0x004DDE50)
#define sithTemplate_CreateEntry_ADDR (0x004DDF30)

int sithTemplate_Startup();
void sithTemplate_Shutdown();
int sithTemplate_New(sithWorld *world, unsigned int numTemplates);
sithThing* sithTemplate_GetEntryByIdx(int idx);
int sithTemplate_Load(sithWorld *world, int a2);
int sithTemplate_OldNew(char *fpath);
void sithTemplate_OldFree();
void sithTemplate_FreeWorld(sithWorld *world);
sithThing* sithTemplate_GetEntryByName(const char *name);
sithThing* sithTemplate_CreateEntry(sithWorld *world);

#endif // _SITHTEMPLATE_H
