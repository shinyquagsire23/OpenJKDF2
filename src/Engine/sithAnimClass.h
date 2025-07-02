#ifndef _SITHANIMCLASS_H
#define _SITHANIMCLASS_H

#include "types.h"

#define sithAnimClass_Load_ADDR (0x004E4ED0)
#define sithAnimClass_LoadEntry_ADDR (0x004E50A0)
#define sithAnimClass_LoadPupEntry_ADDR (0x004E5180)
#define sithAnimClass_New_ADDR (0x004E54C0)
#define sithAnimClass_Free_ADDR (0x04E5530)

int sithAnimClass_Load(sithWorld *world, int a2);
int sithAnimClass_LoadPupEntry(sithAnimclass *animclass, char *fpath);
sithAnimclass* sithAnimClass_LoadEntry(char *a1);
void sithAnimClass_Free(sithWorld *world);

//static int (*sithAnimClass_LoadPupEntry)(sithAnimclass *animclass, char *jkl_fname) = (void*)sithAnimClass_LoadPupEntry_ADDR;
//static int (*_sithAnimClass_Load)(sithWorld* jkl, int b) = (void*)sithAnimClass_Load_ADDR;
//static void (*sithAnimClass_Free)(sithWorld* world) = (void*)sithAnimClass_Free_ADDR;

#endif // _SITHANIMCLASS_H
