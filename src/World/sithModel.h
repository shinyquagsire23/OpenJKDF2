#ifndef _SITHMODEL_H
#define _SITHMODEL_H

#include "General/stdHashTable.h"

#define sithModel_Startup_ADDR (0x004E9660)
#define sithModel_Shutdown_ADDR (0x004E9680)
#define sithModel_Load_ADDR (0x004E96A0)
#define sithModel_Free_ADDR (0x004E9820)
#define sithModel_LoadEntry_ADDR (0x004E98A0)
#define sithModel_GetMemorySize_ADDR (0x004E9980)
#define sithModel_New_ADDR (0x004E9A00)
#define sithModel_GetByIdx_ADDR (0x004E9A60)

typedef struct sithWorld sithWorld;
typedef struct rdModel3 rdModel3;

int sithModel_Startup();
void sithModel_Shutdown();
int sithModel_Load(sithWorld *world, int a2);
void sithModel_Free(sithWorld *world);
rdModel3* sithModel_LoadEntry(const char *model_3do_fname, int unk);
uint32_t sithModel_GetMemorySize(rdModel3 *model);
int sithModel_New(sithWorld *world, int num);
rdModel3* sithModel_GetByIdx(int idx);

//static rdModel3* (*sithModel_LoadEntry_)(const char *model_3do_fname, int unk) = (void*)sithModel_LoadEntry_ADDR;

//#define sithModel_hashtable (*(stdHashTable**)0x84DA3C)

#endif // _SITHMODEL_H
