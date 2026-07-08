#ifndef _SITHMODEL_H
#define _SITHMODEL_H

#include "General/stdHashtbl.h"

#define sithModel_Startup_ADDR (0x004E9660)
#define sithModel_Shutdown_ADDR (0x004E9680)
#define sithModel_ReadStaticModelsListText_ADDR (0x004E96A0)
#define sithModel_FreeWorldModels_ADDR (0x004E9820)
#define sithModel_Load_ADDR (0x004E98A0)
#define sithModel_GetModelMemUsage_ADDR (0x004E9980)
#define sithModel_AllocWorldModels_ADDR (0x004E9A00)
#define sithModel_GetModelByIndex_ADDR (0x004E9A60)

typedef struct SithWorld SithWorld;
typedef struct rdModel3 rdModel3;

int sithModel_Startup();
void sithModel_Shutdown();
int sithModel_ReadStaticModelsListText(SithWorld *world, int a2);
void sithModel_FreeWorldModels(SithWorld *world);
rdModel3* sithModel_Load(const char *model_3do_fname, int unk);
uint32_t sithModel_GetModelMemUsage(rdModel3 *model);
int sithModel_AllocWorldModels(SithWorld *world, int num);
rdModel3* sithModel_GetModelByIndex(int idx);

//static rdModel3* (*sithModel_LoadEntry_)(const char *model_3do_fname, int unk) = (void*)sithModel_Load_ADDR;

//#define sithModel_hashtable (*(tHashTable**)0x84DA3C)

#endif // _SITHMODEL_H
