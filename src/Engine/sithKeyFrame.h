#ifndef _SITHKEYFRAME_H
#define _SITHKEYFRAME_H

#include "General/stdHashtbl.h"
#include "World/sithWorld.h"

#define sithKeyFrame_Load_ADDR (0x004E55B0)
#define sithKeyFrame_GetByIdx_ADDR (0x004E5810)
#define sithKeyFrame_LoadEntry_ADDR (0x004E5850)
#define sithKeyFrame_New_ADDR (0x004E5920)
#define sithKeyFrame_Free_ADDR (0x004E5980)

typedef struct rdKeyframe rdKeyframe;

int sithKeyFrame_Load(SithWorld *pWorld, int bSkip);
rdKeyframe* sithKeyFrame_GetByIdx(int index);
rdKeyframe* sithKeyFrame_LoadEntry(const char *pName);
int sithKeyFrame_New(SithWorld *pWorld, int size);
void sithKeyFrame_Free(SithWorld *pWorld);

#endif // _SITHKEYFRAME_H
