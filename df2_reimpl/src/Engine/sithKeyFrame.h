#ifndef _SITHKEYFRAME_H
#define _SITHKEYFRAME_H

#include "General/stdHashTable.h"
#include "World/sithWorld.h"

#define sithKeyFrame_Load_ADDR (0x004E55B0)
#define sithKeyFrame_GetByIdx_ADDR (0x004E5810)
#define sithKeyFrame_LoadEntry_ADDR (0x004E5850)
#define sithKeyFrame_New_ADDR (0x004E5920)
#define sithKeyFrame_Free_ADDR (0x004E5980)

typedef struct rdKeyframe rdKeyframe;

int sithKeyFrame_Load(sithWorld *world, int a2);
rdKeyframe* sithKeyFrame_GetByIdx(int idx);
rdKeyframe* sithKeyFrame_LoadEntry(const char *fpath);
int sithKeyFrame_New(sithWorld *world, int numKeyframes);
void sithKeyFrame_Free(sithWorld *world);

#define keyframes_hashmap (*(stdHashTable**)0x847E8C)

#endif // _SITHKEYFRAME_H
