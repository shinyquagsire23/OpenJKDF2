#ifndef _SITHKEYFRAME_H
#define _SITHKEYFRAME_H

#define sithKeyFrame_Load_ADDR (0x004E55B0)
#define sithKeyFrame_GetFName_ADDR (0x004E5810)
#define sithKeyFrame_LoadEntry_ADDR (0x004E5850)
#define sithKeyFrame_New_ADDR (0x004E5920)
#define sithKeyFrame_Free_ADDR (0x004E5980)

typedef struct rdKeyframe rdKeyframe;

static rdKeyframe* (*sithKeyFrame_LoadEntry)(const char *a1) = (void*)sithKeyFrame_LoadEntry_ADDR;

#endif // _SITHKEYFRAME_H
