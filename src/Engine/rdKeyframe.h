#ifndef _RDKEYFRAME_H
#define _RDKEYFRAME_H

#include "types.h"
#include "globals.h"

#define rdKeyframe_RegisterLoader_ADDR (0x0044AB80)
#define rdKeyframe_RegisterUnloader_ADDR (0x0044AB90)
#define rdKeyframe_NewEntry_ADDR (0x0044ABA0)
#define rdKeyframe_Load_ADDR (0x0044ABD0)
#define rdKeyframe_LoadEntry_ADDR (0x0044ACA0)
#define rdKeyframe_Write_ADDR (0x0044B1F0)
#define rdKeyframe_FreeEntry_ADDR (0x0044B570)
#define rdKeyframe_FreeJoints_ADDR (0x0044B5F0)

keyframeLoader_t rdKeyframe_RegisterLoader(keyframeLoader_t loader);
keyframeUnloader_t rdKeyframe_RegisterUnloader(keyframeUnloader_t loader);
void rdKeyframe_NewEntry(rdKeyframe *keyframe);
rdKeyframe* rdKeyframe_Load(char *fname);
int rdKeyframe_LoadEntry(char *key_fpath, rdKeyframe *keyframe);
int rdKeyframe_Write(char *out_fpath, rdKeyframe *keyframe, char *creation_method);
void rdKeyframe_FreeEntry(rdKeyframe *keyframe);
void rdKeyframe_FreeJoints(rdKeyframe *keyframe);

#endif // _RDKEYFRAME_H
