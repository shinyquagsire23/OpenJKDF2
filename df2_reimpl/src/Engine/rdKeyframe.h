#ifndef _RDKEYFRAME_H
#define _RDKEYFRAME_H

#include "types.h"
#include "Primitives/rdVector.h"

#define rdKeyframe_RegisterLoader_ADDR (0x0044AB80)
#define rdKeyframe_RegisterUnloader_ADDR (0x0044AB90)
#define rdKeyframe_NewEntry_ADDR (0x0044ABA0)
#define rdKeyframe_Load_ADDR (0x0044ABD0)
#define rdKeyframe_LoadEntry_ADDR (0x0044ACA0)
#define rdKeyframe_Write_ADDR (0x0044B1F0)
#define rdKeyframe_FreeEntry_ADDR (0x0044B570)
#define rdKeyframe_FreeJoints_ADDR (0x0044B5F0)

typedef struct rdKeyframe rdKeyframe; 

typedef int (__cdecl *keyframeLoader_t)(char*);
typedef int (__cdecl *keyframeUnloader_t)(rdKeyframe*);

typedef struct rdMarkers
{
    float marker_float[8];
    int marker_int[8];
} rdMarkers;

typedef struct rdAnimEntry
{
    uint32_t frameNum;
    uint32_t flags;
    rdVector3 pos;
    rdVector3 orientation;
    rdVector3 vel;
    rdVector3 angVel;
} rdAnimEntry;

typedef struct rdJoint
{
    char mesh_name[32];
    uint32_t nodeIdx;
    uint32_t numAnimEntries;
    rdAnimEntry* animEntries;
} rdJoint;

typedef struct rdKeyframe
{
    char name[32];
    uint32_t dword20;
    uint32_t flags;
    uint32_t numJoints;
    uint32_t type;
    float fps;
    uint32_t numFrames;
    uint32_t numJoints2;
    rdJoint* joints;
    uint32_t numMarkers;
    rdMarkers markers;
} rdKeyframe;

#define pKeyframeLoader (*(keyframeLoader_t*)0x73D608)
#define pKeyframeUnloader (*(keyframeUnloader_t*)0x73D60C)

void rdKeyframe_RegisterLoader(keyframeLoader_t loader);
void rdKeyframe_RegisterUnloader(keyframeUnloader_t loader);
void rdKeyframe_NewEntry(rdKeyframe *keyframe);
rdKeyframe* rdKeyframe_Load(char *fname);
int rdKeyframe_LoadEntry(char *key_fpath, rdKeyframe *keyframe);
int rdKeyframe_Write(char *out_fpath, rdKeyframe *keyframe, char *creation_method);
void rdKeyframe_FreeEntry(rdKeyframe *keyframe);
void rdKeyframe_FreeJoints(rdKeyframe *keyframe);

#endif // _RDKEYFRAME_H
