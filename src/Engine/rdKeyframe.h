#ifndef _RDKEYFRAME_H
#define _RDKEYFRAME_H

#include "types.h"
#include "globals.h"
#include "Primitives/rdVector.h"

#define rdKeyframe_RegisterLoader_ADDR (0x0044AB80)
#define rdKeyframe_RegisterUnloader_ADDR (0x0044AB90)
#define rdKeyframe_NewEntry_ADDR (0x0044ABA0)
#define rdKeyframe_Load_ADDR (0x0044ABD0)
#define rdKeyframe_LoadEntry_ADDR (0x0044ACA0)
#define rdKeyframe_Write_ADDR (0x0044B1F0)
#define rdKeyframe_FreeEntry_ADDR (0x0044B570)
#define rdKeyframe_FreeJoints_ADDR (0x0044B5F0)

typedef struct rdMarkers
{
    float marker_float[8];
    int marker_int[8];
} rdMarkers;

typedef struct rdAnimEntry
{
    float frameNum;
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
    uint32_t id;
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

keyframeLoader_t rdKeyframe_RegisterLoader(keyframeLoader_t loader);
keyframeUnloader_t rdKeyframe_RegisterUnloader(keyframeUnloader_t loader);
void rdKeyframe_NewEntry(rdKeyframe *keyframe);
rdKeyframe* rdKeyframe_Load(char *fname);
int rdKeyframe_LoadEntry(char *key_fpath, rdKeyframe *keyframe);
int rdKeyframe_Write(char *out_fpath, rdKeyframe *keyframe, char *creation_method);
void rdKeyframe_FreeEntry(rdKeyframe *keyframe);
void rdKeyframe_FreeJoints(rdKeyframe *keyframe);

#endif // _RDKEYFRAME_H
