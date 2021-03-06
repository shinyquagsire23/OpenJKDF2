#ifndef _RDPUPPET_H
#define _RDPUPPET_H

#include "types.h"

#define rdPuppet_New_ADDR (0x0043E640)
#define rdPuppet_RemoveTrack_ADDR (0x0043E6D0)
#define rdPuppet_Free_ADDR (0x0043E740)
#define rdPuppet_FreeEntry_ADDR (0x0043E760)
#define rdPuppet_SetPause_ADDR (0x0043E770)
#define rdPuppet_AddTrack_ADDR (0x0043E780)
#define rdPuppet_ResetTrack_ADDR (0x0043E870)
#define rdPuppet_SetStatus_ADDR (0x0043E8D0)
#define rdPuppet_SetCallback_ADDR (0x0043E900)
#define rdPuppet_PlayTrack_ADDR (0x0043E920)
#define rdPuppet_FadeInTrack_ADDR (0x0043E950)
#define rdPuppet_FadeOutTrack_ADDR (0x0043E9B0)
#define rdPuppet_SetTrackSpeed_ADDR (0x0043EA10)
#define rdPuppet_SetTrackNoise_ADDR (0x0043EA30)
#define rdPuppet_SetTrackPriority_ADDR (0x0043EA70)
#define rdPuppet_AdvanceTrack_ADDR (0x0043EAA0)
#define rdPuppet_UpdateTracks_ADDR (0x0043ED70)
#define rdPuppet_unk_ADDR (0x0043EE60)
#define rdPuppet_BuildJointMatrices_ADDR (0x0043EEB0)

typedef void (*rdPuppetTrackCallback_t)(sithThing*, uint32_t, uint32_t);

typedef struct rdPuppetTrack
{
    int status;
    int field_4;
    int lowPri;
    int highPri;
    float speed;
    int field_14;
    float playSpeed;
    float fadeSpeed;
    rdHierarchyNode *nodes;
    int field_24;
    int field_28;
    int field_2C;
    int field_30;
    int field_34;
    int field_38;
    int field_3C;
    int field_40;
    float field_44[8];
    int field_64[8];
    int field_84;
    int field_88;
    int field_8C;
    int field_90;
    int field_94;
    int field_98;
    int field_9C;
    int field_A0;
    int field_A4;
    int field_A8;
    int field_AC;
    int field_B0;
    int field_B4;
    int field_B8;
    int field_BC;
    int field_C0;
    int field_C4;
    int field_C8;
    int field_CC;
    int field_D0;
    int field_D4;
    int field_D8;
    int field_DC;
    int field_E0;
    int field_E4;
    int field_E8;
    int field_EC;
    int field_F0;
    int field_F4;
    int field_F8;
    int field_FC;
    int field_100;
    int field_104;
    int field_108;
    int field_10C;
    int field_110;
    int field_114;
    int field_118;
    int field_11C;
    float field_120;
    float field_124;
    rdKeyframe *keyframe;
    rdPuppetTrackCallback_t callback;
    int field_130;
} rdPuppetTrack;

typedef struct rdPuppet
{
    uint32_t paused;
    rdThing *rdthing;
    rdPuppetTrack tracks[4];
} rdPuppet;

rdPuppet* rdPuppet_New(rdThing *thing);
void rdPuppet_Free(rdPuppet *puppet);
void rdPuppet_BuildJointMatrices(rdThing *thing, rdMatrix34 *matrix);
int rdPuppet_ResetTrack(rdPuppet *puppet, int trackNum);
int rdPuppet_UpdateTracks(rdPuppet *puppet, float a2);
int rdPuppet_AddTrack(rdPuppet *puppet, rdKeyframe *keyframe, int lowPri, int highPri);
void rdPuppet_SetCallback(rdPuppet *a1, int trackNum, void *callback);
int rdPuppet_FadeInTrack(rdPuppet *puppet, int trackNum, float speed);
void rdPuppet_AdvanceTrack(rdPuppet *puppet, int trackNum, float a3);
int rdPuppet_FadeOutTrack(rdPuppet *puppet, int trackNum, float speed);
void rdPuppet_SetTrackSpeed(rdPuppet *puppet, int trackNum, float speed);
int rdPuppet_SetStatus(rdPuppet *puppet, int trackNum, int status);
int rdPuppet_PlayTrack(rdPuppet *puppet, int trackNum);
void rdPuppet_unk(rdPuppet *puppet, int trackNum);

//static void (*rdPuppet_unk)(rdPuppet *a1, int a2) = (void*)rdPuppet_unk_ADDR;
//static int (*rdPuppet_AddTrack)(rdPuppet *puppet, rdKeyframe *keyframe, int a3, int a4) = (void*)rdPuppet_AddTrack_ADDR;
//static void (*rdPuppet_SetCallback)(rdPuppet *a1, int trackNum, int callback) = (void*)rdPuppet_SetCallback_ADDR;
static int (*_rdPuppet_UpdateTracks)(rdPuppet *puppet, float a2) = (void*)rdPuppet_UpdateTracks_ADDR;
//static int (*rdPuppet_SetStatus)(rdPuppet *a1, int a2, int a3) = (void*)rdPuppet_SetStatus_ADDR;
//static void (*rdPuppet_SetTrackSpeed)(rdPuppet *a1, int a2, float a3) = (void*)rdPuppet_SetTrackSpeed_ADDR;
//static int (*rdPuppet_PlayTrack)(rdPuppet *a1, int a2) = (void*)rdPuppet_PlayTrack_ADDR;
//static int (*rdPuppet_FadeInTrack)(rdPuppet *a1, int a2, float a3) = (void*)rdPuppet_FadeInTrack_ADDR;
static void (*_rdPuppet_AdvanceTrack)(rdPuppet *puppet, int trackNum, float a3) = (void*)rdPuppet_AdvanceTrack_ADDR;
//static int (*rdPuppet_FadeOutTrack)(rdPuppet *a1, int a2, float a3) = (void*)rdPuppet_FadeOutTrack_ADDR;
//static void (__cdecl *rdPuppet_BuildJointMatrices)(rdThing *thing_1, rdMatrix34 *matrix) = (void*)rdPuppet_BuildJointMatrices_ADDR;

#endif // _RDPUPPET_H
