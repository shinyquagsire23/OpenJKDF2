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

rdPuppet* rdPuppet_New(rdThing *thing);
void rdPuppet_Free(rdPuppet *puppet);
MATH_FUNC void rdPuppet_BuildJointMatrices(rdThing *thing, rdMatrix34 *matrix);
int rdPuppet_ResetTrack(rdPuppet *puppet, int trackNum);
MATH_FUNC int rdPuppet_UpdateTracks(rdPuppet *puppet, flex_t a2);
int rdPuppet_AddTrack(rdPuppet *puppet, rdKeyframe *keyframe, int lowPri, int highPri);
void rdPuppet_SetCallback(rdPuppet *a1, int trackNum, rdPuppetTrackCallback_t callback);
int rdPuppet_FadeInTrack(rdPuppet *puppet, int trackNum, flex_t speed);
MATH_FUNC void rdPuppet_AdvanceTrack(rdPuppet *puppet, int trackNum, flex_t a3);
int rdPuppet_FadeOutTrack(rdPuppet *puppet, int trackNum, flex_t speed);
void rdPuppet_SetTrackSpeed(rdPuppet *puppet, int trackNum, flex_t speed);
int rdPuppet_SetStatus(rdPuppet *puppet, int trackNum, int status);
int rdPuppet_PlayTrack(rdPuppet *puppet, int trackNum);
void rdPuppet_unk(rdPuppet *puppet, int trackNum);
int rdPuppet_RemoveTrack(rdPuppet *puppet, rdThing *rdthing);

//static void (*rdPuppet_unk)(rdPuppet *a1, int a2) = (void*)rdPuppet_unk_ADDR;
//static int (*rdPuppet_AddTrack)(rdPuppet *puppet, rdKeyframe *keyframe, int a3, int a4) = (void*)rdPuppet_AddTrack_ADDR;
//static void (*rdPuppet_SetCallback)(rdPuppet *a1, int trackNum, int callback) = (void*)rdPuppet_SetCallback_ADDR;
//static int (*_rdPuppet_UpdateTracks)(rdPuppet *puppet, flex_t a2) = (void*)rdPuppet_UpdateTracks_ADDR;
//static int (*rdPuppet_SetStatus)(rdPuppet *a1, int a2, int a3) = (void*)rdPuppet_SetStatus_ADDR;
//static void (*rdPuppet_SetTrackSpeed)(rdPuppet *a1, int a2, flex_t a3) = (void*)rdPuppet_SetTrackSpeed_ADDR;
//static int (*rdPuppet_PlayTrack)(rdPuppet *a1, int a2) = (void*)rdPuppet_PlayTrack_ADDR;
//static int (*rdPuppet_FadeInTrack)(rdPuppet *a1, int a2, flex_t a3) = (void*)rdPuppet_FadeInTrack_ADDR;
//static void (*_rdPuppet_AdvanceTrack)(rdPuppet *puppet, int trackNum, flex_t a3) = (void*)rdPuppet_AdvanceTrack_ADDR;
//static int (*rdPuppet_FadeOutTrack)(rdPuppet *a1, int a2, flex_t a3) = (void*)rdPuppet_FadeOutTrack_ADDR;
//static void (__cdecl *rdPuppet_BuildJointMatrices)(rdThing *thing_1, rdMatrix34 *matrix) = (void*)rdPuppet_BuildJointMatrices_ADDR;

#endif // _RDPUPPET_H
