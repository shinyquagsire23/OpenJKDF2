#ifndef _RDPUPPET_H
#define _RDPUPPET_H

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

static void (__cdecl *rdPuppet_Free)(void* pup) = (void*)rdPuppet_Free_ADDR;
static void (__cdecl *rdPuppet_BuildJointMatrices)(rdThing *thing_1, rdMatrix34 *matrix) = (void*)rdPuppet_BuildJointMatrices_ADDR;

#endif // _RDPUPPET_H
