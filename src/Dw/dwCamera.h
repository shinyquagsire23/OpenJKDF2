#ifndef _DWCAMERA_H
#define _DWCAMERA_H

// dwCamera — DroidWorks collision-aware follow camera (SithCamera type
// 0x100, camera slot 7).
//
// Ghidra (DroidWorks.exe) 0x4655e0-0x465c6x, 3 functions:
//   dwCamera_Reset@0x4655e0        (from sithCamera_SetCurrentCamera, type 0x100 branch)
//   dwCamera_Update@0x4656c0       (from sithCamera_Update, case 0x100)
//   dwCamera_TryPosition@0x465a00
//
// The engine side already registers the extra camera slot (see the
// DW_CAMERA blocks in src/Engine/sithCamera.c); these functions implement
// its behavior. Integration (owner: shared-engine hookup, NOT this unit):
//   - sithCamera_Update needs `case 0x100: dwCamera_Update(pCamera); break;`
//   - sithCamera_SetCurrentCamera needs a type-0x100 branch calling
//     dwCamera_Reset(pPrevCamera, pCamera) with the pre-switch current
//     camera, before the final sithCamera_Update.
//
// Per-frame it sweeps a yaw ring (dwCamera_aYawOffsets, first 6 entries,
// widened to all 9 on the retry pass) x a pitch ring (dwCamera_aPitchOffsets,
// 8 entries), mirrored across both yaw signs, and takes the first candidate
// placement behind the target that is collision-clamped inside
// [0.75, 2.5] x wantDist (wantDist = 2 x target model radius) and has a
// clear line of sight from the current camera position; the camera then
// eases toward it at 3 x distance per second and LookAt()s the target.

#include "Dw/dwTypes.h"

// Genuinely-C unit (no C++ features in the binary); guarded for inclusion
// from the C++ DW units.
#ifdef __cplusplus
extern "C" {
#endif

#ifndef PLATFORM_DROIDWORKS
// Retro targets exclude src/Dw/* from the build; the sithCamera.c call sites
// compile to dead no-ops (same pattern as dwMain.h).
#define dwCamera_Reset(pPrevCamera, pCamera)
#define dwCamera_Update(pCamera)
#else

// Candidate yaw offsets, degrees (binary: 0x52d608). The first-chance sweep
// uses entries [0..5]; the widened retry sweep uses all 9.
extern flex_t dwCamera_aYawOffsets[9];

// Candidate pitch offsets, degrees (binary: 0x52d630).
extern flex_t dwCamera_aPitchOffsets[8];

// Angles of the placement chosen by the last successful sweep
// (binary: 0x5470b8 / 0x5470b4). Seeded from the rings' first entries by
// dwCamera_Reset; also feed the no-candidate fallback placement.
extern flex_t dwCamera_curYaw;
extern flex_t dwCamera_curPitch;

// Note: no binary counterpart — statics reset for the soft-reset loop only.
void dwCamera_Startup();

// Snap the camera onto its focus thing and settle it: copies the thing's
// position/orient/sector, then runs one dwCamera_Update with
// sithTime_g_frameTimeFlex temporarily inflated by +1s so the ease-in jumps
// straight to the chosen placement. pPrevCamera is the camera that was
// current before the switch; the reset is skipped when it is non-NULL and
// still the current camera (re-selecting the active camera). @0x4655e0
void dwCamera_Reset(SithCamera* pPrevCamera, SithCamera* pCamera);

// Per-frame follow-cam update for a type-0x100 camera (the sithCamera_Update
// case 0x100 body). @0x4656c0
void dwCamera_Update(SithCamera* pCamera);

// Test one (pitch, yaw) candidate: rotates pBaseOrient by the angles,
// collision-clamps the backward distance along -lvec to the nearest
// obstacle, rejects if the clamped distance leaves [minDist, maxDist], then
// rejects if the move from the camera's current position to the candidate is
// blocked. On success writes the candidate position (pOutPos), the move
// direction (pOutMoveDir) and move distance (pOutMoveDist);
// pOutClampedDist always receives the clamped backward distance. @0x465a00
int dwCamera_TryPosition(SithCamera* pCamera, flex_t pitch, flex_t yaw, SithThing* pFocusThing, const rdMatrix34* pBaseOrient, flex_t wantDist, flex_t minDist, flex_t maxDist, rdVector3* pOutPos, flex_t* pOutClampedDist, rdVector3* pOutMoveDir, flex_t* pOutMoveDist);

#endif // PLATFORM_DROIDWORKS

#ifdef __cplusplus
}
#endif

#endif // _DWCAMERA_H
