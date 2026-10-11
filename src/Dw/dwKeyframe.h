#ifndef _DWKEYFRAME_H
#define _DWKEYFRAME_H

// dwKeyframe — DroidWorks rdKeyframe helper cluster
// (physically emitted in the dwAnim compile-unit range but unrelated to the
// anim widgets: these bake the assembled droid's merged animation and are
// called ONLY by dwDroidStats, plus two marker helpers reused by dwCog).
//
// The functions operate on the ENGINE's rdKeyframe/rdJoint/rdAnimEntry
// structs (src/types.h; the 32-bit binary offsets 0x34 numFrames / 0x3c
// aNodes / joint 0x24 numEntries etc. all map 1:1 onto the named fields).
//
// Genuinely-C cluster (cdecl, no vtables/EH) -> pure C. No module statics —
// no _Startup hook needed.

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// recompute every entry's vel/angularVelocity (and their flags
// bits 1/2) as the per-frame delta to the NEXT entry (wrapping: the last
// entry's span ends at numFrames). Angles go through
// stdMath_NormalizeDeltaAngle.
void dwKeyframe_BuildJointDeltas(rdJoint* pJoint, uint32_t numFrames);

// when pKeyframe->numFrames > 1: resample every joint to exactly
// one entry per frame (dwKeyframe_ResampleJoint) and REVERSE the marker
// times (marker_float[i] = numFrames - marker_float[i] — the whole resample
// samples the animation time-mirrored, see ResampleJoint).
void dwKeyframe_Resample(rdKeyframe* pKeyframe);

// when pJoint->numEntries > 1: replace the joint's entries with
// numFrames entries, entry i sampled at time (numFrames - i) (time-mirrored
// resample; frameNum = i), then rebuild the deltas. The old entry array is
// freed; on allocation failure the joint ends with aEntries == NULL
// (faithful).
void dwKeyframe_ResampleJoint(rdJoint* pJoint, uint32_t numFrames);

// sample the joint's pos/orientation at an arbitrary frame time
// (wrapped into [0, numFrames) via a round-to-nearest fmod — faithful,
// can land slightly negative), lerping from the governing entry via its
// vel/angularVelocity when the corresponding flags bit is set.
// Faithful quirk: when time exceeds every entry's frameNum the scan reads
// one entry PAST the array before stepping back.
void dwKeyframe_SampleJointAt(rdJoint* pJoint, uint32_t numFrames, float time,
                              rdVector3* pPos, rdVector3* pOrient);

// deep-copy a keyframe (header + joints + entries) through the
// DW allocator. On partial allocation failure the clone is released with
// rdKeyframe_Free and NULL is... (faithful: the FAILED clone pointer is
// still returned after rdKeyframe_Free — callers only see NULL when the
// header allocation itself failed; documented quirk, see dwKeyframe.c).
rdKeyframe* dwKeyframe_Clone(rdKeyframe* pKeyframe);

// append a marker (frameNum, type). No bounds check (8 slots max
// in rdMarkers — faithful).
void dwKeyframe_AddMarker(rdKeyframe* pKeyframe, float frameNum, int type);

// AddMarker at numFrames * 0.5.
void dwKeyframe_AddMidMarker(rdKeyframe* pKeyframe, int type);

#ifdef __cplusplus
}
#endif

#endif // _DWKEYFRAME_H
