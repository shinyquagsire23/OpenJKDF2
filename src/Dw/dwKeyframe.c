// dwKeyframe — DroidWorks rdKeyframe helpers (resample/clone/markers).
//
// Decompiled from DroidWorks.exe @0x4039e0-0x403ffx (mis-binned tail of the
// dwAnim compile unit; used only by dwDroidStats to bake the assembled
// droid's merged animation, plus the marker helpers reused by dwCog).
//
// All allocation goes through the DW HostServices (binary: dwHS @0x6b6258 =
// dwMain_pHS here), matching the original. The structs are the engine's
// rdKeyframe/rdJoint/rdAnimEntry from src/types.h — every 32-bit binary
// offset maps onto a named field (joint stride 0x2c, entry stride 0x38);
// sizeof() replaces the hardcoded sizes for 64-bit correctness.

#include "Dw/dwKeyframe.h"

#include "General/stdMath.h"   // stdMath_NormalizeDeltaAngle
#include "Engine/rdKeyframe.h" // rdKeyframe_Free (clone failure path)
#include "stdPlatform.h"

#include <math.h>

extern HostServices* dwMain_pHS; // the DW host-services pointer (dwMain.c); binary global dwHS @0x6b6258

// @4039e0
void dwKeyframe_BuildJointDeltas(rdJoint* pJoint, uint32_t numFrames)
{
    uint32_t i;
    uint32_t numEntries;
    rdAnimEntry* pCur;
    rdAnimEntry* pNext;
    float endFrame;
    float invSpan;
    flex_t dp, dy, dr;

    i = 0;
    numEntries = pJoint->numEntries;
    pCur = pJoint->aEntries;
    if (numEntries == 0)
        return;
    do
    {
        i = i + 1;
        pNext = &pJoint->aEntries[i % numEntries]; // wraps to entry 0 for the last span
        if (pNext == pJoint->aEntries)
            endFrame = (float)numFrames; // last entry: span ends at the anim end
        else
            endFrame = pNext->frameNum;
        invSpan = 1.0f / (endFrame - pCur->frameNum);

        dp = stdMath_NormalizeDeltaAngle(pCur->orientation.x, pNext->orientation.x);
        dy = stdMath_NormalizeDeltaAngle(pCur->orientation.y, pNext->orientation.y);
        dr = stdMath_NormalizeDeltaAngle(pCur->orientation.z, pNext->orientation.z);

        pCur->flags = 0;
        pCur->vel.x = (pNext->pos.x - pCur->pos.x) * invSpan;
        pCur->vel.y = (pNext->pos.y - pCur->pos.y) * invSpan;
        pCur->vel.z = (pNext->pos.z - pCur->pos.z) * invSpan;
        if (pCur->vel.x != 0.0f || pCur->vel.y != 0.0f || pCur->vel.z != 0.0f)
            pCur->flags |= 1;

        pCur->angularVelocity.x = dp * invSpan;
        pCur->angularVelocity.y = dy * invSpan;
        pCur->angularVelocity.z = dr * invSpan;
        if (pCur->angularVelocity.x != 0.0f || pCur->angularVelocity.y != 0.0f
            || pCur->angularVelocity.z != 0.0f)
        {
            pCur->flags |= 2;
        }

        pCur = pCur + 1;
        numEntries = pJoint->numEntries;
    } while (i < numEntries);
}

// @403bc0
void dwKeyframe_Resample(rdKeyframe* pKeyframe)
{
    uint32_t i;

    if (pKeyframe->numFrames <= 1)
        return;
    for (i = 0; i < pKeyframe->numJoints2; i++)
    {
        dwKeyframe_ResampleJoint(&pKeyframe->aNodes[i], pKeyframe->numFrames);
    }
    // Mirror the marker times to match the time-mirrored resample below.
    for (i = 0; i < pKeyframe->numMarkers; i++)
    {
        pKeyframe->markers.marker_float[i] =
            (float)pKeyframe->numFrames - pKeyframe->markers.marker_float[i];
    }
}

// @403c30
void dwKeyframe_ResampleJoint(rdJoint* pJoint, uint32_t numFrames)
{
    rdAnimEntry* paEntries;
    uint32_t i;

    if (pJoint->numEntries <= 1)
        return;

    paEntries = (rdAnimEntry*)dwMain_pHS->alloc(numFrames * sizeof(rdAnimEntry));
    if (paEntries != NULL)
    {
        _memset(paEntries, 0, numFrames * sizeof(rdAnimEntry));
        for (i = 0; i < numFrames; i++)
        {
            // Time-mirrored sample: frame i takes the pose at (numFrames - i).
            dwKeyframe_SampleJointAt(pJoint, numFrames, (float)numFrames - (float)i,
                                     &paEntries[i].pos, &paEntries[i].orientation);
            paEntries[i].frameNum = (float)i;
        }
    }
    // Faithful: the old array is freed and replaced even when the new
    // allocation failed (the joint then has numFrames entries and a NULL
    // aEntries).
    dwMain_pHS->free(pJoint->aEntries);
    pJoint->aEntries = paEntries;
    pJoint->numEntries = numFrames;
    dwKeyframe_BuildJointDeltas(pJoint, numFrames);
}

// @403d00
void dwKeyframe_SampleJointAt(rdJoint* pJoint, uint32_t numFrames, float time,
                              rdVector3* pPos, rdVector3* pOrient)
{
    uint32_t i;
    uint32_t numEntries;
    rdAnimEntry* pEntry;
    float diff, absDiff;

    i = 0;
    // Wrap into range with a ROUND-to-nearest fmod (binary: FRNDINT) — the
    // result can land slightly NEGATIVE for time == numFrames (faithful).
    if (time >= (float)numFrames)
        time = time - rintf(time / (float)numFrames) * (float)numFrames;

    // Find the first entry at-or-after the requested time.
    numEntries = pJoint->numEntries;
    pEntry = pJoint->aEntries;
    if (numEntries != 0)
    {
        do
        {
            if (time <= pEntry->frameNum)
                break;
            i = i + 1;
            pEntry = pEntry + 1;
        } while (i < numEntries);
    }

    // Faithful quirk: when the scan ran off the end, pEntry points one past
    // the array here and this reads it before stepping back below.
    diff = pEntry->frameNum - time;
    absDiff = diff;
    if (diff < 0.0f)
        absDiff = -diff;
    if (absDiff <= 1e-05f)
        diff = 0.0f;

    if (diff == 0.0f || numEntries == 1)
    {
        // Exact hit (or single-entry joint): copy that entry's pose.
        *pPos = pEntry->pos;
    }
    else
    {
        if (numEntries <= i || time < pEntry->frameNum)
            pEntry = pEntry - 1; // step back to the governing entry
        time = time - pEntry->frameNum;
        if ((pEntry->flags & 1) == 0)
        {
            *pPos = pEntry->pos;
        }
        else
        {
            pPos->x = pEntry->vel.x * time + pEntry->pos.x;
            pPos->y = pEntry->vel.y * time + pEntry->pos.y;
            pPos->z = pEntry->vel.z * time + pEntry->pos.z;
        }
        if ((pEntry->flags & 2) != 0)
        {
            pOrient->x = pEntry->angularVelocity.x * time + pEntry->orientation.x;
            pOrient->y = pEntry->angularVelocity.y * time + pEntry->orientation.y;
            pOrient->z = pEntry->angularVelocity.z * time + pEntry->orientation.z;
            return;
        }
    }
    *pOrient = pEntry->orientation;
}

// @403e80
rdKeyframe* dwKeyframe_Clone(rdKeyframe* pKeyframe)
{
    rdKeyframe* pClone;
    rdJoint* pSrcJoint;
    rdJoint* pDstJoint;
    uint32_t i;
    int bOk;

    pClone = (rdKeyframe*)dwMain_pHS->alloc(sizeof(rdKeyframe));
    if (pClone == NULL)
        return NULL;
    *pClone = *pKeyframe; // header copy (binary: 0x84-byte dword copy)

    bOk = 0;
    pClone->aNodes = (rdJoint*)dwMain_pHS->alloc(pKeyframe->numJoints2 * sizeof(rdJoint));
    if (pClone->aNodes != NULL)
    {
        i = 0;
        _memset(pClone->aNodes, 0, pKeyframe->numJoints2 * sizeof(rdJoint));
        for (; i < pKeyframe->numJoints2; i++)
        {
            pSrcJoint = &pKeyframe->aNodes[i];
            pDstJoint = &pClone->aNodes[i];
            *pDstJoint = *pSrcJoint; // incl. the aEntries pointer when numEntries == 0 (faithful alias)
            if (pDstJoint->numEntries != 0)
            {
                pDstJoint->aEntries =
                    (rdAnimEntry*)dwMain_pHS->alloc(pDstJoint->numEntries * sizeof(rdAnimEntry));
                if (pDstJoint->aEntries == NULL)
                    break;
                _memcpy(pDstJoint->aEntries, pSrcJoint->aEntries,
                        pDstJoint->numEntries * sizeof(rdAnimEntry));
            }
        }
        bOk = (i == pKeyframe->numJoints2);
    }
    if (!bOk)
    {
        // Faithful quirk: the failed clone is released with rdKeyframe_Free
        // (binary: rdKeyframe_FUN_0047de40 = the unloader-hook flavor of
        // Free) but the now-DANGLING pointer is still returned. Callers only
        // see NULL when the header allocation itself failed.
        rdKeyframe_Free(pClone);
    }
    return pClone;
}

// @403fb0
void dwKeyframe_AddMarker(rdKeyframe* pKeyframe, float frameNum, int type)
{
    if (pKeyframe == NULL)
        return;
    pKeyframe->markers.marker_float[pKeyframe->numMarkers] = frameNum;
    pKeyframe->markers.marker_int[pKeyframe->numMarkers] = type;
    pKeyframe->numMarkers = pKeyframe->numMarkers + 1;
}

// @403fe0
void dwKeyframe_AddMidMarker(rdKeyframe* pKeyframe, int type)
{
    if (pKeyframe == NULL)
        return;
    dwKeyframe_AddMarker(pKeyframe, (float)pKeyframe->numFrames * 0.5f, type);
}
