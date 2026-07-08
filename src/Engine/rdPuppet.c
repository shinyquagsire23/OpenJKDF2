#include "rdPuppet.h"

#include <math.h>

#include "General/stdMath.h"
#include "Engine/rdroid.h"
#include "Engine/rdThing.h"
#include "stdPlatform.h"
#include "jk.h"

// Un-inlined: Clear track node flags with bounds check (added in Grim Fandango).
static void rdPuppet_ClearTrackNodes(rdPuppet *puppet, int trackNum)
{
    if (puppet->renderData->model3->numHNodes < 0x40)
        _memset(puppet->aTracks[trackNum].aCurKfNodeEntryNums, 0, sizeof(uint32_t) * puppet->renderData->model3->numHNodes);
    else
        _memset(puppet->aTracks[trackNum].aCurKfNodeEntryNums, 0, sizeof(puppet->aTracks[trackNum].aCurKfNodeEntryNums));
}

rdPuppet* rdPuppet_New(rdThing *thing)
{
    rdPuppet* puppet = (rdPuppet *)RDROID_ALLOC(sizeof(rdPuppet));

    if (!puppet )
        return NULL;

    // Added: Moved this memset after the nullptr check
    _memset(puppet, 0, sizeof(rdPuppet));

    puppet->bPaused = 0;
    puppet->renderData = thing;

    for (int i = 0; i < RDPUPPET_MAX_TRACKS; i++)
    {
        puppet->aTracks[i].field_120 = 0.0;
        puppet->aTracks[i].field_124 = 0.0;
        if ( puppet->aTracks[i].callback )
        {
            puppet->aTracks[i].callback(puppet->renderData->pThing, i, 0);
        }
        puppet->aTracks[i].field_4 = 0;
        puppet->aTracks[i].keyframe = NULL;
        puppet->aTracks[i].callback = NULL;
    }
    thing->puppet = puppet;
    return puppet;
}

void rdPuppet_Free(rdPuppet *puppet)
{
    // Moved: no nullptr deref
    if (!puppet) return;

    // Added: prevent UAFs
    for (int i = 0; i < RDPUPPET_MAX_TRACKS; i++)
    {
        puppet->aTracks[i].field_4 = 0;
        puppet->aTracks[i].keyframe = NULL;
        puppet->aTracks[i].callback = NULL;
    }
    
    RDROID_FREE(puppet);
}

void rdPuppet_FreeEntry()
{
}

void rdPuppet_SetPause(rdPuppet *puppet, int bPaused)
{
    puppet->bPaused = bPaused;
}

void rdPuppet_SetTrackNoise(rdPuppet *puppet, int trackNum, flex_t noise)
{
    if ( noise != 0.0f )
    {
        puppet->aTracks[trackNum].status |= 0x1000;
    }
    else
    {
        puppet->aTracks[trackNum].status &= ~0x1000;
    }
    puppet->aTracks[trackNum].field_120 = noise;
}

void rdPuppet_SetTrackPriority(rdPuppet *puppet, int trackNum, int lowPri, int highPri)
{
    puppet->aTracks[trackNum].lowPri = lowPri;
    puppet->aTracks[trackNum].highPri = highPri;
}

// MOTS altered
void rdPuppet_BuildJointMatrices(rdThing *thing, rdMatrix34 *matrix)
{
    rdPuppet *puppet; // eax
    rdPuppetTrack *v4; // ebx
    rdJoint *v8; // esi
    int v9; // edi
    uint32_t v10; // eax
    intptr_t v12; // ecx
    rdAnimEntry *v13;
    rdKeyframe *v17; // ebp
    int v18; // ebx
    unsigned int v19; // ecx
    rdJoint *v20; // edx
    uint32_t v21; // eax
    flex_d_t v23; // st7
    rdAnimEntry *v24; // eax
    int v25; // ecx
    flex_d_t v29; // st6
    flex_d_t v30; // st7
    flex_d_t v33; // st7
    flex_d_t v35; // rtt
    flex_d_t v36; // st4
    flex_t v42; // edx
    flex_d_t v45; // st7
    flex_d_t v46; // st7
    flex_d_t v48; // st5
    flex_d_t v50; // st7
    rdVector3 *v61; // ecx
    flex_t v70; // [esp+14h] [ebp-70h]
    flex_t v71; // [esp+18h] [ebp-6Ch]
    int v73; // [esp+1Ch] [ebp-68h]
    int v75; // [esp+20h] [ebp-64h]
    int v77; // [esp+24h] [ebp-60h]
    rdModel3 *model; // [esp+28h] [ebp-5Ch]
    int v80; // [esp+30h] [ebp-54h]
    int v82; // [esp+34h] [ebp-50h]
    rdVector3 a3; // [esp+3Ch] [ebp-48h] BYREF
    rdVector3 a4; // [esp+48h] [ebp-3Ch] BYREF
    flex_t v86; // [esp+54h] [ebp-30h]
    flex_t v87; // [esp+58h] [ebp-2Ch]
    flex_t v88; // [esp+5Ch] [ebp-28h]
    rdVector3 v89; // [esp+60h] [ebp-24h]
    rdVector3 v90; // [esp+6Ch] [ebp-18h]
    rdVector3 v91; // [esp+78h] [ebp-Ch]
    rdVector3 tmp1;

    model = thing->model3;
    puppet = thing->puppet;
    if ( thing->field_18 )
    {
        return;
    }

    // Added: Fix a crash?
    if (!thing->paJointMatrices) return;

    if ( !puppet || puppet->bPaused )
    {
        for (int i = 0; i < model->numHNodes; i++)
        {
            rdMatrix_Copy34(&thing->paJointMatrices[i], &model->aHierarchyNodes[i].posRotMatrix);
        }
        goto accumulate_finalize;
    }
    
    for (int i = 0; i < RDPUPPET_MAX_TRACKS; i++)
    {
        v4 = &puppet->aTracks[i];

        //if (thing->pThing == sithPlayer_g_pLocalPlayerThing && v4->keyframe)
        //    stdPlatform_Printf("%d %s (%x/%u) %p %x %f\n", i, v4->keyframe->name, v4->keyframe->id, v4->keyframe->id, v4->keyframe, v4->status, v4->playSpeed);

        // Added: aNodes check
        if (!(v4->status && v4->keyframe && v4->keyframe->aNodes)) {
            continue;
        }
        
        for (int j = 0; j < v4->keyframe->numJoints2; j++)
        {
            v8 = &v4->keyframe->aNodes[j];
            v9 = 0;
            if (!v8->numEntries) continue;

            // Added: this spot keeps crashing, add bounds checks
            if (v8->nodeNum < 0 || v8->nodeNum >= RDPUPPET_MAX_NODES)
            {
                v8->nodeNum = 0;
            }

            v10 = v4->aCurKfNodeEntryNums[v8->nodeNum];// nodeNum

            // Added: keep ASAN happy and prevent OOB accesses
            if (v10 >= v8->numEntries) {
                v10 = v8->numEntries - 1;
            }

            if ( v10 == v8->numEntries - 1 ) {
                continue;
            }
            
            v12 = v10 + 1;

            // TODO: TODOA had an OOB access here
            if ( v4->field_120 < (flex_d_t)v8->aEntries[v10 + 1].frameNum ) {
                continue;
            }
            
            v13 = &v8->aEntries[v10 + 2];
            do
            {
                if ( v12 == v8->numEntries - 1 )
                {
                    v9 = 1;
                }
                else if ( v4->field_120 >= (flex_d_t)v13->frameNum )
                {
                    ++v12;
                    ++v13;
                }
                else
                {
                    v9 = 1;
                }
            }
            while ( !v9 );
            v4->aCurKfNodeEntryNums[j] = v12;
        }
    }

    for (v80 = 0; v80 < model->numHNodes; v80++)
    {
        rdHierarchyNode* nodeIter = &model->aHierarchyNodes[v80];
        v75 = 0;
        v73 = 0;
        v70 = 0.0;
        v71 = 0.0;
        rdVector_Zero3(&a4);
        rdVector_Zero3(&a3);
        rdVector_Zero3(&v90);
        rdVector_Zero3(&v91);
        for (int j = 0; j < RDPUPPET_MAX_TRACKS; j++)
        {
            rdPuppetTrack* trackIter = &puppet->aTracks[j];
            v17 = trackIter->keyframe;
            if (!v17) {
                continue;
            }
            // Added: lowmem nullptr checks
            if (!v17->aNodes) {
                continue;
            }
            
            v18 = (v17->type & nodeIter->type) ? trackIter->highPri : trackIter->lowPri;
            // Only blend aTracks that are actively playing (status bit 0x2)
            if (!(trackIter->status & 2)) {
                continue;
            }
            
            v19 = nodeIter->idx;
            v20 = &v17->aNodes[v19]; // overflow in orig? added (moved): v19 < v17->numJoints2, added v20->aEntries nullptr check
            if (!(v19 < v17->numJoints2 && v20->numEntries && v20->aEntries)) {
                continue;
            }
            
            if ( v18 >= v73 && (v18 >= v75 || v70 < 1.0) && v19 < v17->numJoints2 )
            {
                v21 = trackIter->aCurKfNodeEntryNums[v19];

                // Added: prevent overflow
                if (v21 >= v20->numEntries) {
                    v21 = v20->numEntries-1;
                }
                if (v21 < 0) {
                    v21 = 0;
                }

                v23 = trackIter->field_120 - v20->aEntries[v21].frameNum;
                v24 = &v20->aEntries[v21];
                v25 = v24->flags;
                if (v25 & 1)
                {
                    rdVector_Copy3(&v89, &v24->pos);
                    rdVector_ScaleAdd3Acc(&v89, &v24->vel, v23);
                }
                else
                {
                    rdVector_Copy3(&v89, &v24->pos);
                }
                if (v25 & 2)
                {
                    rdVector_Copy3(&tmp1, &v24->orientation);
                    rdVector_ScaleAdd3Acc(&tmp1, &v24->angularVelocity, v23);
                }
                else
                {
                    rdVector_Copy3(&tmp1, &v24->orientation);
                }
                rdVector_Sub3Acc(&v89, &nodeIter->pos);
                rdVector_Sub3Acc(&tmp1, &nodeIter->rot);
                rdVector_NormalizeAngleAcute3(&tmp1);
                if (trackIter->playSpeed <= 1.0)
                {
                    // Added: Make sure anims don't leak in blending
                    if (trackIter->playSpeed < 0.0)
                        trackIter->playSpeed = 0.0;

                    rdVector_Scale3Acc(&v89, trackIter->playSpeed);
                    rdVector_Scale3Acc(&tmp1, trackIter->playSpeed);
                }
                if (v18 == v75)
                {
                    rdVector_Add3Acc(&a4, &v89);
                    rdVector_Add3Acc(&a3, &tmp1);
                    v70 += trackIter->playSpeed;
                }
                else if (v18 <= v75)
                {
                    if (v18 <= v73)
                    {
                        rdVector_Add3Acc(&v90, &v89);
                        rdVector_Add3Acc(&v91, &tmp1);
                        v71 += trackIter->playSpeed;
                    }
                    else
                    {
                        v90 = v89;
                        rdVector_Copy3(&v91, &tmp1);
                        v71 = trackIter->playSpeed;
                        v73 = v18;
                    }
                }
                else
                {
                    v90 = a4;
                    v91 = a3;
                    v71 = v70;
                    v73 = v75;
                    a4 = v89;
                    v75 = v18;
                    rdVector_Copy3(&a3, &tmp1);
                    v70 = trackIter->playSpeed;
                }
            }
        }


        if (v70 >= 1.0 || v71 <= 0.0)
        {
            if (v70 > 1.0) {
                v50 = 1.0 / v70;
                rdVector_Scale3Acc(&a4, v50);
                rdVector_Scale3Acc(&a3, v50);
            }
        }
        else
        {
            if (v71 > 1.0) {
                v45 = 1.0 / v71;
                rdVector_Scale3Acc(&v90, v45);
                rdVector_Scale3Acc(&v91, v45);
            }
            v46 = 1.0 - v70;
            rdVector_ScaleAdd3Acc(&a4, &v90, v46);
            rdVector_ScaleAdd3Acc(&a3, &v91, v46);
        }

        rdVector_NormalizeAngleAcute3(&a3);
        rdVector_Add3Acc(&a4, &nodeIter->pos);
        rdVector_Add3Acc(&a3, &nodeIter->rot);

        rdMatrix_Build34(&thing->paJointMatrices[v80], &a3, &a4);
        v61 = &thing->hierarchyNodes2[v80];
        if ( !rdVector_IsZero3(v61) )
            rdMatrix_PreRotate34(&thing->paJointMatrices[v80], &thing->hierarchyNodes2[v80]);
    }

accumulate_finalize:
    rdThing_AccumulateMatrices(thing, model->aHierarchyNodes, matrix);
    thing->rdFrameNum = rdroid_frameTrue;
}

int rdPuppet_RemoveTrack(rdPuppet *puppet, int trackNum)
{
    if ( puppet->aTracks[trackNum].callback )
        puppet->aTracks[trackNum].callback(puppet->renderData->pThing, trackNum, 0);
    puppet->aTracks[trackNum].status = 0;
    puppet->aTracks[trackNum].keyframe = 0;
    puppet->aTracks[trackNum].callback = 0;
    return 1;
}

// MOTS altered
int rdPuppet_UpdateTracks(rdPuppet *puppet, flex_t deltaSeconds)
{
    //return _rdPuppet_UpdateTracks(puppet, deltaSeconds);
    
    rdPuppetTrack *v3; // esi
    int v13; // [esp+14h] [ebp-4h]

    v13 = 0;
    if (puppet->bPaused)
        return 0;

    for (uint32_t v2 = 0; v2 < RDPUPPET_MAX_TRACKS; v2++)
    {
        rdPuppetTrack* track = &puppet->aTracks[v2];
        if (!track->status)
            continue;

        ++v13;
        if (track->status & 0x200) continue; // MOTS added

        if ( (track->status & 0x10) == 0 )
        {
            rdPuppet_AdvanceTrack(puppet, v2, track->speed * deltaSeconds);
        }

        if (track->status & 4)
        {
            track->playSpeed += track->fadeSpeed * deltaSeconds;
            if ( track->playSpeed >= 1.0 ) // verified
            {
                track->playSpeed = 1.0;
                track->status &= ~0x4;
            }
        }
        else if (track->status & 8)
        {
            track->playSpeed -= track->fadeSpeed * deltaSeconds;
            
            //if (puppet->renderData->pThing == sithPlayer_g_pLocalPlayerThing)
            //    stdPlatform_Printf("%u %f %f %f %f %u\n", v2, track->playSpeed, track->fadeSpeed, deltaSeconds, track->field_124, track->keyframe->numFrames);
            
            if ( track->playSpeed <= 0.0 ) // verified
            {
                if ( (track->status & 0x100) != 0 )
                {
                    track->status &= ~0x8u;
                    track->status |= 0x10;
                }
                else
                {
                    rdPuppet_RemoveTrack(puppet, v2);
                }
            }
        }
    }

    return v13;
}

int rdPuppet_AddTrack(rdPuppet *puppet, rdKeyframe *keyframe, int lowPri, int highPri)
{
    rdPuppetTrack *v4; // ecx
    int newTrackIdx; // esi
    rdPuppetTrack *v6; // eax
    rdPuppetTrack *newTrack; // edx

    v4 = puppet->aTracks;
    for (newTrackIdx = 0; newTrackIdx < RDPUPPET_MAX_TRACKS; newTrackIdx++)
    {
        if ( !puppet->aTracks[newTrackIdx].status )
            break;
    }

    if ( newTrackIdx >= 4 )
    {
        newTrackIdx = 0;
        while ( (v4->status & 8) == 0 || (v4->status & 0x140) != 0 )
        {
            ++newTrackIdx;
            ++v4;
            if ( newTrackIdx >= 4 )
                return -1;
        }

        if ( newTrackIdx >= 4 )
            return -1;

        rdPuppet_RemoveTrack(puppet, newTrackIdx);
    }
    
    newTrack = &puppet->aTracks[newTrackIdx];
    newTrack->speed = keyframe->fps;
    newTrack->keyframe = keyframe;
    newTrack->highPri = highPri;
    newTrack->lowPri = lowPri;
    newTrack->status |= 1;
    newTrack->playSpeed = 0.0;

    rdPuppet_ResetTrack(puppet, newTrackIdx);
    
    return newTrackIdx;
}

void rdPuppet_SetCallback(rdPuppet *a1, int trackNum, rdPuppetTrackCallback_t callback)
{
    a1->aTracks[trackNum].callback = callback;
}

int rdPuppet_FadeInTrack(rdPuppet *puppet, int trackNum, flex_t speed)
{
    puppet->aTracks[trackNum].status = puppet->aTracks[trackNum].status & ~8u | 6;
    if ( speed <= 0.0 )
    {
        puppet->aTracks[trackNum].fadeSpeed = 1.0;
        return 1;
    }
    else
    {
        puppet->aTracks[trackNum].fadeSpeed = 1.0 / speed;
        return 1;
    }
}

void rdPuppet_AdvanceTrack(rdPuppet *puppet, int trackNum, flex_t deltaSecondsKinda)
{
    //_rdPuppet_AdvanceTrack(puppet, trackNum, a3);
    //return;
    
    rdKeyframe *v4; // ecx
    rdPuppetTrack *v5; // esi
    flex_d_t v6; // st7
    //unsigned int v11; // ebx
    rdKeyframe *v12; // ecx
    int v20; // [esp+14h] [ebp-8h]
    flex_t v21; // [esp+18h] [ebp-4h]
    flex_t v22; // [esp+2Ch] [ebp+10h]

    v21 = 0.0;
    v20 = 0;
    v4 = puppet->aTracks[trackNum].keyframe;
    v5 = &puppet->aTracks[trackNum];
    if ( !v4 || deltaSecondsKinda == 0.0 )
        return;
    v22 = deltaSecondsKinda + puppet->aTracks[trackNum].field_124;
    v6 = (flex_d_t)v4->numFrames;
    puppet->aTracks[trackNum].field_120 = v22;

    if ( v22 >= v6 )
    {
        if (v5->status & 0x20)
        {
            puppet->aTracks[trackNum].field_120 = v6;
            v20 = 1;
        }
        else if (v5->status & 0x40)
        {
            puppet->aTracks[trackNum].field_120 = v6;
            v5->status |= 0x10;
        }
        else if ( v5->status & 0x80 )
        {
            puppet->aTracks[trackNum].fadeSpeed = 4.0;
            puppet->aTracks[trackNum].field_120 = v6;
            v5->status &= ~0x4;
            v5->status |= 0x8;
            v5->status |= 0x10;
        }
        else
        {
            v21 = stdMath_Floor(v22 / v6 + 0.5);
            size_t v11 = sizeof(uint32_t) * puppet->renderData->model3->numHNodes;
            puppet->aTracks[trackNum].field_120 -= (flex_d_t)puppet->aTracks[trackNum].keyframe->numFrames * v21;
            
            rdPuppet_ClearTrackNodes(puppet, trackNum);
        }
        
    }
    if ( puppet->aTracks[trackNum].callback )
    {
        if ( v4->numMarkers )
        {
            if ( v21 == 0.0 )
            {
                for (uint32_t v13 = 0; v13 < v4->numMarkers; v13++)
                {
                    if ( v4->markers.marker_float[v13] > (flex_d_t)puppet->aTracks[trackNum].field_120 )
                        break;
                    if ( v4->markers.marker_float[v13] > (flex_d_t)puppet->aTracks[trackNum].field_124 || puppet->aTracks[trackNum].field_124 == 0.0 )
                    {
                        puppet->aTracks[trackNum].callback(puppet->renderData->pThing, trackNum, v4->markers.marker_int[v13]);
                    }
                }
            }
            else if ( v21 <= 1.0 )
            {
                for (uint32_t v17 = 0; v17 < v4->numMarkers; v17++)
                {
                    if ( v4->markers.marker_float[v17] > (flex_d_t)puppet->aTracks[trackNum].field_124
                      || v4->markers.marker_float[v17] <= (flex_d_t)puppet->aTracks[trackNum].field_120 )
                    {
                        puppet->aTracks[trackNum].callback(puppet->renderData->pThing, trackNum, v4->markers.marker_int[v17]);
                    }
                }
            }
            else
            {
                for (uint32_t v15 = 0; v15 < v4->numMarkers; v15++)
                {
                    puppet->aTracks[trackNum].callback(puppet->renderData->pThing, trackNum, v4->markers.marker_int[v15]);
                }
            }
        }
    }

    if ( v20 )
    {
        rdPuppet_RemoveTrack(puppet, trackNum);
    }
    else
    {
        puppet->aTracks[trackNum].field_124 = puppet->aTracks[trackNum].field_120;
    }
}

int rdPuppet_FadeOutTrack(rdPuppet *puppet, int trackNum, flex_t speed)
{
    puppet->aTracks[trackNum].status = puppet->aTracks[trackNum].status & ~4u | 8;
    if ( speed <= 0.0 )
    {
        puppet->aTracks[trackNum].fadeSpeed = 1.0;
        return 1;
    }
    else
    {
        puppet->aTracks[trackNum].fadeSpeed = 1.0 / speed;
        return 1;
    }
}

void rdPuppet_SetTrackSpeed(rdPuppet *puppet, int trackNum, flex_t speed)
{
    puppet->aTracks[trackNum].speed = speed;
}

int rdPuppet_SetStatus(rdPuppet *puppet, int trackNum, int status)
{
    puppet->aTracks[trackNum].status |= status;
    return 1;
}

int rdPuppet_PlayTrack(rdPuppet *puppet, int trackNum)
{
    rdPuppetTrack *v2; // eax

    v2 = &puppet->aTracks[trackNum];
    v2->status = v2->status & ~0x10u | 2;
    v2->playSpeed = 1.0;
    return 1;
}

void rdPuppet_ResetTrack(rdPuppet *puppet, int trackNum)
{
    rdPuppetTrack *v2; // edx

    v2 = &puppet->aTracks[trackNum];

    rdPuppet_ClearTrackNodes(puppet, trackNum);

    v2->field_120 = 0.0;
    v2->field_124 = 0.0;
    v2->status = 3;
}

int rdPuppet_NewEntry(rdPuppet *puppet, rdThing *renderData)
{
    puppet->bPaused = 0;
    puppet->renderData = renderData;
    for (int i = 0; i < RDPUPPET_MAX_TRACKS; i++)
    {
        puppet->aTracks[i].field_120 = 0.0;
        puppet->aTracks[i].field_124 = 0.0;

        rdPuppet_RemoveTrack(puppet, i);
    }

    return 1;
}
