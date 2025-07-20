#include "rdPuppet.h"

#include <math.h>

#include "General/stdMath.h"
#include "Engine/rdroid.h"
#include "Engine/rdThing.h"
#include "stdPlatform.h"
#include "jk.h"

rdPuppet* rdPuppet_New(rdThing *thing)
{
    rdPuppet* puppet = (rdPuppet *)rdroid_pHS->alloc(sizeof(rdPuppet));

    if (!puppet )
        return NULL;

    // Added: Moved this memset after the nullptr check
    _memset(puppet, 0, sizeof(rdPuppet));

    puppet->paused = 0;
    puppet->rdthing = thing;

    for (int i = 0; i < RDPUPPET_MAX_TRACKS; i++)
    {
        puppet->tracks[i].field_120 = 0.0;
        puppet->tracks[i].field_124 = 0.0;
        if ( puppet->tracks[i].callback )
        {
            puppet->tracks[i].callback(puppet->rdthing->parentSithThing, i, 0);
        }
        puppet->tracks[i].field_4 = 0;
        puppet->tracks[i].keyframe = NULL;
        puppet->tracks[i].callback = NULL;
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
        puppet->tracks[i].field_4 = 0;
        puppet->tracks[i].keyframe = NULL;
        puppet->tracks[i].callback = NULL;
    }
    
    rdroid_pHS->free(puppet);
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
    if (!thing->hierarchyNodeMatrices) return;

    if ( !puppet || puppet->paused )
    {
        for (int i = 0; i < model->numHierarchyNodes; i++)
        {
            rdMatrix_Copy34(&thing->hierarchyNodeMatrices[i], &model->hierarchyNodes[i].posRotMatrix);
        }
        goto accumulate_finalize;
    }
    
    for (int i = 0; i < RDPUPPET_MAX_TRACKS; i++)
    {
        v4 = &puppet->tracks[i];

        //if (thing->parentSithThing == sithPlayer_pLocalPlayerThing && v4->keyframe)
        //    stdPlatform_Printf("%d %s (%x/%u) %p %x %f\n", i, v4->keyframe->name, v4->keyframe->id, v4->keyframe->id, v4->keyframe, v4->status, v4->playSpeed);

        // Added: paJoints check
        if (!(v4->status && v4->keyframe && v4->keyframe->paJoints)) {
            continue;
        }
        
        for (int j = 0; j < v4->keyframe->numJoints2; j++)
        {
            v8 = &v4->keyframe->paJoints[j];
            v9 = 0;
            if (!v8->numAnimEntries) continue;

            // Added: this spot keeps crashing, add bounds checks
            if (v8->nodeIdx < 0 || v8->nodeIdx >= RDPUPPET_MAX_NODES)
            {
                v8->nodeIdx = 0;
            }

            v10 = v4->nodes[v8->nodeIdx];// nodeIdx

            // Added: keep ASAN happy and prevent OOB accesses
            if (v10 >= v8->numAnimEntries) {
                v10 = v8->numAnimEntries - 1;
            }

            if ( v10 == v8->numAnimEntries - 1 ) {
                continue;
            }
            
            v12 = v10 + 1;

            // TODO: TODOA had an OOB access here
            if ( v4->field_120 < (flex_d_t)v8->paAnimEntries[v10 + 1].frameNum ) {
                continue;
            }
            
            v13 = &v8->paAnimEntries[v10 + 2];
            do
            {
                if ( v12 == v8->numAnimEntries - 1 )
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
            v4->nodes[j] = v12;
        }
    }

    for (v80 = 0; v80 < model->numHierarchyNodes; v80++)
    {
        rdHierarchyNode* nodeIter = &model->hierarchyNodes[v80];
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
            rdPuppetTrack* trackIter = &puppet->tracks[j];
            v17 = trackIter->keyframe;
            if (!v17) {
                continue;
            }
            // Added: lowmem nullptr checks
            if (!v17->paJoints) {
                continue;
            }
            
            v18 = (v17->type & nodeIter->type) ? trackIter->highPri : trackIter->lowPri;
            if (!trackIter->status & 2) {
                continue;
            }
            
            v19 = nodeIter->idx;
            v20 = &v17->paJoints[v19]; // overflow in orig? added (moved): v19 < v17->numJoints2, added v20->paAnimEntries nullptr check
            if (!(v19 < v17->numJoints2 && v20->numAnimEntries && v20->paAnimEntries)) {
                continue;
            }
            
            if ( v18 >= v73 && (v18 >= v75 || v70 < 1.0) && v19 < v17->numJoints2 )
            {
                v21 = trackIter->nodes[v19];

                // Added: prevent overflow
                if (v21 >= v20->numAnimEntries) {
                    v21 = v20->numAnimEntries-1;
                }
                if (v21 < 0) {
                    v21 = 0;
                }

                v23 = trackIter->field_120 - v20->paAnimEntries[v21].frameNum;
                v24 = &v20->paAnimEntries[v21];
                v25 = v24->flags;
                if (v25 & 1)
                {
                    rdVector_Copy3(&v89, &v24->pos);
                    rdVector_MultAcc3(&v89, &v24->vel, v23);
                }
                else
                {
                    rdVector_Copy3(&v89, &v24->pos);
                }
                if (v25 & 2)
                {
                    rdVector_Copy3(&tmp1, &v24->orientation);
                    rdVector_MultAcc3(&tmp1, &v24->angVel, v23);
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
            rdVector_MultAcc3(&a4, &v90, v46);
            rdVector_MultAcc3(&a3, &v91, v46);
        }

        rdVector_NormalizeAngleAcute3(&a3);
        rdVector_Add3Acc(&a4, &nodeIter->pos);
        rdVector_Add3Acc(&a3, &nodeIter->rot);

        rdMatrix_Build34(&thing->hierarchyNodeMatrices[v80], &a3, &a4);
        v61 = &thing->hierarchyNodes2[v80];
        if ( !rdVector_IsZero3(v61) )
            rdMatrix_PreRotate34(&thing->hierarchyNodeMatrices[v80], &thing->hierarchyNodes2[v80]);
    }

accumulate_finalize:
    rdThing_AccumulateMatrices(thing, model->hierarchyNodes, matrix);
    thing->frameTrue = rdroid_frameTrue;
}

int rdPuppet_ResetTrack(rdPuppet *puppet, int trackNum)
{
    if ( puppet->tracks[trackNum].callback )
        puppet->tracks[trackNum].callback(puppet->rdthing->parentSithThing, trackNum, 0);
    puppet->tracks[trackNum].status = 0;
    puppet->tracks[trackNum].keyframe = 0;
    puppet->tracks[trackNum].callback = 0;
    return 1;
}

// MOTS altered
int rdPuppet_UpdateTracks(rdPuppet *puppet, flex_t deltaSeconds)
{
    //return _rdPuppet_UpdateTracks(puppet, deltaSeconds);
    
    rdPuppetTrack *v3; // esi
    int v13; // [esp+14h] [ebp-4h]

    v13 = 0;
    if (puppet->paused)
        return 0;

    for (uint32_t v2 = 0; v2 < RDPUPPET_MAX_TRACKS; v2++)
    {
        rdPuppetTrack* track = &puppet->tracks[v2];
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
            
            //if (puppet->rdthing->parentSithThing == sithPlayer_pLocalPlayerThing)
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
                    if ( track->callback )
                        track->callback(puppet->rdthing->parentSithThing, v2, 0);
                    track->status = 0;
                    track->keyframe = 0;
                    track->callback = 0;
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
    int result; // eax
    rdPuppetTrack *newTrack; // edx

    v4 = puppet->tracks;
    for (newTrackIdx = 0; newTrackIdx < RDPUPPET_MAX_TRACKS; newTrackIdx++)
    {
        if ( !puppet->tracks[newTrackIdx].status )
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

        if ( puppet->tracks[newTrackIdx].callback )
            puppet->tracks[newTrackIdx].callback(puppet->rdthing->parentSithThing, newTrackIdx, 0);

        puppet->tracks[newTrackIdx].status = 0;
        puppet->tracks[newTrackIdx].keyframe = 0;
        puppet->tracks[newTrackIdx].callback = 0;

        if ( newTrackIdx >= 4 )
            return -1;
    }
    
    newTrack = &puppet->tracks[newTrackIdx];
    newTrack->speed = keyframe->fps;
    newTrack->keyframe = keyframe;
    newTrack->highPri = highPri;
    newTrack->lowPri = lowPri;
    newTrack->status |= 1;
    newTrack->playSpeed = 0.0;
    
    // Added: Added in Grim Fandango, bounds checking
    if (puppet->rdthing->model3->numHierarchyNodes < 0x40)
        _memset(puppet->tracks[newTrackIdx].nodes, 0, sizeof(uint32_t) * puppet->rdthing->model3->numHierarchyNodes);
    else
        _memset(puppet->tracks[newTrackIdx].nodes, 0, sizeof(puppet->tracks[newTrackIdx].nodes));
    result = newTrackIdx;
    newTrack->field_120 = 0.0;
    newTrack->field_124 = 0.0;
    newTrack->status = 3;
    return result;
}

void rdPuppet_SetCallback(rdPuppet *a1, int trackNum, rdPuppetTrackCallback_t callback)
{
    a1->tracks[trackNum].callback = callback;
}

int rdPuppet_FadeInTrack(rdPuppet *puppet, int trackNum, flex_t speed)
{
    puppet->tracks[trackNum].status = puppet->tracks[trackNum].status & ~8u | 6;
    if ( speed <= 0.0 )
    {
        puppet->tracks[trackNum].fadeSpeed = 1.0;
        return 1;
    }
    else
    {
        puppet->tracks[trackNum].fadeSpeed = 1.0 / speed;
        return 1;
    }
}

void rdPuppet_AdvanceTrack(rdPuppet *puppet, int trackNum, flex_t a3)
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
    v4 = puppet->tracks[trackNum].keyframe;
    v5 = &puppet->tracks[trackNum];
    if ( !v4 || a3 == 0.0 )
        return;
    v22 = a3 + puppet->tracks[trackNum].field_124;
    v6 = (flex_d_t)v4->numFrames;
    puppet->tracks[trackNum].field_120 = v22;

    if ( v22 >= v6 )
    {
        if (v5->status & 0x20)
        {
            puppet->tracks[trackNum].field_120 = v6;
            v20 = 1;
        }
        else if (v5->status & 0x40)
        {
            puppet->tracks[trackNum].field_120 = v6;
            v5->status |= 0x10;
        }
        else if ( v5->status & 0x80 )
        {
            puppet->tracks[trackNum].fadeSpeed = 4.0;
            puppet->tracks[trackNum].field_120 = v6;
            v5->status &= ~0x4;
            v5->status |= 0x8;
            v5->status |= 0x10;
        }
        else
        {
            v21 = stdMath_Floor(v22 / v6);
            size_t v11 = sizeof(uint32_t) * puppet->rdthing->model3->numHierarchyNodes;
            puppet->tracks[trackNum].field_120 -= (flex_d_t)puppet->tracks[trackNum].keyframe->numFrames * v21;
            
            // Added: Added in Grim Fandango, bounds checks
            if (puppet->rdthing->model3->numHierarchyNodes < 0x40)
                _memset(puppet->tracks[trackNum].nodes, 0, sizeof(uint32_t) * puppet->rdthing->model3->numHierarchyNodes);
            else
                _memset(puppet->tracks[trackNum].nodes, 0, sizeof(puppet->tracks[trackNum].nodes));
        }
        
    }
    if ( puppet->tracks[trackNum].callback )
    {
        if ( v4->numMarkers )
        {
            if ( v21 == 0.0 )
            {
                for (uint32_t v13 = 0; v13 < v4->numMarkers; v13++)
                {
                    if ( v4->markers.marker_float[v13] > (flex_d_t)puppet->tracks[trackNum].field_120 )
                        break;
                    if ( v4->markers.marker_float[v13] > (flex_d_t)puppet->tracks[trackNum].field_124 || puppet->tracks[trackNum].field_124 == 0.0 )
                    {
                        puppet->tracks[trackNum].callback(puppet->rdthing->parentSithThing, trackNum, v4->markers.marker_int[v13]);
                    }
                }
            }
            else if ( v21 <= 1.0 )
            {
                for (uint32_t v17 = 0; v17 < v4->numMarkers; v17++)
                {
                    if ( v4->markers.marker_float[v17] > (flex_d_t)puppet->tracks[trackNum].field_124
                      || v4->markers.marker_float[v17] <= (flex_d_t)puppet->tracks[trackNum].field_120 )
                    {
                        puppet->tracks[trackNum].callback(puppet->rdthing->parentSithThing, trackNum, v4->markers.marker_int[v17]);
                    }
                }
            }
            else
            {
                for (uint32_t v15 = 0; v15 < v4->numMarkers; v15++)
                {
                    puppet->tracks[trackNum].callback(puppet->rdthing->parentSithThing, trackNum, v4->markers.marker_int[v15]);
                }
            }
        }
    }

    if ( v20 )
    {
        if ( puppet->tracks[trackNum].callback )
            puppet->tracks[trackNum].callback(puppet->rdthing->parentSithThing, trackNum, 0);
        v5->status = 0;
        puppet->tracks[trackNum].keyframe = 0;
        puppet->tracks[trackNum].callback = 0;
    }
    else
    {
        puppet->tracks[trackNum].field_124 = puppet->tracks[trackNum].field_120;
    }
}

int rdPuppet_FadeOutTrack(rdPuppet *puppet, int trackNum, flex_t speed)
{
    puppet->tracks[trackNum].status = puppet->tracks[trackNum].status & ~4u | 8;
    if ( speed <= 0.0 )
    {
        puppet->tracks[trackNum].fadeSpeed = 1.0;
        return 1;
    }
    else
    {
        puppet->tracks[trackNum].fadeSpeed = 1.0 / speed;
        return 1;
    }
}

void rdPuppet_SetTrackSpeed(rdPuppet *puppet, int trackNum, flex_t speed)
{
    puppet->tracks[trackNum].speed = speed;
}

int rdPuppet_SetStatus(rdPuppet *puppet, int trackNum, int status)
{
    puppet->tracks[trackNum].status |= status;
    return 1;
}

int rdPuppet_PlayTrack(rdPuppet *puppet, int trackNum)
{
    rdPuppetTrack *v2; // eax

    v2 = &puppet->tracks[trackNum];
    v2->status = v2->status & ~0x10u | 2;
    v2->playSpeed = 1.0;
    return 1;
}

void rdPuppet_unk(rdPuppet *puppet, int trackNum)
{
    rdPuppetTrack *v2; // edx

    v2 = &puppet->tracks[trackNum];

    // Added: Added in Grim Fandango, bounds checks
    if (puppet->rdthing->model3->numHierarchyNodes < 0x40)
        _memset(v2->nodes, 0, sizeof(uint32_t) * puppet->rdthing->model3->numHierarchyNodes);
    else
        _memset(v2->nodes, 0, sizeof(puppet->tracks[trackNum].nodes));

    v2->field_120 = 0.0;
    v2->field_124 = 0.0;
    v2->status = 3;
}

int rdPuppet_RemoveTrack(rdPuppet *puppet, rdThing *rdthing)
{
    puppet->paused = 0;
    puppet->rdthing = rdthing;
    for (int i = 0; i < RDPUPPET_MAX_TRACKS; i++)
    {
        puppet->tracks[i].field_120 = 0.0;
        puppet->tracks[i].field_124 = 0.0;
        if ( puppet->tracks[i].callback )
        {
            puppet->tracks[i].callback(puppet->rdthing->parentSithThing, i, 0);
        }
        puppet->tracks[i].status = 0;
        puppet->tracks[i].keyframe = 0;
        puppet->tracks[i].callback = 0;
    }

    return 1;
}
