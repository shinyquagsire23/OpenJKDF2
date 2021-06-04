#include "rdPuppet.h"

#include "General/stdMath.h"
#include "Engine/rdroid.h"
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

    for (int i = 0; i < 4; i++)
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
    if ( puppet )
        rdroid_pHS->free(puppet);
}

void rdPuppet_BuildJointMatrices(rdThing *thing, rdMatrix34 *matrix)
{
    rdModel3 *model_; // edx
    rdPuppet *puppet; // eax
    rdPuppetTrack *v4; // ebx
    rdKeyframe *v5; // ecx
    rdJoint *v6; // edx
    int v7; // ecx
    int *v8; // esi
    int v9; // edi
    int v10; // eax
    int v11; // edx
    int v12; // ecx
    float *v13; // edx
    int *v15; // edi
    rdPuppetTrack *v16; // esi
    rdKeyframe *v17; // ebp
    int v18; // ebx
    unsigned int v19; // ecx
    rdJoint *v20; // edx
    int v21; // eax
    rdAnimEntry *v22; // ecx
    double v23; // st7
    rdAnimEntry *v24; // eax
    int v25; // ecx
    double v26; // st5
    double v27; // st6
    double v28; // st5
    double v29; // st6
    double v30; // st7
    float *v31; // eax
    double v32; // st3
    double v33; // st7
    double v34; // rt2
    double v35; // rtt
    double v36; // st4
    double v37; // st7
    double v40; // st6
    double v41; // st4
    float v42; // edx
    float v43; // eax
    double v44; // st4
    double v45; // st7
    double v46; // st7
    double v47; // st6
    double v48; // st5
    double v49; // st7
    double v50; // st7
    double v51; // st7
    double v52; // st6
    double v53; // st5
    double v54; // st4
    double v55; // st3
    double v56; // st2
    double v57; // st7
    double v58; // st2
    double v59; // st6
    rdMatrix34 *v60; // eax
    rdVector3 *v61; // ecx
    int v63; // ebx
    rdHierarchyNode *v64; // eax
    rdMatrix34 *v65; // edx
    rdMatrix34 *v66; // eax
    rdMatrix34 *v67; // esi
    rdMatrix34 *v68; // edi
    float v69; // [esp+0h] [ebp-84h]
    float v70; // [esp+14h] [ebp-70h]
    float v71; // [esp+18h] [ebp-6Ch]
    rdHierarchyNode **v72; // [esp+1Ch] [ebp-68h]
    int v73; // [esp+1Ch] [ebp-68h]
    int v74; // [esp+20h] [ebp-64h]
    int v75; // [esp+20h] [ebp-64h]
    int v76; // [esp+24h] [ebp-60h]
    int v77; // [esp+24h] [ebp-60h]
    rdModel3 *model; // [esp+28h] [ebp-5Ch]
    int v79; // [esp+2Ch] [ebp-58h]
    int v80; // [esp+30h] [ebp-54h]
    int v81; // [esp+34h] [ebp-50h]
    int v82; // [esp+34h] [ebp-50h]
    rdPuppetTrack *v83; // [esp+38h] [ebp-4Ch]
    rdVector3 a3; // [esp+3Ch] [ebp-48h] BYREF
    rdVector3 a4; // [esp+48h] [ebp-3Ch] BYREF
    float v86; // [esp+54h] [ebp-30h]
    float v87; // [esp+58h] [ebp-2Ch]
    float v88; // [esp+5Ch] [ebp-28h]
    rdVector3 v89; // [esp+60h] [ebp-24h]
    rdVector3 v90; // [esp+6Ch] [ebp-18h]
    rdVector3 v91; // [esp+78h] [ebp-Ch]

    model_ = thing->model3;
    puppet = thing->puppet;
    model = model_;
    if ( !thing->field_18 )
    {
        if ( !puppet || puppet->paused )
        {
            v63 = model_->numHierarchyNodes;
            v64 = model_->hierarchyNodes;
            if ( v63 )
            {
                v65 = thing->hierarchyNodeMatrices;
                v66 = &v64->posRotMatrix;
                do
                {
                    v67 = v66;
                    v68 = v65;
                    v66 = (rdMatrix34 *)((char *)v66 + sizeof(rdHierarchyNode));
                    ++v65;
                    --v63;
                    _memcpy(v68, v67, sizeof(rdMatrix34));
                }
                while ( v63 );
            }
        }
        else
        {
            v74 = 4;
            v83 = puppet->tracks;
            v4 = puppet->tracks;
            do
            {
                if ( v4->status )
                {
                    v5 = v4->keyframe;
                    v6 = v5->joints;
                    v7 = v5->numJoints2;
                    if ( v7 )
                    {
                        v8 = &v6->numAnimEntries;
                        v72 = &v4->nodes;
                        v76 = v7;
                        do
                        {
                            v9 = 0;
                            if ( *v8 )
                            {
                                v81 = *v8 - 1;
                                v10 = *((uint32_t *)&v4->nodes + *(v8 - 1));// nodeIdx
                                if ( v10 != v81 )
                                {
                                    v11 = v8[1];
                                    v12 = v10 + 1;
                                    if ( v4->field_120 >= (double)*(float *)(v11 + 56 * (v10 + 1)) )
                                    {
                                        v13 = (float *)(v11 + 56 * (v10 + 2));
                                        do
                                        {
                                            if ( v12 == v81 )
                                            {
                                                v9 = 1;
                                            }
                                            else if ( v4->field_120 >= (double)*v13 )
                                            {
                                                ++v12;
                                                v13 += 14;
                                            }
                                            else
                                            {
                                                v9 = 1;
                                            }
                                        }
                                        while ( !v9 );
                                        *v72 = (rdHierarchyNode *)v12;
                                    }
                                }
                            }
                            v8 += 11;
                            ++v72;
                        }
                        while (v76-- != 1);
                    }
                }
                ++v4;
                --v74;
            }
            while ( v74 );
            v80 = 0;
            if ( model->numHierarchyNodes )
            {
                v82 = 0;
                v77 = 0;
                v15 = &model->hierarchyNodes->idx;
                do
                {
                    v16 = v83;
                    v75 = 0;
                    v73 = 0;
                    v70 = 0.0;
                    v71 = 0.0;
                    a4.x = 0.0;
                    a4.y = 0.0;
                    a4.z = 0.0;
                    a3.x = 0.0;
                    v90.x = 0.0;
                    v91.x = 0.0;
                    a3.y = 0.0;
                    v90.y = 0.0;
                    v91.y = 0.0;
                    a3.z = 0.0;
                    v90.z = 0.0;
                    v91.z = 0.0;
                    v79 = 4;
                    do
                    {
                        v17 = v16->keyframe;
                        if ( v17 )
                        {
                            v18 = (v17->type & v15[1]) != 0 ? v16->highPri : v16->lowPri;
                            if ( (v16->status & 2) != 0 )
                            {
                                v19 = *v15;
                                v20 = &v17->joints[*v15];
                                if ( v20->numAnimEntries )
                                {
                                    if ( v18 >= v73 && (v18 >= v75 || v70 < 1.0) && v17->numJoints2 > v19 )
                                    {
                                        v21 = *((uint32_t *)&v16->nodes + v19);
                                        v22 = v20->animEntries;
                                        v23 = v16->field_120 - *(float *)&v22[v21].frameNum;
                                        v24 = &v22[v21];
                                        v25 = v24->flags;
                                        if ( (v25 & 1) != 0 )
                                        {
                                            v26 = v24->vel.y * v23 + v24->pos.y;
                                            v27 = v24->vel.z * v23 + v24->pos.z;
                                            v89.x = v24->vel.x * v23 + v24->pos.x;
                                            v89.y = v26;
                                            v89.z = v27;
                                        }
                                        else
                                        {
                                            v89 = v24->pos;
                                        }
                                        if ( (v25 & 2) != 0 )
                                        {
                                            v28 = v24->angVel.y * v23 + v24->orientation.y;
                                            v29 = v24->angVel.z * v23 + v24->orientation.z;
                                            v86 = v24->angVel.x * v23 + v24->orientation.x;
                                            v30 = v28;
                                        }
                                        else
                                        {
                                            v31 = &v24->orientation.x;
                                            v86 = *v31;
                                            v87 = v31[1];
                                            v30 = v87;
                                            v88 = v31[2];
                                            v29 = v88;
                                        }
                                        v89.x = v89.x - *((float *)v15 + 10);
                                        v32 = v30;
                                        v33 = v89.z - *((float *)v15 + 12);
                                        v34 = v32 - *((float *)v15 + 14);
                                        v35 = v29 - *((float *)v15 + 15);
                                        v36 = v86 - *((float *)v15 + 13);
                                        v89.y = v89.y - *((float *)v15 + 11);
                                        v89.z = v33;
                                        v87 = v34;
                                        v88 = v35;
                                        v69 = v36;
                                        v86 = stdMath_NormalizeAngleAcute(v69);
                                        v87 = stdMath_NormalizeAngleAcute(v87);
                                        v37 = stdMath_NormalizeAngleAcute(v88);
                                        v88 = v37;
                                        if ( v18 > v75 ) // TODO verify
                                        {
                                            v40 = v16->playSpeed;
                                            v89.x = v40 * v89.x;
                                            v89.y = v40 * v89.y;
                                            v89.z = v40 * v89.z;
                                            v86 = v40 * v86;
                                            v87 = v40 * v87;
                                            v88 = v40 * v88;
                                        }
                                        if ( v18 == v75 )
                                        {
                                            a4.x = a4.x + v89.x;
                                            a4.y = a4.y + v89.y;
                                            v41 = v70 + v16->playSpeed;
                                            a4.z = a4.z + v89.z;
                                            a3.x = a3.x + v86;
                                            a3.y = a3.y + v87;
                                            a3.z = a3.z + v88;
                                            v70 = v41;
                                        }
                                        else if ( v18 <= v75 )
                                        {
                                            if ( v18 <= v73 )
                                            {
                                                v90.x = v90.x + v89.x;
                                                v90.y = v90.y + v89.y;
                                                v44 = v71 + v16->playSpeed;
                                                v90.z = v90.z + v89.z;
                                                v91.x = v91.x + v86;
                                                v91.y = v91.y + v87;
                                                v91.z = v91.z + v88;
                                                v71 = v44;
                                            }
                                            else
                                            {
                                                v90 = v89;
                                                v91.x = v86;
                                                v43 = v16->playSpeed;
                                                v91.y = v87;
                                                v91.z = v88;
                                                v71 = v43;
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
                                            a3.x = v86;
                                            v42 = v16->playSpeed;
                                            v75 = v18;
                                            a3.y = v87;
                                            a3.z = v88;
                                            v70 = v42;
                                        }
                                    }
                                }
                            }
                        }
                        ++v16;
                        --v79;
                    }
                    while ( v79 );
                    if ( v70 >= 1.0 || v71 <= 0.0 )
                    {
                        if ( v70 <= 1.0 )
                            goto LABEL_58;
                        v50 = 1.0 / v70;
                        a4.x = v50 * a4.x;
                        a4.y = v50 * a4.y;
                        a4.z = v50 * a4.z;
                        a3.x = v50 * a3.x;
                        v47 = v50 * a3.y;
                        v49 = v50 * a3.z;
                    }
                    else
                    {
                        if ( v71 > 1.0 )
                        {
                            v45 = 1.0 / v71;
                            v90.x = v45 * v90.x;
                            v90.y = v45 * v90.y;
                            v90.z = v45 * v90.z;
                            v91.x = v45 * v91.x;
                            v91.y = v45 * v91.y;
                            v91.z = v45 * v91.z;
                        }
                        v46 = 1.0 - v70;
                        a4.x = v46 * v90.x + a4.x;
                        a4.y = v46 * v90.y + a4.y;
                        v47 = v46 * v91.y + a3.y;
                        a4.z = v46 * v90.z + a4.z;
                        v48 = v46 * v91.x + a3.x;
                        v49 = v46 * v91.z + a3.z;
                        a3.x = v48;
                    }
                    a3.y = v47;
                    a3.z = v49;
LABEL_58:
                    a3.x = stdMath_NormalizeAngleAcute(a3.x);
                    a3.y = stdMath_NormalizeAngleAcute(a3.y);
                    v51 = stdMath_NormalizeAngleAcute(a3.z);
                    v52 = *((float *)v15 + 10);
                    v53 = *((float *)v15 + 11);
                    v54 = *((float *)v15 + 12);
                    v55 = *((float *)v15 + 13);
                    v56 = v51;
                    v57 = *((float *)v15 + 14);
                    a3.z = v56;
                    v58 = v52;
                    v59 = *((float *)v15 + 15);
                    v60 = thing->hierarchyNodeMatrices;
                    a4.x = v58 + a4.x;
                    a4.y = v53 + a4.y;
                    a4.z = v54 + a4.z;
                    a3.x = v55 + a3.x;
                    a3.y = v57 + a3.y;
                    a3.z = v59 + a3.z;
                    rdMatrix_Build34(&v60[v82], &a3, &a4);
                    v61 = &thing->hierarchyNodes2[v77];
                    if ( v61->x != 0.0 || v61->y != 0.0 || v61->z != 0.0 )
                        rdMatrix_PreRotate34(&thing->hierarchyNodeMatrices[v82], &thing->hierarchyNodes2[v77]);
                    v15 += 45;
                    ++v77;
                    ++v82;
                }
                while ((unsigned int)++v80 < model->numHierarchyNodes);
            }
        }
        rdThing_AccumulateMatrices(thing, model->hierarchyNodes, matrix);
        thing->frameTrue = rdroid_frameTrue;
    }
}
