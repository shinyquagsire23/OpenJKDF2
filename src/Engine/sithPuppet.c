#include "sithPuppet.h"

#include "General/stdHashTable.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithTime.h"
#include "World/sithSector.h"
#include "World/jkPlayer.h"
#include "Engine/sithCollision.h"
#include "World/sithActor.h"
#include "Main/jkGame.h"
#include "Engine/rdPuppet.h"
#include "Engine/sithSoundClass.h"
#include "stdPlatform.h"
#include "AI/sithAI.h"
#include "jk.h"


static const char* sithPuppet_animNames[43] = {
    "--RESERVED--",
    "stand",
    "walk",
    "run",
    "walkback",
    "strafeleft",
    "straferight",
    "death",
    "fire",
    "fire3",
    "fire4",
    "death2",
    "hit",
    "hit2",
    "rising",
    "toss",
    "place",
    "drop",
    "fire2",
    "fall",
    "land",
    "crouchforward",
    "crouchback",
    "activate",
    "magic",
    "choke",
    "leap",
    "jump",
    "reserved",
    "block",
    "block2",
    "turnleft",
    "turnright",
    "fidget",
    "fidget2",
    "magic2",
    "magic3",
    "victory",
    "windup",
    "holster",
    "drawfists",
    "drawgun",
    "drawsaber"
};

int sithPuppet_Startup()
{
    sithPuppet_hashtable = stdHashTable_New(64);
    sithPuppet_keyframesHashtable = stdHashTable_New(256);

    if ( sithPuppet_hashtable && sithPuppet_keyframesHashtable )
    {
        sithPuppet_animNamesToIdxHashtable = stdHashTable_New(86);
        for (int i = 1; i < 43; i++)
        {
            stdHashTable_SetKeyVal(sithPuppet_animNamesToIdxHashtable, sithPuppet_animNames[i], (void *)i);
        }
        return 1;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\Engine\\sithPuppet.c", 163, "Could not allocate memory of puppets.\n", 0, 0, 0, 0);
        return 0;
    }
}

sithPuppet* sithPuppet_NewEntry(sithThing *thing)
{
    sithPuppet *v1; // edi
    sithSector *sector; // eax
    sithPuppet *result; // eax

    v1 = (sithPuppet *)pSithHS->alloc(sizeof(sithPuppet));
    thing->puppet = v1;
    if ( !v1 )
        thing->animclass = 0;
    _memset(v1, 0, sizeof(sithPuppet));
    sector = thing->sector;
    if ( sector && (sector->flags & SITH_SF_UNDERWATER) != 0 )
    {
        result = thing->puppet;
        result->field_4 = 1;
        result->otherTrack = -1;
        result->field_18 = -1;
        result->currentTrack = -1;
    }
    else
    {
        result = thing->puppet;
        result->field_4 = 0;
        result->otherTrack = -1;
        result->field_18 = -1;
        result->currentTrack = -1;
    }
    return result;
}

void sithPuppet_FreeEntry(sithThing *puppet)
{
    if ( puppet->puppet )
    {
        pSithHS->free(puppet->puppet);
        puppet->puppet = 0;
    }
}

void sithPuppet_sub_4E4760(sithThing *thing, int a2)
{
    sithPuppet *puppet; // eax

    if ( thing->animclass )
    {
        puppet = thing->puppet;
        if ( puppet )
        {
            if ( puppet->field_4 != a2 )
            {
                puppet->field_4 = a2;
                puppet->majorMode = puppet->field_0 + 3 * a2;
            }
        }
    }
}

int sithPuppet_PlayMode(sithThing *thing, signed int anim, intptr_t callback)
{
    sithAnimclass *v4; // ebx
    sithPuppet *v6; // edx
    sithAnimclassEntry *v7; // eax
    rdKeyframe *keyframe; // ebx
    int flags; // ebp
    int v10; // eax
    rdPuppet *v11; // ecx
    signed int result; // eax
    int highPri; // [esp+14h] [ebp+4h]
    int lowPri; // [esp+18h] [ebp+8h]

    v4 = thing->animclass;
    if ( !v4 )
        return -1;
    if ( anim < 0 )
        return -1;
    if ( anim >= 43 )
        return -1;
    v6 = thing->puppet;
    v7 = &v4->modes[v6->majorMode].keyframe[anim];
    keyframe = v7->keyframe;
    if ( !v7->keyframe )
        return -1;
    flags = v7->flags;
    lowPri = v7->lowPri;
    highPri = v7->highPri;
    if ( anim != SITH_ANIM_FIDGET && anim != SITH_ANIM_FIDGET2 )
    {
        v6->animStartedMs = sithTime_curMs;
        v10 = v6->currentTrack;
        if ( v10 >= 0 )
        {
            v11 = thing->rdthing.puppet;
            if ( v11->tracks[v10].keyframe )
                rdPuppet_ResetTrack(v11, v10);
            thing->puppet->currentTrack = -1;
        }
    }
    
    result = sithPuppet_StartKey(thing->rdthing.puppet, keyframe, lowPri, highPri, flags, callback);
    if ( result < 0 )
        return -1;
    return result;
}

int sithPuppet_StartKey(rdPuppet *puppet, rdKeyframe *keyframe, int a3, int a4, int a5, intptr_t callback)
{
    int v6; // ecx
    int trackNum; // esi
    signed int result; // eax

    v6 = 1;
    if ( (a5 & 8) != 0 )
    {
        trackNum = 0;
        while ( puppet->tracks[trackNum].keyframe != keyframe )
        {
            ++trackNum;
            if ( trackNum >= 4 )
                goto LABEL_8;
        }
        rdPuppet_unk(puppet, trackNum);
        v6 = 0;
    }
    else
    {
        trackNum = a5;
    }
LABEL_8:
    if ( v6 )
    {
        trackNum = rdPuppet_AddTrack(puppet, keyframe, a3, a4);
        if ( trackNum < 0 )
            return -1;
    }
    if ( callback )
        rdPuppet_SetCallback(puppet, trackNum, callback);
    else
        rdPuppet_SetCallback(puppet, trackNum, sithPuppet_DefaultCallback);
    if ( (a5 & 2) != 0 )
    {
        rdPuppet_SetStatus(puppet, trackNum, 32);
    }
    else if ( (a5 & 0x20) != 0 )
    {
        rdPuppet_SetStatus(puppet, trackNum, 128);
    }
    else if ( (a5 & 4) != 0 )
    {
        rdPuppet_SetStatus(puppet, trackNum, 64);
    }
    if ( (a5 & 1) != 0 )
        rdPuppet_SetTrackSpeed(puppet, trackNum, 0.0);
    if ( (a5 & 0x10) != 0 )
        rdPuppet_PlayTrack(puppet, trackNum);
    else
        rdPuppet_FadeInTrack(puppet, trackNum, 0.1);
    result = trackNum;
    puppet->tracks[trackNum].field_130 = ((playerThingIdx + 1) << 16) | (uint16_t)(trackNum + 1);
    return result;
}

void sithPuppet_ResetTrack(sithThing *puppet)
{
    unsigned int trackNum; // esi
    sithPuppet *v2; // eax

    for ( trackNum = 0; trackNum < 4; ++trackNum )
        rdPuppet_ResetTrack(puppet->rdthing.puppet, trackNum);
    v2 = puppet->puppet;
    v2->playingAnim = NULL;
    v2->otherTrack = -1;
    v2->field_18 = -1;
    v2->currentTrack = -1;
}

void sithPuppet_Tick(sithThing *thing, float deltaSeconds)
{
    double v3; // st7
    sithPuppet *v4; // eax
    sithAnimclassEntry *v5; // ecx
    int v6; // ecx
    double v8; // st7
    char v9; // c0
    sithPuppet *v10; // eax
    double v11; // st7
    sithAnimclass *v12; // edx
    sithAnimclassEntry *v13; // eax
    int v14; // eax
    sithPuppet *v15; // ecx
    unsigned int v16; // edx
    sithAnimclass *v17; // edx
    sithAnimclassEntry *v18; // eax
    int v19; // eax
    rdMatrix34 *v20; // eax
    double v21; // st7
    double v22; // st7
    rdMatrix34 *v23; // ecx
    double v25; // st6
    double v26; // st7
    float *v27; // eax
    int i; // edx
    double v29; // st7
    float *v30; // ecx
    float v31; // [esp+0h] [ebp-18h]
    rdVector3 a1a; // [esp+Ch] [ebp-Ch] BYREF
    float thinga; // [esp+1Ch] [ebp+4h]
    float a2a; // [esp+20h] [ebp+8h]

    if ( thing->animclass && thing->puppet && thing->rdthing.puppet && (g_debugmodeFlags & 2) == 0 )
    {
        if ( thing->moveType == SITH_MT_PHYSICS )
        {
            v3 = sithPuppet_sub_4E4380(thing);
            v4 = thing->puppet;
            v5 = v4->playingAnim;
            if ( v5 )
            {
                if ( (v5->flags & 1) != 0 )
                {
                    v6 = v4->otherTrack;
                    if ( v6 >= 0 )
                    {
                        thinga = v3 * deltaSeconds;
                        v8 = thinga;
                        if ( v8 < 0.0 )
                            v8 = -v8;
                        v31 = v8 * 280.0;
                        rdPuppet_AdvanceTrack(thing->rdthing.puppet, v6, v31);
                    }
                }
            }
            v10 = thing->puppet;
            if ( v10->currentTrack < 0 && v10->currentAnimation == 1 )
            {
                if ( (double)v10->animStartedMs - -30000.0 < (double)sithTime_curMs )
                {
                    v11 = _frand();
                    if ( v11 >= 0.30000001 )
                    {
                        if ( v11 < 0.60000002 )
                        {
                            v17 = thing->animclass;
                            if ( !v17
                              || (v18 = &v17->modes[thing->puppet->majorMode].keyframe[SITH_ANIM_FIDGET2], !v18->keyframe)
                              || (v19 = sithPuppet_StartKey(
                                            thing->rdthing.puppet,
                                            v18->keyframe,
                                            v18->lowPri,
                                            v18->highPri,
                                            v17->modes[thing->puppet->majorMode].keyframe[SITH_ANIM_FIDGET2].flags,
                                            0),
                                  v19 < 0) )
                            {
                                v19 = -1;
                            }
                            thing->puppet->currentTrack = v19;
                        }
                    }
                    else
                    {
                        v12 = thing->animclass;
                        if ( !v12
                          || (v13 = &v12->modes[thing->puppet->majorMode].keyframe[SITH_ANIM_FIDGET], !v13->keyframe)
                          || (v14 = sithPuppet_StartKey(
                                        thing->rdthing.puppet,
                                        v13->keyframe,
                                        v13->lowPri,
                                        v13->highPri,
                                        v12->modes[thing->puppet->majorMode].keyframe[SITH_ANIM_FIDGET].flags,
                                        0),
                              v14 < 0) )
                        {
                            v14 = -1;
                        }
                        v15 = thing->puppet;
                        v16 = sithTime_curMs;
                        v15->currentTrack = v14;
                        v15->animStartedMs = v16;
                    }
                }
            }
        }
        if ( rdPuppet_UpdateTracks(thing->rdthing.puppet, deltaSeconds) && thing->moveType == SITH_MT_PATH )
        {
            thing->lookOrientation.scale.x = 0.0;
            thing->lookOrientation.scale.y = 0.0;
            thing->lookOrientation.scale.z = 0.0;
            thing->rdthing.field_18 = 0;
            rdPuppet_BuildJointMatrices(&thing->rdthing, &thing->lookOrientation);
            v20 = thing->rdthing.hierarchyNodeMatrices;
            v21 = thing->trackParams.field_24.scale.x + v20->scale.x;
            thing->rdthing.field_18 = 1;
            a1a.x = v21;
            a1a.y = thing->trackParams.field_24.scale.y + v20->scale.y;
            v22 = thing->trackParams.field_24.scale.z + v20->scale.z;
            a1a.x = a1a.x - thing->position.x;
            a1a.y = a1a.y - thing->position.y;
            a1a.z = v22 - thing->position.z;
            if ( a1a.x != 0.0 || a1a.y != 0.0 || a1a.z != 0.0 )
            {
                a2a = rdVector_Normalize3Acc(&a1a);
                sithCollision_UpdateThingCollision(thing, &a1a, a2a, 0);
            }
            v23 = thing->rdthing.hierarchyNodeMatrices;
            v25 = thing->position.y;
            v26 = thing->position.z;
            a1a.x = thing->position.x - v23->scale.x;
            v27 = &v23->scale.y;
            a1a.y = v25 - v23->scale.y;
            a1a.z = v26 - v23->scale.z;
            for ( i = thing->rdthing.model3->numHierarchyNodes; i; *v30 = a1a.z + *v30 )
            {
                v29 = a1a.x + *(v27 - 1);
                v30 = v27 + 1;
                v27 += 12;
                --i;
                *(v27 - 13) = v29;
                *(v27 - 12) = a1a.y + *(v27 - 12);
            }
        }
    }
}

float sithPuppet_sub_4E4380(sithThing *thing)
{
    double v2; // st7
    int v3; // ecx
    double v5; // st6
    char missing_1; // c0
    double v8; // st5
    char missing_2; // c0
    sithSector *v10 = NULL; // eax
    sithAnimclass *v11 = NULL; // ebp
    sithPuppet *v12 = NULL; // eax
    double v14; // st6
    char missing_3; // c0
    int anim; // ecx
    sithActor *v17 = NULL; // eax
    sithPuppet *v18 = NULL; // edx
    sithAnimclassEntry *v19 = NULL; // edi
    int v20; // eax
    sithPuppet *v22 = NULL; // eax
    float v23; // [esp+10h] [ebp-10h]
    rdVector3 a1a; // [esp+14h] [ebp-Ch] BYREF
    float thinga; // [esp+24h] [ebp+4h]

    v23 = 0.5;
    if ( !thing->sector
      || thing->physicsParams.vel.x == 0.0 && thing->physicsParams.vel.y == 0.0 && thing->physicsParams.vel.z == 0.0 )
    {
        v2 = 0.0;
        thinga = 0.0;
        v3 = 0;
    }
    else
    {
        rdMatrix_TransformVector34Acc_0(&a1a, &thing->physicsParams.vel, &thing->lookOrientation);
        if ( thing->attach_flags || (thing->physicsParams.physflags & PHYSFLAGS_FLYING) != 0 || (thing->sector->flags & SITH_ANIM_WALK) != 0 )
        {
            v2 = a1a.y;
            v5 = a1a.y;
            if ( v5 < 0.0 )
                v5 = -v5;
            v8 = a1a.x;
            if ( v8 < 0.0 )
                v8 = -v8;
            if ( v5 <= v8 )
            {
                v3 = 0;
                thinga = a1a.x;
            }
            else
            {
                v3 = SITH_ANIM_STAND;
                thinga = a1a.y;
            }
        }
        else
        {
            v2 = a1a.y;
            thinga = thing->physicsParams.vel.z;
            v3 = SITH_ANIM_WALK;
        }
    }
    v10 = thing->sector;
    if ( v10 && (v10->flags & SITH_ANIM_WALK) != 0 )
    {
        v11 = thing->animclass;
        if ( v11 )
        {
            v12 = thing->puppet;
            if ( v12 )
            {
                if ( v12->field_4 != SITH_ANIM_STAND )
                {
                    v12->field_4 = SITH_ANIM_STAND;
                    v12->majorMode = v12->field_0 + 3;
                }
            }
        }
    }
    else
    {
        if ( thing->thingType == THINGTYPE_PLAYER )
            v23 = 1.0;
        v11 = thing->animclass;
        if ( v11 )
        {
            v22 = thing->puppet;
            if ( v22 )
            {
                if ( v22->field_4 )
                {
                    v22->field_4 = 0;
                    v22->majorMode = v22->field_0;
                }
            }
        }
        if ( thing->moveType == SITH_ANIM_STAND && thing->attach_flags && (thing->physicsParams.physflags & (PHYSFLAGS_200000|PHYSFLAGS_CROUCHING)) )
        {
            if ( v3 == SITH_ANIM_STAND && thinga < 0.0 )
                anim = SITH_ANIM_CROUCHBACK;
            else
                anim = SITH_ANIM_CROUCHFORWARD;
            goto LABEL_51;
        }
    }
    v14 = thinga;
    if ( v14 < 0.0 )
        v14 = -v14;
    if ( v14 <= 0.02 )
    {
        if ( thing->thingtype == SITH_ANIM_WALK && (v17 = thing->actor) != 0 )
        {
            thinga = 0.2;
            anim = (v17->flags & 8) != 0 ? SITH_ANIM_TURNLEFT : SITH_ANIM_STAND;
        }
        else
        {
            thinga = thing->physicsParams.angVel.y * 0.00019999999;
            if ( (((bShowInvisibleThings & 0xFF) + (thing->thingIdx & 0xFF)) & 3) != 0 )
                return thinga;
            if ( thinga >= -0.0099999998 )
            {
                anim = SITH_ANIM_TURNRIGHT;
                if ( thinga <= 0.0099999998 )
                    anim = SITH_ANIM_STAND;
            }
            else
            {
                anim = SITH_ANIM_TURNLEFT;
            }
        }
    }
    else if ( v3 )
    {
        if ( v3 == SITH_SF_NOGRAVITY )
        {
            if ( thinga >= 0.0 )
            {
                if ( thinga < (double)v23 )
                    anim = SITH_ANIM_WALK;
                else
                    anim = SITH_ANIM_RUN;
            }
            else
            {
                anim = SITH_ANIM_WALKBACK;
            }
        }
        else if ( thinga <= 0.0 )
        {
            if ( thinga <= -3.0 )
                anim = SITH_ANIM_FALL;
            else
                anim = SITH_ANIM_DROP;
        }
        else if ( v2 <= 0.02 )
        {
            anim = SITH_ANIM_RISING;
        }
        else
        {
            anim = SITH_ANIM_LEAP;
        }
    }
    else if ( thinga <= 0.0 )
    {
        anim = SITH_ANIM_STRAFELEFT;
    }
    else
    {
        anim = SITH_ANIM_STRAFERIGHT;
    }
LABEL_51:
    v18 = thing->puppet;
    v18->currentAnimation = anim;
    v19 = &v11->modes[v18->majorMode].keyframe[anim];
    if ( v19 != v18->playingAnim )
    {
        if ( anim == SITH_ANIM_FALL )
        {
            if ( (thing->thingflags & SITH_TF_DEAD) != 0 || (thing->actorParams.typeflags & THING_TYPEFLAGS_SCREAMING) != 0 )
                goto LABEL_60;
            sithSoundClass_ThingPlaySoundclass4(thing, SITH_SC_FALLING);
            v20 = thing->actorParams.typeflags | THING_TYPEFLAGS_SCREAMING;
        }
        else
        {
            if ( (thing->actorParams.typeflags & THING_TYPEFLAGS_SCREAMING) == 0 )
            {
LABEL_60:
                sithPuppet_sub_4E4A20(thing, v19);
                return thinga;
            }
            sithSoundClass_ThingPauseSoundclass(thing, SITH_SC_FALLING);
            v20 = thing->actorParams.typeflags & ~THING_TYPEFLAGS_SCREAMING;
        }
        thing->actorParams.typeflags = v20;
        goto LABEL_60;
    }
    return thinga;
}

void sithPuppet_sub_4E4A20(sithThing *thing, sithAnimclassEntry *animClass)
{
    rdPuppet *rdPup; // ecx
    sithPuppet *sithPup; // esi
    rdKeyframe **v4; // eax
    int v5; // eax
    int v6; // eax
    rdPuppet *v7; // ecx

    rdPup = thing->rdthing.puppet;
    if ( rdPup && thing->animclass )
    {
        sithPup = thing->puppet;
        v4 = &sithPup->playingAnim->keyframe;
        if ( !v4 || *v4 != animClass->keyframe )
        {
            sithPup->animStartedMs = sithTime_curMs;
            v5 = sithPup->currentTrack;
            if ( v5 >= 0 )
            {
                if ( rdPup->tracks[v5].keyframe )
                    rdPuppet_ResetTrack(rdPup, v5);
                sithPup = thing->puppet;
                sithPup->currentTrack = -1;
            }
            v6 = sithPup->otherTrack;
            if ( v6 >= 0 )
            {
                v7 = thing->rdthing.puppet;
                if ( v7->tracks[v6].keyframe )
                    rdPuppet_FadeOutTrack(v7, v6, 0.1);
                sithPup = thing->puppet;
                sithPup->otherTrack = -1;
            }
            if ( animClass->keyframe )
            {
                sithPup = thing->puppet;
                sithPup->otherTrack = sithPuppet_StartKey(
                                          thing->rdthing.puppet,
                                          animClass->keyframe,
                                          animClass->lowPri,
                                          animClass->highPri,
                                          animClass->flags,
                                          sithPuppet_DefaultCallback);
            }
        }
        sithPup->playingAnim = animClass;
    }
}

void sithPuppet_DefaultCallback(sithThing *thing, int track, uint32_t a3)
{
    unsigned int v3; // esi
    sithPuppet *sithPup; // eax
    int v5; // eax
    uint32_t soundToPlay_base; // edi
    sithThing *v8; // eax
    int v10; // eax
    sithThing *v11; // esi
    sithActor *v12; // eax

    v3 = 0;
    switch ( a3 )
    {
        case 0u:
            sithPup = thing->puppet;
            if ( sithPup )
            {
                if ( track == sithPup->currentTrack )
                    sithPup->currentTrack = -1;
            }
            return;
        case 1u:
        case 2u:
        case 8u:
        case 9u:
            if ( thing->rdthing.puppet->tracks[track].playSpeed < 0.5 )
                return;
            if ( (thing->thingflags & SITH_TF_DEAD) != 0 )
                return;
            if ( thing->thingType == THINGTYPE_CORPSE )
                return;
            v5 = thing->attach_flags;
            if ( !v5 || !thing->soundclass )
                return;
            soundToPlay_base = a3 - 1;
            if ( a3 - 1 > 1 )
                soundToPlay_base = a3 - 6;
            v8 = thing->attachedThing;
            if ( !(v5 & 2) )
            {
                v10 = v8->moveType;
                if ( (v10 & 0x1F0000) != 0 )
                {
                    if ( (v10 & 0x10000) != 0 )
                        goto LABEL_14;
                    if ( (v10 & 0x20000) != 0 )
                    {
                        sithSoundClass_ThingPlaySoundclass(thing, (soundToPlay_base + SITH_SC_LWALKWATER));
                        return;
                    }
                    if ( (v10 & 0x40000) != 0 )
                    {
                        sithSoundClass_ThingPlaySoundclass(thing, (soundToPlay_base + SITH_SC_LWALKPUDDLE));
                        return;
                    }
                    v3 = (~v10 & 0x80000 | 0x200000u) >> 19;
                }
            }
            else
            {
                if ( (v8->thingflags & SITH_TF_METAL) != 0 )
                {
LABEL_14:
                    sithSoundClass_ThingPlaySoundclass(thing, (soundToPlay_base + SITH_SC_LWALKMETAL));
                    return;
                }
                if ( (v8->thingflags & SITH_TF_EARTH) != 0 )
                {
                    sithSoundClass_ThingPlaySoundclass(thing, (soundToPlay_base + SITH_SC_LWALKEARTH));
                    return;
                }
            }
            sithSoundClass_ThingPlaySoundclass(thing, (soundToPlay_base + 4 * v3 + 6));
            return;
        case 3u:
            if ( thing->thingtype == THINGTYPE_ACTOR )
            {
                v12 = thing->actor;
                if ( v12 )
                    sithAI_FireWeapon(v12, 0.0, 0.0, 0.0, v12->field_264, v12->field_26C, v12->field_268);
            }
            return;
        case 4u:
            thing->jkFlags |= 2u;
            return;
        case 5u:
            thing->jkFlags &= ~2u;
            return;
        case 6u:
            if ( thing->rdthing.puppet->tracks[track].playSpeed >= 0.5 && thing->soundclass )
            {
                if ( (thing->physicsParams.physflags & PHYSFLAGS_MIDAIR) != 0 )
                    sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_LSWIMSURFACE);
                else
                    sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_LSWIMUNDER);
            }
            return;
        case 7u:
            if ( thing->rdthing.puppet->tracks[track].playSpeed >= 0.5 && thing->soundclass )
            {
                if ( (thing->physicsParams.physflags & PHYSFLAGS_MIDAIR) != 0 )
                    sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_TREADSURFACE);
                else
                    sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_TREADUNDER);
            }
            return;
        case 0xAu:
            if ( thing->rdthing.puppet->tracks[track].playSpeed >= 0.5 && thing->attach_flags )
                sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_CORPSEHIT);
            return;
        case 0xBu:
            v11 = thing;
            if ( thing->attach_flags )
            {
                sithActor_JumpWithVel(thing, 1.0);
                goto LABEL_50;
            }
            return;
        case 0xCu:
            v11 = thing;
            if ( thing->attach_flags )
            {
                sithActor_JumpWithVel(thing, 2.0);
LABEL_50:
                if ( v11->thingtype == THINGTYPE_ACTOR )
                    v11->actor->flags |= 1u;
            }
            return;
        case 0xDu:
            if ( thing->rdthing.puppet->tracks[track].playSpeed >= 0.5 && thing->soundclass )
            {
                if ( (thing->physicsParams.physflags & PHYSFLAGS_MIDAIR) != 0 )
                    sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_RSWIMSURFACE);
                else
                    sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_RSWIMUNDER);
            }
            return;
        case 0xEu:
            thing->jkFlags |= 0x40u;
            return;
        default:
            return;
    }
}

int sithPuppet_StopKey(rdPuppet *pupper, int track, float a3)
{
    if ( !pupper->tracks[track].keyframe )
        return 0;
    if ( a3 <= 0.0 )
        rdPuppet_ResetTrack(pupper, track);
    else
        rdPuppet_FadeOutTrack(pupper, track, a3);
    return 1;
}

void sithPuppet_SetArmedMode(sithThing *thing, int mode)
{
    sithPuppet *v2; // ecx

    if ( thing->animclass )
    {
        v2 = thing->puppet;
        v2->field_0 = mode;
        v2->majorMode = mode + 2 * v2->field_4 + v2->field_4;
    }
}
