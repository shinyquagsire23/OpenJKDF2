#include "sithPuppet.h"

#include "General/stdMath.h"
#include "General/stdHashtbl.h"
#include "Engine/sithAnimClass.h"
#include "Gameplay/sithTime.h"
#include "World/sithSector.h"
#include "World/jkPlayer.h"
#include "Engine/sithCollision.h"
#include "Gameplay/sithPlayerActions.h"
#include "Main/jkGame.h"
#include "Engine/rdPuppet.h"
#include "World/sithSoundClass.h"
#include "World/sithSurface.h"
#include "stdPlatform.h"
#include "AI/sithAI.h"
#include "jk.h"

#include <math.h>

static const char* sithPuppet_animNames[43+2] = {
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
    "drawsaber",

    // MOTS
    "charge",
    "buttpunch"
};

int sithPuppet_Startup()
{
    sithPuppet_pClassHashtable = stdHashtbl_New(64);
    sithPuppet_pKeyHashtable = stdHashtbl_New(256);

    if ( sithPuppet_pClassHashtable && sithPuppet_pKeyHashtable )
    {
        sithPuppet_pHashtblSubmodes = stdHashtbl_New(SITHPUPPET_NUMANIMS * 2);
        for (int i = 1; i < SITHPUPPET_NUMANIMS; i++)
        {
            stdHashtbl_Add(sithPuppet_pHashtblSubmodes, sithPuppet_animNames[i], (void *)(intptr_t)i);
        }
        return 1;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\Engine\\sithPuppet.c", 163, "Could not allocate memory of puppets.\n", 0, 0, 0, 0);
        return 0;
    }
}

void sithPuppet_Shutdown()
{
    if ( sithPuppet_pClassHashtable )
    {
        stdHashtbl_Free(sithPuppet_pClassHashtable);
        sithPuppet_pClassHashtable = 0;
    }
    if ( sithPuppet_pKeyHashtable )
    {
        stdHashtbl_Free(sithPuppet_pKeyHashtable);
        sithPuppet_pKeyHashtable = 0;
    }
    if ( sithPuppet_pHashtblSubmodes )
    {
        stdHashtbl_Free(sithPuppet_pHashtblSubmodes);
        sithPuppet_pHashtblSubmodes = 0;
    }
}

sithPuppet* sithPuppet_New(SithThing *pThing)
{
    sithPuppet *v1; // edi
    SithSector *sector; // eax
    sithPuppet *result; // eax

    v1 = (sithPuppet *)SITH_ALLOC(sizeof(sithPuppet));
    pThing->puppet = v1;
    if ( !v1 ) {
        pThing->pPuppetClass = 0;
        return NULL; // Added
    }
    _memset(v1, 0, sizeof(sithPuppet));
    sector = pThing->sector;
    if ( sector && (sector->flags & SITH_SECTOR_UNDERWATER) != 0 )
    {
        result = pThing->puppet;
        result->field_4 = 1;
        result->otherTrack = -1;
        result->field_18 = -1;
        result->currentTrack = -1;
    }
    else
    {
        result = pThing->puppet;
        result->field_4 = 0;
        result->otherTrack = -1;
        result->field_18 = -1;
        result->currentTrack = -1;
    }
    return result;
}

void sithPuppet_Free(SithThing *pThing)
{
    if ( pThing->puppet )
    {
        SITH_FREE(pThing->puppet);
        pThing->puppet = 0;
    }
}

void sithPuppet_SetMoveMode(SithThing *pThing, int newMode)
{
    sithPuppet *puppet; // eax

    if ( pThing->pPuppetClass )
    {
        puppet = pThing->puppet;
        if ( puppet )
        {
            if ( puppet->field_4 != newMode )
            {
                puppet->field_4 = newMode;
                puppet->majorMode = puppet->field_0 + 3 * newMode;
            }
        }
    }
}

// MOTS altered
int sithPuppet_PlayMode(SithThing *pThing, signed int submode, rdPuppetTrackCallback_t pfCallback)
{
    SithPuppetClass *v4; // ebx
    sithPuppet *v6; // edx
    SithPuppetClassSubmode *v7; // eax
    rdKeyframe *keyframe; // ebx
    int flags; // ebp
    int v10; // eax
    rdPuppet *v11; // ecx
    signed int result; // eax
    int highPri; // [esp+14h] [ebp+4h]
    int lowPri; // [esp+18h] [ebp+8h]

    v4 = pThing->pPuppetClass;
    if ( !v4 )
        return -1;
    if ( submode < 0 )
        return -1;
    if ( submode >= SITHPUPPET_NUMANIMS )
        return -1;
    v6 = pThing->puppet;

    v7 = &v4->modes[v6->majorMode].keyframe[submode];
    keyframe = v7->keyframe;
    if ( !v7->keyframe )
        return -1;
    flags = v7->flags;
    lowPri = v7->lowPri;
    highPri = v7->highPri;
    if ( submode != SITH_ANIM_FIDGET && submode != SITH_ANIM_FIDGET2 )
    {
        v6->animStartedMs = sithTime_g_msecGameTime;
        v10 = v6->currentTrack;
        if ( v10 >= 0 )
        {
            v11 = pThing->renderData.puppet;
            if ( v11->aTracks[v10].keyframe )
                rdPuppet_RemoveTrack(v11, v10);
            pThing->puppet->currentTrack = -1;
        }
    }
    
    result = sithPuppet_PlayKey(pThing->renderData.puppet, keyframe, lowPri, highPri, flags, pfCallback);
    if ( result < 0 )
        return -1;
    return result;
}

int sithPuppet_PlayKey(rdPuppet *pPuppet, rdKeyframe *pTrack, int lowPriority, int highPriority, int flags, rdPuppetTrackCallback_t pfCallback)
{
    int v6; // ecx
    int trackNum; // esi
    signed int result; // eax

    v6 = 1;
    if ( (flags & 8) != 0 )
    {
        trackNum = 0;
        while ( pPuppet->aTracks[trackNum].keyframe != pTrack )
        {
            ++trackNum;
            if ( trackNum >= 4 )
                goto LABEL_8;
        }
        rdPuppet_ResetTrack(pPuppet, trackNum);
        v6 = 0;
    }
    else
    {
        trackNum = flags;
    }

LABEL_8:
    if ( v6 )
    {
        trackNum = rdPuppet_AddTrack(pPuppet, pTrack, lowPriority, highPriority);
        if ( trackNum < 0 )
            return -1;
    }
    if ( pfCallback )
        rdPuppet_SetCallback(pPuppet, trackNum, pfCallback);
    else
        rdPuppet_SetCallback(pPuppet, trackNum, sithPuppet_DefaultCallback);
    if ( (flags & 2) != 0 )
    {
        rdPuppet_SetStatus(pPuppet, trackNum, 0x20);
    }
    else if ( (flags & 0x20) != 0 )
    {
        rdPuppet_SetStatus(pPuppet, trackNum, 0x80);
    }
    else if ( (flags & 4) != 0 )
    {
        rdPuppet_SetStatus(pPuppet, trackNum, 0x40);
    }
    if ( (flags & 1) != 0 )
        rdPuppet_SetTrackSpeed(pPuppet, trackNum, 0.0);
    if ( (flags & 0x10) != 0 )
        rdPuppet_PlayTrack(pPuppet, trackNum);
    else
        rdPuppet_FadeInTrack(pPuppet, trackNum, 0.1);
    result = trackNum;
    pPuppet->aTracks[trackNum].field_130 = ((playerThingIdx + 1) << 16) | (uint16_t)(trackNum + 1);
    return result;
}

void sithPuppet_ResetTrack(SithThing *pThing)
{
    unsigned int trackNum; // esi
    sithPuppet *v2; // eax

    for ( trackNum = 0; trackNum < 4; ++trackNum )
        rdPuppet_RemoveTrack(pThing->renderData.puppet, trackNum);
    v2 = pThing->puppet;
    v2->playingAnim = NULL;
    v2->otherTrack = -1;
    v2->field_18 = -1;
    v2->currentTrack = -1;

}

// MOTS altered?
void sithPuppet_UpdatePuppet(SithThing *pThing, flex_t secDeltaTime)
{
    flex_d_t v3; // st7
    sithPuppet *v4; // eax
    SithPuppetClassSubmode *v5; // ecx
    int v6; // ecx
    flex_d_t v8; // st7
    char v9; // c0
    sithPuppet *v10; // eax
    flex_d_t v11; // st7
    SithPuppetClass *v12; // edx
    SithPuppetClassSubmode *v13; // eax
    int v14; // eax
    SithPuppetClass *v17; // edx
    SithPuppetClassSubmode *v18; // eax
    int v19; // eax
    rdMatrix34 *v20; // eax
    rdMatrix34 *v23; // ecx
    flex_t *v27; // eax
    int i; // edx
    flex_t v31; // [esp+0h] [ebp-18h]
    rdVector3 a1a; // [esp+Ch] [ebp-Ch] BYREF
    flex_t thinga; // [esp+1Ch] [ebp+4h]
    flex_t a2a; // [esp+20h] [ebp+8h]

    if ( pThing->pPuppetClass && pThing->puppet && pThing->renderData.puppet && (g_debugmodeFlags & DEBUGFLAG_NO_PUPPETS) == 0 )
    {
        if ( pThing->moveType == SITH_MT_PHYSICS )
        {
            v3 = sithPuppet_UpdateThingMove(pThing);
            v4 = pThing->puppet;
            v5 = v4->playingAnim;
            if ( v5 )
            {
                if ( (v5->flags & 1) != 0 )
                {
                    v6 = v4->otherTrack;
                    if ( v6 >= 0 )
                    {
                        thinga = v3 * secDeltaTime;
                        v8 = thinga;
                        if ( v8 < 0.0 )
                            v8 = -v8;
                        v31 = v8 * 280.0;
                        rdPuppet_AdvanceTrack(pThing->renderData.puppet, v6, v31);
                    }
                }
            }
            sithPuppet_PlayFidgetMode(pThing);
        }
        if ( rdPuppet_UpdateTracks(pThing->renderData.puppet, secDeltaTime) && pThing->moveType == SITH_MT_PATH )
        {
            rdVector_Zero3(&pThing->orient.scale);
            pThing->renderData.field_18 = 0;
            rdPuppet_BuildJointMatrices(&pThing->renderData, &pThing->orient);
            v20 = pThing->renderData.paJointMatrices;
            pThing->renderData.field_18 = 1;
            rdVector_Add3(&a1a, &pThing->trackParams.curOrient.scale, &v20->scale);
            rdVector_Sub3Acc(&a1a, &pThing->position);
            if (!rdVector_IsZero3(&a1a))
            {
                a2a = rdVector_Normalize3Acc(&a1a);
                sithCollision_MoveThing(pThing, &a1a, a2a, 0);
            }
            v23 = pThing->renderData.paJointMatrices;
            rdVector_Sub3(&a1a, &pThing->position, &v23->scale);
            for ( i = pThing->renderData.model3->numHNodes; i != 0; i--)
            {
                rdVector_Add3Acc(&v23->scale, &a1a);
                v23++;
            }
        }
    }
}

flex_t sithPuppet_UpdateThingMove(SithThing *pThing)
{
    flex_d_t v2; // st7
    int v3; // ecx
    flex_d_t v5; // st6
    char missing_1; // c0
    flex_d_t v8; // st5
    char missing_2; // c0
    SithSector *v10 = NULL; // eax
    SithPuppetClass *v11 = NULL; // ebp
    sithPuppet *v12 = NULL; // eax
    flex_d_t v14; // st6
    char missing_3; // c0
    int anim; // ecx
    sithPuppet *v18 = NULL; // edx
    SithPuppetClassSubmode *v19 = NULL; // edi
    int v20; // eax
    flex_t v23; // [esp+10h] [ebp-10h]
    rdVector3 a1a; // [esp+14h] [ebp-Ch] BYREF
    flex_t thinga; // [esp+24h] [ebp+4h]

    v23 = 0.5;
    if ( !pThing->sector
      || rdVector_IsZero3(&pThing->physicsParams.vel) )
    {
        v2 = 0.0;
        thinga = 0.0;
        v3 = 0;
    }
    else
    {
        rdMatrix_TransformVectorOrtho34(&a1a, &pThing->physicsParams.vel, &pThing->orient);
        if ( pThing->attach_flags || (pThing->physicsParams.flags & SITH_PF_FLY) != 0 || (pThing->sector->flags & SITH_ANIM_WALK) != 0 )
        {
            v2 = a1a.y;
            v5 = stdMath_Fabs(a1a.y);
            v8 = stdMath_Fabs(a1a.x);

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
            thinga = pThing->physicsParams.vel.z;
            v3 = SITH_ANIM_WALK;
        }
    }

    // MOTS also routes actors with the SITH_AF_ELECTRICWHIP typeflag through the submerged
    // animation set (majorMode = field_0 + 3) even when not underwater. Without this, such MOTS
    // actors play the wrong animation set. Gated on MoTS so JK behavior is unchanged.
    if ( (pThing->sector && (pThing->sector->flags & SITH_SECTOR_UNDERWATER) != 0)
      || (Main_bMotsCompat && (pThing->actorParams.flags & SITH_AF_ELECTRICWHIP) != 0) )
    {
        v11 = pThing->pPuppetClass;
        if ( v11 )
        {
            v12 = pThing->puppet;
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
        if ( pThing->type == SITH_THING_PLAYER )
            v23 = 1.0;
        v11 = pThing->pPuppetClass;
        if ( v11 )
        {
            if ( pThing->puppet )
            {
                if ( pThing->puppet->field_4 )
                {
                    pThing->puppet->field_4 = 0;
                    pThing->puppet->majorMode = pThing->puppet->field_0;
                }
            }
        }
        if ( pThing->moveType == SITH_MT_PHYSICS && pThing->attach_flags && (pThing->physicsParams.flags & (SITH_PF_200000|SITH_PF_CROUCHING)) )
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
        if ( pThing->controlType == SITH_CT_AI && pThing->actor )
        {
            thinga = 0.2;
            anim = (pThing->actor->flags & SITHAI_MODE_TURNING) != 0 ? SITH_ANIM_TURNLEFT : SITH_ANIM_STAND;
        }
        else
        {
            thinga = pThing->physicsParams.angularVelocity.y * 0.0002;
            if ( (((jkPlayer_currentTickIdx & 0xFF) + (pThing->idx & 0xFF)) & 3) != 0 )
                return thinga;
            if ( thinga >= -0.01 )
            {
                anim = SITH_ANIM_TURNRIGHT;
                if ( thinga <= 0.01 )
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
        if ( v3 == SITH_SECTOR_NOGRAVITY )
        {
            if ( thinga >= 0.0 )
            {
                if ( thinga < (flex_d_t)v23 )
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
    v18 = pThing->puppet;
    v18->currentAnimation = anim;

    v19 = &v11->modes[v18->majorMode].keyframe[anim];
    if ( v19 != v18->playingAnim )
    {
        if ( anim == SITH_ANIM_FALL )
        {
            if ( (pThing->flags & SITH_TF_DEAD) != 0 || (pThing->actorParams.flags & SITH_AF_SCREAMING) != 0 )
                goto LABEL_60;
            sithSoundClass_PlayModeFirst(pThing, SITH_SC_FALLING);
            v20 = pThing->actorParams.flags | SITH_AF_SCREAMING;
        }
        else
        {
            if ( (pThing->actorParams.flags & SITH_AF_SCREAMING) == 0 )
            {
LABEL_60:
                sithPuppet_sub_4E4A20(pThing, v19);
                return thinga;
            }
            sithSoundClass_StopMode(pThing, SITH_SC_FALLING);
            v20 = pThing->actorParams.flags & ~SITH_AF_SCREAMING;
        }
        pThing->actorParams.flags = v20;
        goto LABEL_60;
    }
    return thinga;
}

void sithPuppet_sub_4E4A20(SithThing *thing, SithPuppetClassSubmode *animClass)
{
    rdPuppet *rdPup; // ecx
    sithPuppet *sithPup; // esi
    rdKeyframe **v4; // eax
    int v5; // eax
    int v6; // eax
    rdPuppet *v7; // ecx

    rdPup = thing->renderData.puppet;
    if ( rdPup && thing->pPuppetClass )
    {
        sithPup = thing->puppet;
        v4 = &sithPup->playingAnim->keyframe;
        if ( !v4 || *v4 != animClass->keyframe )
        {
            sithPup->animStartedMs = sithTime_g_msecGameTime;
            v5 = sithPup->currentTrack;
            if ( v5 >= 0 )
            {
                if ( rdPup->aTracks[v5].keyframe )
                    rdPuppet_RemoveTrack(rdPup, v5);
                sithPup = thing->puppet;
                sithPup->currentTrack = -1;
            }
            v6 = sithPup->otherTrack;
            if ( v6 >= 0 )
            {
                v7 = thing->renderData.puppet;
                if ( v7->aTracks[v6].keyframe )
                    rdPuppet_FadeOutTrack(v7, v6, 0.1);
                sithPup = thing->puppet;
                sithPup->otherTrack = -1;
            }
            if ( animClass->keyframe )
            {
                sithPup = thing->puppet;
                sithPup->otherTrack = sithPuppet_PlayKey(
                                          thing->renderData.puppet,
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

// MOTS altered
void sithPuppet_DefaultCallback(SithThing *pThing, int32_t track, uint32_t markerType)
{
    unsigned int v3; // esi
    sithPuppet *sithPup; // eax
    uint32_t soundToPlay_base; // edi
    SithThing *v8; // eax
    int v10; // eax
    SithThing *v11; // esi
    SithAIControlBlock *v12; // eax

    v3 = 0;
    switch ( markerType )
    {
        case 0u:
            sithPup = pThing->puppet;
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
            if ( pThing->renderData.puppet->aTracks[track].playSpeed < 0.5 )
                return;
            if ( (pThing->flags & SITH_TF_DEAD) != 0 )
                return;
            if ( pThing->type == SITH_THING_CORPSE )
                return;

            if ( !pThing->attach_flags || !pThing->pSoundClass )
                return;
            soundToPlay_base = markerType - 1;
            if ( markerType - 1 > 1 )
                soundToPlay_base = markerType - 6;
            if ( !(pThing->attach_flags & SITH_ATTACH_THINGFACE) )
            {
                v10 = pThing->attachedSurface->flags;
                if ( (v10 & (SITH_SURFACE_VERYDEEPWATER|SITH_SURFACE_EARTH|SITH_SURFACE_PUDDLE|SITH_SURFACE_WATER|SITH_SURFACE_METAL)) != 0 )
                {
                    if ( (v10 & SITH_SURFACE_METAL) != 0 )
                        goto LABEL_14;
                    if ( (v10 & SITH_SURFACE_WATER) != 0 )
                    {
                        sithSoundClass_PlayModeRandom(pThing, (soundToPlay_base + SITH_SC_LWALKWATER));
                        return;
                    }
                    if ( (v10 & SITH_SURFACE_PUDDLE) != 0 )
                    {
                        sithSoundClass_PlayModeRandom(pThing, (soundToPlay_base + SITH_SC_LWALKPUDDLE));
                        return;
                    }
                    v3 = (~v10 & SITH_SURFACE_EARTH | (unsigned int)SITH_SURFACE_200000) >> 19;
                }
            }
            else
            {
                if ( (pThing->attachedThing->flags & SITH_TF_METAL) != 0 )
                {
LABEL_14:
                    sithSoundClass_PlayModeRandom(pThing, (soundToPlay_base + SITH_SC_LWALKMETAL));
                    return;
                }
                if ( (pThing->attachedThing->flags & SITH_TF_EARTH) != 0 )
                {
                    sithSoundClass_PlayModeRandom(pThing, (soundToPlay_base + SITH_SC_LWALKEARTH));
                    return;
                }
            }
            sithSoundClass_PlayModeRandom(pThing, (soundToPlay_base + 4 * v3 + 6));
            return;
        case 3u:
            if ( pThing->controlType == SITH_CT_AI )
            {
                v12 = pThing->actor;
                if ( v12 )
                    sithAI_FireWeapon(v12, 0.0, 0.0, 0.0, v12->field_264, v12->field_26C, v12->field_268);
            }
            return;
        case 4u:
            pThing->jkFlags |= JKFLAG_SABERDAMAGE;
            return;
        case 5u:
            pThing->jkFlags &= ~JKFLAG_SABERDAMAGE;
            return;
        case 6u:
            if ( pThing->renderData.puppet->aTracks[track].playSpeed >= 0.5 && pThing->pSoundClass )
            {
                if ( (pThing->physicsParams.flags & SITH_PF_ONWATERSURFACE) != 0 )
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_LSWIMSURFACE);
                else
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_LSWIMUNDER);
            }
            return;
        case 7u:
            if ( pThing->renderData.puppet->aTracks[track].playSpeed >= 0.5 && pThing->pSoundClass )
            {
                if ( (pThing->physicsParams.flags & SITH_PF_ONWATERSURFACE) != 0 )
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_TREADSURFACE);
                else
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_TREADUNDER);
            }
            return;
        case 0xAu:
            if ( pThing->renderData.puppet->aTracks[track].playSpeed >= 0.5 && pThing->attach_flags )
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_CORPSEHIT);
            return;
        case 0xBu:
            v11 = pThing;
            if ( pThing->attach_flags )
            {
                sithPlayerActions_JumpWithVel(pThing, 1.0);
                goto LABEL_50;
            }
            return;
        case 0xCu:
            v11 = pThing;
            if ( pThing->attach_flags )
            {
                sithPlayerActions_JumpWithVel(pThing, 2.0);
LABEL_50:
                if ( v11->controlType == SITH_CT_AI )
                    v11->actor->flags |= 1u;
            }
            return;
        case 0xDu:
            if ( pThing->renderData.puppet->aTracks[track].playSpeed >= 0.5 && pThing->pSoundClass )
            {
                if ( (pThing->physicsParams.flags & SITH_PF_ONWATERSURFACE) != 0 )
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_RSWIMSURFACE);
                else
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_RSWIMUNDER);
            }
            return;
        case 0xEu:
            pThing->jkFlags |= JKFLAG_40;
            return;

        // MoTS added
        case 0xF:
            if (!Main_bMotsCompat) return;

            if ((pThing->controlType == SITH_CT_AI) && (v12 = pThing->actor, v12 != (SithAIControlBlock *)0x0)) {
                sithAI_Leap(v12,0.0,0.0,0.0,v12->field_26C,v12->field_264,v12->field_268);
                return;
            }
            return;
        case 0x10:
            if (!Main_bMotsCompat) return;

            if ((pThing->controlType == SITH_CT_AI) && (v12 = pThing->actor, v12 != (SithAIControlBlock *)0x0)) {
                sithAI_Charge(v12,0.0,0.0,0.0,v12->field_26C,v12->field_264,v12->field_268);
            }
            return;
        default:
            return;
    }
}

int sithPuppet_StopKey(rdPuppet *pPuppet, int track, flex_t fadeTime)
{
    if ( !pPuppet->aTracks[track].keyframe )
        return 0;
    if ( fadeTime <= 0.0 )
        rdPuppet_RemoveTrack(pPuppet, track);
    else
        rdPuppet_FadeOutTrack(pPuppet, track, fadeTime);
    return 1;
}

void sithPuppet_SetArmedMode(SithThing *pThing, int newMode)
{
    sithPuppet *v2; // ecx

    if ( pThing->pPuppetClass )
    {
        v2 = pThing->puppet;
        v2->field_0 = newMode;
        v2->majorMode = newMode + 2 * v2->field_4 + v2->field_4;
    }
}

void sithPuppet_PlayFidgetMode(SithThing *pThing)
{
    sithPuppet *puppet; // eax
    flex_d_t v2; // st7
    SithPuppetClass *v3; // edx
    SithPuppetClassSubmode *v4; // eax
    int v5; // eax
    sithPuppet *v6; // esi
    unsigned int v7; // edx
    SithPuppetClass *v8; // edx
    SithPuppetClassSubmode *v9; // eax
    int v10; // eax

    puppet = pThing->puppet;
    if ( puppet->currentTrack < 0 && puppet->currentAnimation == 1 && (flex_d_t)(unsigned int)puppet->animStartedMs - -30000.0 < (flex_d_t)sithTime_g_msecGameTime )
    {
        v2 = _frand();
        if ( v2 >= 0.3 )
        {
            if ( v2 < 0.6 )
            {
                v8 = pThing->pPuppetClass;
                if ( !v8
                  || (v9 = &v8->modes[pThing->puppet->majorMode].keyframe[SITH_ANIM_FIDGET2], !v9->keyframe)
                  || (v10 = sithPuppet_PlayKey(
                                pThing->renderData.puppet,
                                v9->keyframe,
                                v9->lowPri,
                                v9->highPri,
                                v8->modes[pThing->puppet->majorMode].keyframe[SITH_ANIM_FIDGET2].flags,
                                0),
                      v10 < 0) )
                {
                    v10 = -1;
                }
                pThing->puppet->currentTrack = v10;
            }
        }
        else
        {
            v3 = pThing->pPuppetClass;
            if ( !v3
              || (v4 = &v3->modes[pThing->puppet->majorMode].keyframe[SITH_ANIM_FIDGET], !v4->keyframe)
              || (v5 = sithPuppet_PlayKey(
                           pThing->renderData.puppet,
                           v4->keyframe,
                           v4->lowPri,
                           v4->highPri,
                           v3->modes[pThing->puppet->majorMode].keyframe[SITH_ANIM_FIDGET].flags,
                           0),
                  v5 < 0) )
            {
                v5 = -1;
            }
            v6 = pThing->puppet;
            v7 = sithTime_g_msecGameTime;
            v6->currentTrack = v5;
            v6->animStartedMs = v7;
        }
    }
}

void sithPuppet_resetidk(SithThing *pThing)
{
    sithPuppet *puppet; // eax
    int v2; // eax
    rdPuppet *v3; // ecx

    puppet = pThing->puppet;
    puppet->animStartedMs = sithTime_g_msecGameTime;
    v2 = puppet->currentTrack;
    if ( v2 >= 0 )
    {
        v3 = pThing->renderData.puppet;
        if ( v3->aTracks[v2].keyframe )
            rdPuppet_RemoveTrack(v3, v2);
        pThing->puppet->currentTrack = -1;
    }
}

void sithPuppet_advanceidk(SithThing *pThing, flex_t a2)
{
    flex_d_t v3; // st7
    sithPuppet *puppet; // eax
    SithPuppetClassSubmode *v5; // ecx
    int v6; // ecx
    flex_d_t v8; // st7
    flex_t a3; // [esp+0h] [ebp-8h]
    flex_t thinga; // [esp+Ch] [ebp+4h]

    v3 = sithPuppet_UpdateThingMove(pThing);
    puppet = pThing->puppet;
    v5 = puppet->playingAnim;
    if ( v5 )
    {
        if ( (v5->flags & 1) != 0 )
        {
            v6 = puppet->otherTrack;
            if ( v6 >= 0 )
            {
                thinga = v3 * a2;
                v8 = thinga;
                if ( v8 < 0.0 )
                    v8 = -v8;
                a3 = v8 * 280.0;
                rdPuppet_AdvanceTrack(pThing->renderData.puppet, v6, a3);
            }
        }
    }
}