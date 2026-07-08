#include "sithThing.h"

#include "General/stdHashtbl.h"
#include "General/util.h"
#include "General/stdString.h"
#include "World/jkPlayer.h"
#include "World/sithWorld.h"
#include "Gameplay/sithPlayerActions.h"
#include "World/sithWeapon.h"
#include "World/sithExplosion.h"
#include "World/sithItem.h"
#include "Gameplay/sithPlayer.h"
#include "World/sithSector.h"
#include "World/sithTrackThing.h"
#include "World/sithExplosion.h"
#include "Engine/sithCollision.h"
#include "World/sithActor.h"
#include "World/sithSurface.h"
#include "Devices/sithSoundMixer.h"
#include "Dss/sithMulti.h"
#include "Engine/sithPuppet.h"
#include "World/sithTemplate.h"
#include "Engine/sithParticle.h"
#include "World/sithSoundClass.h"
#include "Engine/sithAnimClass.h"
#include "World/sithModel.h"
#include "World/sithSprite.h"
#include "Main/sithMain.h"
#include "Engine/sithCamera.h"
#include "Engine/sithPhysics.h"
#include "Main/jkGame.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "AI/sithAIAwareness.h"
#include "Cog/sithCog.h"
#include "Dss/sithDSSThing.h"
#include "stdPlatform.h"
#include "Dss/sithDSS.h"
#include "General/stdMath.h"
#include "jk.h"

#define NUM_THING_PARAMS (74) // JK is 72
#define NUM_THING_TYPES (13)

// QOL experiment: factor the local player's collision sphere is shrunk to while moving
// horizontally in the air, so its top corner clears tight gap/overhang lips instead of being
// shoved backward. 1.0 = vanilla (disabled); lower = squeezes through tighter openings.
#define SITHTHING_SQUEEZE_RADIUS_FACTOR (0.7)

int sithThing_bInitted;
int sithThing_bInitted2 = 1;

const char* sithThing_aTypes[NUM_THING_TYPES] = {
    "free",
    "camera",
    "actor",
    "weapon",
    "debris",
    "item",
    "explosion",
    "cog",
    "ghost",
    "corpse",
    "player",
    "particle",
    "--invalid--"
};

const char* sithThing_aParams[NUM_THING_PARAMS] = {
    "type",
    "collide",
#ifdef JKM_PARAMS
    "treesize", // MOTS added
#endif
    "move",
    "size",
    "flags",
    "timer",
    "light",
    "attach",
    "pSoundClass",
    "model3d",
    "sprite",
    "surfdrag",
    "airdrag",
    "staticdrag",
    "mass",
    "height",
    "flags",
    "maxrotvel",
    "maxvel",
    "vel",
    "angvel",
    "flags",
    "health",
    "maxthrust",
    "maxrotthrust",
    "jumpspeed",
    "weapon",
    "weapon2",
    "damage",
    "mindamage",
    "damageclass",
    "explode",
    "frame",
    "numframes",
    "puppet",
    "blasttime",
    "force",
    "maxlight",
    "range",
    "flashrgb",
    "aiclass",
    "cog",
    "secRespawnInterval",
#ifdef JKM_PARAMS
    "respawnfactor", // MOTS added
#endif
    "material",
    "rate",
    "count",
    "elementsize",
    "particle",
    "maxhealth",
    "movesize",
    "orientspeed",
    "buoyancy",
    "eyeoffset",
    "minheadpitch",
    "maxheadpitch",
    "fireoffset",
    "lightoffset",
    "lightintensity",
    "points",
    "debris",
    "creatething",
    "trailthing",
    "trailcylradius",
    "trailrandangle",
    "minsize",
    "pitchrange",
    "yawrange",
    "error",
    "fov",
    "chance",
    "orient",
    "fleshhit",
};

int sithThing_Startup()
{
    int v1; // edi
    const char **v2; // esi

    if ( !sithThing_bInitted )
    {
        sithThing_pParseHashtbl = stdHashtbl_New((NUM_THING_PARAMS+1) * 2);
        if ( sithThing_pParseHashtbl )
        {
            v1 = 1;
            v2 = (const char **)sithThing_aParams;
            while ( 1 )
            {
                stdHashtbl_Add(sithThing_pParseHashtbl, *v2++, (void *)(intptr_t)v1++);
                if ( (intptr_t)v2 >= (intptr_t)&sithThing_aParams[NUM_THING_PARAMS] )
                    break;
            }
            sithThing_bInitted2 = 1;
            sithThing_bInitted = 1;
        }
    }
    return 1;
}

int sithThing_Shutdown()
{
    if ( !sithThing_bInitted )
        return 0;
    stdHashtbl_Free(sithThing_pParseHashtbl);
    sithThing_bInitted = 0;
    return 1;
}

void sithThing_RegisterUnknownFunc(sithThing_handler_t handler)
{
    if ( handler )
        sithThing_pfUnknownFunc = handler;
}

// MOTS altered?
void sithThing_Update(flex_t deltaSeconds, int deltaMs)
{
    SithThing* pThingIter; // esi

    if ( sithWorld_g_pCurrentWorld->numThings < 0 )
        return;

    for (int32_t i = 0; i < sithWorld_g_pCurrentWorld->numThings+1; i++)
    {
        pThingIter = &sithWorld_g_pCurrentWorld->aThings[i];
        if (!pThingIter->type)
            continue;
#ifdef TARGET_RETRO_HOMEBREW
        // Added: the current camera's focus must always tick at full rate. In-engine
        // cutscene rigs (boss-intro fly-bys: PlayKey/RotatePivot on an invisible
        // camera thing) never render, so the rendered-recently gates below would
        // throttle their animation to the 1/64 offscreen rate and freeze the shot.
        int bIsCameraFocus = sithCamera_g_pCurCamera
            && (sithCamera_g_pCurCamera->pPrimaryFocusThing == pThingIter
             || sithCamera_g_pCurCamera->pSecondaryFocusThing == pThingIter);
        int bCanUpdateOffscreen = bIsCameraFocus ||
            (((uint8_t)jkPlayer_currentTickIdx + (pThingIter->idx & 0xFF)) & 0x3F) == 0;
        int bActorCanUpdateEveryOther = pThingIter->type == SITH_THING_ACTOR && (((uint8_t)jkPlayer_currentTickIdx + (pThingIter->idx & 0xFF)) & 1) == 0;
        int bActorCanUpdateNow = pThingIter->type == SITH_THING_ACTOR && pThingIter->transformedPos.y < 0.5;
        int bCanAlwaysUpdatePhysics = pThingIter->type == SITH_THING_PLAYER || pThingIter->type == SITH_THING_PARTICLE || pThingIter->type == SITH_THING_WEAPON || pThingIter->type == SITH_THING_DEBRIS || pThingIter->type == SITH_THING_COG;
#endif

        if (!(pThingIter->flags & SITH_TF_DESTROYED))
        {

            if ( pThingIter->msecLifeLeft )
            {
                if ( pThingIter->msecLifeLeft > deltaMs )
                {
                    pThingIter->msecLifeLeft -= deltaMs;
                }
                else
                {
                    sithThing_DestroyDyingThing(pThingIter);
                }
            }

            if ( (pThingIter->flags & SITH_TF_DISABLED) != 0 )
                continue;

            if ( (pThingIter->flags & (SITH_TF_TIMERSET|SITH_TF_PULSESET)) != 0 )
                sithCog_UpdateThingTimer(pThingIter);

            switch ( pThingIter->controlType )
            {
                case SITH_CT_AI:
                    // CPU optimization testing
                    // TODO: Check if a thing has been given a target by a COG and allow it to move, eg easter egg lady in Baron's Hed
#ifdef TARGET_RETRO_HOMEBREW
                    if (pThingIter->type == SITH_THING_PLAYER || pThingIter->renderFrame >= jkPlayer_currentTickIdx-3 || bCanUpdateOffscreen)
#endif
                    sithAI_Tick(pThingIter, deltaSeconds);
                    break;
                case SITH_CT_EXPLOSION:
                    sithExplosion_Update(pThingIter);
                    break;
                case SITH_CT_PARTICLE:
                    sithParticle_Update(pThingIter, deltaSeconds);
                    break;
            }

            switch ( pThingIter->type )
            {
                case SITH_THING_PLAYER:
                    sithPlayer_Update(pThingIter->actorParams.pPlayer, deltaSeconds);
                case SITH_THING_ACTOR:
                    sithActor_Update(pThingIter, deltaMs);
                    break;
                case SITH_THING_WEAPON:
                    sithWeapon_Update(pThingIter, deltaSeconds);
                    break;
            }
            if ( sithThing_pfUnknownFunc && pThingIter->jkFlags )
                sithThing_pfUnknownFunc(pThingIter);
            if ( pThingIter->moveType == SITH_MT_PHYSICS )
            {
                // CPU optimization testing
#ifdef TARGET_RETRO_HOMEBREW
                if (bCanAlwaysUpdatePhysics || pThingIter->renderFrame >= jkPlayer_currentTickIdx-3 || bCanUpdateOffscreen)
#endif
                sithPhysics_UpdateThing(pThingIter, deltaSeconds);
            }
            else if ( pThingIter->moveType == SITH_MT_PATH )
            {
                sithTrackThing_Tick(pThingIter, deltaSeconds);
            }

            // CPU optimization testing
#ifdef TARGET_RETRO_HOMEBREW
            if (bCanAlwaysUpdatePhysics || pThingIter->renderFrame >= jkPlayer_currentTickIdx-3 || bCanUpdateOffscreen)
#endif
            sithThing_UpdateMove(pThingIter, deltaSeconds);

            // CPU optimization testing
#ifdef TARGET_RETRO_HOMEBREW
            if ((pThingIter->type == SITH_THING_PLAYER) || bActorCanUpdateNow || bActorCanUpdateEveryOther || (pThingIter->type != SITH_THING_ACTOR && pThingIter->renderFrame >= jkPlayer_currentTickIdx-3) || bCanUpdateOffscreen)
            sithPuppet_UpdatePuppet(pThingIter, bActorCanUpdateEveryOther ? deltaSeconds * 2 : deltaSeconds);
#else
            sithPuppet_UpdatePuppet(pThingIter, deltaSeconds);
#endif
            continue;
        }

        sithThing_RemoveThing(pThingIter); // Was inlined
    }
}

void sithThing_UpdateMove(SithThing *pThing, flex_t deltaSecs)
{
    int32_t v2; // ebp
    SithSurface *v5; // eax
    rdVector3 v8; // [esp+Ch] [ebp-18h] BYREF
    rdVector3 v1; // [esp+18h] [ebp-Ch] BYREF
    flex_t arg4a; // [esp+2Ch] [ebp+8h]

    v2 = 0;
    if ((pThing->attach_flags & SITH_ATTACH_NOMOVE))
        return;

    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        rdVector_Copy3(&pThing->field_268, &pThing->physicsParams.deltaVelocity);
    }
    else
    {
        v2 = 4;
        rdVector_Zero3(&pThing->field_268);
    }

    if (pThing->attach_flags && pThing->attach_flags & SITH_ATTACH_SURFACE)
    {
        v5 = pThing->attachedSurface;
        if ( (v5->flags & SITH_SURFACE_SCROLLING) != 0 )
        {
            sithSurface_DetachThing(v5, &v8);
            rdVector_ScaleAdd3Acc(&pThing->field_268, &v8, deltaSecs);
        }
    }
    
    if (rdVector_IsZero3(&pThing->field_268))
    {
        if ( pThing->moveType == SITH_MT_PHYSICS && (pThing->attach_flags & (SITH_ATTACH_THINGFACE|SITH_ATTACH_THING)) != 0 && pThing->attachedThing->moveType == SITH_MT_PATH )
            sithPhysics_FindFloor(pThing, 0);
    }
    else
    {
        arg4a = rdVector_Normalize3(&v1, &pThing->field_268);
#ifdef QOL_IMPROVEMENTS
        // QOL experiment: shrink the local player's collision radius for this horizontal
        // ground sweep so the sphere's top corner clears tight gap/overhang lips (vanilla shoves
        // the player back). FindFloor inside UpdateThingCollision re-grounds. SP + local player
        // only so MP stays bit-identical.
        flex_t qolSavedMoveSize = pThing->moveSize;
        int qolSqueeze = jkPlayer_bLedgeSqueeze
                      && !sithNet_isMulti
                      && pThing == sithPlayer_g_pLocalPlayerThing
                      && !pThing->attach_flags
                      && stdMath_Fabs(v1.z) < 1.0;
        if (qolSqueeze)
            pThing->moveSize *= SITHTHING_SQUEEZE_RADIUS_FACTOR;
#endif
        pThing->waggle = sithCollision_MoveThing(pThing, &v1, arg4a, v2);
#ifdef QOL_IMPROVEMENTS
        if (qolSqueeze)
            pThing->moveSize = qolSavedMoveSize;
#endif
    }
}

void sithThing_DestroyDyingThing(SithThing* pThing)
{
    switch ( pThing->type )
    {
        case SITH_THING_ACTOR:
            sithActor_DestroyActor(pThing);
            break;
        case SITH_THING_WEAPON:
            sithWeapon_DestroyWeapon(pThing);
            break;
        case SITH_THING_ITEM:
            sithItem_DestroyItem(pThing);
            break;
        case SITH_THING_CORPSE:
            sithActor_DestroyCorpse(pThing);
            break;
        case SITH_THING_PLAYER:
            return;
        case SITH_THING_PARTICLE:
            sithParticle_DestroyParticle(pThing);
            break;
        default:
            pThing->flags |= SITH_TF_DESTROYED;
            if (pThing->flags & SITH_TF_CAPTURED && !(pThing->flags & SITH_TF_INVULN))
                sithCog_ThingSendMessage(pThing, 0, SITH_MESSAGE_REMOVED);
            break;
    }
}

SithThing* sithThing_GetThingParent(SithThing* pThing)
{
    SithThing *result; // eax
    SithThing *i; // ecx

    result = pThing;
    for ( i = pThing->pParent; i; i = i->pParent )
    {
        if ( result->parentSignature != i->signature )
            break;
        result = i;
    }
    return result;
}

SithThing* sithThing_GetThingByIndex(int idx)
{
    SithThing *result; // eax

    if ( idx < 0 || idx >= sithWorld_g_pCurrentWorld->numThingsLoaded || (result = &sithWorld_g_pCurrentWorld->aThings[idx], result->type == SITH_THING_FREE) )
        result = 0;
    return result;
}

SithThing* sithThing_GetGuidThing(int guid)
{
    SithThing *result; // eax

    if ( guid < 0 )
        return 0;
    if ( (guid & 0xFFFF0000) == 0 && guid < sithWorld_g_pCurrentWorld->numThingsLoaded )
    {
        result = &sithWorld_g_pCurrentWorld->aThings[guid];
        if ( result->type )
            return result;
    }

    if ( sithWorld_g_pCurrentWorld->numThings < 0 )
        return 0;
    
    for (int32_t i = 0; i <= sithWorld_g_pCurrentWorld->numThings; i++)
    {
        SithThing* iter = &sithWorld_g_pCurrentWorld->aThings[i];
        if (iter->guid == guid && iter->type != SITH_THING_FREE) {
            return iter;
        }
    }

    return NULL;
}

void sithThing_DestroyThing(SithThing* pThing)
{
    pThing->flags |= SITH_TF_DESTROYED;
    if ( (pThing->flags & SITH_TF_CAPTURED) != 0 && (pThing->flags & SITH_TF_INVULN) == 0 )
        sithCog_ThingSendMessage(pThing, 0, SITH_MESSAGE_REMOVED);
}

flex_t sithThing_DamageThing(SithThing *pMeshCollided, SithThing *reciever, flex_t amount, int damageType)
{
    flex_t param1; // [esp+0h] [ebp-20h]

    // Added: noclip
    if (pMeshCollided == sithPlayer_g_pLocalPlayerThing && (g_debugmodeFlags & DEBUGFLAG_NOCLIP)) {
        return 0.0;
    }

    if ( amount <= 0.0 )
        return 0.0;
    if ( (pMeshCollided->flags & (SITH_TF_DISABLED|SITH_TF_DEAD|SITH_TF_DESTROYED)) != 0 )
        return 0.0;
    if ( (pMeshCollided->flags & SITH_TF_CAPTURED) != 0 && (pMeshCollided->flags & SITH_TF_INVULN) == 0 )
    {
        param1 = (flex_t)(unsigned int)damageType; // FLEXTODO
        amount = sithCog_ThingSendMessageEx(pMeshCollided, reciever, SITH_MESSAGE_DAMAGED, amount, param1, 0.0, 0.0);
    }
    if ( amount > 0.0 )
    {
        if ( pMeshCollided->type != SITH_THING_ACTOR )
        {
            if ( pMeshCollided->type == SITH_THING_WEAPON )
            {
                sithWeapon_DamageWeapon(pMeshCollided, reciever, amount);
                return amount;
            }
            if ( pMeshCollided->type != SITH_THING_PLAYER )
                return amount;
        }
        amount = amount - sithActor_DamageActor(pMeshCollided, reciever, amount, damageType);
    }
    return amount;
}

//sithThing_Create_idk

void sithThing_FreeWorldThings(SithWorld *pWorld)
{
    // Added: !world check
    if (!pWorld || !pWorld->aThings)
    {
        return;
    }

    sithThing_RemoveWorldThings(pWorld);

    SITH_FREE(pWorld->aThings);
    pWorld->aThings = 0;
    pWorld->numThingsLoaded = 0;
    pWorld->numThings = -1;
}

void sithThing_RemoveWorldThings(SithWorld *pWorld)
{
    SithThing* pThingIter;

    // Added: !world check
    if (!pWorld || !pWorld->aThings)
        return;

    for (int32_t v9 = 0; v9 < pWorld->numThingsLoaded; v9++)
    {
        pThingIter = &pWorld->aThings[v9];
        if (!pThingIter->type)
            continue;

        sithThing_RemoveThing(pThingIter);
    }
}

void sithThing_InitializeWorldThings(void)
{
    sithNet_thingsIdx = 0;
    for (int32_t idx = sithWorld_g_pCurrentWorld->numThingsLoaded - 1; idx >= 0; idx--)
    {
        SithThing* pThing = &sithWorld_g_pCurrentWorld->aThings[idx];
        sithThing_Reset(pThing);

        pThing->idx = idx;
        pThing->guid = -1;
        sithThing_FreeThingIndex(idx);
    }
}

void sithThing_LoadPostProcess()
{
    int32_t v1; // edx
    int32_t *v2; // ebp
    int32_t v6; // eax
    int32_t v8; // ecx

    // Added: Prevent crashes
    if (!sithWorld_g_pCurrentWorld) {
        return;
    }

    sithNet_thingsIdx = 0;
    sithWorld_g_pCurrentWorld->numThings = -1;
    v2 = sithNet_things + 1;
    for (v1 = sithWorld_g_pCurrentWorld->numThingsLoaded - 1; v1 >= 0; v1--)
    {
        if ( sithWorld_g_pCurrentWorld->aThings[v1].type )
        {
            if ( v1 > sithWorld_g_pCurrentWorld->numThings )
                sithWorld_g_pCurrentWorld->numThings = v1;
        }
        else
        {
            if ( v1 == sithWorld_g_pCurrentWorld->numThings )
            {
                for (v6 = v1-1; v6 >= 0; v6--)
                {
                    if (sithWorld_g_pCurrentWorld->aThings[v6].type)
                        break;
                }
                sithWorld_g_pCurrentWorld->numThings = v6;
            }
            *v2++ = v1;
            sithNet_thingsIdx++;
        }
    }
}


void sithThing_RemoveThing(SithThing* pThing)
{
    int32_t v2; // esi
    int32_t v3; // eax
    int32_t v5; // eax

    if ( sithNet_isMulti && sithNet_isServer && (pThing->guid & 0xFFFF0000) == 0 )
        sithMulti_RemoveStaticThing(pThing->guid);

    sithThing_FreeThing(pThing); // Inlined

    v2 = pThing->idx;
    if (sithWorld_g_pCurrentWorld && v2 == sithWorld_g_pCurrentWorld->numThings ) // Added: sithWorld_g_pCurrentWorld nullptr check
    {
        v3 = v2 - 1;
        if ( v2 - 1 >= 0 )
        {
            do
            {
                if (sithWorld_g_pCurrentWorld->aThings[v3].type)
                    break;
                --v3;
            }
            while ( v3 >= 0 );
        }
        sithWorld_g_pCurrentWorld->numThings = v3;
    }
    v5 = sithNet_thingsIdx;
    sithNet_things[sithNet_thingsIdx + 1] = v2;
    sithNet_thingsIdx = v5 + 1;
}

void sithThing_FreeThing(SithThing* pThing)
{
    if ( pThing->attach_flags )
        sithThing_DetachThing(pThing);
    if ( pThing->sector )
        sithThing_ExitSector(pThing);
    if ( pThing->moveType == SITH_MT_PATH && pThing->trackParams.aFrames )
        SITH_FREE(pThing->trackParams.aFrames);
    if ( pThing->controlType == SITH_CT_AI )
        sithAI_Free(pThing);
    if ( pThing->type == SITH_THING_PARTICLE )
        sithParticle_Free(pThing);
    if ( pThing->pPuppetClass )
        sithPuppet_Free(pThing);
    rdThing_FreeEntry(&pThing->renderData);
    sithSoundMixer_FreeThing(pThing);
    pThing->type = SITH_THING_FREE;
    pThing->signature = 0;
    pThing->guid = -1;
}

void sithThing_Initialize(SithThing* pThing)
{
    switch ( pThing->type )
    {
        case SITH_THING_ITEM:
            sithItem_Initialize(pThing);
            break;
        case SITH_THING_EXPLOSION:
            sithExplosion_CreateThing(pThing);
            break;
        case SITH_THING_PARTICLE:
            sithParticle_Initalize(pThing);
            break;
    }
    if ( pThing->renderData.puppet )
        sithPuppet_New(pThing);
    if ( pThing->controlType == SITH_CT_AI )
        sithAI_Create(pThing);
    if ( pThing->pSoundClass )
        sithSoundClass_PlayModeRandom(pThing, SITH_SC_CREATE);

    if ( (sithWorld_g_pCurrentWorld->level_type_maybe & 2) != 0
      && pThing->moveType == SITH_MT_PHYSICS
      && (pThing->physicsParams.flags & (SITH_PF_WALLSTICK|SITH_PF_FLOORSTICK)) != 0 )
    {
        sithPhysics_FindFloor(pThing, 1);
    }
}

// MOTS altered
int sithThing_Reset(SithThing* pThing)
{

    int32_t idx = pThing->idx;
    int32_t sig = pThing->signature;

    // Added: word-safe -- this also initializes template entries, which may live
    // in word-addressable-only memory (DC VRAM arena / NDS slot-2 RAM)
    stdPlatform_Memzero32(pThing, sizeof(SithThing));
    stdPlatform_Memcpy32(&pThing->orient, &rdroid_identMatrix34, sizeof(pThing->orient));

    int out = rdThing_NewEntry(&pThing->renderData, pThing);
    pThing->idx = idx;
    pThing->signature = sig;

#ifdef JKM_LIGHTING
    pThing->archlightIdx = -1; // MOTS added
#endif

    return out;
}

void sithThing_SetSector(SithThing* pThing, SithSector *sector, int a4)
{
    SithSector *v3; // eax

    v3 = pThing->sector;
    if ( v3 )
    {
        if ( v3 == sector )
            return;
        sithThing_ExitSector(pThing);
    }
    sithThing_EnterSector(pThing, sector, 0, a4);
}

void sithThing_ExitSector(SithThing* pThing)
{
    SithSector *sector; // eax
    SithThing *pPrevThingInSector; // ecx
    SithThing *pNextThingInSector; // eax
    rdVector3 pos; // [esp+Ch] [ebp-Ch] BYREF

    if (pThing == sithPlayer_g_pLocalPlayerThing) {
        //jk_printf("OpenJKDF2: Leave sector %p, idx %d\n", pThing->sector, pThing->sector ? pThing->sector->id : -1);
    }

    // Added
    if (!pThing || !pThing->sector) return;

    sector = pThing->sector;
    if ( (sector->flags & 4) == 0 )
        goto LABEL_5;
    pos = pThing->position;
    if ( (pThing->flags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
        sithCog_SectorSendMessage(sector, pThing, SITH_MESSAGE_EXITED);
    if ( !_memcmp(&pos, &pThing->position, sizeof(rdVector3)) )
    {
LABEL_5:
        pPrevThingInSector = pThing->pPrevThingInSector;
        pNextThingInSector = pThing->pNextThingInSector;
        if ( pPrevThingInSector )
        {
            pPrevThingInSector->pNextThingInSector = pNextThingInSector;
            if ( pNextThingInSector )
                pNextThingInSector->pPrevThingInSector = pPrevThingInSector;
        }
        else
        {
            pThing->sector->pFirstThingInSector = pNextThingInSector;
            if ( pNextThingInSector )
            {
                pNextThingInSector->pPrevThingInSector = 0;
                pThing->sector = 0;
                pThing->pPrevThingInSector = 0;
                pThing->pNextThingInSector = 0;
                return;
            }
        }
        pThing->sector = 0;
        pThing->pPrevThingInSector = 0;
        pThing->pNextThingInSector = 0;
    }
}

void sithThing_EnterSector(SithThing* pThing, SithSector *sector, int a3, int a4)
{
    SithSector *v7; // eax
    SithThing* i;

    if (pThing == sithPlayer_g_pLocalPlayerThing) {
        //jk_printf("OpenJKDF2: Enter sector %p, idx %d\n", sector, sector ? sector->id : -1);
    }

    // Added: Check that sector is non-null
    if (!sector) {
        jk_printf("OpenJKDF2: Tried to enter NULL sector??\n");
        return;
    }

    // Added: Prevent thing getting linked in twice
    for ( i = sector->pFirstThingInSector; i; i = i->pNextThingInSector )
    {
        if (i == pThing) {
            pThing->sector = sector; // just in case?
            jk_printf("OpenJKDF2: Tried to flex_d_t enter sector??\n");
            return;
        }
    }

    pThing->pNextThingInSector = sector->pFirstThingInSector;
    if ( sector->pFirstThingInSector )
        sector->pFirstThingInSector->pPrevThingInSector = pThing;

    pThing->pPrevThingInSector = 0;
    sector->pFirstThingInSector = pThing;
    pThing->sector = sector;

    if (sector->flags & SITH_SECTOR_UNDERWATER)
    {
        if ( pThing->attach_flags && !(pThing->attach_flags & SITH_ATTACH_NOMOVE) && pThing->moveType == SITH_MT_PHYSICS )
            sithThing_DetachThing(pThing);

        if (!(pThing->flags & SITH_TF_WATER))
            sithThing_EnterWater(pThing, a3 | a4);
    }
    else if (pThing->flags & SITH_TF_WATER)
    {
        sithThing_ExitWater(pThing, a3 | a4);
    }

    if ( !a4 )
    {
        if ( (pThing->sector->flags & SITH_SECTOR_COGLINKED) != 0 && (pThing->flags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
            sithCog_SectorSendMessage(pThing->sector, pThing, SITH_MESSAGE_ENTERED);
    }
}

void sithThing_EnterWater(SithThing* pThing, int a2)
{
    SithThing *v4; // ecx
    sithCog *v5; // eax
    sithCog *v6; // eax

    pThing->flags |= SITH_TF_WATER;
    if ( pThing->pPuppetClass )
        sithPuppet_SetMoveMode(pThing, 1);
    if ( (pThing->flags & SITH_TF_DROWNS) != 0 )
    {
        pThing->flags |= SITH_TF_DESTROYED;
        if ( (pThing->flags & SITH_TF_CAPTURED) != 0 && (pThing->flags & SITH_TF_INVULN) == 0 )
            sithCog_ThingSendMessage(pThing, 0, SITH_MESSAGE_REMOVED);
    }
    else if ( !a2 )
    {
#ifdef QOL_IMPROVEMENTS
        // Prevent splash sound spam if they're not actually making significant movement
        if ( pThing->pSoundClass && stdMath_Fabs(pThing->physicsParams.vel.z) > 0.02 )  
#else
        if ( pThing->pSoundClass )
#endif
        {
            if ( pThing->moveType == SITH_MT_PHYSICS && pThing->physicsParams.vel.z > -1.0 )
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_ENTERWATERSLOW);
            else
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_ENTERWATER);
        }
        v4 = sithPlayer_g_pLocalPlayerThing;
        if ( sithPlayer_g_pLocalPlayerThing && (pThing->flags & SITH_TF_SPLASHES) != 0 && (pThing->flags & SITH_TF_INVULN) == 0 )
        {
            v5 = sithPlayer_g_pLocalPlayerThing->pCog;
            if ( v5 )
            {
                sithCog_SendMessage(v5, SITH_MESSAGE_SPLASH, SENDERTYPE_THING, pThing->idx, 0, 1, 0);
                v4 = sithPlayer_g_pLocalPlayerThing;
            }
            v6 = v4->pCaptureCog;
            if ( v6 )
                sithCog_SendMessage(v6, SITH_MESSAGE_SPLASH, SENDERTYPE_THING, pThing->idx, 0, 1, 0);
        }

        // MOTS added: wtf??
        if (Main_bMotsCompat) {
            if ( pThing->moveType == SITH_MT_PHYSICS ) {
                
                // No water slowdown? Bug??
                int tmp;
                if (tmp = pThing->physicsParams.flags | SITH_PF_800000, 
                    pThing->physicsParams.flags = tmp, 
                    tmp == 0) {
                    pThing->physicsParams.vel.z *= 0.25;
                }
            }
        }
        else {
            if ( pThing->moveType == SITH_MT_PHYSICS ) {
                pThing->physicsParams.vel.z *= 0.25;
            }
        }
    }
}

void sithThing_ExitWater(SithThing* pThing, int a2)
{
    pThing->flags &= ~SITH_TF_WATER;
    if ( pThing->pPuppetClass )
        sithPuppet_SetMoveMode(pThing, 0);

#ifdef QOL_IMPROVEMENTS
    // Prevent splash sound spam if they're not actually making significant movement
    if ( pThing->pSoundClass && stdMath_Fabs(pThing->physicsParams.vel.z) > 0.02 )  
#else
    if ( pThing->pSoundClass )
#endif
    {
        if ( pThing->moveType == SITH_MT_PHYSICS && rdVector_Len3(&pThing->physicsParams.vel) < 1.0 )
            sithSoundClass_PlayModeRandom(pThing, SITH_SC_EXITWATERSLOW);
        else
            sithSoundClass_PlayModeRandom(pThing, SITH_SC_EXITWATER);
    }

    if ( (pThing->flags & SITH_TF_WATERCREATURE) != 0 )
    {
        pThing->flags |= SITH_TF_DESTROYED;
        if ( (pThing->flags & SITH_TF_CAPTURED) != 0 && (pThing->flags & SITH_TF_INVULN) == 0 )
            sithCog_ThingSendMessage(pThing, 0, SITH_MESSAGE_REMOVED);
    }
    else if ( !a2 )
    {
        if ( sithPlayer_g_pLocalPlayerThing )
        {
            if ( (pThing->flags & SITH_TF_SPLASHES) != 0 && (pThing->flags & SITH_TF_INVULN) == 0 )
            {
                if ( sithPlayer_g_pLocalPlayerThing->pCog )
                {
                    sithCog_SendMessage(sithPlayer_g_pLocalPlayerThing->pCog, SITH_MESSAGE_SPLASH, 3, pThing->idx, 0, 0, 0);
                }

                if ( sithPlayer_g_pLocalPlayerThing->pCaptureCog )
                {
                    sithCog_SendMessage(sithPlayer_g_pLocalPlayerThing->pCaptureCog, SITH_MESSAGE_SPLASH, 3, pThing->idx, 0, 0, 0);
                }
            }
        }
    }
}

// Unused or inlined
SithThing* sithThing_Create(uint32_t thingType)
{
    SithPathFrame *psVar1;
    SithWorld *pWorld;
    int iVar3;
    SithThing *pThingRet;
    int iVar4;

    pWorld = sithWorld_g_pCurrentWorld;
    if (sithNet_thingsIdx == 0) {
        iVar4 = -1;
        iVar3 = sithNet_thingsIdx;
    }
    else {
        iVar4 = (int)sithNet_things[sithNet_thingsIdx];
        iVar3 = sithNet_thingsIdx + -1;
        sithNet_thingsIdx = iVar3;
        if (sithWorld_g_pCurrentWorld->numThings < iVar4) {
            sithWorld_g_pCurrentWorld->numThings = iVar4;
        }
    }
    if (iVar4 < 0) {
        if (((thingType != SITH_THING_EXPLOSION) && (thingType != SITH_THING_DEBRIS)) &&
                (thingType != SITH_THING_PARTICLE))
        {
            int i = 0;
            for (uint32_t uVar5 = 0; uVar5 < pWorld->numThingsLoaded; uVar5++) {
                SithThing* pThing = &pWorld->aThings[uVar5];
                if (((pThing->flags & SITH_TF_DESTROYED) != 0) ||
                        (((pThing->type == SITH_THING_DEBRIS || (pThing->type == SITH_THING_PARTICLE))
                          && (pThing->msecLifeLeft != 0))))
                {
                    sithThing_RemoveThing(pThing); // was inlined
                }
                iVar3 = sithNet_thingsIdx;
                if (10 < i) break;
                i = i + 1;
            }
            if (iVar3 == 0) {
                iVar4 = -1;
            }
            else {
                iVar4 = sithNet_things[iVar3];
                sithNet_thingsIdx = iVar3 + -1;
                if (pWorld->numThings < iVar4) {
                    pWorld->numThings = iVar4;
                }
            }
        }
        if (iVar4 < 0) {
            return NULL;
        }
    }
    pThingRet = pWorld->aThings + iVar4;
    sithThing_Reset(pThingRet);
    pThingRet->idx = iVar4;
    if (sithThing_guidEntropy == 0) {
        sithThing_guidEntropy = 1; // TODO: this is a 32-bit write?
    }
    iVar3 = playerThingIdx + 1;
    uint32_t uVar5 = sithThing_guidEntropy & 0xffff;
    sithThing_guidEntropy = sithThing_guidEntropy + 1;
    pThingRet->signature = sithThing_bInitted2;
    sithThing_bInitted2 = sithThing_bInitted2 + 1;
    pThingRet->guid = (iVar3 << 16) | uVar5;
    //pThingRet->guid = uVar5 | (1 << 16); // TODO weird MP bug?
    if (sithThing_bInitted2 == 0) {
        sithThing_bInitted2 = 1;
    }
    return pThingRet;
}

void sithThing_SetPositionAndOrient(SithThing *pThing, rdVector3 *pos, rdMatrix34 *rot)
{
    rdVector_Copy3(&pThing->position, pos);
    rdMatrix_Copy34(&pThing->orient, rot);
    rdVector_Zero3(&pThing->orient.scale);
}

// MOTS altered
int sithThing_SetThingModel(SithThing* pThing, rdModel3 *pModel)
{
    rdThing *v2; // edi
    rdPuppet *v4; // ebx

    v2 = &pThing->renderData;
    if ( pThing->renderData.type == RD_THING_MODEL3 && pThing->renderData.model3 == pModel )
        return 0;
    v4 = pThing->renderData.puppet;
    pThing->renderData.puppet = 0;
    rdThing_FreeEntry(&pThing->renderData);
    rdThing_NewEntry(v2, pThing);
    rdThing_SetModel3(v2, pModel);
    pThing->renderData.puppet = v4;

    // MOTS added
    if (Main_bMotsCompat)
        pThing->unk = 1;

    return 1;
}

SithThing* sithThing_SetThingBasedOn(SithThing *pThing, SithThing *pTemplateThing)
{
    SithThing *result; // eax
    int v10; // [esp+10h] [ebp-Ch]
    int v11; // [esp+14h] [ebp-8h]
    SithThing *v12; // [esp+18h] [ebp-4h]
    int thinga; // [esp+20h] [ebp+4h]

    thinga = pThing->idx;
    v11 = pThing->guid;
    v10 = pThing->signature;
    v12 = pThing->renderData.pThing;
    if ( pTemplateThing )
    {
        stdPlatform_Memcpy32(pThing, pTemplateThing, sizeof(SithThing)); // Added: word-safe (aThings/aThingTemplates may be word-addressable-only)
        if ( pThing->renderData.type == RD_THING_MODEL3 )
        {
            rdThing_SetModel3(&pThing->renderData, pThing->renderData.model3);
        }
        else if ( pThing->renderData.type == RD_THING_PARTICLE )
        {
            rdThing_SetParticleCloud(&pThing->renderData, pThing->renderData.particlecloud);
        }
        if ( pThing->pPuppetClass )
            rdPuppet_New(&pThing->renderData);
        if ( pThing->moveType == SITH_MT_PATH && pTemplateThing->trackParams.aFrames )
        {
            // Added: made this more explicit
            pThing->trackParams.sizeFrames = pTemplateThing->trackParams.sizeFrames;
            pThing->trackParams.aFrames = (SithPathFrame *)SITH_ALLOC(sizeof(SithPathFrame) * pThing->trackParams.sizeFrames);
            if (pThing->trackParams.aFrames) // Added: nullptr check
                _memcpy(pThing->trackParams.aFrames, pTemplateThing->trackParams.aFrames, sizeof(SithPathFrame) * pThing->trackParams.sizeFrames);
        }
    }
    else
    {
        sithThing_Reset(pThing);
    }
    pThing->idx = thinga;
    result = v12;
    pThing->pTemplate = pTemplateThing;
    pThing->guid = v11;
    pThing->signature = v10;
    pThing->renderData.pThing = v12;
    return result;
}

SithThing* sithThing_CreateThingAtPos(SithThing *pTemplateThing, const rdVector3 *position, const rdMatrix34 *orient, SithSector *sector, SithThing *pPrevThingInSector)
{
    SithThing* pThingRet = sithThing_Create(pTemplateThing->type); // was inlined

    if (!pThingRet)
        return 0;

    sithThing_SetThingBasedOn(pThingRet, pTemplateThing);
    pThingRet->position = *position;
    stdPlatform_Memcpy32(&pThingRet->orient, orient, sizeof(pThingRet->orient)); // Added: word-safe (aThings may be in extram)
    rdVector_Zero3(&pThingRet->orient.scale);
    rdMatrix_PreMultiply34(&pThingRet->orient, &pTemplateThing->orient);
    sithThing_EnterSector(pThingRet, sector, 1, 0);
    if (pPrevThingInSector)
    {
        pThingRet->pParent = pPrevThingInSector;
        pThingRet->parentSignature = pPrevThingInSector->signature;
    }

    sithThing_Initialize(pThingRet); // was inlined

    if ( pThingRet->moveType == SITH_MT_PHYSICS && (pThingRet->physicsParams.flags & SITH_PF_20000) == 0 )
        rdMatrix_TransformVector34Acc(&pThingRet->physicsParams.vel, &pThingRet->orient);
    if ( pThingRet->pCog )
        sithCog_SendMessage(pThingRet->pCog, SITH_MESSAGE_CREATED, 3, pThingRet->idx, 0, 0, 0);
    if ( pThingRet->pCreateThingTemplate )
    {
        SithThing* v26 = sithThing_CreateThingAtPos(pThingRet->pCreateThingTemplate, position, orient, sector, pPrevThingInSector);
        if ( v26 )
        {
            if ( (pThingRet->flags & SITH_TF_INVULN) != 0 )
            {
                v26->flags |= SITH_TF_INVULN;
            }
        }
    }
    return pThingRet;
}

SithThing* sithThing_CreateThing(SithThing *pTemplateThing, SithThing *spawnThing)
{
    SithSector *v2; // eax
    SithThing *result; // eax
    SithThing *v4; // edi
    rdVector3 diffVec; // [esp+Ch] [ebp-24h] BYREF
    rdVector3 v7; // [esp+18h] [ebp-18h] BYREF
    rdVector3 dstVec; // [esp+24h] [ebp-Ch] BYREF

    if ( pTemplateThing->renderData.type == RD_THING_MODEL3 )
    {
        diffVec = pTemplateThing->renderData.model3->insertOffset;
    }
    else if ( pTemplateThing->renderData.type == RD_THING_SPRITE3 )
    {
        diffVec = pTemplateThing->renderData.sprite3->offset;
    }
    else
    {
        rdVector_Zero3(&diffVec);
    }
    if ( spawnThing->renderData.type == RD_THING_MODEL3 )
    {
        v7 = spawnThing->renderData.model3->insertOffset;
    }
    else if ( spawnThing->renderData.type == RD_THING_SPRITE3 )
    {
        v7 = spawnThing->renderData.sprite3->offset;
    }
    else
    {
        rdVector_Zero3(&v7);
    }
    rdVector_Sub3Acc(&diffVec, &v7);
    rdMatrix_TransformVector34(&dstVec, &diffVec, &spawnThing->orient);
    rdVector_Add3(&v7, &dstVec, &spawnThing->position);
    v2 = sithCollision_FindSectorInRadius(spawnThing->sector, &spawnThing->position, &v7, 0.0);
    result = sithThing_CreateThingAtPos(pTemplateThing, &v7, &spawnThing->orient, v2, 0);
    v4 = result;
    if ( result )
    {
        if ( result->moveType == SITH_MT_PATH
          && spawnThing->moveType == SITH_MT_PATH
          && spawnThing->trackParams.aFrames
          && !result->trackParams.aFrames )
        {
            sithTrackThing_idkpathmove(result, spawnThing, &diffVec);
        }
        result = v4;
    }
    return result;
}

void sithThing_AttachThingToSurface(SithThing* pThing, SithSurface *surface, int a3)
{
    int v4; // ebp
    int *v6; // eax
    SithWorld *v7; // edx
    rdVector3 *v8; // ecx
    flex_d_t v14; // st7
    int v15; // edi
    rdVector3 a2a; // [esp+Ch] [ebp-Ch] BYREF

    // Added: Safety checking
    if (!pThing) {
        stdPlatform_Printf("OpenJKDF2: NULL pThing in sithThing_AttachThingToSurface!\n");
        return;
    }
    // Added: Safety checking
    if (pThing->moveType != SITH_MT_PHYSICS) {
        stdPlatform_Printf("OpenJKDF2: Non-physics pThing in sithThing_AttachThingToSurface!\n");
        return;
    }

    v4 = 1;
    if ( pThing->attach_flags )
    {
        if ( (pThing->attach_flags & 1) != 0 && pThing->attachedSurface == surface )
            return;
        v4 = 0;
        sithThing_DetachThing(pThing);
    }
    v6 = surface->surfaceInfo.face.vertexPosIdx;
    v7 = sithWorld_g_pCurrentWorld;
    pThing->attach_flags = 1;
    v8 = &v7->aVertices[*v6];
    pThing->field_38.x = v8->x;
    pThing->field_38.y = v8->y;
    pThing->attachedSurface = surface;
    pThing->field_38.z = v8->z;
    pThing->attachedSufaceInfo = &surface->surfaceInfo;
    pThing->physicsParams.flags &= ~SITH_PF_100;
    if ( (surface->flags & SITH_SURFACE_SCROLLING) != 0 && pThing->moveType == SITH_MT_PHYSICS )
    {
        sithSurface_DetachThing(surface, &a2a);
        rdVector_Sub3Acc(&pThing->physicsParams.vel, &a2a);
    }
    if ( (surface->flags & SITH_SURFACE_COG_LINKED) != 0 && (pThing->flags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
        sithCog_SurfaceSendMessage(surface, pThing, SITH_MESSAGE_ENTERED);
    if ( !a3 && v4 )
    {
        v14 = -rdVector_Dot3(&pThing->physicsParams.vel, &surface->surfaceInfo.face.normal);
        if ( v14 > 2.5 )
        {
            sithCollision_FallHurt(pThing, v14);
            if ( pThing->pSoundClass )
            {
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDHURT);
            }
            
        }
        if ( pThing->pSoundClass )
        {
            v15 = surface->flags;
            if ( (v15 & (SITH_SURFACE_VERYDEEPWATER|SITH_SURFACE_EARTH|SITH_SURFACE_PUDDLE|SITH_SURFACE_WATER|SITH_SURFACE_METAL)) != 0 )
            {
                if ( (v15 & SITH_SURFACE_METAL) != 0 )
                {
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDMETAL);
                }
                else if ( (v15 & SITH_SURFACE_WATER) != 0 )
                {
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDWATER);
                }
                else if ( (v15 & SITH_SURFACE_PUDDLE) != 0 )
                {
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDPUDDLE);
                }
                else
                {
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDEARTH);
                }
            }
            else
            {
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_LANDHARD);
            }
        }
        if ( pThing->pPuppetClass && pThing->moveType == SITH_MT_PHYSICS && (pThing->physicsParams.flags & SITH_PF_CROUCHING) == 0 )
            sithPuppet_PlayMode(pThing, SITH_ANIM_LAND, 0);
        return;
    }
}

void sithThing_AttachThingToThingFace(SithThing *a1, SithThing *a2, rdFace *a3, rdVector3 *a4, int a5)
{
    int *v7; // eax
    int v8; // eax
    SithThing *v9; // eax
    flex_d_t v14; // st6
    flex_d_t downward_velocity; // st7
    int v18; // [esp+10h] [ebp-1Ch]
    rdVector3 a2a; // [esp+14h] [ebp-18h] BYREF
    rdVector3 out; // [esp+20h] [ebp-Ch] BYREF
    flex_t a1a; // [esp+30h] [ebp+4h]

    v18 = 1;
    if ( a1->attach_flags )
    {
        if ( (a1->attach_flags & SITH_ATTACH_THINGFACE) != 0 && a1->attachedThing == a2 && (rdFace *)a1->attachedSufaceInfo == a3 )
            return;
        v18 = 0;
        sithThing_DetachThing(a1);
    }
    v7 = a3->vertexPosIdx;
    a1->attach_flags = SITH_ATTACH_THINGFACE;
    a1->attachedSufaceInfo = (sithSurfaceInfo *)a3;
    v8 = *v7;
    a1->attachedThing = a2;
    a1->field_38 = a4[v8];
    v9 = a2->pAttachedThing;
    a1->pNextAttachedThing = v9;
    if ( v9 )
        v9->pPrevAttachedThing = a1;
    a1->pPrevAttachedThing = 0;
    a2->pAttachedThing = a1;
    a1->physicsParams.flags &= ~SITH_PF_100;
    if ( a2->moveType == SITH_MT_PHYSICS )
    {
        rdVector_Sub3Acc(&a1->physicsParams.vel, &a2->physicsParams.vel);
    }
    else if ( a2->moveType == SITH_MT_PATH )
    {
        rdVector_ScaleAdd3Acc(&a1->physicsParams.vel, &a2->trackParams.vel, -a2->trackParams.moveVel);
    }
    rdVector_Sub3(&a2a, &a1->position, &a2->position);
    rdMatrix_TransformVectorOrtho34(&a1->field_4C, &a2a, &a2->orient);
    if ( (a2->flags & SITH_TF_CAPTURED) != 0 && (a1->flags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
        sithCog_ThingSendMessage(a2, a1, SITH_MESSAGE_ENTERED);
    if ( v18 && !a5 )
    {
        rdMatrix_TransformVector34(&out, &a3->normal, &a2->orient);
        downward_velocity = -rdVector_Dot3(&a1->physicsParams.vel, &out);
        if ( downward_velocity > 2.5 )
        {
            a1a = downward_velocity;
            sithCollision_FallHurt(a1, a1a);
            sithSoundClass_PlayModeRandom(a1, SITH_SC_LANDHURT);
        }
        if ( a1->pSoundClass )
        {
            if ( (a2->flags & SITH_TF_METAL) != 0 )
            {
                sithSoundClass_PlayModeRandom(a1, SITH_SC_LANDMETAL);
            }
            else if ( (SITH_TF_EARTH & a2->flags) != 0 )
            {
                sithSoundClass_PlayModeRandom(a1, SITH_SC_LANDEARTH);
            }
            else
            {
                sithSoundClass_PlayModeRandom(a1, SITH_SC_LANDHARD);
            }
        }
    }
}

void sithThing_AttachThingToThing(SithThing *parent, SithThing *child)
{
    int v2; // eax
    SithThing *v3; // eax
    rdVector3 a2; // [esp+8h] [ebp-Ch] BYREF

    v2 = parent->attach_flags;
    if ( v2 )
    {
        if ( (v2 & SITH_ATTACH_THING) != 0 && parent->attachedThing == child )
            return;
        sithThing_DetachThing(parent);
    }
    v3 = child->pAttachedThing;
    parent->attach_flags = SITH_ATTACH_THING;
    parent->attachedThing = child;
    parent->pNextAttachedThing = v3;
    if ( v3 )
        v3->pPrevAttachedThing = parent;

    parent->pPrevAttachedThing = 0;
    child->pAttachedThing = parent;
    rdVector_Sub3(&a2, &parent->position, &child->position);
    rdMatrix_TransformVectorOrtho34(&parent->field_4C, &a2, &child->orient);
    if ( (child->flags & SITH_TF_CAPTURED) != 0 && (parent->flags & (SITH_TF_DISABLED|SITH_TF_INVULN)) == 0 )
        sithCog_ThingSendMessage(child, parent, SITH_MESSAGE_ENTERED);
}

int sithThing_DetachThing(SithThing* pThing)
{
    uint32_t *v2; // edi
    SithThing *v3; // ebx
    flex_d_t v12; // rt2
    SithThing *v13; // ecx
    SithThing *v14; // eax
    int result; // eax
    SithSurface *attached; // ebx
    rdVector3 a2; // [esp+Ch] [ebp-Ch] BYREF

    v2 = &pThing->attach_flags;
    if ( (pThing->attach_flags & (SITH_ATTACH_THING|SITH_ATTACH_THINGFACE)) == 0 )
    {
        if ( (pThing->attach_flags & SITH_ATTACH_SURFACE) != 0 )
        {
            attached = pThing->attachedSurface;
            if ( (attached->flags & SITH_SURFACE_SCROLLING) != 0 && pThing->moveType == SITH_MT_PHYSICS )
            {
                sithSurface_DetachThing(attached, &a2);
                rdVector_Add3Acc(&pThing->physicsParams.vel, &a2);
            }
            if ( (attached->flags & SITH_SURFACE_COG_LINKED) != 0 && (pThing->flags & SITH_TF_INVULN) == 0 )
                sithCog_SurfaceSendMessage(attached, pThing, SITH_MESSAGE_EXITED);
        }
        result = 0;

        stdPlatform_Memzero32(v2, sizeof(uint32_t) + sizeof(rdVector3) + sizeof(sithSurfaceInfo*) + sizeof(flex_t) + sizeof(rdVector3) + sizeof(void*)); // TODO // Added: word-safe
        return result;
    }
    v3 = pThing->attachedThing;
    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        if ( v3->moveType == SITH_MT_PHYSICS )
        {
            rdVector_Add3Acc(&pThing->physicsParams.vel, &v3->physicsParams.vel);
        }
        else
        {
            if ( v3->moveType != SITH_MT_PATH )
                goto LABEL_8;
            pThing->physicsParams.vel.x = (v3->trackParams.vel.x * v3->trackParams.moveVel) + pThing->physicsParams.vel.x;
            pThing->physicsParams.vel.y = (v3->trackParams.vel.y * v3->trackParams.moveVel) + pThing->physicsParams.vel.y;
            pThing->physicsParams.vel.z = (v3->trackParams.vel.z * v3->trackParams.moveVel) + pThing->physicsParams.vel.z;
        }
    }
LABEL_8:
    if ( (v3->flags & SITH_TF_CAPTURED) != 0 && (pThing->flags & SITH_TF_INVULN) == 0 )
        sithCog_ThingSendMessage(v3, pThing, SITH_MESSAGE_EXITED);
    v13 = pThing->pPrevAttachedThing;
    v14 = pThing->pNextAttachedThing;
    if ( v13 )
    {
        v13->pNextAttachedThing = v14;
        if ( v14 )
        {
            v14->pPrevAttachedThing = v13;
            result = 0;
            pThing->pPrevAttachedThing = 0;
            pThing->pNextAttachedThing = 0;
            stdPlatform_Memzero32(v2, sizeof(uint32_t) + sizeof(rdVector3) + sizeof(sithSurfaceInfo*) + sizeof(flex_t) + sizeof(rdVector3) + sizeof(void*));// TODO // Added: word-safe
            return result;
        }
    }
    else
    {
        v3->pAttachedThing = v14;
        if ( v14 )
            v14->pPrevAttachedThing = 0;
    }
    result = 0;
    pThing->pPrevAttachedThing = 0;
    pThing->pNextAttachedThing = 0;
    stdPlatform_Memzero32(v2, sizeof(uint32_t) + sizeof(rdVector3) + sizeof(sithSurfaceInfo*) + sizeof(flex_t) + sizeof(rdVector3) + sizeof(void*));// TODO // Added: word-safe
    return result;
}

void sithThing_DetachAttachedThings(SithThing* pThing)
{
    SithThing *v1; // eax
    SithThing *v2; // esi

    v1 = pThing->pAttachedThing;
    if ( v1 )
    {
        do
        {
            v2 = v1->pNextAttachedThing;
            sithThing_DetachThing(v1);
            v1 = v2;
        }
        while ( v2 );
    }
}

//sithThing_IsAttachFlagsAnd6
//sithThing_LotsOfFreeing

// MOTS altered
int sithThing_ReadStaticThingsListText(SithWorld *pWorld, int a2)
{
    SithThing *v4; // esi
    int32_t v5; // esi
    int32_t v6; // eax
    int32_t v10; // ebx
    SithThing* paThings; // eax
    int32_t v20; // eax
    SithThing *v21; // esi
    SithThing *v22; // ebx
    int32_t v23; // eax
    SithSector *v24; // edi
    int32_t v27; // edi
    StdConffileArg *v28; // ebx
    rdVector3 a3; // [esp+14h] [ebp-48h] BYREF
    rdVector3 pos; // [esp+20h] [ebp-3Ch] BYREF
    rdMatrix34 a; // [esp+2Ch] [ebp-30h] BYREF
    int32_t v36; // [esp+64h] [ebp+8h]
    int32_t v38; // [esp+64h] [ebp+8h]

    sithThing_bInitted2 = 1;
    if ( a2 && pWorld->aThings )
    {
        for (v36 = 0; v36 < pWorld->numThingsLoaded; v36++)
        {
            v4 = &pWorld->aThings[v36];
            if ( v4->type )
            {
                if ( sithNet_isMulti && sithNet_isServer && (v4->guid & 0xFFFF0000) == 0 )
                    sithMulti_RemoveStaticThing(v4->guid);
                sithThing_FreeThing(v4);
                v5 = v4->idx;
                if ( v5 == sithWorld_g_pCurrentWorld->numThings )
                {
                    for (v6 = v5 - 1; v6 >= 0; v6--)
                    {
                        if (sithWorld_g_pCurrentWorld->aThings[v6].type)
                            break;
                    }
                    sithWorld_g_pCurrentWorld->numThings = v6;
                }
                sithNet_things[1 + sithNet_thingsIdx++] = v5;
            }
        }
        SITH_FREE(pWorld->aThings);
        pWorld->aThings = 0;
        pWorld->numThingsLoaded = 0;
        pWorld->numThings = -1;
    }
    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_g_entry.aArgs[0].value, "world") )
        return 0;
    if ( _strcmp(stdConffile_g_entry.aArgs[1].value, "aThings") )
        return 0;
    v10 = _atoi(stdConffile_g_entry.aArgs[2].value);
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: word-safe struct (audited); slow-but-loads on NDS
    paThings = (SithThing *)SITH_ALLOC(sizeof(SithThing) * v10);
    TWL_EXTRAM_RESTORE(pSithHS); }

    sithWorld_g_pCurrentWorld->aThings = paThings;
    if ( !paThings )
        return 0;
    sithWorld_g_pCurrentWorld->numThingsLoaded = v10;
    sithThing_InitializeWorldThings();
    sithNet_thingsIdx = 0;
    v20 = 0x1000 << jkPlayer_setDiff;
    if ( (g_submodeFlags & 1) != 0 )
        v20 |= 0x8000u;
    else
        v20 |= 0x10000u;
    v38 = v20;
    while ( stdConffile_ReadArgs() )
    {
        if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "end") )
            break;
        v21 = &sithWorld_g_pCurrentWorld->aThings[_atoi(stdConffile_g_entry.aArgs[0].value)];
        v22 = sithTemplate_GetTemplate(stdConffile_g_entry.aArgs[1].value);
        if ( stdConffile_g_entry.numArgs >= 0xAu )
        {
            pos.x = _atof(stdConffile_g_entry.aArgs[3].value);
            pos.y = _atof(stdConffile_g_entry.aArgs[4].value);
            pos.z = _atof(stdConffile_g_entry.aArgs[5].value);
            a3.x = _atof(stdConffile_g_entry.aArgs[6].value);
            a3.y = _atof(stdConffile_g_entry.aArgs[7].value);
            a3.z = _atof(stdConffile_g_entry.aArgs[8].value);
            rdMatrix_BuildRotate34(&a, &a3);
            v23 = _atoi(stdConffile_g_entry.aArgs[9].value);
            if ( v23 >= 0 && v23 < sithWorld_g_pCurrentWorld->numSectors )
            {
                v24 = &sithWorld_g_pCurrentWorld->aSectors[v23];
                if ( stdConffile_g_entry.numArgs >= 11 && (stdConffile_g_entry.aArgs[10].key == stdConffile_g_entry.aArgs[10].value)) // MOTS added (w/o comparison)
                {
                    // && (!stdConffile_g_entry.aArgs[10].key || strlen(stdConffile_g_entry.aArgs[10].key) == 0)
                    v23 = _atoi(stdConffile_g_entry.aArgs[10].value);
                    v21->archlightIdx = v23;
                    //printf("%p %p %x\n", , v21->archlightIdx);
                }
                sithThing_SetThingBasedOn(v21, v22);
                sithThing_SetPositionAndOrient(v21, &pos, &a);
                sithThing_EnterSector(v21, v24, 1, 1);
                sithThing_Initialize(v21);
                v21->signature = sithThing_bInitted2++;
                v21->guid = v21->idx;
                v27 = 10;
                if ( stdConffile_g_entry.numArgs > 10 )
                {
                    v28 = &stdConffile_g_entry.aArgs[10];
                    do
                    {
                        sithThing_ParseArg(v28, v21);
                        ++v27;
                        ++v28;
                    }
                    while ( v27 < stdConffile_g_entry.numArgs );
                }
                if ( (v21->flags & v38) != 0 )
                {
                    sithThing_FreeThing(v21);
                }
                else
                {
#ifdef SITH_DEBUG_STRUCT_NAMES
                    stdString_SafeStrCopy(v21->aName, stdConffile_g_entry.aArgs[2].value, 0x20);
#endif
                }
            }
        }
    }
    sithThing_LoadPostProcess();
    return 1;
}

int sithThing_ParseArg(StdConffileArg *arg, SithThing* pThing)
{
    int32_t v2; // ebp
    int32_t param; // eax
    int32_t paramIdx; // edi
    int32_t v7; // eax
    int32_t v8; // eax

    v2 = 0;
    param = (int)(intptr_t)stdHashtbl_Find(sithThing_pParseHashtbl, arg->key);
    paramIdx = param;
    if ( !param )
        return 0;
    if ( sithThing_ParseThingArg(arg, pThing, param) )
        return 1;
    switch ( pThing->type )
    {
        case SITH_THING_ACTOR:
        case SITH_THING_PLAYER:
            v7 = sithActor_ParseArg(arg, pThing, paramIdx);
            goto LABEL_10;
        case SITH_THING_WEAPON:
            v7 = sithWeapon_ParseArg(arg, pThing, paramIdx);
            goto LABEL_10;
        case SITH_THING_ITEM:
            v7 = sithItem_ParseArg(arg, pThing, paramIdx);
            goto LABEL_10;
        case SITH_THING_EXPLOSION:
            v7 = sithExplosion_ParseArg(arg, pThing, paramIdx);
            goto LABEL_10;
        case SITH_THING_PARTICLE:
            v7 = sithParticle_ParseArg(arg, pThing, paramIdx);
LABEL_10:
            v2 = v7;
            break;
        default:
            break;
    }
    if ( v2 )
        return 1;
    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        v8 = sithPhysics_ParseArg(arg, pThing, paramIdx);
    }
    else
    {
        if ( pThing->moveType != SITH_MT_PATH )
            goto LABEL_18;
        v8 = sithTrackThing_LoadPathParams(arg, pThing, paramIdx);
    }
    v2 = v8;
LABEL_18:
    if ( v2 )
        return 1;
    return pThing->controlType == SITH_CT_AI && sithAI_ParseArg(arg, pThing, paramIdx);
}

// MOTS altered
int sithThing_ParseThingArg(StdConffileArg *arg, SithThing* pThing, int param)
{
    int32_t v3; // ebp
    const char **v4; // edi
    int32_t v5; // eax
    int32_t result; // eax
    SithAIClass *pClass; // eax
    SithAIControlBlock *pActor; // esi
    int32_t collide; // eax
    flex_d_t size; // st7
    uint32_t thingType; // eax
    flex_d_t moveSize; // st7
    flex_d_t light; // st7
    flex_d_t lifeLeftSec; // st7
    rdModel3 *pModel; // eax
    rdParticle *pParticle; // edi
    rdSprite *pSprite; // eax
    SithPuppetClass *pAnimClass; // eax
    sithCog *pCog; // eax
    rdVector3 orientation; // [esp+10h] [ebp-Ch] BYREF
    flex32_t orientationx, orientationy, orientationz;
    uint32_t thingFlags;
    flex32_t tmpF;

    switch ( param )
    {
        case SITHTHING_ARG_TYPE:
            v3 = SITH_THING_FREE;
            for (int i = 0; i < NUM_THING_TYPES; i++)
            {
                if (!_strcmp(arg->value, sithThing_aTypes[i]))
                {
                    v3 = i;
                    break;
                }
            }
            v5 = v3;

            pThing->type = v5;
            if (v5 == SITH_THING_ACTOR) {
                pThing->controlType = SITH_CT_AI;
                return 1;
            }
            if (v5 == SITH_THING_EXPLOSION) {
                pThing->controlType = SITH_CT_EXPLOSION;
                return 1;
            }
            if (v5 == SITH_THING_PARTICLE) {
                pThing->controlType = SITH_CT_PARTICLE;
                return 1;
            }
            result = 1;
            break;
        case THINGPARAM_COLLIDE:
            collide = _atoi(arg->value);
            if ( collide < 0 || collide > 3 )
                goto LABEL_59;
            pThing->collide = collide;
            result = 1;
            break;
#ifdef JKM_PARAMS
          case THINGPARAM_TREESIZE:
            tmpF = _atof(arg->value);
            if (tmpF < 0.0) {
              return 0;
            }
            pThing->treeSize = tmpF;
            return 1;
#endif
        case THINGPARAM_MOVE:
            if ( !_strcmp(arg->value, "physics") )
            {
                pThing->moveType = SITH_MT_PHYSICS;
                result = 1;
            }
            else if ( !_strcmp(arg->value, "path") )
            {
                pThing->moveType = SITH_MT_PATH;
                result = 1;
            }
            else
            {
                if ( _strcmp(arg->value, "none") )
                    goto LABEL_59;
                pThing->moveType = SITH_MT_NONE;
                result = 1;
            }
            break;
        case THINGPARAM_SIZE:
            size = _atof(arg->value);
            if ( size < 0.0 )
                goto LABEL_56;
            pThing->moveSize = size;
            pThing->collideSize = size;
            result = 1;
            break;
        case THINGPARAM_THINGFLAGS:
            if ( _sscanf(arg->value, "%x", &thingFlags) != 1 )
                goto LABEL_59;
            pThing->flags = thingFlags;
            result = 1;
            break;
        case THINGPARAM_TIMER:
            lifeLeftSec = _atof(arg->value);
            if ( lifeLeftSec < 0.0 )
                goto LABEL_56;
            pThing->msecLifeLeft = (__int64)(lifeLeftSec * 1000.0);
            result = 1;
            break;
        case THINGPARAM_LIGHT:
            light = _atof(arg->value);
            if ( light < 0.0 )
                goto LABEL_56;
            pThing->light = light;
            pThing->lightMin = light;
            pThing->flags |= SITH_TF_EMITLIGHT;
            result = 1;
            break;
        case THINGPARAM_SOUNDCLASS:
            pThing->pSoundClass = sithSoundClass_Load(arg->value);
            result = 1;
            break;
        case THINGPARAM_MODEL3D:
            rdThing_FreeEntry(&pThing->renderData);
            pModel = sithModel_Load(arg->value, 0);
            if ( pModel )
            {
                rdThing_SetModel3(&pThing->renderData, pModel);
                if ( pThing->collideSize == 0.0 )
                    pThing->collideSize = pThing->renderData.model3->radius;
                if ( pThing->moveSize != 0.0 )
                    goto LABEL_58;
                result = 1;
                pThing->moveSize = pThing->renderData.model3->radius;
            }
            else
            {
                stdPrintf(
                    pSithHS->errorPrint,
                    ".\\World\\sithThing.c",
                    2540,
                    "Could not load model '%s' specified on line %d.\n",
                    arg->value,
                    stdConffile_linenum);
                result = 0;
            }
            break;
        case THINGPARAM_SPRITE:
            rdThing_FreeEntry(&pThing->renderData);
            pSprite = sithSprite_Load(arg->value);
            if ( pSprite )
            {
                rdThing_SetSprite3(&pThing->renderData, pSprite);
                result = 1;
            }
            else
            {
                stdPrintf(pSithHS->errorPrint, ".\\World\\sithThing.c", 2573, "Could not create sprite %s, line %d.\n", arg->value, stdConffile_linenum);
                result = 0;
            }
            break;
        case THINGPARAM_PUPPET:
            pAnimClass = sithAnimClass_LoadEntry(arg->value);
            pThing->pPuppetClass = pAnimClass;
            if ( !pAnimClass || pThing->renderData.puppet )
                goto LABEL_58;
            rdPuppet_New(&pThing->renderData);
            result = 1;
            break;
        case THINGPARAM_AICLASS:
            pThing->controlType = SITH_CT_AI;
            pClass = sithAIClass_Load(arg->value);
            pThing->pClass = pClass;
            pActor = pThing->actor;
            if ( !pActor || !pClass )
                goto LABEL_58;
            pActor->pClass = pClass;
            pActor->numInstincts = pClass->numEntries;
            result = 1;
            break;
        case THINGPARAM_COG:
            pCog = sithCog_Load(arg->value);
            pThing->pCog = pCog;
            if ( !pCog )
                return 1;

            // MOTS added
            if (Main_bMotsCompat) {
                pCog->flags |= SITH_COG_CLASS;
                if (pCog->flags & SITH_COG_SERVER) {
                    pCog->flags |= SITH_COG_CLASS | SITH_COG_LOCAL;
                }
            }
            else {
                pCog->flags |= SITH_COG_CLASS | SITH_COG_LOCAL;
            }

            pThing->flags |= SITH_TF_CAPTURED;
            result = 1;
            break;
        case THINGPARAM_PARTICLE:
            pParticle = sithParticle_Load(arg->value);
            if ( !pParticle )
                goto LABEL_58;
            rdThing_FreeEntry(&pThing->renderData);
            rdThing_SetParticleCloud(&pThing->renderData, pParticle);
            result = 1;
            break;
        case THINGPARAM_MOVESIZE:
            thingType = pThing->type;
            if ( thingType == SITH_THING_ACTOR || thingType == SITH_THING_PLAYER )
                goto LABEL_58;
            moveSize = _atof(arg->value);
            if ( moveSize < 0.0 )
            {
LABEL_56:
                result = 0;
            }
            else
            {
                pThing->moveSize = moveSize;
                result = 1;
            }
            break;
        case THINGPARAM_CREATETHING:
            pThing->pCreateThingTemplate = sithTemplate_GetTemplate(arg->value);
            result = 1;
            break;
        case THINGPARAM_ORIENT:
            if ( _sscanf(arg->value, "(%f/%f/%f)", &orientationx, &orientationy, &orientationz) == 3 )
            {
                orientation.x = orientationx; // FLEXTODO
                orientation.y = orientationy; // FLEXTODO
                orientation.z = orientationz; // FLEXTODO
                rdMatrix_BuildRotate34(&pThing->orient, &orientation);
LABEL_58:
                result = 1;
            }
            else
            {
                result = 0;
            }
            break;
        default:
LABEL_59:
            result = 0;
            break;
    }
    return result;
}

//sithThing_TypeIdxFromStr

int sithThing_ValidateThingPointer(SithThing* pThing)
{
    uint32_t v1; // ecx
    int result; // eax

    result = 0;
    if ( pThing )
    {
        v1 = pThing->idx;
        if ( v1 == pThing - sithWorld_g_pCurrentWorld->aThings && v1 < (SITH_MAX_THINGS-1) )
            result = 1;
    }
    return result;
}

uint32_t sithThing_CalcThingChecksum(SithThing* pThing, uint32_t last_hash)
{
    uint32_t hash;

    hash = util_Weirdchecksum((uint8_t *)&pThing->flags, sizeof(uint32_t), last_hash);
    hash = util_Weirdchecksum((uint8_t *)&pThing->type, sizeof(uint32_t), hash);
    hash = util_Weirdchecksum((uint8_t *)&pThing->moveType, sizeof(uint32_t), hash);
    hash = util_Weirdchecksum((uint8_t *)&pThing->controlType, sizeof(uint32_t), hash);

    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.flags, sizeof(uint32_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.airDrag, sizeof(flex_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.surfDrag, sizeof(flex_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.staticDrag, sizeof(flex_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.mass, sizeof(flex_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->physicsParams.height, sizeof(flex_t), hash);
    }
    if ( pThing->type == SITH_THING_ACTOR )
    {
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.flags, sizeof(uint32_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.health, sizeof(flex_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.maxHealth, sizeof(flex_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.jumpSpeed, sizeof(flex_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.maxThrust, sizeof(flex_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->actorParams.maxRotVelocity, sizeof(flex_t), hash);
    }
    else if ( pThing->type == SITH_THING_WEAPON )
    {
        hash = util_Weirdchecksum((uint8_t *)&pThing->weaponParams.flags, sizeof(uint32_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->weaponParams.damage, sizeof(flex_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->weaponParams.unk8, sizeof(uint32_t), hash); // ???
        hash = util_Weirdchecksum((uint8_t *)&pThing->weaponParams.minDamage, sizeof(flex_t), hash);
        hash = util_Weirdchecksum((uint8_t *)&pThing->weaponParams.range, sizeof(flex_t), hash);
    }
    return hash;
}

void sithThing_SyncThing(SithThing *pThing, int flags)
{
    if (!sithMessage_g_outputstream) return;

    for (uint32_t v3 = 0; v3 < sithNet_syncIdx; v3++)
    {
        if (sithNet_aSyncThings[v3] == pThing) {
            sithNet_aSyncFlags[v3] |= flags;
            return;
        }
    }

    if ( sithNet_syncIdx < SITH_MAX_SYNC_THINGS ) // Added: != -> <
    {
        sithNet_aSyncThings[sithNet_syncIdx] = pThing;
        sithNet_aSyncFlags[sithNet_syncIdx] = flags;
        sithNet_syncIdx++;
    }
}

void sithThing_SyncThings()
{
    for (uint32_t v0 = 0; v0 < sithNet_syncIdx; v0++)
    {
        // 1 for multiplayer hackfix
#if 0
        if (sithNet_aSyncThings[v0]->guid >> 16 != playerThingIdx + 1 || (!(sithNet_aSyncThings[v0]->guid >> 16) && !sithNet_isServer)) {
            printf("%u tried to sync explicitly: 0x%08x type %x, flags %x\n", playerThingIdx, sithNet_aSyncThings[v0]->guid, sithNet_aSyncThings[v0]->type, sithNet_aSyncFlags[v0]);
            continue;
        }
        printf("%u Syncing explicitly: 0x%08x type %x, flags %x\n", playerThingIdx, sithNet_aSyncThings[v0]->guid, sithNet_aSyncThings[v0]->type, sithNet_aSyncFlags[v0]);
#endif
        if (sithNet_aSyncFlags[v0] & SITHTHING_SYNC_FULL)
        {
            // Added: this used to be outside the loop?
            sithDSSThing_FullDescription(sithNet_aSyncThings[v0], -1, 255);
            //return; // Removed, this used to stop the loop.
        }
        else
        {
            if (sithNet_aSyncFlags[v0] & SITHTHING_SYNC_STATE)
                sithDSSThing_UpdateState(sithNet_aSyncThings[v0], -1, 255);

            if (sithNet_aSyncFlags[v0] & SITHTHING_SYNC_POS)
                sithDSSThing_Pos(sithNet_aSyncThings[v0], -1, 0);
        }

        // Added: Co-op
        if (sithMulti_multiModeFlags & MULTIMODEFLAG_COOP && (sithNet_aSyncFlags[v0] & THING_SYNC_AI)) {
            if (sithNet_aSyncThings[v0]->actor && sithNet_aSyncThings[v0]->actor->pClass)
                sithDSS_AIStatus(sithNet_aSyncThings[v0]->actor, -1, 1);
        }

        // Added: Co-op
        if (sithMulti_multiModeFlags & MULTIMODEFLAG_COOP && (sithNet_aSyncFlags[v0] & THING_SYNC_PUPPET)) {
            if (sithNet_aSyncThings[v0]->renderData.puppet)
                sithDSS_PuppetStatus(sithNet_aSyncThings[v0], -1, 255);
        }
    }

    sithNet_syncIdx = 0;
    return;
}

int sithThing_CanSync(SithThing* pThing)
{
    if ( pThing->type )
        return !pThing->msecLifeLeft || pThing->type != SITH_THING_DEBRIS && pThing->type != SITH_THING_PARTICLE;

    return 0;
}

int sithThing_FreeThingIndex(int a1)
{
    int32_t v1; // eax

    if ( a1 == sithWorld_g_pCurrentWorld->numThings )
    {
        v1 = a1 - 1;
        for (v1 = a1 - 1; v1 >= 0; v1--)
        {
            if (sithWorld_g_pCurrentWorld->aThings[v1].type)
                break;
        }
        sithWorld_g_pCurrentWorld->numThings = v1;
    }
    sithNet_things[1 + sithNet_thingsIdx++] = a1;
    return sithNet_thingsIdx;
}

//sithThing_Release

int sithThing_Release(SithThing *pThing)
{
    SithCogThingLink *v1; // eax
    SithCogThingLink *v2; // ecx

    v1 = sithCog_aThingLinks;
    v2 = &sithCog_aThingLinks[sithCog_numThingLinks];
    if ( v2 <= sithCog_aThingLinks )
        return 0;
    while ( v1->thing != pThing )
    {
        if ( ++v1 >= v2 )
            return 0;
    }
    return 1;
}

// MOTS added
int sithThing_MotsTick(int param_1,int param_2,flex_t param_3)
{
    if (!Main_bMotsCompat) return 1;

    if (sithCog_pActionCog && (sithCog_actionCogIdk & (1 << (param_1 & 0x1f)))) 
    {
        flex_t fVar1 = sithCog_SendMessageEx(sithCog_pActionCog,SITH_MESSAGE_PLAYERACTION,0,0,0,0,0,(flex_t)param_1,(flex_t)param_2,param_3,0.0); // FLEXTODO
        if (fVar1 == 0.0) {
            return 0;
        }
    }
    return 1;
}

