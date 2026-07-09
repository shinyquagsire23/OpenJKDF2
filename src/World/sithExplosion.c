#include "sithExplosion.h"

#include "AI/sithAIAwareness.h"
#include "World/sithThing.h"
#include "Engine/sithCollision.h"
#include "World/sithSector.h"
#include "World/sithTemplate.h"
#include "World/sithSurface.h"
#include "Engine/sithPhysics.h"
#include "Primitives/rdMath.h"
#include "jk.h"

void sithExplosion_CreateThing(SithThing *pThing)
{
    rdMaterial *v3; // ecx
    unsigned int v4; // ecx
    rdVector3 rot; // [esp+Ch] [ebp-Ch] BYREF

    pThing->explosionParams.msecLifeLeft = pThing->msecLifeLeft;
    if ( (pThing->explosionParams.flags & SITHEXPLOSION_FLAG_ANIMATED_SPRITE) != 0 && pThing->renderData.type == RD_THING_SPRITE3 )
    {
        v3 = pThing->renderData.sprite3->face.material;
        if ( v3 && (v4 = v3->num_texinfo, v4 > 1) )
        {
            sithSurface_sub_4F00A0(pThing, (flex_d_t)v4 / (flex_d_t)(unsigned int)pThing->msecLifeLeft * 1000.0, 0x200000); // TODO enum
        }
        else
        {
            pThing->explosionParams.flags &= ~SITHEXPLOSION_FLAG_ANIMATED_SPRITE;
        }
    }
    if ( (pThing->explosionParams.flags & SITH_TF_20) != 0 )
    {
        rot.x = 0.0;
        rot.y = 0.0;
        rot.z = _frand() * 360.0;
        rdMatrix_PostRotate34(&pThing->orient, &rot);
    }
}

void sithExplosion_Update(SithThing *pThing)
{
    flex_d_t v5; // st7
    flex_d_t v6; // st6

    SITH_ASSERTREL(pThing); // Added: OpenJones3D sithExplosion_Update assert (pExplode is &pThing->explosionParams)

    if ((pThing->explosionParams.flags & SITHEXPLOSION_FLAG_HAS_BLAST_PHASE)
      && pThing->msecLifeLeft <= pThing->explosionParams.msecBlastTime)
    {
        sithExplosion_MakeBlast(pThing);
        pThing->explosionParams.flags &= ~SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
    }
    if ((pThing->explosionParams.flags & SITHEXPLOSION_FLAG_VARIABLE_LIGHT) 
        && (pThing->flags & SITH_TF_EMITLIGHT))
    {
        if (pThing->msecLifeLeft <= pThing->explosionParams.msecBlastTime)
        {
            v5 = (flex_d_t)pThing->msecLifeLeft;
            v6 = (flex_d_t)pThing->explosionParams.msecBlastTime;
        }
        else
        {
            v5 = (flex_d_t)(pThing->explosionParams.msecLifeLeft - pThing->msecLifeLeft);
            v6 = (flex_d_t)(unsigned int)(pThing->explosionParams.msecLifeLeft - pThing->explosionParams.msecBlastTime);
        }
        pThing->light = pThing->explosionParams.maxLight * (v5 / v6) + pThing->lightMin;
    }
}

void sithExplosion_MakeBlast(SithThing *pThing)
{
    SithCollision *i; // ebp
    SithThing **apDebries; // edi
    rdVector3 a2; // [esp+24h] [ebp-3Ch] BYREF
    rdMatrix34 a3; // [esp+30h] [ebp-30h] BYREF

    SITH_ASSERTREL(pThing && (pThing->type == SITH_THING_EXPLOSION)); // Added: OpenJones3D sithExplosion_MakeBlast assert

    flex_t range = pThing->explosionParams.range;
    flex_t force = pThing->explosionParams.force;
    flex_t damage = pThing->explosionParams.damage;
    if ( range > 0.0 && (damage > 0.0 || force > 0.0) )
    {
        sithAIAwareness_CreateTransmittingEvent(pThing->sector, &pThing->position, 1, 3.0, pThing);
        sithCollision_SearchForCollisions(pThing->sector, 0, &pThing->position, &rdroid_zeroVector3, 0.0, range, RAYCAST_400 | RAYCAST_80 | RAYCAST_2);
        for ( i = sithCollision_PopStack(); i; i = sithCollision_PopStack() )
        {
            flex_d_t v3 = i->distance / range;
            flex_t a1a = rdMath_clampf(1.0 - (v3 * v3), 0.25, 1.0);

            if ( (i->type & SITHCOLLISION_WORLD) != 0 )
            {
                sithSurface_HandleThingImpact(i->surface, pThing, a1a * damage, pThing->explosionParams.damageType);
            }
            else
            {
                SITH_ASSERTREL((i->type & SITHCOLLISION_THING)); // Added: OpenJones3D sithExplosion_MakeBlast collision-type assert

                SithThing* v4 = i->pThingCollided;
                if ( ((pThing->explosionParams.flags & SITHEXPLOSION_FLAG_NO_DAMAGE_TO_SHOOTER) == 0
                   || v4 != pThing->pParent
                   || v4->signature != pThing->parentSignature)
                  && sithCollision_HasLOS(pThing, v4, 1) )
                {
                    if ( force != 0.0 && v4->moveType == SITH_MT_PHYSICS && (v4->physicsParams.flags & SITH_PF_USEBLASTFORCE) != 0 )
                    {
                        rdVector_Scale3(&a2, &i->hitNorm, -(a1a * force));
                        sithPhysics_ApplyForce(v4, &a2);
                    }
                    if ( damage != 0.0 )
                    {
                        sithThing_DamageThing(v4, pThing, a1a * damage, pThing->explosionParams.damageType);
                    }
                }
            }
        }
        sithCollision_DecreaseStackLevel();
    }
    
    apDebries = pThing->explosionParams.apDebries;
    for (int i = 0; i < 4; i++)
    {
        if ( *apDebries )
        {
            a2.x = _frand() * 360.0;
            a2.y = _frand() * 360.0;
            a2.z = _frand() * 360.0;
            rdMatrix_BuildRotate34(&a3, &a2);
            sithThing_CreateThingAtPos(*apDebries, &pThing->position, &a3, pThing->sector, 0);
        }
        ++apDebries;
    }
}

int sithExplosion_ParseArg(StdConffileArg *pArg, SithThing *pThing, int adjNum)
{
    int v15; // esi
    SithThing **i; // eax
    int tmp;

    SITH_ASSERTREL(pThing && pArg); // Added: OpenJones3D sithExplosion_ParseArg assert (adjNum bound term omitted; no SITHTHING_NUMADJECTIVES in DF2)

    switch ( adjNum )
    {
        case THINGPARAM_TYPEFLAGS:
            if (_sscanf(pArg->value, "%x", &tmp) != 1)
                return 0;

            pThing->explosionParams.flags = tmp;
            return 1;

        case THINGPARAM_DAMAGE:
            pThing->explosionParams.damage = _atof(pArg->value);
            pThing->explosionParams.flags |= (SITHEXPLOSION_FLAG_HAS_BLAST_PHASE|SITHEXPLOSION_FLAG_DAMAGE_IN_BLAST_RADIUS);
            return 1;

        case THINGPARAM_DAMAGECLASS:
            if (_sscanf(pArg->value, "%x", &tmp) != 1)
                return 0;
            pThing->explosionParams.damageType = tmp;
            return 1;

        case THINGPARAM_BLASTTIME:
            pThing->explosionParams.msecBlastTime = (int)(_atof(pArg->value) * 1000.0);
            pThing->explosionParams.flags |= SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
            return 1;

        case THINGPARAM_FORCE:
            pThing->explosionParams.force = _atof(pArg->value);
            pThing->explosionParams.flags |= SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
            return 1;

        case THINGPARAM_MAXLIGHT:
            pThing->explosionParams.maxLight = _atof(pArg->value);
            pThing->explosionParams.flags |= SITHEXPLOSION_FLAG_VARIABLE_LIGHT;
            return 1;

        case THINGPARAM_RANGE:
            pThing->explosionParams.range = _atof(pArg->value);
            pThing->explosionParams.flags |= SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
            return 1;

        case THINGPARAM_FLASHRGB:
            if ( _sscanf(
                     pArg->value,
                     "(%d/%d/%d)",
                     &pThing->explosionParams.flashR,
                     &pThing->explosionParams.flashG,
                     &pThing->explosionParams.flashB) != 3 )
                return 0;
            return 1;

        case THINGPARAM_DEBRIS:
            v15 = 0;
            for ( i = pThing->explosionParams.apDebries; *i; ++i )
            {
                if ( (unsigned int)++v15 >= 4 )
                    return 1;
            }
            pThing->explosionParams.apDebries[v15] = sithTemplate_GetTemplate(pArg->value);
            return 1;

        default:
            return 0;
    }
}
