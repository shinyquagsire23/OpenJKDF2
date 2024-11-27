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
#ifdef RAGDOLLS
#include "Primitives/rdRagdoll.h"
#endif

void sithExplosion_CreateThing(sithThing *explosion)
{
    rdMaterial *v3; // ecx
    unsigned int v4; // ecx
    rdVector3 rot; // [esp+Ch] [ebp-Ch] BYREF

    explosion->explosionParams.lifeLeftMs = explosion->lifeLeftMs;
    if ( (explosion->explosionParams.typeflags & SITHEXPLOSION_FLAG_ANIMATED_SPRITE) != 0 && explosion->rdthing.type == RD_THINGTYPE_SPRITE3 )
    {
        v3 = explosion->rdthing.sprite3->face.material;
        if ( v3 && (v4 = v3->num_texinfo, v4 > 1) )
        {
            sithSurface_sub_4F00A0(explosion, (double)v4 / (double)(unsigned int)explosion->lifeLeftMs * 1000.0, 0x200000); // TODO enum
        }
        else
        {
            explosion->explosionParams.typeflags &= ~SITHEXPLOSION_FLAG_ANIMATED_SPRITE;
        }
    }
    if ( (explosion->explosionParams.typeflags & SITHEXPLOSION_FLAG_RANDOM_SPRITE_ORIENT) != 0 )
    {
        rot.x = 0.0;
        rot.y = 0.0;
        rot.z = _frand() * 360.0;
        rdMatrix_PostRotate34(&explosion->lookOrientation, &rot);
    }
}

void sithExplosion_Tick(sithThing *explosion)
{
    double v5; // st7
    double v6; // st6

    if ((explosion->explosionParams.typeflags & SITHEXPLOSION_FLAG_HAS_BLAST_PHASE)
      && explosion->lifeLeftMs <= explosion->explosionParams.blastTime)
    {
        sithExplosion_UpdateForce(explosion);
        explosion->explosionParams.typeflags &= ~SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
    }
    if ((explosion->explosionParams.typeflags & SITHEXPLOSION_FLAG_VARIABLE_LIGHT) 
        && (explosion->thingflags & SITH_TF_LIGHT))
    {
        if (explosion->lifeLeftMs <= explosion->explosionParams.blastTime)
        {
            v5 = (double)explosion->lifeLeftMs;
            v6 = (double)explosion->explosionParams.blastTime;
        }
        else
        {
            v5 = (double)(explosion->explosionParams.lifeLeftMs - explosion->lifeLeftMs);
            v6 = (double)(unsigned int)(explosion->explosionParams.lifeLeftMs - explosion->explosionParams.blastTime);
        }
        explosion->light = explosion->explosionParams.maxLight * (v5 / v6) + explosion->lightMin;
    }
}

void sithExplosion_UpdateForce(sithThing *explosion)
{
    sithCollisionSearchEntry *i; // ebp
    sithThing **debrisTemplates; // edi
    rdVector3 a2; // [esp+24h] [ebp-3Ch] BYREF
    rdMatrix34 a3; // [esp+30h] [ebp-30h] BYREF

    float range = explosion->explosionParams.range;
    float force = explosion->explosionParams.force;
    float damage = explosion->explosionParams.damage;
    if ( range > 0.0 && (damage > 0.0 || force > 0.0) )
    {
        sithAIAwareness_AddEntry(explosion->sector, &explosion->position, 1, 3.0, explosion);
        sithCollision_SearchRadiusForThings(explosion->sector, 0, &explosion->position, &rdroid_zeroVector3, 0.0, range, RAYCAST_400 | SITH_RAYCAST_COLLIDE_SPHERE_ONLY | RAYCAST_2);
        for ( i = sithCollision_NextSearchResult(); i; i = sithCollision_NextSearchResult() )
        {
            double v3 = i->distance / range;
            float a1a = rdMath_clampf(1.0 - (v3 * v3), 0.25, 1.0);

            if ( (i->hitType & SITHCOLLISION_WORLD) != 0 )
            {
                sithSurface_SendDamageToThing(i->surface, explosion, a1a * damage, explosion->explosionParams.damageClass);
            }
            else
            {
                sithThing* v4 = i->receiver;
                if ( ((explosion->explosionParams.typeflags & SITHEXPLOSION_FLAG_NO_DAMAGE_TO_SHOOTER) == 0
                   || v4 != explosion->prev_thing
                   || v4->signature != explosion->child_signature)
                  && sithCollision_HasLos(explosion, v4, 1) )
                {
                    if ( force != 0.0 && v4->moveType == SITH_MT_PHYSICS && (v4->physicsParams.physflags & SITH_PF_FEELBLASTFORCE) != 0 )
                    {
                        rdVector_Scale3(&a2, &i->hitNorm, -(a1a * force));
                        sithPhysics_ThingApplyForce(v4, &a2);
                    }
#ifdef RAGDOLLS
					else if ( force != 0.0 && v4->moveType == SITH_MT_RAGDOLL && v4->rdthing.pRagdoll && v4->physicsParams.mass != 0)
					{
						rdVector_Scale3(&a2, &i->hitNorm, -(a1a * force));
						sithPhysics_ThingRagdollApplyForce(v4, &a2, &explosion->position, range);
					}
#endif
                    if ( damage != 0.0 )
                    {
                        sithThing_Damage(v4, explosion, a1a * damage, explosion->explosionParams.damageClass, -1);
                    }
                }
            }
        }
        sithCollision_SearchClose();
    }
    
    debrisTemplates = explosion->explosionParams.debrisTemplates;
    for (int i = 0; i < 4; i++)
    {
        if ( *debrisTemplates )
        {
            a2.x = _frand() * 360.0;
            a2.y = _frand() * 360.0;
            a2.z = _frand() * 360.0;
            rdMatrix_BuildRotate34(&a3, &a2);
            sithThing_Create(*debrisTemplates, &explosion->position, &a3, explosion->sector, 0);
        }
        ++debrisTemplates;
    }
}

int sithExplosion_LoadThingParams(stdConffileArg *arg, sithThing *thing, int param)
{
    int v15; // esi
    sithThing **i; // eax
    int tmp;

    switch ( param )
    {
        case THINGPARAM_TYPEFLAGS:
            if (_sscanf(arg->value, "%x", &tmp) != 1)
                return 0;

            thing->explosionParams.typeflags = tmp;
            return 1;

        case THINGPARAM_DAMAGE:
            thing->explosionParams.damage = _atof(arg->value);
            thing->explosionParams.typeflags |= (SITHEXPLOSION_FLAG_HAS_BLAST_PHASE|SITHEXPLOSION_FLAG_DAMAGE_IN_BLAST_RADIUS);
            return 1;

        case THINGPARAM_DAMAGECLASS:
            if (_sscanf(arg->value, "%x", &tmp) != 1)
                return 0;
            thing->explosionParams.damageClass = tmp;
            return 1;

        case THINGPARAM_BLASTTIME:
            thing->explosionParams.blastTime = (int)(_atof(arg->value) * 1000.0);
            thing->explosionParams.typeflags |= SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
            return 1;

        case THINGPARAM_FORCE:
            thing->explosionParams.force = _atof(arg->value);
            thing->explosionParams.typeflags |= SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
            return 1;

        case THINGPARAM_MAXLIGHT:
            thing->explosionParams.maxLight = _atof(arg->value);
            thing->explosionParams.typeflags |= SITHEXPLOSION_FLAG_VARIABLE_LIGHT;
            return 1;

        case THINGPARAM_RANGE:
            thing->explosionParams.range = _atof(arg->value);
            thing->explosionParams.typeflags |= SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
            return 1;

        case THINGPARAM_FLASHRGB:
            if ( _sscanf(
                     arg->value,
                     "(%d/%d/%d)",
                     &thing->explosionParams.flashR,
                     &thing->explosionParams.flashG,
                     &thing->explosionParams.flashB) != 3 )
                return 0;
            return 1;

        case THINGPARAM_DEBRIS:
            v15 = 0;
            for ( i = thing->explosionParams.debrisTemplates; *i; ++i )
            {
                if ( (unsigned int)++v15 >= 4 )
                    return 1;
            }
            thing->explosionParams.debrisTemplates[v15] = sithTemplate_GetEntryByName(arg->value);
            return 1;

        default:
            return 0;
    }
}
