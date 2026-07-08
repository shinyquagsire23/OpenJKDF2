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

void sithExplosion_CreateThing(SithThing *explosion)
{
    rdMaterial *v3; // ecx
    unsigned int v4; // ecx
    rdVector3 rot; // [esp+Ch] [ebp-Ch] BYREF

    explosion->explosionParams.msecLifeLeft = explosion->msecLifeLeft;
    if ( (explosion->explosionParams.flags & SITHEXPLOSION_FLAG_ANIMATED_SPRITE) != 0 && explosion->renderData.type == RD_THING_SPRITE3 )
    {
        v3 = explosion->renderData.sprite3->face.material;
        if ( v3 && (v4 = v3->num_texinfo, v4 > 1) )
        {
            sithSurface_sub_4F00A0(explosion, (flex_d_t)v4 / (flex_d_t)(unsigned int)explosion->msecLifeLeft * 1000.0, 0x200000); // TODO enum
        }
        else
        {
            explosion->explosionParams.flags &= ~SITHEXPLOSION_FLAG_ANIMATED_SPRITE;
        }
    }
    if ( (explosion->explosionParams.flags & SITH_TF_20) != 0 )
    {
        rot.x = 0.0;
        rot.y = 0.0;
        rot.z = _frand() * 360.0;
        rdMatrix_PostRotate34(&explosion->orient, &rot);
    }
}

void sithExplosion_Update(SithThing *explosion)
{
    flex_d_t v5; // st7
    flex_d_t v6; // st6

    if ((explosion->explosionParams.flags & SITHEXPLOSION_FLAG_HAS_BLAST_PHASE)
      && explosion->msecLifeLeft <= explosion->explosionParams.msecBlastTime)
    {
        sithExplosion_MakeBlast(explosion);
        explosion->explosionParams.flags &= ~SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
    }
    if ((explosion->explosionParams.flags & SITHEXPLOSION_FLAG_VARIABLE_LIGHT) 
        && (explosion->flags & SITH_TF_EMITLIGHT))
    {
        if (explosion->msecLifeLeft <= explosion->explosionParams.msecBlastTime)
        {
            v5 = (flex_d_t)explosion->msecLifeLeft;
            v6 = (flex_d_t)explosion->explosionParams.msecBlastTime;
        }
        else
        {
            v5 = (flex_d_t)(explosion->explosionParams.msecLifeLeft - explosion->msecLifeLeft);
            v6 = (flex_d_t)(unsigned int)(explosion->explosionParams.msecLifeLeft - explosion->explosionParams.msecBlastTime);
        }
        explosion->light = explosion->explosionParams.maxLight * (v5 / v6) + explosion->lightMin;
    }
}

void sithExplosion_MakeBlast(SithThing *explosion)
{
    SithCollision *i; // ebp
    SithThing **apDebries; // edi
    rdVector3 a2; // [esp+24h] [ebp-3Ch] BYREF
    rdMatrix34 a3; // [esp+30h] [ebp-30h] BYREF

    flex_t range = explosion->explosionParams.range;
    flex_t force = explosion->explosionParams.force;
    flex_t damage = explosion->explosionParams.damage;
    if ( range > 0.0 && (damage > 0.0 || force > 0.0) )
    {
        sithAIAwareness_CreateTransmittingEvent(explosion->sector, &explosion->position, 1, 3.0, explosion);
        sithCollision_SearchForCollisions(explosion->sector, 0, &explosion->position, &rdroid_zeroVector3, 0.0, range, RAYCAST_400 | RAYCAST_80 | RAYCAST_2);
        for ( i = sithCollision_PopStack(); i; i = sithCollision_PopStack() )
        {
            flex_d_t v3 = i->distance / range;
            flex_t a1a = rdMath_clampf(1.0 - (v3 * v3), 0.25, 1.0);

            if ( (i->hitType & SITHCOLLISION_WORLD) != 0 )
            {
                sithSurface_HandleThingImpact(i->surface, explosion, a1a * damage, explosion->explosionParams.damageType);
            }
            else
            {
                SithThing* v4 = i->receiver;
                if ( ((explosion->explosionParams.flags & SITHEXPLOSION_FLAG_NO_DAMAGE_TO_SHOOTER) == 0
                   || v4 != explosion->pParent
                   || v4->signature != explosion->parentSignature)
                  && sithCollision_HasLOS(explosion, v4, 1) )
                {
                    if ( force != 0.0 && v4->moveType == SITH_MT_PHYSICS && (v4->physicsParams.flags & SITH_PF_USEBLASTFORCE) != 0 )
                    {
                        rdVector_Scale3(&a2, &i->hitNorm, -(a1a * force));
                        sithPhysics_ApplyForce(v4, &a2);
                    }
                    if ( damage != 0.0 )
                    {
                        sithThing_DamageThing(v4, explosion, a1a * damage, explosion->explosionParams.damageType);
                    }
                }
            }
        }
        sithCollision_DecreaseStackLevel();
    }
    
    apDebries = explosion->explosionParams.apDebries;
    for (int i = 0; i < 4; i++)
    {
        if ( *apDebries )
        {
            a2.x = _frand() * 360.0;
            a2.y = _frand() * 360.0;
            a2.z = _frand() * 360.0;
            rdMatrix_BuildRotate34(&a3, &a2);
            sithThing_CreateThingAtPos(*apDebries, &explosion->position, &a3, explosion->sector, 0);
        }
        ++apDebries;
    }
}

int sithExplosion_ParseArg(StdConffileArg *arg, SithThing *thing, int param)
{
    int v15; // esi
    SithThing **i; // eax
    int tmp;

    switch ( param )
    {
        case THINGPARAM_TYPEFLAGS:
            if (_sscanf(arg->value, "%x", &tmp) != 1)
                return 0;

            thing->explosionParams.flags = tmp;
            return 1;

        case THINGPARAM_DAMAGE:
            thing->explosionParams.damage = _atof(arg->value);
            thing->explosionParams.flags |= (SITHEXPLOSION_FLAG_HAS_BLAST_PHASE|SITHEXPLOSION_FLAG_DAMAGE_IN_BLAST_RADIUS);
            return 1;

        case THINGPARAM_DAMAGECLASS:
            if (_sscanf(arg->value, "%x", &tmp) != 1)
                return 0;
            thing->explosionParams.damageType = tmp;
            return 1;

        case THINGPARAM_BLASTTIME:
            thing->explosionParams.msecBlastTime = (int)(_atof(arg->value) * 1000.0);
            thing->explosionParams.flags |= SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
            return 1;

        case THINGPARAM_FORCE:
            thing->explosionParams.force = _atof(arg->value);
            thing->explosionParams.flags |= SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
            return 1;

        case THINGPARAM_MAXLIGHT:
            thing->explosionParams.maxLight = _atof(arg->value);
            thing->explosionParams.flags |= SITHEXPLOSION_FLAG_VARIABLE_LIGHT;
            return 1;

        case THINGPARAM_RANGE:
            thing->explosionParams.range = _atof(arg->value);
            thing->explosionParams.flags |= SITHEXPLOSION_FLAG_HAS_BLAST_PHASE;
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
            for ( i = thing->explosionParams.apDebries; *i; ++i )
            {
                if ( (unsigned int)++v15 >= 4 )
                    return 1;
            }
            thing->explosionParams.apDebries[v15] = sithTemplate_GetTemplate(arg->value);
            return 1;

        default:
            return 0;
    }
}
