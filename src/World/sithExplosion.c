#include "sithExplosion.h"

#include "World/sithThing.h"
#include "World/sithUnk3.h"
#include "World/sithSector.h"
#include "Engine/sithTemplate.h"
#include "Engine/sithSurface.h"
#include "jk.h"

void sithExplosion_CreateThing(sithThing *explosion)
{
    rdMaterial *v3; // ecx
    unsigned int v4; // ecx
    rdVector3 rot; // [esp+Ch] [ebp-Ch] BYREF

    explosion->explosionParams.lifeLeftMs = explosion->lifeLeftMs;
    if ( (explosion->explosionParams.typeflags & SITH_TF_LIGHT) != 0 && explosion->rdthing.type == RD_THINGTYPE_SPRITE3 )
    {
        v3 = explosion->rdthing.sprite3->face.material;
        if ( v3 && (v4 = v3->num_texinfo, v4 > 1) )
        {
            sithSurface_sub_4F00A0(explosion, (double)v4 / (double)(unsigned int)explosion->lifeLeftMs * 1000.0, 0x200000); // TODO enum
        }
        else
        {
            explosion->explosionParams.typeflags &= ~THING_TYPEFLAGS_1;
        }
    }
    if ( (explosion->explosionParams.typeflags & SITH_TF_20) != 0 )
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

    if ((explosion->explosionParams.typeflags & THING_TYPEFLAGS_FORCE)
      && explosion->lifeLeftMs <= explosion->explosionParams.blastTime)
    {
        sithExplosion_UpdateForce(explosion);
        explosion->explosionParams.typeflags &= ~THING_TYPEFLAGS_FORCE;
    }
    if ((explosion->explosionParams.typeflags & THING_TYPEFLAGS_LIGHT) 
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
    sithUnk3SearchEntry *i; // ebp
    double v3; // st6
    sithThing *v4; // edi
    double v5; // st6
    double v6; // st7
    double v7; // st5
    sithThing **debrisTemplates; // edi
    int v9; // ebx
    float v10; // [esp+0h] [ebp-60h]
    float v11; // [esp+0h] [ebp-60h]
    float damage; // [esp+18h] [ebp-48h]
    float force; // [esp+1Ch] [ebp-44h]
    float range; // [esp+20h] [ebp-40h]
    rdVector3 a2; // [esp+24h] [ebp-3Ch] BYREF
    rdMatrix34 a3; // [esp+30h] [ebp-30h] BYREF
    float a1a; // [esp+64h] [ebp+4h]

    range = explosion->explosionParams.range;
    force = explosion->explosionParams.force;
    damage = explosion->explosionParams.damage;
    if ( range > 0.0 && (damage > 0.0 || force > 0.0) )
    {
        sithSector_AddEntry(explosion->sector, &explosion->position, 1, 3.0, explosion);
        sithUnk3_SearchRadiusForThings(explosion->sector, 0, &explosion->position, &rdroid_zeroVector3, 0.0, range, 0x482);
        for ( i = sithUnk3_NextSearchResult(); i; i = sithUnk3_NextSearchResult() )
        {
            v3 = i->distance / range;
            a1a = 1.0 - v3 * v3;
            if ( a1a < 0.25 )
            {
                a1a = 0.25;
            }
            else if ( a1a > 1.0 )
            {
                a1a = 1.0;
            }
            if ( (i->collideType & 2) != 0 )
            {
                v10 = a1a * damage;
                sithSurface_SendDamageToThing(i->surface, explosion, v10, explosion->explosionParams.damageClass);
            }
            else
            {
                v4 = i->receiver;
                if ( ((explosion->actorParams.typeflags & THING_TYPEFLAGS_40) == 0
                   || v4 != explosion->prev_thing
                   || v4->signature != explosion->child_signature)
                  && sithUnk3_HasLos(explosion, v4, 1) )
                {
                    if ( force != 0.0 && v4->move_type == SITH_MT_PHYSICS && (v4->physicsParams.physflags & PHYSFLAGS_FEELBLASTFORCE) != 0 )
                    {
                        v5 = -(a1a * force);
                        v6 = i->field_14.y * v5;
                        v7 = i->field_14.z * v5;
                        a2.x = i->field_14.x * v5;
                        a2.y = v6;
                        a2.z = v7;
                        sithSector_ThingApplyForce(v4, &a2);
                    }
                    if ( damage != 0.0 )
                    {
                        v11 = a1a * damage;
                        sithThing_Damage(v4, explosion, v11, explosion->explosionParams.damageClass);
                    }
                }
            }
        }
        sithUnk3_SearchClose();
    }
    debrisTemplates = explosion->explosionParams.debrisTemplates;
    v9 = 4;
    do
    {
        if ( *debrisTemplates )
        {
            a2.x = _frand() * 360.0;
            a2.y = _frand() * 360.0;
            a2.z = _frand() * 360.0;
            rdMatrix_BuildRotate34(&a3, &a2);
            sithThing_SpawnThingInSector(*debrisTemplates, &explosion->position, &a3, explosion->sector, 0);
        }
        ++debrisTemplates;
        --v9;
    }
    while ( v9 );
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
            thing->explosionParams.typeflags |= (THING_TYPEFLAGS_DAMAGE|THING_TYPEFLAGS_FORCE);
            return 1;

        case THINGPARAM_DAMAGECLASS:
            if (_sscanf(arg->value, "%x", &tmp) != 1)
                return 0;
            thing->explosionParams.damageClass = tmp;
            return 1;

        case THINGPARAM_BLASTTIME:
            thing->explosionParams.blastTime = (int)(_atof(arg->value) * 1000.0);
            thing->explosionParams.typeflags |= THING_TYPEFLAGS_FORCE;
            return 1;

        case THINGPARAM_FORCE:
            thing->explosionParams.force = _atof(arg->value);
            thing->explosionParams.typeflags |= THING_TYPEFLAGS_FORCE;
            return 1;

        case THINGPARAM_MAXLIGHT:
            thing->explosionParams.maxLight = _atof(arg->value);
            thing->explosionParams.typeflags |= THING_TYPEFLAGS_LIGHT;
            return 1;

        case THINGPARAM_RANGE:
            thing->explosionParams.range = _atof(arg->value);
            thing->explosionParams.typeflags |= THING_TYPEFLAGS_FORCE;
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
