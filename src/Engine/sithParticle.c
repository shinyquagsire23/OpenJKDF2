#include "sithParticle.h"

#include "World/sithWorld.h"
#include "Primitives/rdParticle.h"
#include "General/stdHashTable.h"
#include "General/stdConffile.h"
#include "Engine/sithMaterial.h"
#include "Primitives/rdVector.h"
#include "stdPlatform.h"

#include "jk.h"

static stdHashTable *sithParticle_alloc;

int sithParticle_Startup()
{
    sithParticle_alloc = stdHashTable_New(128);

    if ( sithParticle_alloc )
        return 1;

    stdPrintf(pSithHS->errorPrint, ".\\Engine\\sithParticle.c", 66, "Failed to allocate memory for particless.\n", 0, 0, 0, 0);
    return 0;
}

void sithParticle_Shutdown()
{
    if ( sithParticle_alloc )
    {
        stdHashTable_Free(sithParticle_alloc);
        sithParticle_alloc = 0;
    }
}

rdParticle* sithParticle_LoadEntry(const char *a1)
{
    sithWorld *v1; // ebx
    rdParticle *v2; // edi
    rdParticle *result; // eax
    unsigned int v4; // eax
    rdParticle *v5; // esi
    char v6[128]; // [esp+Ch] [ebp-80h] BYREF

    v1 = sithWorld_pLoading;
    if ( !sithWorld_pLoading->particles )
    {
        v2 = (rdParticle *)pSithHS->alloc(64 * sizeof(rdParticle));
        v1->particles = v2;
        if ( v2 )
        {
            v1->numParticles = 64;
            v1->numParticlesLoaded = 0;
            _memset(v2, 0, 64 * sizeof(rdParticle));
        }
    }
    result = (rdParticle *)stdHashTable_GetKeyVal(sithParticle_alloc, a1);
    if ( !result )
    {
        v4 = v1->numParticlesLoaded;
        if ( v4 < v1->numParticles )
        {
            v5 = &v1->particles[v4];
            _sprintf(v6, "%s%c%s", "misc\\par", '\\', a1);
            if ( rdParticle_LoadEntry(v6, v5) )
            {
                stdHashTable_SetKeyVal(sithParticle_alloc, v5->name, v5);
                ++v1->numParticlesLoaded;
                result = v5;
            }
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

int sithParticle_New(sithWorld *world, int numParticles)
{
    rdParticle *newParticle; // edi

    newParticle = (rdParticle *)pSithHS->alloc(sizeof(rdParticle) * numParticles);
    world->particles = newParticle;
    if ( !newParticle )
        return 0;
    world->numParticles = numParticles;
    world->numParticlesLoaded = 0;
    _memset(newParticle, 0, sizeof(rdParticle) * numParticles);
    return 1;
}

int sithParticle_LoadThingParams(stdConffileArg *arg, sithThing *thing, int param)
{
    switch (param)
    {
        case THINGPARAM_TYPEFLAGS:
            if ( _sscanf(arg->value, "%x", &thing->particleParams.typeFlags) == 1 )
                return 1;
            return 0;

        case THINGPARAM_MAXTHRUST:
            thing->particleParams.growthSpeed = _atof(arg->value);
            return 1;

        case THINGPARAM_RANGE:
            thing->particleParams.range = _atof(arg->value);
            return 1;

        case THINGPARAM_MATERIAL:
            thing->particleParams.material = sithMaterial_LoadEntry(arg->value, 0, 0);
            return 1;

        case THINGPARAM_RATE:
            thing->particleParams.rate = _atof(arg->value);
            return 1;

        case THINGPARAM_COUNT:
            thing->particleParams.count = _atoi(arg->value);
            return 1;

        case THINGPARAM_ELEMENTSIZE:
            thing->particleParams.elementSize = _atof(arg->value);
            return 1;

        case THINGPARAM_MINSIZE:
            thing->particleParams.minSize = _atof(arg->value);
            return 1;

        case THINGPARAM_PITCHRANGE:
            thing->particleParams.pitchRange = _atof(arg->value);
            return 1;

        case THINGPARAM_YAWRANGE:
            thing->particleParams.yawRange = _atof(arg->value);
            return 1;

        default:
            return 0;
    }
}

void sithParticle_Tick(sithThing *particle, float deltaMs)
{
    double v2; // st7
    char typeFlags; // al
    unsigned int i; // edi
    rdParticle *v5; // eax
    int v6; // ebp
    unsigned int v7; // esi
    int *v8; // eax
    double v11; // st7
    double v12; // st7
    double v13; // st6
    double v14; // rt2
    double v15; // st6
    float v16; // [esp+0h] [ebp-44h]
    rdVector3 a2a; // [esp+8h] [ebp-3Ch] BYREF
    rdMatrix34 a1a; // [esp+14h] [ebp-30h] BYREF
    float deltaMsa; // [esp+4Ch] [ebp+8h]

    v2 = deltaMs + particle->particleParams.field_2C;
    typeFlags = particle->particleParams.typeFlags;
    particle->particleParams.field_2C = v2;
    if ( (typeFlags & THING_TYPEFLAGS_20) != 0 )
    {
        i = 0;
        v5 = particle->rdthing.particlecloud;
        v6 = particle->particleParams.material->num_texinfo;
        v16 = v2 * 1000.0 / (double)(unsigned int)particle->lifeLeftMs * deltaMs;
        if ( v5->numVertices )
        {
            do
            {
                v7 = v6 - v5->vertexCel[i] - 1;
                if ( v6 - v5->vertexCel[i] != 1 )
                {
                    if ( (double)v7 * v16 > _frand() )
                    {
                        v8 = &particle->rdthing.particlecloud->vertexCel[i];
                        ++*v8;
                    }
                }
                v5 = particle->rdthing.particlecloud;
                ++i;
            }
            while ( i < v5->numVertices );
        }
    }
    if ( (particle->particleParams.typeFlags & THING_TYPEFLAGS_1) != 0 )
    {
        if ( particle->particleParams.field_28 < 0.0099999998)
        {
            v11 = 0.0099999998 / particle->particleParams.field_28;
            particle->particleParams.field_28 = 0.0099999998;
            deltaMsa = v11;
        }
        else
        {
            v12 = particle->particleParams.growthSpeed * deltaMs + particle->particleParams.field_28;
            v13 = v12 / particle->particleParams.field_28;
            deltaMsa = v13;
            v14 = v13;
            v15 = v12;
            v11 = v14;
            particle->particleParams.field_28 = v15;
        }
        a2a.z = v11;
        a2a.y = v11;
        a2a.x = v11;
        rdMatrix_BuildScale34(&a1a, &a2a);
        rdMatrix_PostMultiply34(&particle->lookOrientation, &a1a);
        particle->rdthing.particlecloud->cloudRadius = particle->rdthing.particlecloud->cloudRadius * deltaMsa;
    }
}

void sithParticle_CreateThing(sithThing *thing)
{
    int v1; // ecx
    rdThing *v3; // ebp
    rdParticle *v4; // edi
    int v5; // edx
    rdMaterial *v6; // eax
    unsigned int v7; // ebx
    rdParticle *v8; // eax
    double v9; // st7
    unsigned int v10; // ebp
    int v11; // edi
    rdParticle *v13; // ecx
    rdVector3 *v14; // eax
    double v15; // st7
    rdVector3 *v16; // eax
    int v17; // eax
    rdParticle *v18; // ecx
    float v19; // edx
    float v20; // [esp+10h] [ebp-20h]
    float v21; // [esp+14h] [ebp-1Ch]
    float v22; // [esp+18h] [ebp-18h]
    rdVector3 v23; // [esp+24h] [ebp-Ch] BYREF
    float thinga; // [esp+34h] [ebp+4h]

    v1 = 2;
    v3 = &thing->rdthing;
    if ( thing->rdthing.type == RD_THINGTYPE_PARTICLECLOUD )
    {
        v4 = rdParticle_Clone(thing->rdthing.particlecloud);
        rdThing_SetParticleCloud(v3, v4);
        v5 = v4->numVertices;
        thing->particleParams.material = v4->material;
        thing->particleParams.count = v5;
        thing->particleParams.field_28 = 1.0;
    }
    else
    {
        v6 = thing->particleParams.material;
        v7 = v6->num_texinfo;
        if ( (thing->particleParams.typeFlags & THING_TYPEFLAGS_LIGHT) != 0 )
            v1 = 0;

        v8 = rdParticle_New(thing->particleParams.count, thing->particleParams.elementSize, v6, v1, 1);
        if ( v8 )
        {
            rdThing_SetParticleCloud(v3, v8);
            if ( thing->particleParams.pitchRange == 0.0 )
                v20 = 720.0;
            else
                v20 = thing->particleParams.pitchRange + thing->particleParams.pitchRange;
            if ( thing->particleParams.yawRange == 0.0 )
                v21 = 720.0;
            else
                v21 = thing->particleParams.yawRange + thing->particleParams.yawRange;
            v9 = thing->particleParams.range - thing->particleParams.minSize;
            v22 = v9;
            if ( v9 <= 0.0 )
                v22 = 0.0;
            v10 = 0;
            if ( thing->rdthing.particlecloud->numVertices )
            {
                v11 = 0;
                do
                {
                    v23.x = (_frand() - 0.5) * v20;
                    v23.z = 0.0;
                    v23.y = (_frand() - 0.5) * v21;
                    thinga = _frand() * v22 + thing->particleParams.minSize;
                    rdVector_Rotate3(&thing->rdthing.particlecloud->vertices[v11], &rdroid_yVector3, &v23);
                    v13 = thing->rdthing.particlecloud;
                    v14 = v13->vertices;
                    v15 = v14[v11].x;
                    v16 = &v14[v11];
                    v16->x = v15 * thinga;
                    v16->y = v16->y * thinga;
                    v16->z = v16->z * thinga;
                    if ( v7 > 1 && (thing->particleParams.typeFlags & THING_TYPEFLAGS_DAMAGE) != 0 )
                    {
                        v17 = (int)(_frand() * (double)v7);
                        if ( v17 >= v7 - 1 )
                            v17 = v7 - 1;
                        v13 = thing->rdthing.particlecloud;
                        v13->vertexCel[v10] = v17;
                    }
                    else
                    {
                        v13->vertexCel[v10] = -1;
                    }
                    ++v10;
                    ++v11;
                }
                while ( v10 < v13->numVertices );
            }
            v18 = thing->rdthing.particlecloud;
            v19 = thing->particleParams.range;
            thing->particleParams.field_28 = 1.0;
            v18->cloudRadius = v19;
        }
    }
}

void sithParticle_Remove(sithThing *particle)
{
    unsigned int v1;
    rdParticle* particlePrim;

    if (!(particle->particleParams.typeFlags & THING_TYPEFLAGS_8))
    {
        sithThing_Destroy(particle);
        return;
    }


    v1 = (unsigned int)(particle->particleParams.rate * 0.1);
    if ( !v1 )
        v1 = 1;

    particlePrim = particle->rdthing.particlecloud;

    if (v1 < particlePrim->numVertices)
    {
        particlePrim->numVertices -= v1;
        particle->lifeLeftMs = (int)(_frand() * 100.0) + 1;
    }
    else
    {
        sithThing_Destroy(particle);
    }
}

void sithParticle_FreeEntry(sithThing *thing)
{
    if (thing->rdthing.particlecloud)
    {
        rdParticle_Free(thing->rdthing.particlecloud);
        thing->rdthing.particlecloud = 0;
    }
}

void sithParticle_Free(sithWorld *world)
{
    if (!world->numParticlesLoaded) return;

    for (int i = 0; i < world->numParticlesLoaded; i++)
    {
        stdHashTable_FreeKey(sithParticle_alloc, world->particles[i].name);
        rdParticle_FreeEntry(&world->particles[i]);
    }
    
    pSithHS->free(world->particles);
    world->particles = 0;
    world->numParticles = 0;
    world->numParticlesLoaded = 0;
}
