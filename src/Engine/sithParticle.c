#include "sithParticle.h"

#include "World/sithWorld.h"
#include "Primitives/rdParticle.h"
#include "General/stdHashtbl.h"
#include "General/stdConffile.h"
#include "World/sithMaterial.h"
#include "Primitives/rdVector.h"
#include "stdPlatform.h"

#include "jk.h"

static tHashTable *sithParticle_alloc;

int sithParticle_Startup()
{
    sithParticle_alloc = stdHashtbl_New(128);

    if ( sithParticle_alloc )
        return 1;

    stdPrintf(pSithHS->errorPrint, ".\\Engine\\sithParticle.c", 66, "Failed to allocate memory for particless.\n", 0, 0, 0, 0);
    return 0;
}

void sithParticle_Shutdown()
{
    if ( sithParticle_alloc )
    {
        stdHashtbl_Free(sithParticle_alloc);
        sithParticle_alloc = 0;
    }
}

rdParticle* sithParticle_Load(const char *pName)
{
    SithWorld *v1; // ebx
    rdParticle *v2; // edi
    rdParticle *result; // eax
    unsigned int v4; // eax
    rdParticle *v5; // esi
    char v6[128]; // [esp+Ch] [ebp-80h] BYREF

    v1 = sithWorld_g_pLastLoadedWorld;
    if ( !sithWorld_g_pLastLoadedWorld->aParticles )
    {
        v2 = (rdParticle *)SITH_ALLOC(SITHPARTICLE_MAX_PARTICLES * sizeof(rdParticle));
        v1->aParticles = v2;
        if ( v2 )
        {
            v1->sizeParticles = SITHPARTICLE_MAX_PARTICLES;
            v1->numParticles = 0;
            _memset(v2, 0, SITHPARTICLE_MAX_PARTICLES * sizeof(rdParticle));
        }
    }
    result = (rdParticle *)stdHashtbl_Find(sithParticle_alloc, pName);
    if ( !result )
    {
        v4 = v1->numParticles;
        if ( v4 < v1->sizeParticles )
        {
            v5 = &v1->aParticles[v4];
            _sprintf(v6, "%s%c%s", "misc\\par", '\\', pName);
            if ( rdParticle_LoadEntry(v6, v5) )
            {
                stdHashtbl_Add(sithParticle_alloc, v5->name, v5);
                ++v1->numParticles;
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

int sithParticle_AllocWorldParticles(SithWorld *pWorld, int size)
{
    rdParticle *newParticle; // edi

    newParticle = (rdParticle *)SITH_ALLOC(sizeof(rdParticle) * size);
    pWorld->aParticles = newParticle;
    if ( !newParticle )
        return 0;
    pWorld->sizeParticles = size;
    pWorld->numParticles = 0;
    _memset(newParticle, 0, sizeof(rdParticle) * size);
    return 1;
}

int sithParticle_ParseArg(StdConffileArg *pArg, SithThing *pThing, int adjNum)
{
    switch (adjNum)
    {
        case THINGPARAM_TYPEFLAGS:
            if ( _sscanf(pArg->value, "%x", &pThing->particleParams.flags) == 1 )
                return 1;
            return 0;

        case THINGPARAM_MAXTHRUST:
            pThing->particleParams.growthSpeed = _atof(pArg->value);
            return 1;

        case THINGPARAM_RANGE:
            pThing->particleParams.range = _atof(pArg->value);
            return 1;

        case THINGPARAM_MATERIAL:
            pThing->particleParams.material = sithMaterial_Load(pArg->value, 0, 0);
            return 1;

        case THINGPARAM_RATE:
            pThing->particleParams.rate = _atof(pArg->value);
            return 1;

        case THINGPARAM_COUNT:
            pThing->particleParams.count = _atoi(pArg->value);
            return 1;

        case THINGPARAM_ELEMENTSIZE:
            pThing->particleParams.size = _atof(pArg->value);
            return 1;

        case THINGPARAM_MINSIZE:
            pThing->particleParams.minRadius = _atof(pArg->value);
            return 1;

        case THINGPARAM_PITCHRANGE:
            pThing->particleParams.pitchRange = _atof(pArg->value);
            return 1;

        case THINGPARAM_YAWRANGE:
            pThing->particleParams.yawRange = _atof(pArg->value);
            return 1;

        default:
            return 0;
    }
}

void sithParticle_Update(SithThing *pThing, flex_t secDeltaTime)
{
    flex_d_t v2; // st7
    char flags; // al
    unsigned int i; // edi
    rdParticle *v5; // eax
    int v6; // ebp
    unsigned int v7; // esi
    int *v8; // eax
    flex_d_t v11; // st7
    flex_d_t v12; // st7
    flex_d_t v13; // st6
    flex_d_t v14; // rt2
    flex_d_t v15; // st6
    flex_t v16; // [esp+0h] [ebp-44h]
    rdVector3 a2a; // [esp+8h] [ebp-3Ch] BYREF
    rdMatrix34 a1a; // [esp+14h] [ebp-30h] BYREF
    flex_t deltaMsa; // [esp+4Ch] [ebp+8h]

    v2 = secDeltaTime + pThing->particleParams.field_2C;
    flags = pThing->particleParams.flags;
    pThing->particleParams.field_2C = v2;
    if ( (flags & SITHPARTICLE_FLAG_RANDOM_CEL_CHANGE) != 0 )
    {
        i = 0;
        v5 = pThing->renderData.particlecloud;
        v6 = pThing->particleParams.material->num_texinfo;
        v16 = v2 * 1000.0 / (flex_d_t)(unsigned int)pThing->msecLifeLeft * secDeltaTime;
        if ( v5->numVertices )
        {
            do
            {
                v7 = v6 - v5->aVertMatCelNums[i] - 1;
                if ( v6 - v5->aVertMatCelNums[i] != 1 )
                {
                    if ( (flex_d_t)v7 * v16 > _frand() )
                    {
                        v8 = &pThing->renderData.particlecloud->aVertMatCelNums[i];
                        ++*v8;
                    }
                }
                v5 = pThing->renderData.particlecloud;
                ++i;
            }
            while ( i < v5->numVertices );
        }
    }
    if ( (pThing->particleParams.flags & SITHPARTICLE_FLAG_OUTWARD_EXPANDING) != 0 )
    {
        if ( pThing->particleParams.field_28 < 0.01)
        {
            v11 = 0.01 / pThing->particleParams.field_28;
            pThing->particleParams.field_28 = 0.01;
            deltaMsa = v11;
        }
        else
        {
            v12 = pThing->particleParams.growthSpeed * secDeltaTime + pThing->particleParams.field_28;
            v13 = v12 / pThing->particleParams.field_28;
            deltaMsa = v13;
            v14 = v13;
            v15 = v12;
            v11 = v14;
            pThing->particleParams.field_28 = v15;
        }
        a2a.z = v11;
        a2a.y = v11;
        a2a.x = v11;
        rdMatrix_BuildScale34(&a1a, &a2a);
        rdMatrix_PostMultiply34(&pThing->orient, &a1a);
        pThing->renderData.particlecloud->cloudRadius = pThing->renderData.particlecloud->cloudRadius * deltaMsa;
    }
}

void sithParticle_Initalize(SithThing *pThing)
{
    int v1; // ecx
    rdThing *v3; // ebp
    rdParticle *v4; // edi
    int v5; // edx
    rdMaterial *v6; // eax
    unsigned int v7; // ebx
    rdParticle *v8; // eax
    flex_d_t v9; // st7
    unsigned int v10; // ebp
    int v11; // edi
    rdParticle *v13; // ecx
    rdVector3 *v14; // eax
    flex_d_t v15; // st7
    rdVector3 *v16; // eax
    int v17; // eax
    rdParticle *v18; // ecx
    flex_t v19; // edx
    flex_t v20; // [esp+10h] [ebp-20h]
    flex_t v21; // [esp+14h] [ebp-1Ch]
    flex_t v22; // [esp+18h] [ebp-18h]
    rdVector3 v23; // [esp+24h] [ebp-Ch] BYREF
    flex_t thinga; // [esp+34h] [ebp+4h]

    v1 = 2;
    v3 = &pThing->renderData;
    if ( pThing->renderData.type == RD_THING_PARTICLE )
    {
        v4 = rdParticle_Duplicate(pThing->renderData.particlecloud);
        rdThing_SetParticleCloud(v3, v4);
        v5 = v4->numVertices;
        pThing->particleParams.material = v4->material;
        pThing->particleParams.count = v5;
        pThing->particleParams.field_28 = 1.0;
    }
    else
    {
        v6 = pThing->particleParams.material;
        v7 = v6->num_texinfo;
        if ( (pThing->particleParams.flags & SITHPARTICLE_FLAG_EMIT_LIGHT) != 0 )
            v1 = 0;

        v8 = rdParticle_New(pThing->particleParams.count, pThing->particleParams.size, v6, v1, 1);
        if ( v8 )
        {
            rdThing_SetParticleCloud(v3, v8);
            if ( pThing->particleParams.pitchRange == 0.0 )
                v20 = 720.0;
            else
                v20 = pThing->particleParams.pitchRange + pThing->particleParams.pitchRange;
            if ( pThing->particleParams.yawRange == 0.0 )
                v21 = 720.0;
            else
                v21 = pThing->particleParams.yawRange + pThing->particleParams.yawRange;
            v9 = pThing->particleParams.range - pThing->particleParams.minRadius;
            v22 = v9;
            if ( v9 <= 0.0 )
                v22 = 0.0;
            v10 = 0;
            if ( pThing->renderData.particlecloud->numVertices )
            {
                v11 = 0;
                do
                {
                    v23.x = (_frand() - 0.5) * v20;
                    v23.z = 0.0;
                    v23.y = (_frand() - 0.5) * v21;
                    thinga = _frand() * v22 + pThing->particleParams.minRadius;
                    rdVector_Rotate3(&pThing->renderData.particlecloud->aVertices[v11], &rdroid_yVector3, &v23);
                    v13 = pThing->renderData.particlecloud;
                    v14 = v13->aVertices;
                    v15 = v14[v11].x;
                    v16 = &v14[v11];
                    v16->x = v15 * thinga;
                    v16->y = v16->y * thinga;
                    v16->z = v16->z * thinga;
                    if ( v7 > 1 && (pThing->particleParams.flags & SITHPARTICLE_FLAG_RANDOM_START_CEL) != 0 )
                    {
                        v17 = (int)(_frand() * (flex_d_t)v7);
                        if ( v17 >= v7 - 1 )
                            v17 = v7 - 1;
                        v13 = pThing->renderData.particlecloud;
                        v13->aVertMatCelNums[v10] = v17;
                    }
                    else
                    {
                        v13->aVertMatCelNums[v10] = -1;
                    }
                    ++v10;
                    ++v11;
                }
                while ( v10 < v13->numVertices );
            }
            v18 = pThing->renderData.particlecloud;
            v19 = pThing->particleParams.range;
            pThing->particleParams.field_28 = 1.0;
            v18->cloudRadius = v19;
        }
    }
}

void sithParticle_DestroyParticle(SithThing *pThing)
{
    unsigned int v1;
    rdParticle* particlePrim;

    if (!(pThing->particleParams.flags & SITHPARTICLE_FLAG_FADE_OUT_OVER_TIME))
    {
        sithThing_DestroyThing(pThing);
        return;
    }


    v1 = (unsigned int)(pThing->particleParams.rate * 0.1);
    if ( !v1 )
        v1 = 1;

    particlePrim = pThing->renderData.particlecloud;

    if (v1 < particlePrim->numVertices)
    {
        particlePrim->numVertices -= v1;
        pThing->msecLifeLeft = (int)(_frand() * 100.0) + 1;
    }
    else
    {
        sithThing_DestroyThing(pThing);
    }
}

void sithParticle_Free(SithThing *pThing)
{
    if (pThing->renderData.particlecloud)
    {
        rdParticle_Free(pThing->renderData.particlecloud);
        pThing->renderData.particlecloud = 0;
    }
}

void sithParticle_FreeWorldParticles(SithWorld *pWorld)
{
    if (!pWorld->numParticles) return;

    for (int i = 0; i < pWorld->numParticles; i++)
    {
        stdHashtbl_Remove(sithParticle_alloc, pWorld->aParticles[i].name);
        rdParticle_FreeEntry(&pWorld->aParticles[i]);
    }
    
    SITH_FREE(pWorld->aParticles);
    pWorld->aParticles = 0;
    pWorld->sizeParticles = 0;
    pWorld->numParticles = 0;
}
