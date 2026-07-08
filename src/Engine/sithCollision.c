#include "sithCollision.h"

#include "World/sithThing.h"
#include "World/sithWeapon.h"
#include "World/sithItem.h"
#include "World/sithActor.h"
#include "World/sithSector.h"
#include "Engine/sithIntersect.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithSurface.h"
#include "World/sithSoundClass.h"
#include "Gameplay/sithTime.h"
#include "Engine/sithPhysics.h"
#include "Engine/sithCamera.h"
#include "General/stdMath.h"
#include "Primitives/rdMath.h"
#include "jk.h"

static int sithCollision_initted = 0;

int sithCollision_bDebugCollide = 0;

int sithCollision_Startup()
{
    if ( sithCollision_initted )
        return 0;

    _memset(sithCollision_collisionHandlers, 0, 144 * sizeof(SithCollideResult)); // sizeof(sithCollision_collisionHandlers)
    _memset(sithCollision_aThingSurfaceCollideResults, 0, 12 * sizeof(int)); // sizeof(sithCollision_aThingSurfaceCollideResults)
    sithCollision_AddCollisionHandler(SITH_THING_ACTOR, SITH_THING_ACTOR, sithActor_ActorCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_ACTOR, SITH_THING_PLAYER, sithActor_ActorCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_ACTOR, SITH_THING_COG, sithActor_ActorCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_PLAYER, SITH_THING_PLAYER, sithCollision_ThingCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_PLAYER, SITH_THING_COG, sithCollision_ThingCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_DEBRIS, SITH_THING_ACTOR, sithCollision_ParticleAndActorCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_DEBRIS, SITH_THING_PLAYER, sithCollision_ParticleAndActorCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_DEBRIS, SITH_THING_DEBRIS, sithCollision_ThingCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_WEAPON, SITH_THING_ACTOR, sithWeapon_ThingCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_WEAPON, SITH_THING_PLAYER, sithWeapon_ThingCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_WEAPON, SITH_THING_DEBRIS, sithWeapon_ThingCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_WEAPON, SITH_THING_COG, sithWeapon_ThingCollisionHandler, 0);
    sithCollision_AddCollisionHandler(SITH_THING_ITEM, SITH_THING_PLAYER, sithItem_PlayerCollisionHandler, 0);

    sithCollision_AddSurfaceCollisionHandler(SITH_THING_ACTOR, sithActor_SurfaceCollisionHandler);
    sithCollision_AddSurfaceCollisionHandler(SITH_THING_WEAPON, sithWeapon_SurfaceCollisionHandler);

    sithCollision_initted = 1;
    return 1;
}

int sithCollision_Shutdown()
{
    int result; // eax

    result = sithCollision_initted;
    if ( sithCollision_initted )
        sithCollision_initted = 0;
    return result;
}

void sithCollision_AddCollisionHandler(int type1, int type2, sithCollision_collisionHandler_t pProcessFunc, sithCollision_searchHandler_t a4)
{
    int idx = type2 + 12 * type1;
    sithCollision_collisionHandlers[idx].handler = pProcessFunc;
    sithCollision_collisionHandlers[idx].pUnknownFunc = a4;
    sithCollision_collisionHandlers[idx].bDifferentTypHandler = 0;
    if ( type1 != type2 )
    {
        idx = type1 + 12 * type2;
        sithCollision_collisionHandlers[idx].handler = pProcessFunc;
        sithCollision_collisionHandlers[idx].pUnknownFunc = a4;
        sithCollision_collisionHandlers[idx].bDifferentTypHandler = 1;
    }
}

void sithCollision_AddSurfaceCollisionHandler(int type, sithCollisionHitHandler_t a2)
{
    sithCollision_aThingSurfaceCollideResults[type] = a2;
}

SithCollision* sithCollision_PopStack()
{
    SithCollision* retVal = NULL;
    flex_t maxDist = 3.4e38;
    
    for (int i = 0; i < sithCollision_aNumStackCollisions[sithCollision_searchStackIdx]; i++)
    {
        SithCollision* iter = &sithCollision_aCollisions[sithCollision_searchStackIdx].collisions[i];
        if ( !iter->bEnumerated )
        {
            if ( maxDist <= iter->distance )
            {
                if ( maxDist == iter->distance && retVal->type & (SITHCOLLISION_THINGTOUCH | SITHCOLLISION_THINGCROSS) && iter->type & SITHCOLLISION_THINGADJOINCROSS ) // TODO enums
                    retVal = iter;
            }
            else
            {
                maxDist = iter->distance;
                retVal = iter;
            }
        }
    }

    if ( retVal )
    {
        retVal->bEnumerated = 1;
        return retVal;
    }
    else
    {
        sithCollision_aNumStackCollisions[sithCollision_searchStackIdx] = 0;
        sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx] = 0;
        return NULL;
    }
}

flex_t sithCollision_SearchForCollisions(SithSector *pStartSector, SithThing *pThing, const rdVector3 *pStartPos, const rdVector3 *pMoveNorm, flex_t moveDist, flex_t radius, int flags)
{
    SithCollision *i; // ebp
    SithSector *pSurfAdjSector; // esi
    unsigned int num; // eax
    unsigned int chk; // edi
    unsigned int v17; // edx
    unsigned int v18; // ebp
    SithSector *j; // eax
    SithSurfaceAdjoin *pAdjoin; // ebx
    SithSector *pAdjoinSector; // esi
    SithSector *v24; // edx
    unsigned int v26; // [esp+10h] [ebp-8h]
    flex_t curMoveDist; // [esp+2Ch] [ebp+14h]


    sithCollision_searchStackIdx++;
    sithCollision_aNumStackCollisions[sithCollision_searchStackIdx] = 0;
    sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx] = 1;
    curMoveDist = moveDist;
    sithCollision_apSearchedSectors[sithCollision_searchStackIdx].aSectors[0] = pStartSector;

    if (!pStartSector) {
        jk_printf("OpenJKDF2 WARN: sithCollision_SearchForCollisions received NULL pStartSector!\n");
        return 0.0f;
    }

    if ( (flags & RAYCAST_1) == 0 )
        curMoveDist = sithCollision_SearchForThingCollisions(pStartSector, pThing, pStartPos, pMoveNorm, moveDist, radius, flags);
    sithCollision_SearchForSurfaceCollisions(pStartSector, pStartPos, pMoveNorm, curMoveDist, radius, flags);

    v26 = 0;
    for ( i = sithCollision_aCollisions[sithCollision_searchStackIdx].collisions; v26 < sithCollision_aNumStackCollisions[sithCollision_searchStackIdx]; ++v26 )
    {
        if ( i->type == SITHCOLLISION_ADJOINTOUCH )
        {
            if ( (flags & RAYCAST_400) != 0 || i->distance <= (flex_d_t)curMoveDist )
            {
                pSurfAdjSector = i->surface->pAdjoin->sector;
                num = sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx];
                for (chk = 0; chk < num; chk++)
                {
                    if ( sithCollision_apSearchedSectors[sithCollision_searchStackIdx].aSectors[chk] == pSurfAdjSector )
                        break;
                }
                
                if ( chk >= num && num != 64)
                {
                    sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx] = num + 1;
                    sithCollision_apSearchedSectors[sithCollision_searchStackIdx].aSectors[num] = pSurfAdjSector;
                    if ( (flags & RAYCAST_1) == 0 )
                        curMoveDist = sithCollision_SearchForThingCollisions(pSurfAdjSector, pThing, pStartPos, pMoveNorm, curMoveDist, radius, flags);
                    sithCollision_SearchForSurfaceCollisions(pSurfAdjSector, pStartPos, pMoveNorm, curMoveDist, radius, flags);
                }
            }
            i->bEnumerated = 1;
        }
        ++i;
    }
    if ( curMoveDist != 0.0 && (flags & RAYCAST_800) != 0 )
    {
        v17 = sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx];
        for (v18 = 0; v18 < v17; v18++)
        {
            j = sithCollision_apSearchedSectors[sithCollision_searchStackIdx].aSectors[v18];
            for (pAdjoin = j->adjoins; pAdjoin != NULL; pAdjoin = pAdjoin->next)
            {
                if (!(pAdjoin->flags & SITHSURF_ADJOIN_ALLOW_MOVEMENT)) continue;

                pAdjoinSector = pAdjoin->sector;
                if (!pAdjoinSector->pFirstThingInSector) continue;
                
                num = sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx];
                for (chk = 0; chk < num; chk++)
                {
                    v24 = sithCollision_apSearchedSectors[sithCollision_searchStackIdx].aSectors[chk];
                    if ( v24 == pAdjoinSector )
                        break;
                }

                if (chk >= num && num != 64)
                {
                    sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx] = num + 1;
                    sithCollision_apSearchedSectors[sithCollision_searchStackIdx].aSectors[num] = pAdjoinSector;
                    curMoveDist = sithCollision_SearchForThingCollisions(pAdjoinSector, pThing, pStartPos, pMoveNorm, curMoveDist, radius, flags);
                }
            }
        }
    }
    return curMoveDist;
}

void sithCollision_DecreaseStackLevel()
{
    --sithCollision_searchStackIdx;
}

flex_t sithCollision_SearchForThingCollisions(SithSector *pSector, SithThing *pMeshCollided, const rdVector3 *a2, const rdVector3 *a3, flex_t a4, flex_t range, int flags)
{
    SithThing *v7; // esi
    SithThing *v8; // ebp
    int v9; // ebx
    int v10; // eax
    SithThing *v13; // ecx
    SithThing *v14; // eax
    SithThing *v15; // ecx
    SithThing *v16; // eax
    int v19; // eax
    rdFace *v21; // ebx
    int v22; // edx
    flex_t v23; // st7
    SithCollision *v24; // ecx
    rdMesh *senderMesh; // edx
    sithCollision_searchHandler_t handler;
    int v27; // eax
    rdFace *a10; // [esp+4h] [ebp-18h] BYREF
    rdVector3 a11; // [esp+10h] [ebp-Ch] BYREF

    senderMesh = 0;
    a10 = 0;
    v7 = pSector->pFirstThingInSector;
    if ( v7 )
    {
        v8 = pMeshCollided;
        v10 = flags & RAYCAST_8;
        while (1)
        {
            if ( (!v10 || (v7->flags & SITH_TF_80))
              && ((flags & RAYCAST_10) == 0 || (v7->flags & SITH_TF_STANDABLE) != 0)
              && v7->collide
              && (v7->flags & (SITH_TF_DISABLED|SITH_TF_DESTROYED)) == 0
              && ((flags & RAYCAST_2000) == 0 || v7->type == SITH_THING_COG) )
            {
                if ( !v8 )
                    goto LABEL_41;
                if ( v8 != v7 )
                {
                    if ( sithCollision_collisionHandlers[12 * v8->type + v7->type].handler )
                    {
                        if ( (v8->flags & SITH_TF_DEAD) == 0
                          && (v7->flags & SITH_TF_DEAD) == 0
                          && (v8->type != SITH_THING_WEAPON
                           || (v8->actorParams.flags & SITH_AF_CANROTATEHEAD) == 0
                           || ((v13 = v8->pParent) == 0 || (v14 = v7->pParent) == 0 || v13 != v14 || v8->parentSignature != v7->parentSignature)
                           && (v13 != v7 || v8->parentSignature != v7->signature))
                          && (v7->type != SITH_THING_WEAPON
                           || (v7->actorParams.flags & SITH_AF_CANROTATEHEAD) == 0
                           || ((v15 = v7->pParent) == 0 || (v16 = v8->pParent) == 0 || v15 != v16 || v7->parentSignature != v8->parentSignature)
                           && (v15 != v8 || v7->parentSignature != v8->signature)) )
                        {
                            if ( (v8->attach_flags & (SITH_ATTACH_THINGFACE | SITH_ATTACH_THING)) == 0 || v8->attachedThing != v7 || (v8->attach_flags & SITH_ATTACH_NOMOVE) == 0 && (flags & RAYCAST_40) == 0 )
                            {
                                if ( (v7->attach_flags & (SITH_ATTACH_THINGFACE | SITH_ATTACH_THING)) == 0 || v7->attachedThing != v8 || (v7->attach_flags & SITH_ATTACH_NOMOVE) == 0 && (flags & RAYCAST_40) == 0 )
                                {
LABEL_41:
                                    v19 = sithIntersect_CheckSphereThingIntersection(v8, a2, a3, a4, range, v7, flags, &v23, &senderMesh, &a10, &a11);
                                    if ( v19 )
                                    {
                                        v21 = a10;
                                        v22 = sithCollision_aNumStackCollisions[sithCollision_searchStackIdx];
                                        if ( v22 != 128 )
                                        {
                                            v19 |= SITHCOLLISION_THING;
                                            sithCollision_aNumStackCollisions[sithCollision_searchStackIdx] = v22 + 1;
                                            v24 = &sithCollision_aCollisions[sithCollision_searchStackIdx].collisions[v22];
                                            v24->surface = 0;
                                            v24->bEnumerated = 0;
                                            v24->type = v19;
                                            v24->distance = v23;
                                            v24->pThingCollided = v7;
                                            v24->pMeshCollided = senderMesh;
                                            v24->face = v21;
                                            rdVector_Copy3(&v24->hitNorm, &a11);
                                        }
                                        if ( v8 )
                                        {
                                            handler = sithCollision_collisionHandlers[12 * v8->type + v7->type].pUnknownFunc;
                                            if ( handler )
                                                v27 = handler(v8, v7);
                                            else
                                                v27 = 0;
                                            if ( v27 )
                                                a4 = v23;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Added: Prevent deadlocks in some conditions
            if (v7->pNextThingInSector == v7) break;
            v7 = v7->pNextThingInSector;
            if ( !v7 )
                break;
        }
    }
    return a4;
}

void sithCollision_SearchForSurfaceCollisions(SithSector *sector, const rdVector3 *vec1, const rdVector3 *vec2, flex_t a4, flex_t a5, int raycastFlags)
{
    SithSurface *v12; // esi
    SithSurfaceAdjoin *v15; // eax
    unsigned int v17; // ecx
    unsigned int v18; // edi
    SithSector **v19; // eax
    int v20; // ecx
    flex_d_t v21; // st7
    SithCollision *v23; // eax
    int v24; // ecx
    unsigned int v25; // edi
    unsigned int v26; // edx
    SithSector **v27; // eax
    int v28; // edx
    flex_d_t v29; // st7
    SithCollision *v31; // eax
    int v32; // edx
    flex_d_t v33; // st7
    SithCollision *v34; // eax
    rdVector3 *v35; // ecx
    int v36; // ecx
    flex_d_t v37; // st7
    int v38; // edx
    SithCollision *v40; // eax
    int v42; // [esp+0h] [ebp-40h] BYREF
    flex_t a7; // [esp+10h] [ebp-30h] BYREF
    int v47; // [esp+20h] [ebp-20h]
    flex_t v48; // [esp+24h] [ebp-1Ch] BYREF
    rdVector3 pushVel; // [esp+34h] [ebp-Ch] BYREF
    rdVector3 tmp;
    
    // Added: nullptr check
    //if (!sector) return;

    rdVector_Copy3(&tmp, vec1);
    rdVector_ScaleAdd3Acc(&tmp, vec2, a4);

    if(sithIntersect_IsSphereInSectorBox(&tmp, a5, sector))
    {
        return;
    }

    for (v47 = 0; v47 < sector->numSurfaces; v47++)
    {
        v12 = &sector->surfaces[v47];
        v15 = v12->pAdjoin;
        if ( (v12->flags & SITH_SURFACE_HAS_COLLISION) == 0 && !v15 )
            continue;

        if ( !v15 )
        {
LABEL_46:
            if ( (raycastFlags & RAYCAST_4) == 0 && ((raycastFlags & RAYCAST_10) == 0 || (v12->flags & SITH_SURFACE_FLOOR) != 0) )
            {
                v35 = sithWorld_g_pCurrentWorld->aVertices;
                
                if ( rdMath_DistancePointToPlane(&tmp, &v12->surfaceInfo.face.normal, &v35[*v12->surfaceInfo.face.vertexPosIdx]) <= a5 )
                {
                    v36 = sithIntersect_CheckSphereFaceIntersectionEx(vec1, vec2, a4, a5, &v12->surfaceInfo.face, v35, &a7, &pushVel, raycastFlags);
                    if ( v36 )
                    {
                        if ( (raycastFlags & RAYCAST_400) != 0 || rdVector_Dot3(vec2, &pushVel) < 0.0 )
                        {
                            v37 = a7;
                            v38 = sithCollision_aNumStackCollisions[sithCollision_searchStackIdx];
                            if ( v38 != 128 )
                            {
                                sithCollision_aNumStackCollisions[sithCollision_searchStackIdx] = v38 + 1;
                                v40 = &sithCollision_aCollisions[sithCollision_searchStackIdx].collisions[v38];
                                v40->pThingCollided = 0;
                                v40->bEnumerated = 0;
                                v40->type = v36 | SITHCOLLISION_WORLD;
                                v40->distance = v37;
                                v40->surface = v12;
                                if ( &v42 != (int *)-52 )
                                    v40->hitNorm = pushVel;
                            }
                        }
                    }
                }
            }
            continue;
        }

        if ( (raycastFlags & RAYCAST_4) == 0 )
        {
            if ( (raycastFlags & (RAYCAST_1000 | RAYCAST_100)) != 0 && (v15->flags & SITHSURF_ADJOIN_VISIBLE) == 0 )
                goto LABEL_46;
            if ( (raycastFlags & RAYCAST_200) != 0 )
            {
                if ( (raycastFlags & RAYCAST_100) != 0 )
                    goto LABEL_22;
                if ( (v15->flags & SITHSURF_ADJOIN_ALLOW_AI_ONLY) != 0 )
                    goto LABEL_46;
            }
            if ( (raycastFlags & RAYCAST_100) == 0 && (v15->flags & SITHSURF_ADJOIN_ALLOW_MOVEMENT) == 0 )
                goto LABEL_46;
        }
LABEL_22:
        // Standing?
        if ( sithIntersect_CheckSphereFaceIntersection(vec1, vec2, a4, a5, &v12->surfaceInfo, sithWorld_g_pCurrentWorld->aVertices, &a7, raycastFlags) )
        {
            if ( !(raycastFlags & RAYCAST_4) || (raycastFlags & RAYCAST_1) == 0 )
            {
                v17 = 0;
                v18 = sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx];
                if ( v18 )
                {
                    v19 = sithCollision_apSearchedSectors[sithCollision_searchStackIdx].aSectors;
                    while ( *v19 != v15->sector )
                    {
                        ++v17;
                        ++v19;
                        if ( v17 >= v18 )
                        {
                            goto LABEL_30;
                        }
                    }
                }
                else
                {
LABEL_30:
                    v20 = sithCollision_aNumStackCollisions[sithCollision_searchStackIdx];
                    v21 = a7;
                    if ( v20 != 128 )
                    {
                        sithCollision_aNumStackCollisions[sithCollision_searchStackIdx] = v20 + 1;
                        v23 = &sithCollision_aCollisions[sithCollision_searchStackIdx].collisions[v20];
                        v23->pThingCollided = 0;
                        v23->bEnumerated = 0;
                        v23->type = SITHCOLLISION_ADJOINTOUCH;
                        v23->distance = v21;
                        v23->surface = v12;
                    }
                }
            }

            // Falling?
            if ( (raycastFlags & RAYCAST_2) == 0 && sithIntersect_CheckSphereFaceIntersection(vec1, vec2, a4, 0.0, &v12->surfaceInfo, sithWorld_g_pCurrentWorld->aVertices, &v48, raycastFlags) )
            {
                v24 = sithCollision_searchStackIdx;
                if ( (raycastFlags & RAYCAST_4) && (raycastFlags & RAYCAST_1) != 0 )
                {
                    v25 = sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx];
                    v26 = 0;
                    if ( v25 )
                    {
                        v27 = sithCollision_apSearchedSectors[sithCollision_searchStackIdx].aSectors;
                        while ( *v27 != v15->sector )
                        {
                            ++v26;
                            ++v27;
                            if ( v26 >= v25 )
                                goto LABEL_42;
                        }
                    }
                    else
                    {
LABEL_42:
                        v28 = sithCollision_aNumStackCollisions[sithCollision_searchStackIdx];
                        v29 = a7;
                        if ( v28 != 128 )
                        {
                            sithCollision_aNumStackCollisions[sithCollision_searchStackIdx] = v28 + 1;
                            v31 = &sithCollision_aCollisions[sithCollision_searchStackIdx].collisions[v28];
                            v31->pThingCollided = 0;
                            v31->bEnumerated = 0;
                            v31->type = SITHCOLLISION_ADJOINTOUCH;
                            v31->distance = v29;
                            v31->surface = v12;
                        }
                    }
                }
                v32 = sithCollision_aNumStackCollisions[v24];
                v33 = v48;
                if ( v32 != 128 )
                {
                    sithCollision_aNumStackCollisions[v24] = v32 + 1;
                    v34 = &sithCollision_aCollisions[sithCollision_searchStackIdx].collisions[v32];
                    v34->pThingCollided = 0;
                    v34->bEnumerated = 0;
                    v34->type = SITHCOLLISION_ADJOINCROSS;
                    v34->distance = v33;
                    v34->surface = v12;
                }
            }
        }
    }
}

SithSector* sithCollision_FindSectorInRadius(SithSector *pStartSector, const rdVector3 *pStartPos, rdVector3 *pEndPos, flex_t a5)
{
    flex_d_t v4; // st6
    SithSector *result; // eax
    int v7; // edi
    sithCollisionSearchResult *v8; // ebx
    SithCollision *v9; // edx
    flex_d_t v10; // st7
    SithCollision *v11; // ecx
    int v12; // esi
    rdVector3 a1; // [esp+8h] [ebp-Ch] BYREF
    flex_t a3a; // [esp+1Ch] [ebp+8h]

    if ( sithIntersect_IsSphereInSector(pEndPos, 0.0, pStartSector) )
        return pStartSector;
    rdVector_Sub3(&a1, pEndPos, pStartPos);
    a3a = rdVector_Normalize3Acc(&a1);
    sithCollision_SearchForCollisions(pStartSector, 0, pStartPos, &a1, a3a, a5, RAYCAST_1);
    v7 = sithCollision_searchStackIdx;
    v8 = &sithCollision_aCollisions[sithCollision_searchStackIdx];
    while ( 1 )
    {
        v9 = 0;
        v10 = 3.4e38;
        v11 = (SithCollision *)v8;
        if ( sithCollision_aNumStackCollisions[v7] )
        {
            v12 = sithCollision_aNumStackCollisions[v7];
            do
            {
                if ( !v11->bEnumerated )
                {
                    if ( v10 <= v11->distance )
                    {
                        if ( v10 == v11->distance && (v9 && v9->type & (SITHCOLLISION_THINGTOUCH | SITHCOLLISION_THINGCROSS)) != 0 && (v11->type & 4) != 0 ) // Added: v9 null check
                            v9 = v11;
                    }
                    else
                    {
                        v10 = v11->distance;
                        v9 = v11;
                    }
                }
                ++v11;
                --v12;
            }
            while ( v12 );
        }
        if ( v9 )
        {
            v9->bEnumerated = 1;
        }
        else
        {
            sithCollision_aNumStackCollisions[v7] = 0;
            sithCollision_aNumSearchedSectors[v7] = 0;
        }
        if ( !v9 )
            break;
        if ( (v9->type & SITHCOLLISION_ADJOINCROSS) == 0 )
        {
            rdVector_Copy3(pEndPos, pStartPos);
            rdVector_ScaleAdd3Acc(pEndPos, &a1, v9->distance);
            break;
        }
        pStartSector = v9->surface->pAdjoin->sector;
    }
    result = pStartSector;
    sithCollision_searchStackIdx = v7 - 1;
    return result;
}

void sithCollision_FallHurt(SithThing *thing, flex_t vel)
{
    flex_d_t v2; // st7

    v2 = (vel - 2.5) * (vel - 2.5) * 45.0;
    if ( v2 > 1.0 )
    {
        sithSoundClass_PlayModeRandom(thing, SITH_SC_HITDAMAGED);
        sithThing_DamageThing(thing, thing, v2, SITH_DAMAGE_FALL);
    }
}

void sithCollision_RotateThing(SithThing *thing, rdMatrix34 *orient)
{
    SithThing *i; // esi
    rdVector3 a1a; // [esp+18h] [ebp-Ch] BYREF
    rdVector3 tmp;

    rdMatrix_PreMultiply34(&thing->orient, orient);
    for ( i = thing->pAttachedThing; i; i = i->pNextAttachedThing )
    {
        rdVector_Sub3(&tmp, &i->position, &thing->position);
        rdVector_Copy3(&i->orient.scale, &tmp);
        sithCollision_RotateThing(i, orient);
        if ( (i->attach_flags & SITH_ATTACH_NOMOVE) == 0 )
        {
            rdVector_Sub3(&a1a, &i->orient.scale, &tmp);
            if ( !rdVector_IsZero3(&a1a) )
            {
                sithCollision_MoveThing(i, &a1a, rdVector_Normalize3Acc(&a1a), 0);
            }
        }
        rdVector_Zero3(&i->orient.scale);
    }
}

flex_t sithCollision_MoveThing(SithThing *pThing, rdVector3 *a2, flex_t a6, int flags)
{
    SithThing *v5; // ebp
    SithThing *v10; // esi
    flex_d_t v11; // st7
    flex_d_t v12; // st7
    //char v15; // c0
    int v16; // edi
    flex_t v17; // edx
    //int v18; // edx
    SithCollision *v19; // esi
    //flex_d_t v20; // st7
    //SithCollision *v21; // ecx
    int v22; // ebx
    flex_d_t v23; // st6
    flex_d_t v24; // st7
    flex_d_t v25; // st7
    flex_d_t v30; // st5
    SithThing *v34; // ecx
    int v35; // eax
    int v36; // eax
    SithSurface *v37; // eax
    flex_d_t v44; // st7
    //char v46; // c3
    //char v49; // c0
    //char v52; // c0
    SithThing *i; // esi
    int v61; // eax
    SithSurface *amount; // [esp+0h] [ebp-54h]
    flex_t v64; // [esp+18h] [ebp-3Ch]
    flex_t v65; // [esp+1Ch] [ebp-38h]
    unsigned int v66; // [esp+20h] [ebp-34h]
    rdVector3 direction; // [esp+24h] [ebp-30h] BYREF
    rdVector3 posCopy;
    rdVector3 out; // [esp+3Ch] [ebp-18h] BYREF
    rdVector3 v72; // [esp+48h] [ebp-Ch] BYREF
    SithSector* sectTmp;

    v64 = 0.0;
    v65 = 0.0;
    v66 = 0;
    if ( a6 <= 0.0 )
        return 0.0;
    v5 = pThing;
    if (pThing->collide == SITH_COLLIDE_NONE)
    {
        flags |= RAYCAST_1 | RAYCAST_4;
    }
    if ( pThing->moveType == SITH_MT_PATH )
    {
        flags |= RAYCAST_4;
    }
    if ( pThing->type == SITH_THING_PLAYER )
    {
        flags |= RAYCAST_200;
    }
    if ( (flags & RAYCAST_1) == 0 )
    {
        flags |= RAYCAST_800;
    }
    v10 = pThing->pAttachedThing;
    for ( direction = *a2; v10; v10 = v10->pNextAttachedThing )
    {
        if (v10->attach_flags & SITH_ATTACH_NOMOVE)
            continue;

        v11 = sithCollision_MoveThing(v10, a2, a6, RAYCAST_40);
        if ( v11 >= a6 ) continue;
        
        if ( (v10->attach_flags & SITH_ATTACH_THINGFACE) != 0 )
        {
            rdMatrix_TransformVector34(&out, &v10->attachedSufaceInfo->face.normal, &v5->orient);
            v12 = stdMath_ClipNearZero(rdVector_Dot3(a2, &out));
            if ( v12 <= 0.0 ) {
                continue;
            }
        }

        if ( (v5->flags & SITH_TF_NOIMPACTDAMAGE) == 0 )
        {
            sithThing_DamageThing(v10, v5, (a6 - v11) * 100.0, SITH_DAMAGE_IMPACT);
        }
        a6 = v11;
    }
    sithCollision_dword_8B4BE4 = 0;
    sectTmp = v5->sector;
    if ( a6 == 0.0 )
    {
LABEL_78:
        if ( v66 < 4 )
            goto LABEL_81;
    }
    else
    {
        while ( v66 < 4 )
        {
            v16 = 0;
            rdVector_Copy3(&posCopy, &v5->position);
            out = direction;
            v17 = v5->moveSize;
            sectTmp = v5->sector;

            sithCollision_bDebugCollide = 0; // Added
            if (pThing == sithPlayer_g_pLocalPlayerThing) {
                sithCollision_bDebugCollide = 0;
            }
            sithCollision_SearchForCollisions(sectTmp, v5, &v5->position, &direction, a6, v17, flags);
            sithCollision_bDebugCollide = 0; // Added
            v36 = 0; // Added
            while ( 1 )
            {
                v19 = sithCollision_PopStack();
                if ( !v19 ) {
                    break;
                }

                if ( v19->distance != 0.0 )
                {
                    rdVector_Copy3(&v5->position, &posCopy);
                    rdVector_ScaleAdd3Acc(&v5->position, &direction, v19->distance);
                }
                if ( v19->distance >= (flex_d_t)a6 )
                {
                    rdVector_Zero3(&v5->field_268);
                }
                else
                {
                    v25 = a6 - v19->distance;
                    rdVector_Scale3(&v5->field_268, &direction, v25);
                    if ( v5->moveType == SITH_MT_PHYSICS
                      && (v5->physicsParams.flags & SITH_PF_SURFACEBOUNCE) != 0
                      && (!rdVector_IsZero3(&v5->physicsParams.gravityForce)) )
                    {
                        v30 = 1.0 - v19->distance / a6;
                        v65 = v30;
                        rdVector_ScaleAdd3Acc(&v5->physicsParams.vel, &v5->physicsParams.gravityForce, -v30);
                    }
                }
                if ( (v19->type & SITHCOLLISION_THING) != 0 )
                {
                    // Added: noclip
                    if (!(g_debugmodeFlags & DEBUGFLAG_NOCLIP) || pThing != sithPlayer_g_pLocalPlayerThing)
                    {
                        if (!(g_debugmodeFlags & DEBUGFLAG_NOCLIP) || ((g_debugmodeFlags & DEBUGFLAG_NOCLIP) && v19->pThingCollided != sithPlayer_g_pLocalPlayerThing))
                        {
                            v34 = v19->pThingCollided;
                            v35 = v34->type + 12 * v5->type;
                            if ( sithCollision_collisionHandlers[v35].bDifferentTypHandler )
                                v36 = sithCollision_collisionHandlers[v35].handler(v34, v5, v19, 1);
                            else
                                v36 = sithCollision_collisionHandlers[v35].handler(
                                          v5,
                                          v34,
                                          v19,
                                          0);
                        }
                    }
                    else {
                        v36 = 0; // Added: noclip
                    }
                }
                else if ( (v19->type & SITHCOLLISION_ADJOINCROSS) != 0 )
                {
                    v37 = v19->surface;
                    rdVector_Copy3(&v72, &v5->position);
                    if ( (v37->flags & SITH_SURFACE_COG_LINKED) != 0 )
                        sithCog_SurfaceSendMessage(v37, v5, 8);
                    sithThing_SetSector(v5, v19->surface->pAdjoin->sector, 0);
                    v36 = _memcmp(&v72, &v5->position, sizeof(rdVector3)) != 0;
                }
                else
                {
                    // Added: noclip
                    if (!(g_debugmodeFlags & DEBUGFLAG_NOCLIP) || pThing != sithPlayer_g_pLocalPlayerThing)
                    {
                        amount = v19->surface;
                        if ( sithCollision_aThingSurfaceCollideResults[v5->type] )
                            v36 = sithCollision_aThingSurfaceCollideResults[v5->type](v5, amount, v19);
                        else
                            v36 = sithCollision_HandleThingHitSurface(v5, amount, v19);
                    }
                    else {
                        v36 = 0; // Added: noclip
                    }
                }
                v16 = v36;
                if ( v65 != 0.0 && v5->moveType == SITH_MT_PHYSICS) // Added: physics check
                {
                    rdVector_Scale3(&v5->field_268, &v5->physicsParams.vel, v65 * sithTime_g_frameTimeFlex);
                    v65 = 0.0;
                }
                if ( v36 )
                {
                    break;
                }
            }
            sithCollision_DecreaseStackLevel();

            // Added: noclip
            if ((g_debugmodeFlags & DEBUGFLAG_NOCLIP) && pThing == sithPlayer_g_pLocalPlayerThing) {
                v16 = 0;
            }

            if ( v16 )
            {
                v64 = v19->distance + v64;
                a6 = 0.0;
                if (!rdVector_IsZero3(&v5->field_268))
                    a6 = stdMath_ClipNearZero(rdVector_Normalize3(&direction, &v5->field_268));
                ++v66;
            }
            else
            {
                v44 = v64 + a6;
                rdVector_Copy3(&v5->position, &posCopy);
                rdVector_ScaleAdd3Acc(&v5->position, &direction, a6);
                rdVector_Zero3(&v5->field_268);
                a6 = 0.0;
                v64 = v44;
            }
            if ( (v5->flags & 2) != 0 )
                return v64;
            if ( a6 == 0.0 )
                goto LABEL_78;
        }
    }

    // Added: noclip
    if (!(g_debugmodeFlags & DEBUGFLAG_NOCLIP) || pThing != sithPlayer_g_pLocalPlayerThing)
    {
        if ( v5->moveType == SITH_MT_PHYSICS )
            sithPhysics_ResetThingMovement(v5);
    }
LABEL_81:
    
    v64 = stdMath_ClipNearZero(v64);
    if ( v5->collide && v5->moveType == SITH_MT_PHYSICS && !sithIntersect_IsSphereInSector(&v5->position, 0.0, v5->sector) )
    {
        // Added: noclip
        if (!(g_debugmodeFlags & DEBUGFLAG_NOCLIP) || pThing != sithPlayer_g_pLocalPlayerThing)
        {
            rdVector_Copy3(&v5->position, &posCopy);
            rdVector_Copy3(&direction, &out);
            sithThing_SetSector(v5, sectTmp, 0);
            if ( v5->msecLifeLeft )
                sithThing_DestroyThing(v5);
        }
        else {
            for (int i = 0; i < sithWorld_g_pCurrentWorld->numSectors; i++)
            {
                int found = 0;
                if (sithIntersect_IsSphereInSector(&v5->position, 0.0, &sithWorld_g_pCurrentWorld->aSectors[i]))
                {
                    found = 1;
                    sithPlayer_bNoClippingRend = 0;
                    sithThing_SetSector(v5, &sithWorld_g_pCurrentWorld->aSectors[i], 0);
                    break;
                }

                if (!found)
                {
                    sithPlayer_bNoClippingRend = 1;
                }
            }
        }
    }

    for ( i = v5->pAttachedThing; i; i = i->pNextAttachedThing )
    {
        if (!(i->attach_flags & SITH_ATTACH_NOMOVE)) continue;
        rdMatrix_TransformVector34(&i->position, &i->field_4C, &v5->orient);
        rdVector_Add3Acc(&i->position, &v5->position);
        if ( i->sector != v5->sector )
            sithThing_SetSector(i, v5->sector, 0);
    }
    if ( v5->moveType == SITH_MT_PHYSICS )
    {
        if ( v64 == 0.0 )
            return 0.0;
        if (!(flags & RAYCAST_40))
        {
            // A floor-sticking thing only re-finds/attaches to the floor when it's
            // descending slowly, i.e. vel.z in [-2.0, 0.2].
            if ( (v5->attach_flags) != 0 && !(v5->attach_flags & SITH_ATTACH_NOMOVE)
              || (v5->physicsParams.flags & SITH_PF_FLOORSTICK) != 0
              && (v5->physicsParams.vel.z >= -2.0 && v5->physicsParams.vel.z <= 0.2) )
            {
                sithPhysics_FindFloor(v5, 0);
            }
        }
    }
    return v64;
}

int sithCollision_HandleThingHitSurface(SithThing *thing, SithSurface *surface, SithCollision *a3)
{
    SithThing *v3; // esi
    flex_t a1a; // [esp+Ch] [ebp+4h]

    v3 = thing;
    if ( thing->moveType != SITH_MT_PHYSICS )
        return 0;
    a1a = -rdVector_Dot3(&a3->hitNorm, &thing->physicsParams.vel);

    if ( !sithCollision_CollideHurt(thing, &a3->hitNorm, a3->distance, surface->flags & SITH_SURFACE_80) )
        return 0;

    if ( (surface->flags & SITH_SURFACE_COG_LINKED) != 0 && (v3->flags & SITH_TF_INVULN) == 0 && surface->surfaceInfo.lastTouchedMs + 500 <= sithTime_g_clockTime )
    {
        surface->surfaceInfo.lastTouchedMs = sithTime_g_clockTime;
        sithCog_SurfaceSendMessage(surface, v3, SITH_MESSAGE_TOUCHED);
    }
    if ( a1a > 0.15000001 )
    {
        if ( a1a > 1.0 )
            a1a = 1.0;
        if ( (surface->flags & SITH_SURFACE_METAL) != 0 )
        {
            sithSoundClass_PlayModeFirstEx(v3, SITH_SC_HITMETAL, a1a);
            return 1;
        }
        sithSoundClass_PlayModeFirstEx(v3, SITH_SC_HITHARD, a1a);
    }
    return 1;
}

int sithCollision_ThingCollisionHandler(SithThing *thing1, SithThing *thing2, SithCollision *a3, int isInverse)
{
    SithThing *v4; // esi
    SithThing *v5; // edi
    flex_d_t v6; // st6
    //char v9; // c0
    flex_d_t v11; // st7
    //char v14; // c0
    flex_d_t v15; // st7
    flex_t a3a; // [esp+0h] [ebp-38h]
    rdVector3 a2; // [esp+14h] [ebp-24h] BYREF
    rdVector3 forceVec; // [esp+20h] [ebp-18h] BYREF
    rdVector3 v19; // [esp+2Ch] [ebp-Ch] BYREF
    flex_t senderb; // [esp+3Ch] [ebp+4h]
    flex_t pMeshCollided; // [esp+3Ch] [ebp+4h]
    flex_t sendera; // [esp+3Ch] [ebp+4h]
    flex_t a1a; // [esp+40h] [ebp+8h]

    if ( isInverse )
    {
        v4 = thing2;
        v5 = thing1;
    }
    else
    {
        v4 = thing1;
        v5 = thing2;
    }
    a2 = a3->hitNorm;

    if ( (v4->flags & SITH_TF_CAPTURED) != 0 && (v4->flags & SITH_TF_INVULN) == 0 )
        sithCog_ThingSendMessage(v4, v5, SITH_MESSAGE_TOUCHED);
    if ( (v5->flags & SITH_TF_CAPTURED) != 0 && (v4->flags & SITH_TF_INVULN) == 0 )
        sithCog_ThingSendMessage(v5, v4, SITH_MESSAGE_TOUCHED);

    if ( v4->moveType != SITH_MT_PHYSICS || v4->physicsParams.mass == 0.0 )
    {
        if ( v5->moveType != SITH_MT_PHYSICS || v5->physicsParams.mass == 0.0 )
            return 1;
        v11 = rdVector_Dot3(&v4->field_268, &a2);
        v11 = stdMath_ClipNearZero(v11);
        if ( v11 < 0.0 )
        {
            sendera = -v11 * 1.0001;
            rdVector_Neg3(&v19, &a2);
            v15 = sithCollision_MoveThing(v5, &v19, sendera, 0);
            if ( v15 < sendera )
            {
                if ( (v4->flags & SITH_TF_NOIMPACTDAMAGE) == 0 )
                {
                    a1a = v15;
                    a3a = (sendera - a1a) * 100.0;
                    sithThing_DamageThing(v5, v4, a3a, SITH_DAMAGE_IMPACT);
                }
                rdVector_Zero3(&v4->field_268);
            }
            return 1;
        }
        return 0;
    }
    if ( v5->moveType == SITH_MT_PHYSICS && v5->physicsParams.mass != 0.0 )
    {
        v6 = rdVector_Dot3(&v5->physicsParams.vel, &a2) - rdVector_Dot3(&v4->physicsParams.vel, &a2);
        v6 = stdMath_ClipNearZero(v6);
        if ( v6 <= 0.0 )
            return 0;

        if ( (v4->physicsParams.flags & SITH_PF_SURFACEBOUNCE) == 0 )
            v6 = v6 * 0.5;
        if ( (v5->physicsParams.flags & SITH_PF_SURFACEBOUNCE) == 0 )
            v6 = v6 * 0.5;
        
        // (2*mass^2) / (2*mass)
        senderb = (v5->physicsParams.mass * v4->physicsParams.mass + v5->physicsParams.mass * v4->physicsParams.mass)
                / (v5->physicsParams.mass + v4->physicsParams.mass);

        rdVector_Scale3(&forceVec, &a2, v6 * senderb);
        sithPhysics_ApplyForce(v4, &forceVec);
        rdVector_Neg3Acc(&forceVec);
        sithPhysics_ApplyForce(v5, &forceVec);
        return sithCollision_CollideHurt(v4, &a2, a3->distance, 0);
    }
    pMeshCollided = 0.0f;
    if (v4->moveType == SITH_MT_PHYSICS) // Added
        pMeshCollided = -rdVector_Dot3(&v4->physicsParams.vel, &a2);
    if ( !sithCollision_CollideHurt(v4, &a2, a3->distance, 0) )
        return 0;
    if ( pMeshCollided <= 0.15000001 )
        return 1;
    if ( pMeshCollided > 1.0 )
        pMeshCollided = 1.0;
    if ( (v5->flags & SITH_TF_METAL) != 0 )
        sithSoundClass_PlayModeFirstEx(v4, SITH_SC_HITMETAL, pMeshCollided);
    else
        sithSoundClass_PlayModeFirstEx(v4, SITH_SC_HITHARD, pMeshCollided);
    return 1;
}

int sithCollision_CollideHurt(SithThing *a1, rdVector3 *a2, flex_t a3, int a4)
{
    int result; // eax
    flex_d_t v10; // st6
    flex_d_t v19; // st7
    flex_d_t v22; // st7
    flex_d_t v26; // st7
    flex_d_t v31; // st6
    flex_d_t v32; // st7
    flex_d_t v33; // st5
    flex_d_t v35; // st7
    flex_d_t v36; // st7
    flex_d_t v39; // st7
    flex_d_t v40; // st7
    flex_t v43; // [esp+8h] [ebp-4h]
    flex_t a1a; // [esp+10h] [ebp+4h]
    flex_t amount; // [esp+14h] [ebp+8h]

    if ( a1->moveType != SITH_MT_PHYSICS )
        return 0;
    amount = -rdVector_Dot3(&a1->field_268, a2);
    a1a = stdMath_ClipNearZero(amount);
    if ( a1a <= 0.0 )
        return 0;
    v43 = 1.9;
    if ( (a1->physicsParams.flags & SITH_PF_SURFACEBOUNCE) == 0 )
        v43 = 1.0001;
    if ( a3 == 0.0 && sithCollision_dword_8B4BE4 )
    {
        if ( amount <= 0.0 )
        {
            result = 0;
        }
        else
        {
            v10 = -rdVector_Dot3(&a1->physicsParams.vel, a2);
            rdVector_ScaleAdd3Acc(&a1->field_268, a2, amount);
            if ( v10 > 0.0 )
            {
                rdVector_ScaleAdd3Acc(&a1->physicsParams.vel, a2, v10);
            }
            v19 = -rdVector_Dot3(a2, &sithCollision_collideHurtIdk);
            rdVector_ScaleAdd3Acc(&sithCollision_collideHurtIdk, a2, v19);
            rdVector_Normalize3Acc(&sithCollision_collideHurtIdk);
            v22 = -rdVector_Dot3(&a1->physicsParams.vel, &sithCollision_collideHurtIdk);
            if ( v22 > 0.0 )
            {
                rdVector_ScaleAdd3Acc(&a1->physicsParams.vel, &sithCollision_collideHurtIdk, v22);
            }
            v26 = -rdVector_Dot3(&a1->field_268, &sithCollision_collideHurtIdk);
            if ( v26 > 0.0 )
            {
                rdVector_ScaleAdd3Acc(&a1->field_268, &sithCollision_collideHurtIdk, v26);
            }
            result = 1;
        }
    }
    else
    {
        v31 = a1->physicsParams.vel.y * a2->y;
        v32 = a1->physicsParams.vel.x * a2->x;
        v33 = a1->physicsParams.vel.z * a2->z;
        sithCollision_dword_8B4BE4 = 1;
        sithCollision_collideHurtIdk.x = a2->x;
        sithCollision_collideHurtIdk.y = a2->y;
        sithCollision_collideHurtIdk.z = a2->z;
        v35 = -(v32 + v33 + v31);
        if ( v35 > 0.0 )
        {
            v36 = v43 * v35;
            rdVector_ScaleAdd3Acc(&a1->physicsParams.vel, a2, v36);
            if ( !a4 && v35 > 2.5 )
            {
                v39 = (v35 - 2.5) * (v35 - 2.5) * 45.0;
                //printf("%f %f, %f %f %f\n", v39, v35, a1->physicsParams.vel.x, a1->physicsParams.vel.y, a1->physicsParams.vel.z);
                if ( v39 > 1.0 )
                {
                    sithSoundClass_PlayModeRandom(a1, SITH_SC_HITDAMAGED);
                    sithThing_DamageThing(a1, a1, v39, SITH_DAMAGE_FALL);
                }
            }
        }
        v40 = v43 * a1a;
        rdVector_ScaleAdd3Acc(&a1->field_268, a2, v40);
        result = 1;
    }
    return result;
}

int sithCollision_HasLOS(SithThing *thing1, SithThing *thing2, int flag)
{
    int searchFlags; // edi
    int v4; // edi
    SithCollision *v5; // ebp
    flex_d_t v6; // st7
    SithCollision *v7; // edx
    SithCollision *v8; // ecx
    SithThing *v10; // edx
    int result; // eax
    int v12; // [esp+10h] [ebp-10h]
    rdVector3 a1a; // [esp+14h] [ebp-Ch] BYREF
    flex_t a6; // [esp+2Ch] [ebp+Ch]

    v12 = 1;
    searchFlags = RAYCAST_2000 | RAYCAST_100 | RAYCAST_20 | RAYCAST_2;
    if ( flag )
        searchFlags = RAYCAST_2000 | RAYCAST_20 | RAYCAST_2;
    rdVector_Sub3(&a1a, &thing2->position, &thing1->position);
    a6 = rdVector_Normalize3Acc(&a1a);
    sithCollision_SearchForCollisions(thing1->sector, 0, &thing1->position, &a1a, a6, 0.0, searchFlags);
    v4 = sithCollision_searchStackIdx;
    v5 = sithCollision_aCollisions[sithCollision_searchStackIdx].collisions;
    while ( 1 )
    {
        v6 = 3.4e38;
        v7 = 0;
        v8 = v5;
        for (int i = 0; i < sithCollision_aNumStackCollisions[v4]; i++)
        {
            if ( !v8->bEnumerated )
            {
                if ( v6 <= v8->distance )
                {
                    if ( v6 == v8->distance 
                        && (v7->type & (SITHCOLLISION_THINGTOUCH|SITHCOLLISION_THINGCROSS)) 
                        && (v8->type & SITHCOLLISION_THINGADJOINCROSS))
                        v7 = v8;
                }
                else
                {
                    v6 = v8->distance;
                    v7 = v8;
                }
            }
            ++v8;
        }
        if ( v7 )
        {
            v7->bEnumerated = 1;
        }
        else
        {
            sithCollision_aNumStackCollisions[v4] = 0;
            sithCollision_aNumSearchedSectors[v4] = 0;
        }
        if ( !v7 )
            break;
        if ( (v7->type & SITHCOLLISION_THING) != 0 )
        {
            v10 = v7->pThingCollided;
            if ( v10 == thing2 )
            {
                result = 1;
                sithCollision_searchStackIdx = v4 - 1;
                return result;
            }
            if ( v10 == thing1 )
                continue;
        }
        v12 = 0;
        break;
    }
    result = v12;
    sithCollision_searchStackIdx = v4 - 1;
    return result;
}

void sithCollision_sub_4E77A0(SithThing *thing, rdMatrix34 *a2)
{
    SithThing *v5; // edi
    rdVector3 a2a; // [esp+10h] [ebp-6Ch] BYREF
    rdMatrix34 out; // [esp+1Ch] [ebp-60h] BYREF
    rdMatrix34 mat1; // [esp+4Ch] [ebp-30h] BYREF
    flex_t a1a; // [esp+84h] [ebp+8h]

    if ( thing->pAttachedThing )
    {
        rdMatrix_Normalize34(a2);
        rdVector_Copy3(&a2->scale, &thing->position);
        rdVector_Copy3(&thing->orient.scale, &thing->position);
        rdMatrix_InvertOrtho34(&mat1, &thing->orient);
        v5 = thing->pAttachedThing;
        while ( v5 )
        {
            rdVector_Copy3(&v5->orient.scale, &v5->position);
            rdMatrix_Multiply34(&out, &mat1, &v5->orient);
            rdMatrix_PostMultiply34(&out, a2);
            rdVector_Sub3(&a2a, &out.scale, &v5->position);
            a1a = rdVector_Normalize3Acc(&a2a);
            rdVector_Zero3(&out.scale);
            if ( a1a != 0.0 )
            {
                sithCollision_MoveThing(v5, &a2a, a1a, RAYCAST_40);
            }
            sithCollision_sub_4E77A0(v5, &out);
            if ( v5->moveType == SITH_MT_PHYSICS )
            {
                v5->physicsParams.flags &= ~SITH_PF_100;
            }
            v5 = v5->pNextAttachedThing;
        }
    }
    else if ( (((jkPlayer_currentTickIdx & 0xFF) + (thing->idx & 0xFF)) & 7) == 0 )
    {
        rdMatrix_Normalize34(a2);
    }
    rdVector_Zero3(&a2->scale);
    stdPlatform_Memcpy32(&thing->orient, a2, sizeof(thing->orient)); // Added: word-safe (aThings may be in extram)
}

int sithCollision_ParticleAndActorCollisionHandler(SithThing *thing, SithThing *thing2, SithCollision *searchEnt, int isSolid)
{
    int result; // eax
    flex_t mass; // [esp+14h] [ebp+4h]

    flex_t tmp = 0.0; // Added 0.0, original game overwrites &searchEnt...

    // Added: check move type
    mass = (thing->moveType == SITH_MT_PHYSICS) ? thing->physicsParams.mass : (flex_t)0.0;

    if ( isSolid )
        return sithCollision_ThingCollisionHandler(thing, thing2, searchEnt, isSolid);

    if ( thing->moveType == SITH_MT_PHYSICS )
        tmp = -rdVector_Dot3(&searchEnt->hitNorm, &thing->physicsParams.vel);

    if (sithCollision_ThingCollisionHandler(thing, thing2, searchEnt, 0))
    {
        if ( tmp > 0.25 )
        {
            sithThing_DamageThing(thing2, thing, mass * 0.3 * tmp, SITH_DAMAGE_IMPACT);
        }
        return 1;
    }
    return 0;
}

// Find nearest collision result from search
static SithCollision* sithCollision_PopClosest()
{
    SithCollision *best = NULL;
    flex_t bestDist = 3.4e38f;
    int numResults = sithCollision_aNumStackCollisions[sithCollision_searchStackIdx];

    for (int i = 0; i < numResults; i++)
    {
        SithCollision *entry = &sithCollision_aCollisions[sithCollision_searchStackIdx].collisions[i];
        if ( !entry->bEnumerated )
        {
            if ( bestDist <= entry->distance )
            {
                if ( bestDist == entry->distance && best && (best->type & 0x18) && (entry->type & 4) )
                    best = entry;
            }
            else
            {
                bestDist = entry->distance;
                best = entry;
            }
        }
    }
    return best;
}

SithThing* sithCollision_RaycastFromCamera(rdVector3 *pos)
{
    rdVector3 dir;
    rdVector3 camPos;

    if ( !sithCamera_g_pCurCamera->sector )
        return NULL;

    camPos.x = pos->x - sithCamera_g_pCurCamera->offset.x;
    camPos.y = sithCamera_g_pCurCamera->lookPos.y;
    camPos.z = sithCamera_g_pCurCamera->offset.z - pos->y;

    rdMatrix_TransformPoint34Acc(&camPos, &sithCamera_g_pCurCamera->orient);

    rdVector_Sub3(&dir, &camPos, &sithCamera_g_pCurCamera->lookPos);
    rdVector_Normalize3Acc(&dir);

    sithCollision_SearchForCollisions(sithCamera_g_pCurCamera->sector, NULL,
        &sithCamera_g_pCurCamera->lookPos, &dir, 100.0f, 0.0f, 0x103);

    SithCollision *best = sithCollision_PopClosest();
    SithThing *result = NULL;
    if ( best )
    {
        best->bEnumerated = 1;
        result = best->pThingCollided;
    }

    sithCollision_aNumStackCollisions[sithCollision_searchStackIdx] = 0;
    sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx] = 0;
    sithCollision_searchStackIdx--;
    return result;
}

SithThing* sithCollision_RaycastSector(SithSector *sector, rdVector3 *startPos, rdVector3 *dir, flex_t dist, flex_t radius, uint32_t *pHitType)
{
    sithCollision_SearchForCollisions(sector, NULL, startPos, dir, dist, radius, 0x103);

    SithCollision *best = sithCollision_PopClosest();
    SithThing *result = NULL;
    if ( best )
    {
        best->bEnumerated = 1;
        *pHitType = best->type;
        result = best->pThingCollided;
    }

    sithCollision_aNumStackCollisions[sithCollision_searchStackIdx] = 0;
    sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx] = 0;
    sithCollision_searchStackIdx--;
    return result;
}

int sithCollision_CheckPathClear(SithSector *sector, rdVector3 *startPos, rdVector3 *endPos, flex_t radius)
{
    rdVector3 dir;
    rdVector_Sub3(&dir, endPos, startPos);
    flex_t dist = rdVector_Normalize3Acc(&dir);

    sithCollision_SearchForCollisions(sector, NULL, startPos, &dir, dist, radius, 0x12A);

    SithCollision *best = sithCollision_PopClosest();
    int result = 1;
    if ( best )
    {
        best->bEnumerated = 1;
        result = 0;
    }

    sithCollision_aNumStackCollisions[sithCollision_searchStackIdx] = 0;
    sithCollision_aNumSearchedSectors[sithCollision_searchStackIdx] = 0;
    sithCollision_searchStackIdx--;
    return result;
}
