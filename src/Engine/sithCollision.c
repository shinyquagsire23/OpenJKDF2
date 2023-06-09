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
#include "General/stdMath.h"
#include "Primitives/rdMath.h"
#include "jk.h"

static int sithCollision_initted = 0;

int sithCollision_bDebugCollide = 0;

int sithCollision_Startup()
{
    if ( sithCollision_initted )
        return 0;

    _memset(sithCollision_collisionHandlers, 0, 144 * sizeof(sithCollisionEntry)); // sizeof(sithCollision_collisionHandlers)
    _memset(sithCollision_funcList, 0, 12 * sizeof(int)); // sizeof(sithCollision_funcList)
    sithCollision_RegisterCollisionHandler(SITH_THING_ACTOR, SITH_THING_ACTOR, sithActor_ActorActorCollide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_ACTOR, SITH_THING_PLAYER, sithActor_ActorActorCollide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_ACTOR, SITH_THING_COG, sithActor_ActorActorCollide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_PLAYER, SITH_THING_PLAYER, sithCollision_DebrisDebrisCollide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_PLAYER, SITH_THING_COG, sithCollision_DebrisDebrisCollide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_DEBRIS, SITH_THING_ACTOR, sithCollision_DebrisPlayerCollide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_DEBRIS, SITH_THING_PLAYER, sithCollision_DebrisPlayerCollide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_DEBRIS, SITH_THING_DEBRIS, sithCollision_DebrisDebrisCollide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_WEAPON, SITH_THING_ACTOR, sithWeapon_Collide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_WEAPON, SITH_THING_PLAYER, sithWeapon_Collide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_WEAPON, SITH_THING_DEBRIS, sithWeapon_Collide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_WEAPON, SITH_THING_COG, sithWeapon_Collide, 0);
    sithCollision_RegisterCollisionHandler(SITH_THING_ITEM, SITH_THING_PLAYER, sithItem_Collide, 0);

    sithCollision_RegisterHitHandler(SITH_THING_ACTOR, (void*)sithActor_sub_4ED1D0);
    sithCollision_RegisterHitHandler(SITH_THING_WEAPON, sithWeapon_HitDebug);

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

void sithCollision_RegisterCollisionHandler(int type1, int type2, void* pProcessFunc, void* a4)
{
    int idx = type2 + 12 * type1;
    sithCollision_collisionHandlers[idx].handler = pProcessFunc;
    sithCollision_collisionHandlers[idx].search_handler = a4;
    sithCollision_collisionHandlers[idx].inverse = 0;
    if ( type1 != type2 )
    {
        idx = type1 + 12 * type2;
        sithCollision_collisionHandlers[idx].handler = pProcessFunc;
        sithCollision_collisionHandlers[idx].search_handler = a4;
        sithCollision_collisionHandlers[idx].inverse = 1;
    }
}

void sithCollision_RegisterHitHandler(int type, void* a2)
{
    sithCollision_funcList[type] = a2;
}

sithCollisionSearchEntry* sithCollision_NextSearchResult()
{
    sithCollisionSearchEntry* retVal = NULL;
    float maxDist = 3.4e38;
    
    for (int i = 0; i < sithCollision_searchNumResults[sithCollision_searchStackIdx]; i++)
    {
        sithCollisionSearchEntry* iter = &sithCollision_searchStack[sithCollision_searchStackIdx].collisions[i];
        if ( !iter->hasBeenEnumerated )
        {
            if ( maxDist <= iter->distance )
            {
                if ( maxDist == iter->distance && retVal->hitType & (SITHCOLLISION_THINGTOUCH | SITHCOLLISION_THINGCROSS) && iter->hitType & SITHCOLLISION_THINGADJOINCROSS ) // TODO enums
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
        retVal->hasBeenEnumerated = 1;
        return retVal;
    }
    else
    {
        sithCollision_searchNumResults[sithCollision_searchStackIdx] = 0;
        sithCollision_stackIdk[sithCollision_searchStackIdx] = 0;
        return NULL;
    }
}

float sithCollision_SearchRadiusForThings(sithSector *pStartSector, sithThing *pThing, const rdVector3 *pStartPos, const rdVector3 *pMoveNorm, float moveDist, float radius, int flags)
{
    float v10; // eax
    sithCollisionSearchEntry *i; // ebp
    sithSector *v13; // esi
    unsigned int v14; // eax
    unsigned int v15; // edi
    unsigned int v17; // edx
    unsigned int v18; // ebp
    sithSector *j; // eax
    sithAdjoin *v20; // ebx
    sithSector *v21; // esi
    unsigned int v22; // eax
    unsigned int v23; // edi
    sithSector *v24; // edx
    float v25; // [esp+10h] [ebp-8h]
    unsigned int v26; // [esp+10h] [ebp-8h]
    float a1a; // [esp+1Ch] [ebp+4h]
    float a5a; // [esp+2Ch] [ebp+14h]


    sithCollision_searchStackIdx++;
    sithCollision_searchNumResults[sithCollision_searchStackIdx] = 0;
    sithCollision_stackIdk[sithCollision_searchStackIdx] = 1;
    v25 = moveDist;
    sithCollision_stackSectors[sithCollision_searchStackIdx].sectors[0] = pStartSector;

    if (!pStartSector) {
        jk_printf("OpenJKDF2 WARN: sithCollision_SearchRadiusForThings received NULL pStartSector!\n");
        return 0.0f;
    }

    if ( (flags & RAYCAST_1) == 0 )
        v25 = sithCollision_UpdateSectorThingCollision(pStartSector, pThing, pStartPos, pMoveNorm, moveDist, radius, flags);
    sithCollision_sub_4E86D0(pStartSector, pStartPos, pMoveNorm, v25, radius, flags);

    v10 = v25;
    v26 = 0;
    a5a = v10;
    for ( i = sithCollision_searchStack[sithCollision_searchStackIdx].collisions; v26 < sithCollision_searchNumResults[sithCollision_searchStackIdx]; ++v26 )
    {
        if ( i->hitType == SITHCOLLISION_ADJOINTOUCH )
        {
            if ( (flags & RAYCAST_400) != 0 || i->distance <= (double)a5a )
            {
                v13 = i->surface->adjoin->sector;
                a1a = a5a;
                v14 = sithCollision_stackIdk[sithCollision_searchStackIdx];
                for (v15 = 0; v15 < v14; v15++)
                {
                    if ( sithCollision_stackSectors[sithCollision_searchStackIdx].sectors[v15] == v13 )
                        break;
                }
                
                if ( v15 >= v14 && v14 != 64)
                {
                    sithCollision_stackIdk[sithCollision_searchStackIdx] = v14 + 1;
                    sithCollision_stackSectors[sithCollision_searchStackIdx].sectors[v14] = v13;
                    if ( (flags & 1) == 0 )
                        a1a = sithCollision_UpdateSectorThingCollision(v13, pThing, pStartPos, pMoveNorm, a5a, radius, flags);
                    sithCollision_sub_4E86D0(v13, pStartPos, pMoveNorm, a1a, radius, flags);
                    a5a = a1a;
                }
            }
            i->hasBeenEnumerated = 1;
        }
        ++i;
    }
    if ( a5a != 0.0 && (flags & RAYCAST_800) != 0 )
    {
        v17 = sithCollision_stackIdk[sithCollision_searchStackIdx];
        for (v18 = 0; v18 < v17; v18++)
        {
            j = sithCollision_stackSectors[sithCollision_searchStackIdx].sectors[v18];
            for (v20 = j->adjoins; v20 != NULL; v20 = v20->next)
            {
                if (!(v20->flags & SITHSURF_ADJOIN_ALLOW_MOVEMENT)) continue;

                v21 = v20->sector;
                if (!v21->thingsList) continue;
                
                v22 = sithCollision_stackIdk[sithCollision_searchStackIdx];
                for (v23 = 0; v23 < v22; v23++)
                {
                    v24 = sithCollision_stackSectors[sithCollision_searchStackIdx].sectors[v23];
                    if ( v24 == v21 )
                        break;
                }

                if ( v23 >= v22 && v22 != 64)
                {
                    sithCollision_stackIdk[sithCollision_searchStackIdx] = v22 + 1;
                    sithCollision_stackSectors[sithCollision_searchStackIdx].sectors[v22] = v21;
                    a5a = sithCollision_UpdateSectorThingCollision(v21, pThing, pStartPos, pMoveNorm, a5a, radius, flags);
                }
            }
        }
    }
    return a5a;
}

void sithCollision_SearchClose()
{
    --sithCollision_searchStackIdx;
}

float sithCollision_UpdateSectorThingCollision(sithSector *pSector, sithThing *sender, const rdVector3 *a2, const rdVector3 *a3, float a4, float range, int flags)
{
    sithThing *v7; // esi
    sithThing *v8; // ebp
    int v9; // ebx
    int v10; // eax
    sithThing *v13; // ecx
    sithThing *v14; // eax
    sithThing *v15; // ecx
    sithThing *v16; // eax
    int v19; // eax
    rdFace *v21; // ebx
    int v22; // edx
    float v23; // st7
    sithCollisionSearchEntry *v24; // ecx
    rdMesh *senderMesh; // edx
    sithCollision_searchHandler_t handler;
    int v27; // eax
    rdFace *a10; // [esp+4h] [ebp-18h] BYREF
    rdVector3 a11; // [esp+10h] [ebp-Ch] BYREF

    senderMesh = 0;
    a10 = 0;
    v7 = pSector->thingsList;
    if ( v7 )
    {
        v8 = sender;
        v10 = flags & 8;
        while (1)
        {
            if ( (!v10 || (v7->thingflags & SITH_TF_80))
              && ((flags & RAYCAST_10) == 0 || (v7->thingflags & SITH_TF_STANDABLE) != 0)
              && v7->collide
              && (v7->thingflags & (SITH_TF_DISABLED|SITH_TF_WILLBEREMOVED)) == 0
              && ((flags & RAYCAST_2000) == 0 || v7->type == SITH_THING_COG) )
            {
                if ( !v8 )
                    goto LABEL_41;
                if ( v8 != v7 )
                {
                    if ( sithCollision_collisionHandlers[12 * v8->type + v7->type].handler )
                    {
                        if ( (v8->thingflags & SITH_TF_DEAD) == 0
                          && (v7->thingflags & SITH_TF_DEAD) == 0
                          && (v8->type != SITH_THING_WEAPON
                           || (v8->actorParams.typeflags & SITH_AF_CAN_ROTATE_HEAD) == 0
                           || ((v13 = v8->prev_thing) == 0 || (v14 = v7->prev_thing) == 0 || v13 != v14 || v8->child_signature != v7->child_signature)
                           && (v13 != v7 || v8->child_signature != v7->signature))
                          && (v7->type != SITH_THING_WEAPON
                           || (v7->actorParams.typeflags & SITH_AF_CAN_ROTATE_HEAD) == 0
                           || ((v15 = v7->prev_thing) == 0 || (v16 = v8->prev_thing) == 0 || v15 != v16 || v7->child_signature != v8->child_signature)
                           && (v15 != v8 || v7->child_signature != v8->signature)) )
                        {
                            if ( (v8->attach_flags & (SITH_ATTACH_THINGSURFACE | SITH_ATTACH_THING)) == 0 || v8->attachedThing != v7 || (v8->attach_flags & SITH_ATTACH_NO_MOVE) == 0 && (flags & RAYCAST_40) == 0 )
                            {
                                if ( (v7->attach_flags & (SITH_ATTACH_THINGSURFACE | SITH_ATTACH_THING)) == 0 || v7->attachedThing != v8 || (v7->attach_flags & SITH_ATTACH_NO_MOVE) == 0 && (flags & RAYCAST_40) == 0 )
                                {
LABEL_41:
                                    v19 = sithIntersect_CollideThings(v8, a2, a3, a4, range, v7, flags, &v23, &senderMesh, &a10, &a11);
                                    if ( v19 )
                                    {
                                        v21 = a10;
                                        v22 = sithCollision_searchNumResults[sithCollision_searchStackIdx];
                                        if ( v22 != 128 )
                                        {
                                            v19 |= SITHCOLLISION_THING;
                                            sithCollision_searchNumResults[sithCollision_searchStackIdx] = v22 + 1;
                                            v24 = &sithCollision_searchStack[sithCollision_searchStackIdx].collisions[v22];
                                            v24->surface = 0;
                                            v24->hasBeenEnumerated = 0;
                                            v24->hitType = v19;
                                            v24->distance = v23;
                                            v24->receiver = v7;
                                            v24->sender = senderMesh;
                                            v24->face = v21;
                                            rdVector_Copy3(&v24->hitNorm, &a11);
                                        }
                                        if ( v8 )
                                        {
                                            handler = sithCollision_collisionHandlers[12 * v8->type + v7->type].search_handler;
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
            if (v7->nextThing == v7) break;
            v7 = v7->nextThing;
            if ( !v7 )
                break;
        }
    }
    return a4;
}

void sithCollision_sub_4E86D0(sithSector *sector, const rdVector3 *vec1, const rdVector3 *vec2, float a4, float a5, int unk3Flags)
{
    sithSurface *v12; // esi
    sithAdjoin *v15; // eax
    unsigned int v17; // ecx
    unsigned int v18; // edi
    sithSector **v19; // eax
    int v20; // ecx
    double v21; // st7
    sithCollisionSearchEntry *v23; // eax
    int v24; // ecx
    unsigned int v25; // edi
    unsigned int v26; // edx
    sithSector **v27; // eax
    int v28; // edx
    double v29; // st7
    sithCollisionSearchEntry *v31; // eax
    int v32; // edx
    double v33; // st7
    sithCollisionSearchEntry *v34; // eax
    rdVector3 *v35; // ecx
    int v36; // ecx
    double v37; // st7
    int v38; // edx
    sithCollisionSearchEntry *v40; // eax
    int v42; // [esp+0h] [ebp-40h] BYREF
    float a7; // [esp+10h] [ebp-30h] BYREF
    int v47; // [esp+20h] [ebp-20h]
    float v48; // [esp+24h] [ebp-1Ch] BYREF
    rdVector3 pushVel; // [esp+34h] [ebp-Ch] BYREF
    rdVector3 tmp;
    
    // Added: nullptr check
    //if (!sector) return;

    rdVector_Copy3(&tmp, vec1);
    rdVector_MultAcc3(&tmp, vec2, a4);

    if(sithIntersect_IsSphereInSectorBox(&tmp, a5, sector))
    {
        return;
    }

    for (v47 = 0; v47 < sector->numSurfaces; v47++)
    {
        v12 = &sector->surfaces[v47];
        v15 = v12->adjoin;
        if ( (v12->surfaceFlags & SITH_SURFACE_HAS_COLLISION) == 0 && !v15 )
            continue;

        if ( !v15 )
        {
LABEL_46:
            if ( (unk3Flags & RAYCAST_4) == 0 && ((unk3Flags & RAYCAST_10) == 0 || (v12->surfaceFlags & SITH_SURFACE_FLOOR) != 0) )
            {
                v35 = sithWorld_pCurrentWorld->vertices;
                
                if ( rdMath_DistancePointToPlane(&tmp, &v12->surfaceInfo.face.normal, &v35[*v12->surfaceInfo.face.vertexPosIdx]) <= a5 )
                {
                    v36 = sithIntersect_sub_508D20(vec1, vec2, a4, a5, &v12->surfaceInfo.face, v35, &a7, &pushVel, unk3Flags);
                    if ( v36 )
                    {
                        if ( (unk3Flags & RAYCAST_400) != 0 || rdVector_Dot3(vec2, &pushVel) < 0.0 )
                        {
                            v37 = a7;
                            v38 = sithCollision_searchNumResults[sithCollision_searchStackIdx];
                            if ( v38 != 128 )
                            {
                                sithCollision_searchNumResults[sithCollision_searchStackIdx] = v38 + 1;
                                v40 = &sithCollision_searchStack[sithCollision_searchStackIdx].collisions[v38];
                                v40->receiver = 0;
                                v40->hasBeenEnumerated = 0;
                                v40->hitType = v36 | SITHCOLLISION_WORLD;
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

        if ( (unk3Flags & RAYCAST_4) == 0 )
        {
            if ( (unk3Flags & (RAYCAST_1000 | RAYCAST_100)) != 0 && (v15->flags & SITHSURF_ADJOIN_VISIBLE) == 0 )
                goto LABEL_46;
            if ( (unk3Flags & RAYCAST_200) != 0 )
            {
                if ( (unk3Flags & RAYCAST_100) != 0 )
                    goto LABEL_22;
                if ( (v15->flags & SITHSURF_ADJOIN_ALLOW_AI_ONLY) != 0 )
                    goto LABEL_46;
            }
            if ( (unk3Flags & RAYCAST_100) == 0 && (v15->flags & SITHSURF_ADJOIN_ALLOW_MOVEMENT) == 0 )
                goto LABEL_46;
        }
LABEL_22:
        // Standing?
        if ( sithIntersect_sub_5090B0(vec1, vec2, a4, a5, &v12->surfaceInfo, sithWorld_pCurrentWorld->vertices, &a7, unk3Flags) )
        {
            if ( !(unk3Flags & RAYCAST_4) || (unk3Flags & RAYCAST_1) == 0 )
            {
                v17 = 0;
                v18 = sithCollision_stackIdk[sithCollision_searchStackIdx];
                if ( v18 )
                {
                    v19 = sithCollision_stackSectors[sithCollision_searchStackIdx].sectors;
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
                    v20 = sithCollision_searchNumResults[sithCollision_searchStackIdx];
                    v21 = a7;
                    if ( v20 != 128 )
                    {
                        sithCollision_searchNumResults[sithCollision_searchStackIdx] = v20 + 1;
                        v23 = &sithCollision_searchStack[sithCollision_searchStackIdx].collisions[v20];
                        v23->receiver = 0;
                        v23->hasBeenEnumerated = 0;
                        v23->hitType = SITHCOLLISION_ADJOINTOUCH;
                        v23->distance = v21;
                        v23->surface = v12;
                    }
                }
            }

            // Falling?
            if ( (unk3Flags & RAYCAST_2) == 0 && sithIntersect_sub_5090B0(vec1, vec2, a4, 0.0, &v12->surfaceInfo, sithWorld_pCurrentWorld->vertices, &v48, unk3Flags) )
            {
                v24 = sithCollision_searchStackIdx;
                if ( (unk3Flags & RAYCAST_4) && (unk3Flags & RAYCAST_1) != 0 )
                {
                    v25 = sithCollision_stackIdk[sithCollision_searchStackIdx];
                    v26 = 0;
                    if ( v25 )
                    {
                        v27 = sithCollision_stackSectors[sithCollision_searchStackIdx].sectors;
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
                        v28 = sithCollision_searchNumResults[sithCollision_searchStackIdx];
                        v29 = a7;
                        if ( v28 != 128 )
                        {
                            sithCollision_searchNumResults[sithCollision_searchStackIdx] = v28 + 1;
                            v31 = &sithCollision_searchStack[sithCollision_searchStackIdx].collisions[v28];
                            v31->receiver = 0;
                            v31->hasBeenEnumerated = 0;
                            v31->hitType = SITHCOLLISION_ADJOINTOUCH;
                            v31->distance = v29;
                            v31->surface = v12;
                        }
                    }
                }
                v32 = sithCollision_searchNumResults[v24];
                v33 = v48;
                if ( v32 != 128 )
                {
                    sithCollision_searchNumResults[v24] = v32 + 1;
                    v34 = &sithCollision_searchStack[sithCollision_searchStackIdx].collisions[v32];
                    v34->receiver = 0;
                    v34->hasBeenEnumerated = 0;
                    v34->hitType = SITHCOLLISION_ADJOINCROSS;
                    v34->distance = v33;
                    v34->surface = v12;
                }
            }
        }
    }
}

sithSector* sithCollision_GetSectorLookAt(sithSector *pStartSector, const rdVector3 *pStartPos, rdVector3 *pEndPos, float a5)
{
    double v4; // st6
    sithSector *result; // eax
    int v7; // edi
    sithCollisionSearchResult *v8; // ebx
    sithCollisionSearchEntry *v9; // edx
    double v10; // st7
    sithCollisionSearchEntry *v11; // ecx
    int v12; // esi
    rdVector3 a1; // [esp+8h] [ebp-Ch] BYREF
    float a3a; // [esp+1Ch] [ebp+8h]

    if ( sithIntersect_IsSphereInSector(pEndPos, 0.0, pStartSector) )
        return pStartSector;
    rdVector_Sub3(&a1, pEndPos, pStartPos);
    a3a = rdVector_Normalize3Acc(&a1);
    sithCollision_SearchRadiusForThings(pStartSector, 0, pStartPos, &a1, a3a, a5, 1);
    v7 = sithCollision_searchStackIdx;
    v8 = &sithCollision_searchStack[sithCollision_searchStackIdx];
    while ( 1 )
    {
        v9 = 0;
        v10 = 3.4e38;
        v11 = (sithCollisionSearchEntry *)v8;
        if ( sithCollision_searchNumResults[v7] )
        {
            v12 = sithCollision_searchNumResults[v7];
            do
            {
                if ( !v11->hasBeenEnumerated )
                {
                    if ( v10 <= v11->distance )
                    {
                        if ( v10 == v11->distance && (v9->hitType & (SITHCOLLISION_THINGTOUCH | SITHCOLLISION_THINGCROSS)) != 0 && (v11->hitType & 4) != 0 )
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
            v9->hasBeenEnumerated = 1;
        }
        else
        {
            sithCollision_searchNumResults[v7] = 0;
            sithCollision_stackIdk[v7] = 0;
        }
        if ( !v9 )
            break;
        if ( (v9->hitType & SITHCOLLISION_ADJOINCROSS) == 0 )
        {
            rdVector_Copy3(pEndPos, pStartPos);
            rdVector_MultAcc3(pEndPos, &a1, v9->distance);
            break;
        }
        pStartSector = v9->surface->adjoin->sector;
    }
    result = pStartSector;
    sithCollision_searchStackIdx = v7 - 1;
    return result;
}

void sithCollision_FallHurt(sithThing *thing, float vel)
{
    double v2; // st7

    v2 = (vel - 2.5) * (vel - 2.5) * 45.0;
    if ( v2 > 1.0 )
    {
        sithSoundClass_PlayModeRandom(thing, SITH_SC_HITDAMAGED);
        sithThing_Damage(thing, thing, v2, SITH_DAMAGE_FALL);
    }
}

void sithCollision_sub_4E7670(sithThing *thing, rdMatrix34 *orient)
{
    sithThing *i; // esi
    rdVector3 a1a; // [esp+18h] [ebp-Ch] BYREF
    rdVector3 tmp;

    rdMatrix_PreMultiply34(&thing->lookOrientation, orient);
    for ( i = thing->attachedParentMaybe; i; i = i->childThing )
    {
        rdVector_Sub3(&tmp, &i->position, &thing->position);
        rdVector_Copy3(&i->lookOrientation.scale, &tmp);
        sithCollision_sub_4E7670(i, orient);
        if ( (i->attach_flags & SITH_ATTACH_NO_MOVE) == 0 )
        {
            rdVector_Sub3(&a1a, &i->lookOrientation.scale, &tmp);
            if ( !rdVector_IsZero3(&a1a) )
            {
                sithCollision_UpdateThingCollision(i, &a1a, rdVector_Normalize3Acc(&a1a), 0);
            }
        }
        rdVector_Zero3(&i->lookOrientation.scale);
    }
}

float sithCollision_UpdateThingCollision(sithThing *pThing, rdVector3 *a2, float a6, int a8)
{
    sithThing *v5; // ebp
    sithThing *v10; // esi
    double v11; // st7
    double v12; // st7
    //char v15; // c0
    int v16; // edi
    float v17; // edx
    //int v18; // edx
    sithCollisionSearchEntry *v19; // esi
    //double v20; // st7
    //sithCollisionSearchEntry *v21; // ecx
    int v22; // ebx
    double v23; // st6
    double v24; // st7
    double v25; // st7
    double v30; // st5
    sithThing *v34; // ecx
    int v35; // eax
    int v36; // eax
    sithSurface *v37; // eax
    double v44; // st7
    //char v46; // c3
    //char v49; // c0
    //char v52; // c0
    sithThing *i; // esi
    int v61; // eax
    sithSurface *amount; // [esp+0h] [ebp-54h]
    float v64; // [esp+18h] [ebp-3Ch]
    float v65; // [esp+1Ch] [ebp-38h]
    unsigned int v66; // [esp+20h] [ebp-34h]
    rdVector3 direction; // [esp+24h] [ebp-30h] BYREF
    rdVector3 posCopy;
    rdVector3 out; // [esp+3Ch] [ebp-18h] BYREF
    rdVector3 v72; // [esp+48h] [ebp-Ch] BYREF
    sithSector* sectTmp;

    v64 = 0.0;
    v65 = 0.0;
    v66 = 0;
    if ( a6 <= 0.0 )
        return 0.0;
    v5 = pThing;
    if ( !pThing->collide )
    {
        a8 |= 0x5;
    }
    if ( pThing->moveType == SITH_MT_PATH )
    {
        a8 |= 0x4;
    }
    if ( pThing->type == SITH_THING_PLAYER )
    {
        a8 |= 0x200;
    }
    if ( (a8 & 1) == 0 )
    {
        a8 |= 0x800;
    }
    v10 = pThing->attachedParentMaybe;
    for ( direction = *a2; v10; v10 = v10->childThing )
    {
        if (v10->attach_flags & SITH_ATTACH_NO_MOVE)
            continue;

        v11 = sithCollision_UpdateThingCollision(v10, a2, a6, 64);
        if ( v11 >= a6 ) continue;
        
        if ( (v10->attach_flags & SITH_ATTACH_THINGSURFACE) != 0 )
        {
            rdMatrix_TransformVector34(&out, &v10->attachedSufaceInfo->face.normal, &v5->lookOrientation);
            v12 = stdMath_ClipPrecision(rdVector_Dot3(a2, &out));
            if ( v12 <= 0.0 ) {
                continue;
            }
        }

        if ( (v5->thingflags & SITH_TF_NOIMPACTDAMAGE) == 0 )
        {
            sithThing_Damage(v10, v5, (a6 - v11) * 100.0, SITH_DAMAGE_IMPACT);
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
            if (pThing == sithPlayer_pLocalPlayerThing) {
                sithCollision_bDebugCollide = 0;
            }
            sithCollision_SearchRadiusForThings(sectTmp, v5, &v5->position, &direction, a6, v17, a8);
            sithCollision_bDebugCollide = 0; // Added
            v36 = 0; // Added
            while ( 1 )
            {
                v19 = sithCollision_NextSearchResult();
                if ( !v19 ) {
                    break;
                }

                if ( v19->distance != 0.0 )
                {
                    rdVector_Copy3(&v5->position, &posCopy);
                    rdVector_MultAcc3(&v5->position, &direction, v19->distance);
                }
                if ( v19->distance >= (double)a6 )
                {
                    rdVector_Zero3(&v5->field_268);
                }
                else
                {
                    v25 = a6 - v19->distance;
                    rdVector_Scale3(&v5->field_268, &direction, v25);
                    if ( v5->moveType == SITH_MT_PHYSICS
                      && (v5->physicsParams.physflags & SITH_PF_SURFACEBOUNCE) != 0
                      && (!rdVector_IsZero3(&v5->physicsParams.addedVelocity)) )
                    {
                        v30 = 1.0 - v19->distance / a6;
                        v65 = v30;
                        rdVector_MultAcc3(&v5->physicsParams.vel, &v5->physicsParams.addedVelocity, -v30);
                    }
                }
                if ( (v19->hitType & SITHCOLLISION_THING) != 0 )
                {
                    // Added: noclip
                    if (!(g_debugmodeFlags & DEBUGFLAG_NOCLIP) || pThing != sithPlayer_pLocalPlayerThing)
                    {
                        if (!(g_debugmodeFlags & DEBUGFLAG_NOCLIP) || ((g_debugmodeFlags & DEBUGFLAG_NOCLIP) && v19->receiver != sithPlayer_pLocalPlayerThing))
                        {
                            v34 = v19->receiver;
                            v35 = v34->type + 12 * v5->type;
                            if ( sithCollision_collisionHandlers[v35].inverse )
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
                else if ( (v19->hitType & SITHCOLLISION_ADJOINCROSS) != 0 )
                {
                    v37 = v19->surface;
                    rdVector_Copy3(&v72, &v5->position);
                    if ( (v37->surfaceFlags & SITH_SURFACE_COG_LINKED) != 0 )
                        sithCog_SendMessageFromSurface(v37, v5, 8);
                    sithThing_MoveToSector(v5, v19->surface->adjoin->sector, 0);
                    v36 = _memcmp(&v72, &v5->position, sizeof(rdVector3)) != 0;
                }
                else
                {
                    // Added: noclip
                    if (!(g_debugmodeFlags & DEBUGFLAG_NOCLIP) || pThing != sithPlayer_pLocalPlayerThing)
                    {
                        amount = v19->surface;
                        if ( sithCollision_funcList[v5->type] )
                            v36 = sithCollision_funcList[v5->type](v5, amount, v19);
                        else
                            v36 = sithCollision_DefaultHitHandler(v5, amount, v19);
                    }
                    else {
                        v36 = 0; // Added: noclip
                    }
                }
                v16 = v36;
                if ( v65 != 0.0 && v5->moveType == SITH_MT_PHYSICS) // Added: physics check
                {
                    rdVector_Scale3(&v5->field_268, &v5->physicsParams.vel, v65 * sithTime_deltaSeconds);
                    v65 = 0.0;
                }
                if ( v36 )
                {
                    break;
                }
            }
            sithCollision_SearchClose();

            // Added: noclip
            if ((g_debugmodeFlags & DEBUGFLAG_NOCLIP) && pThing == sithPlayer_pLocalPlayerThing) {
                v16 = 0;
            }

            if ( v16 )
            {
                v64 = v19->distance + v64;
                a6 = 0.0;
                if (!rdVector_IsZero3(&v5->field_268))
                    a6 = stdMath_ClipPrecision(rdVector_Normalize3(&direction, &v5->field_268));
                ++v66;
            }
            else
            {
                v44 = v64 + a6;
                rdVector_Copy3(&v5->position, &posCopy);
                rdVector_MultAcc3(&v5->position, &direction, a6);
                rdVector_Zero3(&v5->field_268);
                a6 = 0.0;
                v64 = v44;
            }
            if ( (v5->thingflags & 2) != 0 )
                return v64;
            if ( a6 == 0.0 )
                goto LABEL_78;
        }
    }

    // Added: noclip
    if (!(g_debugmodeFlags & DEBUGFLAG_NOCLIP) || pThing != sithPlayer_pLocalPlayerThing)
    {
        if ( v5->moveType == SITH_MT_PHYSICS )
            sithPhysics_ThingStop(v5);
    }
LABEL_81:
    
    v64 = stdMath_ClipPrecision(v64);
    if ( v5->collide && v5->moveType == SITH_MT_PHYSICS && !sithIntersect_IsSphereInSector(&v5->position, 0.0, v5->sector) )
    {
        // Added: noclip
        if (!(g_debugmodeFlags & DEBUGFLAG_NOCLIP) || pThing != sithPlayer_pLocalPlayerThing)
        {
            rdVector_Copy3(&v5->position, &posCopy);
            rdVector_Copy3(&direction, &out);
            sithThing_MoveToSector(v5, sectTmp, 0);
            if ( v5->lifeLeftMs )
                sithThing_Destroy(v5);
        }
        else {
            for (int i = 0; i < sithWorld_pCurrentWorld->numSectors; i++)
            {
                int found = 0;
                if (sithIntersect_IsSphereInSector(&v5->position, 0.0, &sithWorld_pCurrentWorld->sectors[i]))
                {
                    found = 1;
                    sithPlayer_bNoClippingRend = 0;
                    sithThing_MoveToSector(v5, &sithWorld_pCurrentWorld->sectors[i], 0);
                    break;
                }

                if (!found)
                {
                    sithPlayer_bNoClippingRend = 1;
                }
            }
        }
    }

    for ( i = v5->attachedParentMaybe; i; i = i->childThing )
    {
        if (!(i->attach_flags & SITH_ATTACH_NO_MOVE)) continue;
        rdMatrix_TransformVector34(&i->position, &i->field_4C, &v5->lookOrientation);
        rdVector_Add3Acc(&i->position, &v5->position);
        if ( i->sector != v5->sector )
            sithThing_MoveToSector(i, v5->sector, 0);
    }
    if ( v5->moveType == SITH_MT_PHYSICS )
    {
        if ( v64 == 0.0 )
            return 0.0;
        if (!(a8 & 0x40))
        {
            if ( (v5->attach_flags) != 0 && !(v5->attach_flags & SITH_ATTACH_NO_MOVE)
              || (v5->physicsParams.physflags & SITH_PF_FLOORSTICK) != 0
              && (v5->physicsParams.vel.z < -2.0 || v5->physicsParams.vel.z <= 0.2) )
            {
                sithPhysics_FindFloor(v5, 0);
            }
        }
    }
    return v64;
}

int sithCollision_DefaultHitHandler(sithThing *thing, sithSurface *surface, sithCollisionSearchEntry *a3)
{
    sithThing *v3; // esi
    float a1a; // [esp+Ch] [ebp+4h]

    v3 = thing;
    if ( thing->moveType != SITH_MT_PHYSICS )
        return 0;
    a1a = -rdVector_Dot3(&a3->hitNorm, &thing->physicsParams.vel);

    if ( !sithCollision_CollideHurt(thing, &a3->hitNorm, a3->distance, surface->surfaceFlags & SITH_SURFACE_80) )
        return 0;

    if ( (surface->surfaceFlags & SITH_SURFACE_COG_LINKED) != 0 && (v3->thingflags & SITH_TF_INVULN) == 0 && surface->surfaceInfo.lastTouchedMs + 500 <= sithTime_curMsAbsolute )
    {
        surface->surfaceInfo.lastTouchedMs = sithTime_curMsAbsolute;
        sithCog_SendMessageFromSurface(surface, v3, SITH_MESSAGE_TOUCHED);
    }
    if ( a1a > 0.15000001 )
    {
        if ( a1a > 1.0 )
            a1a = 1.0;
        if ( (surface->surfaceFlags & SITH_SURFACE_METAL) != 0 )
        {
            sithSoundClass_PlayThingSoundclass(v3, SITH_SC_HITMETAL, a1a);
            return 1;
        }
        sithSoundClass_PlayThingSoundclass(v3, SITH_SC_HITHARD, a1a);
    }
    return 1;
}

int sithCollision_DebrisDebrisCollide(sithThing *thing1, sithThing *thing2, sithCollisionSearchEntry *a3, int isInverse)
{
    sithThing *v4; // esi
    sithThing *v5; // edi
    double v6; // st6
    //char v9; // c0
    double v11; // st7
    //char v14; // c0
    double v15; // st7
    float a3a; // [esp+0h] [ebp-38h]
    rdVector3 a2; // [esp+14h] [ebp-24h] BYREF
    rdVector3 forceVec; // [esp+20h] [ebp-18h] BYREF
    rdVector3 v19; // [esp+2Ch] [ebp-Ch] BYREF
    float senderb; // [esp+3Ch] [ebp+4h]
    float sender; // [esp+3Ch] [ebp+4h]
    float sendera; // [esp+3Ch] [ebp+4h]
    float a1a; // [esp+40h] [ebp+8h]

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

    if ( (v4->thingflags & SITH_TF_CAPTURED) != 0 && (v4->thingflags & SITH_TF_INVULN) == 0 )
        sithCog_SendMessageFromThing(v4, v5, SITH_MESSAGE_TOUCHED);
    if ( (v5->thingflags & SITH_TF_CAPTURED) != 0 && (v4->thingflags & SITH_TF_INVULN) == 0 )
        sithCog_SendMessageFromThing(v5, v4, SITH_MESSAGE_TOUCHED);

    if ( v4->moveType != SITH_MT_PHYSICS || v4->physicsParams.mass == 0.0 )
    {
        if ( v5->moveType != SITH_MT_PHYSICS || v5->physicsParams.mass == 0.0 )
            return 1;
        v11 = rdVector_Dot3(&v4->field_268, &a2);
        v11 = stdMath_ClipPrecision(v11);
        if ( v11 < 0.0 )
        {
            sendera = -v11 * 1.0001;
            rdVector_Neg3(&v19, &a2);
            v15 = sithCollision_UpdateThingCollision(v5, &v19, sendera, 0);
            if ( v15 < sendera )
            {
                if ( (v4->thingflags & SITH_TF_NOIMPACTDAMAGE) == 0 )
                {
                    a1a = v15;
                    a3a = (sendera - a1a) * 100.0;
                    sithThing_Damage(v5, v4, a3a, SITH_DAMAGE_IMPACT);
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
        v6 = stdMath_ClipPrecision(v6);
        if ( v6 <= 0.0 )
            return 0;

        if ( (v4->physicsParams.physflags & SITH_PF_SURFACEBOUNCE) == 0 )
            v6 = v6 * 0.5;
        if ( (v5->physicsParams.physflags & SITH_PF_SURFACEBOUNCE) == 0 )
            v6 = v6 * 0.5;
        
        // (2*mass^2) / (2*mass)
        senderb = (v5->physicsParams.mass * v4->physicsParams.mass + v5->physicsParams.mass * v4->physicsParams.mass)
                / (v5->physicsParams.mass + v4->physicsParams.mass);

        rdVector_Scale3(&forceVec, &a2, v6 * senderb);
        sithPhysics_ThingApplyForce(v4, &forceVec);
        rdVector_Neg3Acc(&forceVec);
        sithPhysics_ThingApplyForce(v5, &forceVec);
        return sithCollision_CollideHurt(v4, &a2, a3->distance, 0);
    }
    sender = 0.0f;
    if (v4->moveType == SITH_MT_PHYSICS) // Added
        sender = -rdVector_Dot3(&v4->physicsParams.vel, &a2);
    if ( !sithCollision_CollideHurt(v4, &a2, a3->distance, 0) )
        return 0;
    if ( sender <= 0.15000001 )
        return 1;
    if ( sender > 1.0 )
        sender = 1.0;
    if ( (v5->thingflags & SITH_TF_METAL) != 0 )
        sithSoundClass_PlayThingSoundclass(v4, SITH_SC_HITMETAL, sender);
    else
        sithSoundClass_PlayThingSoundclass(v4, SITH_SC_HITHARD, sender);
    return 1;
}

int sithCollision_CollideHurt(sithThing *a1, rdVector3 *a2, float a3, int a4)
{
    int result; // eax
    double v10; // st6
    double v19; // st7
    double v22; // st7
    double v26; // st7
    double v31; // st6
    double v32; // st7
    double v33; // st5
    double v35; // st7
    double v36; // st7
    double v39; // st7
    double v40; // st7
    float v43; // [esp+8h] [ebp-4h]
    float a1a; // [esp+10h] [ebp+4h]
    float amount; // [esp+14h] [ebp+8h]

    if ( a1->moveType != SITH_MT_PHYSICS )
        return 0;
    amount = -rdVector_Dot3(&a1->field_268, a2);
    a1a = stdMath_ClipPrecision(amount);
    if ( a1a <= 0.0 )
        return 0;
    v43 = 1.9;
    if ( (a1->physicsParams.physflags & SITH_PF_SURFACEBOUNCE) == 0 )
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
            rdVector_MultAcc3(&a1->field_268, a2, amount);
            if ( v10 > 0.0 )
            {
                rdVector_MultAcc3(&a1->physicsParams.vel, a2, v10);
            }
            v19 = -rdVector_Dot3(a2, &sithCollision_collideHurtIdk);
            rdVector_MultAcc3(&sithCollision_collideHurtIdk, a2, v19);
            rdVector_Normalize3Acc(&sithCollision_collideHurtIdk);
            v22 = -rdVector_Dot3(&a1->physicsParams.vel, &sithCollision_collideHurtIdk);
            if ( v22 > 0.0 )
            {
                rdVector_MultAcc3(&a1->physicsParams.vel, &sithCollision_collideHurtIdk, v22);
            }
            v26 = -rdVector_Dot3(&a1->field_268, &sithCollision_collideHurtIdk);
            if ( v26 > 0.0 )
            {
                rdVector_MultAcc3(&a1->field_268, &sithCollision_collideHurtIdk, v26);
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
            rdVector_MultAcc3(&a1->physicsParams.vel, a2, v36);
            if ( !a4 && v35 > 2.5 )
            {
                v39 = (v35 - 2.5) * (v35 - 2.5) * 45.0;
                //printf("%f %f, %f %f %f\n", v39, v35, a1->physicsParams.vel.x, a1->physicsParams.vel.y, a1->physicsParams.vel.z);
                if ( v39 > 1.0 )
                {
                    sithSoundClass_PlayModeRandom(a1, SITH_SC_HITDAMAGED);
                    sithThing_Damage(a1, a1, v39, SITH_DAMAGE_FALL);
                }
            }
        }
        v40 = v43 * a1a;
        rdVector_MultAcc3(&a1->field_268, a2, v40);
        result = 1;
    }
    return result;
}

int sithCollision_HasLos(sithThing *thing1, sithThing *thing2, int flag)
{
    int v3; // edi
    int v4; // edi
    sithCollisionSearchEntry *v5; // ebp
    double v6; // st7
    sithCollisionSearchEntry *v7; // edx
    sithCollisionSearchEntry *v8; // ecx
    sithThing *v10; // edx
    int result; // eax
    int v12; // [esp+10h] [ebp-10h]
    rdVector3 a1a; // [esp+14h] [ebp-Ch] BYREF
    float a6; // [esp+2Ch] [ebp+Ch]

    v12 = 1;
    v3 = 0x2122;
    if ( flag )
        v3 = 0x2022;
    rdVector_Sub3(&a1a, &thing2->position, &thing1->position);
    a6 = rdVector_Normalize3Acc(&a1a);
    sithCollision_SearchRadiusForThings(thing1->sector, 0, &thing1->position, &a1a, a6, 0.0, v3);
    v4 = sithCollision_searchStackIdx;
    v5 = sithCollision_searchStack[sithCollision_searchStackIdx].collisions;
    while ( 1 )
    {
        v6 = 3.4e38;
        v7 = 0;
        v8 = v5;
        for (int i = 0; i < sithCollision_searchNumResults[v4]; i++)
        {
            if ( !v8->hasBeenEnumerated )
            {
                if ( v6 <= v8->distance )
                {
                    if ( v6 == v8->distance 
                        && (v7->hitType & (SITHCOLLISION_THINGTOUCH|SITHCOLLISION_THINGCROSS)) 
                        && (v8->hitType & SITHCOLLISION_THINGADJOINCROSS))
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
            v7->hasBeenEnumerated = 1;
        }
        else
        {
            sithCollision_searchNumResults[v4] = 0;
            sithCollision_stackIdk[v4] = 0;
        }
        if ( !v7 )
            break;
        if ( (v7->hitType & SITHCOLLISION_THING) != 0 )
        {
            v10 = v7->receiver;
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

void sithCollision_sub_4E77A0(sithThing *thing, rdMatrix34 *a2)
{
    sithThing *v5; // edi
    rdVector3 a2a; // [esp+10h] [ebp-6Ch] BYREF
    rdMatrix34 out; // [esp+1Ch] [ebp-60h] BYREF
    rdMatrix34 mat1; // [esp+4Ch] [ebp-30h] BYREF
    float a1a; // [esp+84h] [ebp+8h]

    if ( thing->attachedParentMaybe )
    {
        rdMatrix_Normalize34(a2);
        rdVector_Copy3(&a2->scale, &thing->position);
        rdVector_Copy3(&thing->lookOrientation.scale, &thing->position);
        rdMatrix_InvertOrtho34(&mat1, &thing->lookOrientation);
        v5 = thing->attachedParentMaybe;
        while ( v5 )
        {
            rdVector_Copy3(&v5->lookOrientation.scale, &v5->position);
            rdMatrix_Multiply34(&out, &mat1, &v5->lookOrientation);
            rdMatrix_PostMultiply34(&out, a2);
            rdVector_Sub3(&a2a, &out.scale, &v5->position);
            a1a = rdVector_Normalize3Acc(&a2a);
            rdVector_Zero3(&out.scale);
            if ( a1a != 0.0 )
            {
                sithCollision_UpdateThingCollision(v5, &a2a, a1a, 64);
            }
            sithCollision_sub_4E77A0(v5, &out);
            if ( v5->moveType == SITH_MT_PHYSICS )
            {
                v5->physicsParams.physflags &= ~SITH_PF_100;
            }
            v5 = v5->childThing;
        }
    }
    else if ( (((bShowInvisibleThings & 0xFF) + (thing->thingIdx & 0xFF)) & 7) == 0 )
    {
        rdMatrix_Normalize34(a2);
    }
    rdVector_Zero3(&a2->scale);
    _memcpy(&thing->lookOrientation, a2, sizeof(thing->lookOrientation));
}

int sithCollision_DebrisPlayerCollide(sithThing *thing, sithThing *thing2, sithCollisionSearchEntry *searchEnt, int isSolid)
{
    int result; // eax
    float mass; // [esp+14h] [ebp+4h]

    float tmp = 0.0; // Added 0.0, original game overwrites &searchEnt...

    // Added: check move type
    mass = (thing->moveType == SITH_MT_PHYSICS) ? thing->physicsParams.mass : 0.0;

    if ( isSolid )
        return sithCollision_DebrisDebrisCollide(thing, thing2, searchEnt, isSolid);

    if ( thing->moveType == SITH_MT_PHYSICS )
        tmp = -rdVector_Dot3(&searchEnt->hitNorm, &thing->physicsParams.vel);

    if (sithCollision_DebrisDebrisCollide(thing, thing2, searchEnt, 0))
    {
        if ( tmp > 0.25 )
        {
            sithThing_Damage(thing2, thing, mass * 0.3 * tmp, SITH_DAMAGE_IMPACT);
        }
        return 1;
    }
    return 0;
}
