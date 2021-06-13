#include "sithUnk3.h"

#include "World/sithThing.h"
#include "World/sithWeapon.h"
#include "World/sithItem.h"
#include "World/sithUnk4.h"
#include "World/sithSector.h"
#include "World/sithCollide.h"
#include "World/sithWorld.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithSurface.h"
#include "jk.h"

static int sithUnk3_initted = 0;

int sithUnk3_Startup()
{
    if ( sithUnk3_initted )
        return 0;

    _memset(sithUnk3_collisionHandlers, 0, 144 * sizeof(sithUnk3Entry)); // sizeof(sithUnk3_collisionHandlers)
    _memset(sithUnk3_funcList, 0, 12 * sizeof(int)); // sizeof(sithUnk3_funcList)
    sithUnk3_RegisterCollisionHandler(THINGTYPE_ACTOR, THINGTYPE_ACTOR, sithUnk4_ActorActorCollide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_ACTOR, THINGTYPE_PLAYER, sithUnk4_ActorActorCollide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_ACTOR, THINGTYPE_COG, sithUnk4_ActorActorCollide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_PLAYER, THINGTYPE_PLAYER, sithUnk3_DebrisDebrisCollide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_PLAYER, THINGTYPE_COG, sithUnk3_DebrisDebrisCollide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_DEBRIS, THINGTYPE_ACTOR, sithUnk3_DebrisPlayerCollide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_DEBRIS, THINGTYPE_PLAYER, sithUnk3_DebrisPlayerCollide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_DEBRIS, THINGTYPE_DEBRIS, sithUnk3_DebrisDebrisCollide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_WEAPON, THINGTYPE_ACTOR, sithWeapon_Collide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_WEAPON, THINGTYPE_PLAYER, sithWeapon_Collide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_WEAPON, THINGTYPE_DEBRIS, sithWeapon_Collide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_WEAPON, THINGTYPE_COG, sithWeapon_Collide, 0);
    sithUnk3_RegisterCollisionHandler(THINGTYPE_ITEM, THINGTYPE_PLAYER, sithItem_Collide, 0);

    sithUnk3_RegisterHitHandler(THINGTYPE_ACTOR, (void*)sithUnk4_sub_4ED1D0_ADDR);
    sithUnk3_RegisterHitHandler(THINGTYPE_WEAPON, sithWeapon_HitDebug);

    sithUnk3_initted = 1;
    return 1;
}

void sithUnk3_RegisterCollisionHandler(int idxA, int idxB, void* func, void* a4)
{
    int idx = idxB + 12 * idxA;
    sithUnk3_collisionHandlers[idx].handler = func;
    sithUnk3_collisionHandlers[idx].search_handler = a4;
    sithUnk3_collisionHandlers[idx].inverse = 0;
    if ( idxA != idxB )
    {
        idx = idxA + 12 * idxB;
        sithUnk3_collisionHandlers[idx].handler = func;
        sithUnk3_collisionHandlers[idx].search_handler = a4;
        sithUnk3_collisionHandlers[idx].inverse = 1;
    }
}

void sithUnk3_RegisterHitHandler(int thingType, void* a2)
{
    sithUnk3_funcList[thingType] = a2;
}

sithUnk3SearchEntry* sithUnk3_NextSearchResult()
{
    sithUnk3SearchEntry* retVal = NULL;
    float maxDist = 3.4e38;
    
    for (int i = 0; i < sithUnk3_searchNumResults[sithUnk3_searchStackIdx]; i++)
    {
        sithUnk3SearchEntry* iter = &sithUnk3_searchStack[sithUnk3_searchStackIdx].collisions[i];
        if ( !iter->hasBeenEnumerated )
        {
            if ( maxDist <= iter->distance )
            {
                if ( maxDist == iter->distance && retVal->collideType & 0x18 && iter->collideType & 4 ) // TODO enums
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
        sithUnk3_searchNumResults[sithUnk3_searchStackIdx] = 0;
        sithUnk3_stackIdk[sithUnk3_searchStackIdx] = 0;
        return NULL;
    }
}

float sithUnk3_SearchRadiusForThings(sithSector *sector, sithThing *a2, const rdVector3 *position, const rdVector3 *direction, float a5, float range, int flags)
{
    int v7; // eax
    int16_t v8; // di
    int v9; // ecx
    float v10; // eax
    int v11; // ebx
    sithUnk3SearchEntry *i; // ebp
    sithSector *v13; // esi
    unsigned int v14; // eax
    unsigned int v15; // edi
    sithSector **v16; // edx
    unsigned int v17; // edx
    unsigned int v18; // ebp
    sithSector *j; // eax
    sithAdjoin *v20; // ebx
    sithSector *v21; // esi
    unsigned int v22; // eax
    unsigned int v23; // edi
    sithSector **v24; // edx
    float v25; // [esp+10h] [ebp-8h]
    unsigned int v26; // [esp+10h] [ebp-8h]
    float a1a; // [esp+1Ch] [ebp+4h]
    unsigned int a1b; // [esp+1Ch] [ebp+4h]
    float a5a; // [esp+2Ch] [ebp+14h]

    v7 = sithUnk3_searchStackIdx + 1;
    v8 = flags;
    sithUnk3_searchStackIdx = v7;
    sithUnk3_searchNumResults[v7] = 0;
    sithUnk3_stackIdk[v7] = 1;
    v25 = a5;
    sithUnk3_stackSectors[v7].sectors[0] = sector;
    if ( (flags & 1) == 0 )
        v25 = sithUnk3_UpdateSectorThingCollision(sector, a2, position, direction, a5, range, flags);
    sithUnk3_sub_4E86D0(sector, position, direction, v25, range, flags);
    v9 = sithUnk3_searchStackIdx;
    v10 = v25;
    v26 = 0;
    a5a = v10;
    v11 = sithUnk3_searchStackIdx;
    for ( i = sithUnk3_searchStack[sithUnk3_searchStackIdx].collisions; v26 < sithUnk3_searchNumResults[v9]; ++v26 )
    {
        if ( i->collideType == 64 )
        {
            if ( (v8 & 0x400) != 0 || i->distance <= (double)a5a )
            {
                v13 = i->surface->adjoin->sector;
                a1a = a5a;
                v14 = sithUnk3_stackIdk[v11];
                v15 = 0;
                if ( v14 )
                {
                    v16 = sithUnk3_stackSectors[v9].sectors;
                    while ( *v16 != v13 )
                    {
                        ++v15;
                        ++v16;
                        if ( v15 >= v14 )
                            goto LABEL_11;
                    }
                }
                else
                {
LABEL_11:
                    if ( v14 != 64 )
                    {
                        sithUnk3_stackIdk[v11] = v14 + 1;
                        sithUnk3_stackSectors[v9].sectors[v14] = v13;
                        if ( (flags & 1) == 0 )
                            a1a = sithUnk3_UpdateSectorThingCollision(v13, a2, position, direction, a5a, range, flags);
                        sithUnk3_sub_4E86D0(v13, position, direction, a1a, range, flags);
                        v9 = sithUnk3_searchStackIdx;
                        a5a = a1a;
                    }
                }
            }
            v8 = flags;
            i->hasBeenEnumerated = 1;
        }
        v11 = v9;
        ++i;
    }
    if ( a5a != 0.0 && (v8 & 0x800) != 0 )
    {
        v17 = sithUnk3_stackIdk[v9];
        v18 = 0;
        a1b = v17;
        for ( j = sithUnk3_stackSectors[v9].sectors[0]; v18 < v17; j = sithUnk3_stackSectors[v9].sectors[v18] )
        {
            v20 = j->adjoins;
            if ( v20 )
            {
                do
                {
                    if ( (v20->flags & 2) != 0 )
                    {
                        v21 = v20->sector;
                        if ( v21->thingsList )
                        {
                            v22 = sithUnk3_stackIdk[v9];
                            v23 = 0;
                            if ( v22 )
                            {
                                v24 = sithUnk3_stackSectors[v9].sectors;
                                while ( *v24 != v21 )
                                {
                                    ++v23;
                                    ++v24;
                                    if ( v23 >= v22 )
                                        goto LABEL_27;
                                }
                            }
                            else
                            {
LABEL_27:
                                if ( v22 != 64 )
                                {
                                    sithUnk3_stackIdk[v9] = v22 + 1;
                                    sithUnk3_stackSectors[v9].sectors[v22] = v21;
                                    a5a = sithUnk3_UpdateSectorThingCollision(v21, a2, position, direction, a5a, range, flags);
                                    v9 = sithUnk3_searchStackIdx;
                                }
                            }
                        }
                    }
                    v20 = v20->next;
                }
                while ( v20 );
                v17 = a1b;
            }
            ++v18;
        }
    }
    return a5a;
}

float sithUnk3_UpdateSectorThingCollision(sithSector *a1, sithThing *sender, const rdVector3 *a2, const rdVector3 *a3, float a4, float range, int flags)
{
    sithThing *v7; // esi
    sithThing *v8; // ebp
    int v9; // ebx
    int v10; // eax
    int v11; // eax
    int v12; // edx
    sithThing *v13; // ecx
    sithThing *v14; // eax
    sithThing *v15; // ecx
    sithThing *v16; // eax
    int v17; // eax
    int v18; // eax
    int v19; // eax
    rdFace *v21; // ebx
    int v22; // edx
    float v23; // st7
    sithUnk3SearchEntry *v24; // ecx
    rdMesh *senderMesh; // edx
    sithUnk3_collisionHandler_t handler;
    int v27; // eax
    rdFace *a10; // [esp+4h] [ebp-18h] BYREF
    int i; // [esp+Ch] [ebp-10h]
    rdVector3 a11; // [esp+10h] [ebp-Ch] BYREF

    senderMesh = 0;
    a10 = 0;
    v7 = a1->thingsList;
    if ( v7 )
    {
        v8 = sender;
        v9 = flags;
        v10 = flags & 8;
        for ( i = v10; ; v10 = i )
        {
            if ( (!v10 || (v7->thingflags & SITH_TF_80))
              && ((v9 & 0x10) == 0 || (v7->thingflags & SITH_TF_STANDABLE) != 0)
              && v7->collide
              && (v7->thingflags & (SITH_TF_DISABLED|SITH_TF_WILLBEREMOVED)) == 0
              && ((v9 & 0x2000) == 0 || v7->thingType == THINGTYPE_COG) )
            {
                if ( !v8 )
                    goto LABEL_41;
                if ( v8 != v7 )
                {
                    v11 = v8->thingType;
                    v12 = v7->thingType;
                    if ( sithUnk3_collisionHandlers[12 * v11 + v12].handler )
                    {
                        if ( (v8->thingflags & SITH_TF_DEAD) == 0
                          && (v7->thingflags & SITH_TF_DEAD) == 0
                          && (v11 != THINGTYPE_WEAPON
                           || (v8->actorParams.typeflags & THING_TYPEFLAGS_1) == 0
                           || ((v13 = v8->prev_thing) == 0 || (v14 = v7->prev_thing) == 0 || v13 != v14 || v8->child_signature != v7->child_signature)
                           && (v13 != v7 || v8->child_signature != v7->signature))
                          && (v12 != THINGTYPE_WEAPON
                           || (v7->actorParams.typeflags & THING_TYPEFLAGS_1) == 0
                           || ((v15 = v7->prev_thing) == 0 || (v16 = v8->prev_thing) == 0 || v15 != v16 || v7->child_signature != v8->child_signature)
                           && (v15 != v8 || v7->child_signature != v8->signature)) )
                        {
                            v17 = v8->attach_flags;
                            if ( (v17 & 6) == 0 || v8->attachedThing != v7 || (v17 & 8) == 0 && (v9 & 0x40) == 0 )
                            {
                                v18 = v7->attach_flags;
                                if ( (v18 & 6) == 0 || v7->attachedThing != v8 || (v18 & 8) == 0 && (v9 & 0x40) == 0 )
                                {
LABEL_41:
                                    v19 = sithCollide_sub_5080D0(v8, a2, a3, a4, range, v7, v9, &v23, &senderMesh, &a10, &a11);
                                    if ( v19 )
                                    {
                                        v21 = a10;
                                        v22 = sithUnk3_searchNumResults[sithUnk3_searchStackIdx];
                                        if ( v22 != 128 )
                                        {
                                            v19 |= 1;
                                            sithUnk3_searchNumResults[sithUnk3_searchStackIdx] = v22 + 1;
                                            v24 = &sithUnk3_searchStack[sithUnk3_searchStackIdx].collisions[v22];
                                            v24->surface = 0;
                                            v24->hasBeenEnumerated = 0;
                                            v24->collideType = v19;
                                            v24->distance = v23;
                                            v24->receiver = v7;
                                            v24->sender = senderMesh;
                                            v24->face = v21;
                                            rdVector_Copy3(&v24->field_14, &a11);
                                        }
                                        if ( v8 )
                                        {
                                            handler = sithUnk3_collisionHandlers[12 * v8->thingType + v7->thingType].search_handler;
                                            if ( handler )
                                                v27 = handler(v8, v7);
                                            else
                                                v27 = 0;
                                            if ( v27 )
                                                a4 = v23;
                                        }
                                        v9 = flags;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            v7 = v7->nextThing;
            if ( !v7 )
                break;
        }
    }
    return a4;
}

void sithUnk3_sub_4E86D0(sithSector *sector, const rdVector3 *vec1, const rdVector3 *vec2, float a4, float a5, int unk3Flags)
{
    double v8; // st6
    double v9; // st7
    int v11; // eax
    sithSurface *v12; // esi
    int unk3Flags_; // ebx
    int v14; // ecx
    sithAdjoin *v15; // eax
    int v16; // eax
    unsigned int v17; // ecx
    unsigned int v18; // edi
    sithSector **v19; // eax
    int v20; // ecx
    double v21; // st7
    sithUnk3SearchEntry *v23; // eax
    int v24; // ecx
    unsigned int v25; // edi
    unsigned int v26; // edx
    sithSector **v27; // eax
    int v28; // edx
    double v29; // st7
    sithUnk3SearchEntry *v31; // eax
    int v32; // edx
    double v33; // st7
    sithUnk3SearchEntry *v34; // eax
    rdVector3 *v35; // ecx
    int v36; // ecx
    double v37; // st7
    int v38; // edx
    sithUnk3SearchEntry *v40; // eax
    unsigned int v41; // edx
    int v42; // [esp+0h] [ebp-40h] BYREF
    float a7; // [esp+10h] [ebp-30h] BYREF
    sithWorld *v44; // [esp+14h] [ebp-2Ch]
    int v45; // [esp+18h] [ebp-28h]
    sithAdjoin *v46; // [esp+1Ch] [ebp-24h]
    int v47; // [esp+20h] [ebp-20h]
    float v48; // [esp+24h] [ebp-1Ch] BYREF
    float v49; // [esp+28h] [ebp-18h]
    float v50; // [esp+2Ch] [ebp-14h]
    float v51; // [esp+30h] [ebp-10h]
    rdVector3 v52; // [esp+34h] [ebp-Ch] BYREF

    v8 = vec2->y * a4 + vec1->y;
    v9 = vec2->z * a4 + vec1->z;
    v49 = vec2->x * a4 + vec1->x;
    v50 = v8;
    v51 = v9;
    v44 = sithWorld_pCurWorld;
    if ( (sector->flags & SITH_SF_COLLIDEBOX) == 0
      || v51 - a5 <= sector->collidebox_onecorner.z
      || v50 - a5 <= sector->collidebox_onecorner.y
      || v49 - a5 <= sector->collidebox_onecorner.x
      || v49 + a5 >= sector->collidebox_othercorner.x
      || v50 + a5 >= sector->collidebox_othercorner.y
      || v51 + a5 >= sector->collidebox_othercorner.z )
    {
        v11 = sector->numSurfaces;
        v12 = sector->surfaces;
        v47 = 0;
        if ( v11 )
        {
            unk3Flags_ = unk3Flags;
            while ( 1 )
            {
                v14 = v12->surfaceFlags;
                v15 = v12->adjoin;
                v46 = v15;
                if ( (v14 & 4) == 0 && !v15 )
                    goto LABEL_56;
                if ( !v15 )
                {
LABEL_46:
                    if ( (unk3Flags_ & 4) == 0 && ((unk3Flags_ & 0x10) == 0 || (v14 & 1) != 0) )
                    {
                        v35 = v44->vertices;
                        if ( (v51 - v35[*v12->surfaceInfo.face.vertexPosIdx].z) * v12->surfaceInfo.face.normal.z
                           + (v50 - v35[*v12->surfaceInfo.face.vertexPosIdx].y) * v12->surfaceInfo.face.normal.y
                           + (v49 - v35[*v12->surfaceInfo.face.vertexPosIdx].x) * v12->surfaceInfo.face.normal.x <= a5 )
                        {
                            v36 = sithCollide_sub_508D20(vec1, vec2, a4, a5, &v12->surfaceInfo.face, v35, &a7, &v52, unk3Flags_);
                            if ( v36 )
                            {
                                if ( (unk3Flags_ & 0x400) != 0 || vec2->y * v52.y + vec2->z * v52.z + vec2->x * v52.x < 0.0 )
                                {
                                    v37 = a7;
                                    v38 = sithUnk3_searchNumResults[sithUnk3_searchStackIdx];
                                    if ( v38 != 128 )
                                    {
                                        sithUnk3_searchNumResults[sithUnk3_searchStackIdx] = v38 + 1;
                                        v40 = &sithUnk3_searchStack[sithUnk3_searchStackIdx].collisions[v38];
                                        v40->receiver = 0;
                                        v40->hasBeenEnumerated = 0;
                                        v40->collideType = v36 | 2;
                                        v40->distance = v37;
                                        v40->surface = v12;
                                        if ( &v42 != (int *)-52 )
                                            v40->field_14 = v52;
                                    }
                                }
                            }
                        }
                    }
                    goto LABEL_56;
                }
                v16 = v15->flags;
                v45 = unk3Flags_ & 4;
                if ( (unk3Flags_ & 4) == 0 )
                {
                    if ( (unk3Flags_ & 0x1100) != 0 && (v16 & 1) == 0 )
                        goto LABEL_46;
                    if ( (unk3Flags_ & 0x200) != 0 )
                    {
                        if ( (unk3Flags_ & 0x100) != 0 )
                            goto LABEL_22;
                        if ( (v16 & 0x10) != 0 )
                            goto LABEL_46;
                    }
                    if ( (unk3Flags_ & 0x100) == 0 && (v16 & 2) == 0 )
                        goto LABEL_46;
                }
LABEL_22:
                if ( sithCollide_sub_5090B0(vec1, vec2, a4, a5, &v12->surfaceInfo, v44->vertices, &a7, unk3Flags_) )
                {
                    if ( !v45 || (unk3Flags_ & 1) == 0 )
                    {
                        v17 = 0;
                        v18 = sithUnk3_stackIdk[sithUnk3_searchStackIdx];
                        if ( v18 )
                        {
                            v19 = sithUnk3_stackSectors[sithUnk3_searchStackIdx].sectors;
                            while ( *v19 != v46->sector )
                            {
                                ++v17;
                                ++v19;
                                if ( v17 >= v18 )
                                {
                                    unk3Flags_ = unk3Flags;
                                    goto LABEL_30;
                                }
                            }
                            unk3Flags_ = unk3Flags;
                        }
                        else
                        {
LABEL_30:
                            v20 = sithUnk3_searchNumResults[sithUnk3_searchStackIdx];
                            v21 = a7;
                            if ( v20 != 128 )
                            {
                                sithUnk3_searchNumResults[sithUnk3_searchStackIdx] = v20 + 1;
                                v23 = &sithUnk3_searchStack[sithUnk3_searchStackIdx].collisions[v20];
                                v23->receiver = 0;
                                v23->hasBeenEnumerated = 0;
                                v23->collideType = 64;
                                v23->distance = v21;
                                v23->surface = v12;
                            }
                        }
                    }
                    if ( (unk3Flags_ & 2) == 0 && sithCollide_sub_5090B0(vec1, vec2, a4, 0.0, &v12->surfaceInfo, v44->vertices, &v48, unk3Flags_) )
                    {
                        v24 = sithUnk3_searchStackIdx;
                        if ( v45 && (unk3Flags_ & 1) != 0 )
                        {
                            v25 = sithUnk3_stackIdk[sithUnk3_searchStackIdx];
                            v26 = 0;
                            if ( v25 )
                            {
                                v27 = sithUnk3_stackSectors[sithUnk3_searchStackIdx].sectors;
                                while ( *v27 != v46->sector )
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
                                v28 = sithUnk3_searchNumResults[sithUnk3_searchStackIdx];
                                v29 = a7;
                                if ( v28 != 128 )
                                {
                                    sithUnk3_searchNumResults[sithUnk3_searchStackIdx] = v28 + 1;
                                    v31 = &sithUnk3_searchStack[sithUnk3_searchStackIdx].collisions[v28];
                                    v31->receiver = 0;
                                    v31->hasBeenEnumerated = 0;
                                    v31->collideType = 64;
                                    v31->distance = v29;
                                    v31->surface = v12;
                                }
                            }
                        }
                        v32 = sithUnk3_searchNumResults[v24];
                        v33 = v48;
                        if ( v32 != 128 )
                        {
                            sithUnk3_searchNumResults[v24] = v32 + 1;
                            v34 = &sithUnk3_searchStack[sithUnk3_searchStackIdx].collisions[v32];
                            v34->receiver = 0;
                            v34->hasBeenEnumerated = 0;
                            v34->collideType = 32;
                            v34->distance = v33;
                            v34->surface = v12;
                        }
                    }
                }
LABEL_56:
                ++v12;
                v41 = sector->numSurfaces;
                if ( ++v47 >= v41 )
                    return;
            }
        }
    }
}

sithSector* sithUnk3_GetSectorLookAt(sithSector *sector, const rdVector3 *a3, rdVector3 *a4, float a5)
{
    double v4; // st6
    sithSector *result; // eax
    int v7; // edi
    sithUnk3SearchResult *v8; // ebx
    sithUnk3SearchEntry *v9; // edx
    double v10; // st7
    sithUnk3SearchEntry *v11; // ecx
    int v12; // esi
    double v13; // st6
    double v14; // st7
    rdVector3 a1; // [esp+8h] [ebp-Ch] BYREF
    float a3a; // [esp+1Ch] [ebp+8h]

    if ( sithCollide_IsSphereInSector(a4, 0.0, sector) )
        return sector;
    a1.x = a4->x - a3->x;
    a1.y = a4->y - a3->y;
    a1.z = a4->z - a3->z;
    a3a = rdVector_Normalize3Acc(&a1);
    sithUnk3_SearchRadiusForThings(sector, 0, a3, &a1, a3a, a5, 1);
    v7 = sithUnk3_searchStackIdx;
    v8 = &sithUnk3_searchStack[sithUnk3_searchStackIdx];
    while ( 1 )
    {
        v9 = 0;
        v10 = 3.4e38;
        v11 = (sithUnk3SearchEntry *)v8;
        if ( sithUnk3_searchNumResults[v7] )
        {
            v12 = sithUnk3_searchNumResults[v7];
            do
            {
                if ( !v11->hasBeenEnumerated )
                {
                    if ( v10 <= v11->distance )
                    {
                        if ( v10 == v11->distance && (v9->collideType & 0x18) != 0 && (v11->collideType & 4) != 0 )
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
            sithUnk3_searchNumResults[v7] = 0;
            sithUnk3_stackIdk[v7] = 0;
        }
        if ( !v9 )
            break;
        if ( (v9->collideType & 0x20) == 0 )
        {
            v13 = v9->distance * a1.y + a3->y;
            v14 = v9->distance * a1.z + a3->z;
            a4->x = v9->distance * a1.x + a3->x;
            a4->y = v13;
            a4->z = v14;
            break;
        }
        sector = v9->surface->adjoin->sector;
    }
    result = sector;
    sithUnk3_searchStackIdx = v7 - 1;
    return result;
}
