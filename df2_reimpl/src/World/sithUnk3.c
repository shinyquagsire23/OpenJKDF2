#include "sithUnk3.h"

#include "World/sithThing.h"
#include "World/sithWeapon.h"
#include "World/sithItem.h"
#include "World/sithUnk4.h"
#include "World/sithSector.h"
#include "World/sithCollide.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithSurface.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithTime.h"
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

void sithUnk3_SearchClose()
{
    --sithUnk3_searchStackIdx;
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
    sithUnk3_searchHandler_t handler;
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

void sithUnk3_FallHurt(sithThing *thing, float vel)
{
    double v2; // st7
    float vela; // [esp+8h] [ebp+8h]

    v2 = (vel - 2.5) * (vel - 2.5) * 45.0;
    if ( v2 > 1.0 )
    {
        sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_HITDAMAGED);
        vela = v2;
        sithThing_Damage(thing, thing, vela, 64);
    }
}

void sithUnk3_sub_4E7670(sithThing *thing, rdMatrix34 *orient)
{
    sithThing *i; // esi
    float *v4; // edi
    double v5; // st7
    double v6; // st7
    char v8; // c3
    float v9; // [esp+Ch] [ebp-18h]
    float v10; // [esp+10h] [ebp-14h]
    float v11; // [esp+14h] [ebp-10h]
    rdVector3 a1a; // [esp+18h] [ebp-Ch] BYREF
    float mat2; // [esp+2Ch] [ebp+8h]

    rdMatrix_PreMultiply34(&thing->lookOrientation, orient);
    for ( i = thing->attachedParentMaybe; i; i = i->childThing )
    {
        v4 = &i->lookOrientation.scale.x;
        v9 = i->position.x - thing->position.x;
        v5 = i->position.y - thing->position.y;
        i->lookOrientation.scale.x = v9;
        v10 = v5;
        v6 = i->position.z - thing->position.z;
        i->lookOrientation.scale.y = v10;
        v11 = v6;
        i->lookOrientation.scale.z = v11;
        sithUnk3_sub_4E7670(i, orient);
        if ( (i->attach_flags & 8) == 0 )
        {
            a1a.x = *v4 - v9;
            a1a.y = i->lookOrientation.scale.y - v10;
            a1a.z = i->lookOrientation.scale.z - v11;
            if ( a1a.x != 0.0 || a1a.y != 0.0 || a1a.z != 0.0 )
            {
                mat2 = rdVector_Normalize3Acc(&a1a);
                sithUnk3_UpdateThingCollision(i, &a1a, mat2, 0);
            }
        }
        *v4 = 0.0;
        i->lookOrientation.scale.y = 0.0;
        i->lookOrientation.scale.z = 0.0;
    }
}

float sithUnk3_UpdateThingCollision(sithThing *a3, rdVector3 *a2, float a6, int a8)
{
    sithThing *v5; // ebp
    sithThing *v10; // esi
    double v11; // st7
    double v12; // st7
    double v14; // st6
    //char v15; // c0
    int v16; // edi
    float v17; // edx
    int v18; // edx
    sithUnk3SearchEntry *v19; // esi
    double v20; // st7
    sithUnk3SearchEntry *v21; // ecx
    int v22; // ebx
    double v23; // st6
    double v24; // st7
    double v25; // st7
    double v26; // st6
    double v27; // st5
    float *v28; // ebx
    double v30; // st5
    double v31; // rtt
    double v32; // rt0
    double v33; // st5
    sithThing *v34; // ecx
    int v35; // eax
    int v36; // eax
    sithSurface *v37; // eax
    int (__cdecl *v38)(sithThing *, sithSurface *, sithUnk3SearchEntry *); // eax
    double v39; // st7
    double v40; // st6
    double v41; // st4
    double v42; // st6
    double v43; // st5
    double v44; // st7
    //char v46; // c3
    double v48; // st7
    //char v49; // c0
    double v51; // st7
    //char v52; // c0
    float v53; // edx
    float v54; // eax
    float v55; // ecx
    float v56; // edx
    sithThing *i; // esi
    sithSector *v58; // eax
    sithSector *v59; // ecx
    int v60; // eax
    int v61; // eax
    float amounta; // [esp+0h] [ebp-54h]
    sithSurface *amount; // [esp+0h] [ebp-54h]
    float v64; // [esp+18h] [ebp-3Ch]
    float v65; // [esp+1Ch] [ebp-38h]
    unsigned int v66; // [esp+20h] [ebp-34h]
    rdVector3 direction; // [esp+24h] [ebp-30h] BYREF
    float v68; // [esp+30h] [ebp-24h]
    float v69; // [esp+34h] [ebp-20h]
    float v70; // [esp+38h] [ebp-1Ch]
    rdVector3 out; // [esp+3Ch] [ebp-18h] BYREF
    rdVector3 v72; // [esp+48h] [ebp-Ch] BYREF
    sithSector* sectTmp;

    v64 = 0.0;
    v65 = 0.0;
    v66 = 0;
    if ( a6 <= 0.0 )
        return 0.0;
    v5 = a3;
    if ( !a3->collide )
    {
        a8 |= 0x5;
    }
    if ( a3->move_type == MOVETYPE_PATH )
    {
        a8 |= 0x4;
    }
    if ( a3->thingType == THINGTYPE_PLAYER )
    {
        a8 |= 0x200;
    }
    if ( (a8 & 1) == 0 )
    {
        a8 |= 0x800;
    }
    v10 = a3->attachedParentMaybe;
    for ( direction = *a2; v10; v10 = v10->childThing )
    {
        if ( (v10->attach_flags & 8) == 0 )
        {
            v11 = sithUnk3_UpdateThingCollision(v10, a2, a6, 64);
            if ( v11 < a6 )
            {
                if ( (v10->attach_flags & 2) == 0 )
                    goto LABEL_20;
                rdMatrix_TransformVector34(&out, &v10->attachedSufaceInfo->face.normal, &v5->lookOrientation);
                v12 = a2->z * out.z + a2->y * out.y + out.x * a2->x;
                v14 = v12;
                if ( v14 < 0.0 )
                    v14 = -v12;
                if ( v14 <= 0.0000099999997 )
                    v12 = 0.0;
                if ( v12 > 0.0 )
                {
LABEL_20:
                    if ( (v5->thingflags & 0x800) == 0 )
                    {
                        amounta = (a6 - v11) * 100.0;
                        sithThing_Damage(v10, v5, amounta, 1);
                    }
                    a6 = v11;
                }
            }
        }
    }
    sithUnk3_dword_8B4BE4 = 0;
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
            v68 = v5->position.x;
            v69 = v5->position.y;
            out = direction;
            v17 = v5->moveSize;
            v70 = v5->position.z;
            sectTmp = v5->sector;
            sithUnk3_SearchRadiusForThings(sectTmp, v5, &v5->position, &direction, a6, v17, a8);
            while ( 1 )
            {
                v18 = sithUnk3_searchStackIdx;
                v19 = 0;
                v20 = 3.4e38;
                v21 = sithUnk3_searchStack[sithUnk3_searchStackIdx].collisions;
                if ( sithUnk3_searchNumResults[sithUnk3_searchStackIdx] )
                {
                    v22 = sithUnk3_searchNumResults[sithUnk3_searchStackIdx];
                    do
                    {
                        if ( !v21->hasBeenEnumerated )
                        {
                            if ( v20 <= v21->distance )
                            {
                                if ( v20 == v21->distance && (v19->collideType & 0x18) != 0 && (v21->collideType & 4) != 0 )
                                    v19 = v21;
                            }
                            else
                            {
                                v20 = v21->distance;
                                v19 = v21;
                            }
                        }
                        ++v21;
                        --v22;
                    }
                    while ( v22 );
                }
                if ( v19 )
                {
                    v19->hasBeenEnumerated = 1;
                }
                else
                {
                    sithUnk3_searchNumResults[sithUnk3_searchStackIdx] = 0;
                    sithUnk3_stackIdk[v18] = 0;
                }
                if ( !v19 )
                    break;

                if ( v19->distance != 0.0 )
                {
                    v23 = v19->distance * direction.y + v69;
                    v24 = v19->distance * direction.z + v70;
                    v5->position.x = v19->distance * direction.x + v68;
                    v5->position.y = v23;
                    v5->position.z = v24;
                }
                if ( v19->distance >= (double)a6 )
                {
                    v28 = &v5->field_268.x;
                    v5->field_268.x = 0.0;
                    v5->field_268.y = 0.0;
                    v5->field_268.z = 0.0;
                }
                else
                {
                    v25 = a6 - v19->distance;
                    v26 = direction.y * v25;
                    v27 = direction.z * v25;
                    v28 = &v5->field_268.x;
                    v5->field_268.x = direction.x * v25;
                    v5->field_268.y = v26;
                    v5->field_268.z = v27;
                    if ( v5->move_type == MOVETYPE_PHYSICS
                      && (v5->physicsParams.physflags & 0x20) != 0
                      && (v5->physicsParams.addedVelocity.x != 0.0 || v5->physicsParams.addedVelocity.y != 0.0 || v5->physicsParams.addedVelocity.z != 0.0) )
                    {
                        v30 = 1.0 - v19->distance / a6;
                        v65 = v30;
                        v31 = -v30;
                        v32 = v5->physicsParams.addedVelocity.y * v31 + v5->physicsParams.vel.y;
                        v33 = v5->physicsParams.addedVelocity.z * v31 + v5->physicsParams.vel.z;
                        v5->physicsParams.vel.x = v5->physicsParams.addedVelocity.x * v31 + v5->physicsParams.vel.x;
                        v5->physicsParams.vel.y = v32;
                        v5->physicsParams.vel.z = v33;
                    }
                }
                if ( (v19->collideType & 1) != 0 )
                {
                    v34 = v19->receiver;
                    v35 = v34->thingType + 12 * v5->thingType;
                    if ( sithUnk3_collisionHandlers[v35].inverse )
                        v36 = sithUnk3_collisionHandlers[v35].handler(v34, v5, v19, 1);
                    else
                        v36 = sithUnk3_collisionHandlers[v35].handler(
                                  v5,
                                  v34,
                                  v19,
                                  0);
                }
                else if ( (v19->collideType & 0x20) != 0 )
                {
                    v72.x = v5->position.x;
                    v72.y = v5->position.y;
                    v37 = v19->surface;
                    v72.z = v5->position.z;
                    if ( (v37->surfaceFlags & 2) != 0 )
                        sithCog_SendMessageFromSurface(v37, v5, 8);
                    sithThing_MoveToSector(v5, v19->surface->adjoin->sector, 0);
                    v36 = _memcmp(&v72, &v5->position, sizeof(rdVector3)) != 0;
                }
                else
                {
                    amount = v19->surface;
                    v38 = (int (__cdecl *)(sithThing *, sithSurface *, sithUnk3SearchEntry *))sithUnk3_funcList[v5->thingType];
                    if ( v38 )
                        v36 = v38(v5, amount, v19);
                    else
                        v36 = sithUnk3_DefaultHitHandler(v5, amount, v19);
                }
                v16 = v36;
                if ( v65 != 0.0 )
                {
                    v39 = v65 * sithTime_deltaSeconds;
                    v40 = v5->physicsParams.vel.y * v39;
                    v41 = v5->physicsParams.vel.z * v39;
                    *v28 = v5->physicsParams.vel.x * v39;
                    v5->field_268.y = v40;
                    v5->field_268.z = v41;
                    v65 = 0.0;
                }
                if ( v36 )
                {
                    v18 = sithUnk3_searchStackIdx;
                    break;
                }
            }
            sithUnk3_searchStackIdx = v18 - 1;
            if ( v16 )
            {
                v64 = v19->distance + v64;
                if ( v5->field_268.x == 0.0 && v5->field_268.y == 0.0 && v5->field_268.z == 0.0 )
                    goto LABEL_74;
                a6 = rdVector_Normalize3(&direction, &v5->field_268);
                v48 = a6;
                if ( v48 < 0.0 )
                    v48 = -v48;
                if ( v48 <= 0.0000099999997 )
LABEL_74:
                    a6 = 0.0;
                ++v66;
            }
            else
            {
                v42 = direction.y * a6 + v69;
                v43 = direction.z * a6 + v70;
                v44 = v64 + a6;
                v5->position.x = direction.x * a6 + v68;
                v5->position.y = v42;
                v5->position.z = v43;
                a6 = 0.0;
                v5->field_268.x = 0.0;
                v64 = v44;
                v5->field_268.y = 0.0;
                v5->field_268.z = 0.0;
            }
            if ( (v5->thingflags & 2) != 0 )
                return v64;
            if ( a6 == 0.0 )
                goto LABEL_78;
        }
    }
    if ( v5->move_type == MOVETYPE_PHYSICS )
        sithSector_StopPhysicsThing(v5);
LABEL_81:
    v51 = v64;
    if ( v51 < 0.0 )
        v51 = -v51;
    if ( v51 <= 0.0000099999997 )
        v64 = 0.0;
    if ( v5->collide )
    {
        if ( v5->move_type == MOVETYPE_PHYSICS && !sithCollide_IsSphereInSector(&v5->position, 0.0, v5->sector) )
        {
            v53 = v69;
            v54 = v70;
            v5->position.x = v68;
            v55 = out.x;
            v5->position.y = v53;
            v56 = out.y;
            direction.x = v55;
            v5->position.z = v54;
            direction.y = v56;
            direction.z = out.z;
            sithThing_MoveToSector(v5, sectTmp, 0);
            if ( v5->lifeLeftMs )
                sithThing_Destroy(v5);
        }
    }
    for ( i = v5->attachedParentMaybe; i; i = i->childThing )
    {
        if ( (i->attach_flags & 8) != 0 )
        {
            rdMatrix_TransformVector34(&i->position, &i->field_4C, &v5->lookOrientation);
            v58 = v5->sector;
            v59 = i->sector;
            i->position.x = v5->position.x + i->position.x;
            i->position.y = v5->position.y + i->position.y;
            i->position.z = v5->position.z + i->position.z;
            if ( v59 != v58 )
                sithThing_MoveToSector(i, v58, 0);
        }
    }
    if ( v5->move_type == MOVETYPE_PHYSICS )
    {
        if ( v64 == 0.0 )
            return 0.0;
        if ( (a8 & 0x40) == 0 )
        {
            if ( (v60 = v5->attach_flags) != 0 && (v60 & 8) == 0
              || (v5->physicsParams.physflags & 0x40) != 0
              && (v5->physicsParams.vel.z < -2.0 || v5->physicsParams.vel.z > 0.2 ? (v61 = 0) : (v61 = 1), v61) )
            {
                sithSector_ThingLandIdk(v5, 0);
            }
        }
    }
    return v64;
}

int sithUnk3_DefaultHitHandler(sithThing *thing, sithSurface *surface, sithUnk3SearchEntry *a3)
{
    sithThing *v3; // esi
    float a1a; // [esp+Ch] [ebp+4h]

    v3 = thing;
    if ( thing->move_type != MOVETYPE_PHYSICS )
        return 0;
    a1a = -(a3->field_14.y * thing->physicsParams.vel.y
          + a3->field_14.z * thing->physicsParams.vel.z
          + thing->physicsParams.vel.x * a3->field_14.x);

    if ( !sithUnk3_CollideHurt(thing, &a3->field_14, a3->distance, surface->surfaceFlags & 0x80) )
        return 0;

    if ( (surface->surfaceFlags & SURFACEFLAGS_2) != 0 && (v3->thingflags & 0x100) == 0 && surface->surfaceInfo.lastTouchedMs + 500 <= sithTime_curMsAbsolute )
    {
        surface->surfaceInfo.lastTouchedMs = sithTime_curMsAbsolute;
        sithCog_SendMessageFromSurface(surface, v3, SITH_MESSAGE_TOUCHED);
    }
    if ( a1a > 0.15000001 )
    {
        if ( a1a > 1.0 )
            a1a = 1.0;
        if ( (surface->surfaceFlags & SURFACEFLAGS_METAL) != 0 )
        {
            sithSoundClass_PlayThingSoundclass(v3, SITH_SC_HITMETAL, a1a);
            return 1;
        }
        sithSoundClass_PlayThingSoundclass(v3, SITH_SC_HITHARD, a1a);
    }
    return 1;
}

int sithUnk3_DebrisDebrisCollide(sithThing *thing1, sithThing *thing2, sithUnk3SearchEntry *a3, int isInverse)
{
    sithThing *v4; // esi
    sithThing *v5; // edi
    double v6; // st6
    double v8; // st5
    //char v9; // c0
    double v11; // st7
    double v13; // st6
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
    a2 = a3->field_14;

    if ( (v4->thingflags & SITH_TF_CAPTURED) != 0 && (v4->thingflags & SITH_TF_INVULN) == 0 )
        sithCog_SendMessageFromThing(v4, v5, SITH_MESSAGE_TOUCHED);
    if ( (v5->thingflags & SITH_TF_CAPTURED) != 0 && (v4->thingflags & SITH_TF_INVULN) == 0 )
        sithCog_SendMessageFromThing(v5, v4, SITH_MESSAGE_TOUCHED);

    if ( v4->move_type != MOVETYPE_PHYSICS || v4->physicsParams.mass == 0.0 )
    {
        if ( v5->move_type != MOVETYPE_PHYSICS || v5->physicsParams.mass == 0.0 )
            return 1;
        v11 = v4->field_268.x * a2.x + v4->field_268.z * a2.z + v4->field_268.y * a2.y;
        v13 = v11;
        if ( v13 < 0.0 )
            v13 = -v11;
        if ( v13 <= 0.0000099999997 )
            v11 = 0.0;
        if ( v11 < 0.0 )
        {
            sendera = -v11 * 1.0001;
            v19.x = -a2.x;
            v19.y = -a2.y;
            v19.z = -a2.z;
            v15 = sithUnk3_UpdateThingCollision(v5, &v19, sendera, 0);
            if ( v15 < sendera )
            {
                if ( (v4->thingflags & SITH_TF_NOIMPACTDAMAGE) == 0 )
                {
                    a1a = v15;
                    a3a = (sendera - a1a) * 100.0;
                    sithThing_Damage(v5, v4, a3a, 1);
                }
                v4->field_268.x = 0.0;
                v4->field_268.y = 0.0;
                v4->field_268.z = 0.0;
            }
            return 1;
        }
        return 0;
    }
    if ( v5->move_type == MOVETYPE_PHYSICS && v5->physicsParams.mass != 0.0 )
    {
        v6 = v5->physicsParams.vel.z * a2.z
           + v5->physicsParams.vel.y * a2.y
           + v5->physicsParams.vel.x * a2.x
           - (v4->physicsParams.vel.z * a2.z
            + v4->physicsParams.vel.y * a2.y
            + v4->physicsParams.vel.x * a2.x);
        v8 = v6;
        if ( v8 < 0.0 )
            v8 = -v6;
        if ( v8 <= 0.0000099999997 )
            v6 = 0.0;
        if ( v6 <= 0.0 )
            return 0;
        if ( (v4->physicsParams.physflags & PHYSFLAGS_SURFACEBOUNCE) == 0 )
            v6 = v6 * 0.5;
        if ( (v5->physicsParams.physflags & PHYSFLAGS_SURFACEBOUNCE) == 0 )
            v6 = v6 * 0.5;
        senderb = (v5->physicsParams.mass * v4->physicsParams.mass + v5->physicsParams.mass * v4->physicsParams.mass)
                / (v5->physicsParams.mass + v4->physicsParams.mass);
        forceVec.x = v6 * a2.x * senderb;
        forceVec.y = v6 * a2.y * senderb;
        forceVec.z = v6 * a2.z * senderb;
        sithSector_ThingApplyForce(v4, &forceVec);
        forceVec.x = -forceVec.x;
        forceVec.y = -forceVec.y;
        forceVec.z = -forceVec.z;
        sithSector_ThingApplyForce(v5, &forceVec);
        return sithUnk3_CollideHurt(v4, &a2, a3->distance, 0);
    }
    sender = -(v4->physicsParams.vel.z * a2.z + v4->physicsParams.vel.y * a2.y + v4->physicsParams.vel.x * a2.x);
    if ( !sithUnk3_CollideHurt(v4, &a2, a3->distance, 0) )
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

int sithUnk3_CollideHurt(sithThing *a1, rdVector3 *a2, float a3, int a4)
{
    int result; // eax
    double v8; // st7
    double v10; // st6
    double v11; // st7
    double v12; // st5
    double v14; // st7
    double v17; // st6
    double v18; // st5
    double v19; // st7
    double v20; // st6
    double v21; // st5
    double v22; // st7
    double v23; // st6
    double v24; // st5
    double v25; // st7
    double v26; // st7
    double v27; // st6
    double v28; // st5
    double v29; // st7
    double v30; // st4
    double v31; // st6
    double v32; // st7
    double v33; // st5
    float v34; // edx
    double v35; // st7
    double v36; // st7
    double v37; // st6
    double v38; // st5
    double v39; // st7
    double v40; // st7
    double v41; // st6
    double v42; // st5
    float v43; // [esp+8h] [ebp-4h]
    float a1a; // [esp+10h] [ebp+4h]
    float amount; // [esp+14h] [ebp+8h]
    float amounta; // [esp+14h] [ebp+8h]
    float amountb; // [esp+14h] [ebp+8h]

    if ( a1->move_type != MOVETYPE_PHYSICS )
        return 0;
    amount = -(a1->field_268.x * a2->x + a2->z * a1->field_268.z + a1->field_268.y * a2->y);
    a1a = amount;
    v8 = amount;
    if ( v8 < 0.0 )
        v8 = -v8;
    if ( v8 <= 0.0000099999997 )
        a1a = 0.0;
    if ( a1a <= 0.0 )
        return 0;
    v43 = 1.9;
    if ( (a1->physicsParams.physflags & PHYSFLAGS_SURFACEBOUNCE) == 0 )
        v43 = 1.0001;
    if ( a3 == 0.0 && sithUnk3_dword_8B4BE4 )
    {
        if ( amount <= 0.0 )
        {
            result = 0;
        }
        else
        {
            v10 = -(a1->physicsParams.vel.x * a2->x + a1->physicsParams.vel.z * a2->z + a1->physicsParams.vel.y * a2->y);
            v11 = a2->y * amount + a1->field_268.y;
            v12 = a2->z * amount + a1->field_268.z;
            a1->field_268.x = a2->x * amount + a1->field_268.x;
            a1->field_268.y = v11;
            v14 = v10;
            a1->field_268.z = v12;
            if ( v10 > 0.0 )
            {
                v17 = a2->y * v10 + a1->physicsParams.vel.y;
                v18 = a2->z * v14 + a1->physicsParams.vel.z;
                a1->physicsParams.vel.x = a2->x * v14 + a1->physicsParams.vel.x;
                a1->physicsParams.vel.y = v17;
                a1->physicsParams.vel.z = v18;
            }
            v19 = -(a2->y * sithUnk3_collideHurtIdk.y + a2->z * sithUnk3_collideHurtIdk.z + a2->x * sithUnk3_collideHurtIdk.x);
            v20 = a2->y * v19 + sithUnk3_collideHurtIdk.y;
            v21 = a2->z * v19 + sithUnk3_collideHurtIdk.z;
            sithUnk3_collideHurtIdk.x = a2->x * v19 + sithUnk3_collideHurtIdk.x;
            sithUnk3_collideHurtIdk.y = v20;
            sithUnk3_collideHurtIdk.z = v21;
            rdVector_Normalize3Acc(&sithUnk3_collideHurtIdk);
            v22 = -(a1->physicsParams.vel.z * sithUnk3_collideHurtIdk.z
                  + a1->physicsParams.vel.x * sithUnk3_collideHurtIdk.x
                  + a1->physicsParams.vel.y * sithUnk3_collideHurtIdk.y);
            if ( v22 > 0.0 )
            {
                v23 = v22 * sithUnk3_collideHurtIdk.y + a1->physicsParams.vel.y;
                v24 = v22 * sithUnk3_collideHurtIdk.x + a1->physicsParams.vel.x;
                v25 = v22 * sithUnk3_collideHurtIdk.z + a1->physicsParams.vel.z;
                a1->physicsParams.vel.x = v24;
                a1->physicsParams.vel.y = v23;
                a1->physicsParams.vel.z = v25;
            }
            v26 = -(a1->field_268.x * sithUnk3_collideHurtIdk.x + a1->field_268.y * sithUnk3_collideHurtIdk.y + a1->field_268.z * sithUnk3_collideHurtIdk.z);
            if ( v26 > 0.0 )
            {
                v27 = v26 * sithUnk3_collideHurtIdk.y + a1->field_268.y;
                v28 = v26 * sithUnk3_collideHurtIdk.x + a1->field_268.x;
                v29 = v26 * sithUnk3_collideHurtIdk.z + a1->field_268.z;
                a1->field_268.x = v28;
                a1->field_268.y = v27;
                a1->field_268.z = v29;
            }
            result = 1;
        }
    }
    else
    {
        v30 = a2->y;
        v31 = a1->physicsParams.vel.y;
        v32 = a1->physicsParams.vel.x * a2->x;
        v33 = a1->physicsParams.vel.z * a2->z;
        sithUnk3_dword_8B4BE4 = 1;
        sithUnk3_collideHurtIdk.x = a2->x;
        v34 = a2->z;
        sithUnk3_collideHurtIdk.y = a2->y;
        sithUnk3_collideHurtIdk.z = v34;
        v35 = -(v32 + v33 + v31 * v30);
        amounta = v35;
        if ( v35 > 0.0 )
        {
            v36 = v43 * amounta;
            v37 = a2->y * v36 + a1->physicsParams.vel.y;
            v38 = a2->z * v36 + a1->physicsParams.vel.z;
            a1->physicsParams.vel.x = a2->x * v36 + a1->physicsParams.vel.x;
            a1->physicsParams.vel.y = v37;
            a1->physicsParams.vel.z = v38;
            if ( !a4 && amounta > 2.5 )
            {
                v39 = (amounta - 2.5) * (amounta - 2.5) * 45.0;
                if ( v39 > 1.0 )
                {
                    sithSoundClass_ThingPlaySoundclass(a1, SITH_SC_HITDAMAGED);
                    amountb = v39;
                    sithThing_Damage(a1, a1, amountb, 0x40);
                }
            }
        }
        v40 = v43 * a1a;
        v41 = a2->y * v40 + a1->field_268.y;
        v42 = a2->z * v40 + a1->field_268.z;
        a1->field_268.x = a2->x * v40 + a1->field_268.x;
        a1->field_268.y = v41;
        a1->field_268.z = v42;
        result = 1;
    }
    return result;
}

int sithUnk3_HasLos(sithThing *thing1, sithThing *thing2, int flag)
{
    int v3; // edi
    int v4; // edi
    sithUnk3SearchEntry *v5; // ebp
    double v6; // st7
    sithUnk3SearchEntry *v7; // edx
    sithUnk3SearchEntry *v8; // ecx
    int v9; // esi
    sithThing *v10; // edx
    int result; // eax
    int v12; // [esp+10h] [ebp-10h]
    rdVector3 a1a; // [esp+14h] [ebp-Ch] BYREF
    float a6; // [esp+2Ch] [ebp+Ch]

    v12 = 1;
    v3 = 0x2122;
    if ( flag )
        v3 = 0x2022;
    a1a.x = thing2->position.x - thing1->position.x;
    a1a.y = thing2->position.y - thing1->position.y;
    a1a.z = thing2->position.z - thing1->position.z;
    a6 = rdVector_Normalize3Acc(&a1a);
    sithUnk3_SearchRadiusForThings(thing1->sector, 0, &thing1->position, &a1a, a6, 0.0, v3);
    v4 = sithUnk3_searchStackIdx;
    v5 = sithUnk3_searchStack[sithUnk3_searchStackIdx].collisions;
    while ( 1 )
    {
        v6 = 3.4e38;
        v7 = 0;
        v8 = v5;
        if ( sithUnk3_searchNumResults[v4] )
        {
            v9 = sithUnk3_searchNumResults[v4];
            do
            {
                if ( !v8->hasBeenEnumerated )
                {
                    if ( v6 <= v8->distance )
                    {
                        if ( v6 == v8->distance && (v7->collideType & 0x18) != 0 && (v8->collideType & 4) != 0 )
                            v7 = v8;
                    }
                    else
                    {
                        v6 = v8->distance;
                        v7 = v8;
                    }
                }
                ++v8;
                --v9;
            }
            while ( v9 );
        }
        if ( v7 )
        {
            v7->hasBeenEnumerated = 1;
        }
        else
        {
            sithUnk3_searchNumResults[v4] = 0;
            sithUnk3_stackIdk[v4] = 0;
        }
        if ( !v7 )
            break;
        if ( (v7->collideType & 1) != 0 )
        {
            v10 = v7->receiver;
            if ( v10 == thing2 )
            {
                result = 1;
                sithUnk3_searchStackIdx = v4 - 1;
                return result;
            }
            if ( v10 == thing1 )
                continue;
        }
        v12 = 0;
        break;
    }
    result = v12;
    sithUnk3_searchStackIdx = v4 - 1;
    return result;
}

int sithUnk3_sub_4E77A0(sithThing *thing, rdMatrix34 *a2)
{
    sithThing *v2; // ebx
    float v4; // eax
    sithThing *v5; // edi
    sithThing *v6; // ebp
    long double v7; // st7
    int result; // eax
    rdVector3 a2a; // [esp+10h] [ebp-6Ch] BYREF
    rdMatrix34 out; // [esp+1Ch] [ebp-60h] BYREF
    rdMatrix34 mat1; // [esp+4Ch] [ebp-30h] BYREF
    float a1a; // [esp+84h] [ebp+8h]

    v2 = thing;
    if ( thing->attachedParentMaybe )
    {
        rdMatrix_Normalize34(a2);
        a2->scale = thing->position;
        thing->lookOrientation.scale.x = thing->position.x;
        v4 = thing->position.z;
        thing->lookOrientation.scale.y = thing->position.y;
        thing->lookOrientation.scale.z = v4;
        rdMatrix_InvertOrtho34(&mat1, &thing->lookOrientation);
        v5 = thing->attachedParentMaybe;
        if ( v5 )
        {
            do
            {
                v6 = v5->childThing;
                v5->lookOrientation.scale.x = v5->position.x;
                v5->lookOrientation.scale.y = v5->position.y;
                v5->lookOrientation.scale.z = v5->position.z;
                rdMatrix_Multiply34(&out, &mat1, &v5->lookOrientation);
                rdMatrix_PostMultiply34(&out, a2);
                a2a.x = out.scale.x - v5->position.x;
                a2a.y = out.scale.y - v5->position.y;
                a2a.z = out.scale.z - v5->position.z;
                v7 = rdVector_Normalize3Acc(&a2a);
                out.scale.x = 0.0;
                out.scale.y = 0.0;
                out.scale.z = 0.0;
                if ( v7 != 0.0 )
                {
                    a1a = v7;
                    sithUnk3_UpdateThingCollision(v5, &a2a, a1a, 64);
                }
                sithUnk3_sub_4E77A0(v5, &out);
                if ( v5->move_type == MOVETYPE_PHYSICS )
                {
                    v5->physicsParams.physflags &= ~1;
                }
                v5 = v6;
            }
            while ( v6 );
            v2 = thing;
        }
    }
    else if ( (((bShowInvisibleThings & 0xFF) + (thing->thingIdx & 0xFF)) & 7) == 0 )
    {
        rdMatrix_Normalize34(a2);
    }
    result = 0;
    a2->scale.x = 0.0;
    a2->scale.y = 0.0;
    a2->scale.z = 0.0;
    _memcpy(&v2->lookOrientation, a2, sizeof(v2->lookOrientation));
    return result;
}

int sithUnk3_DebrisPlayerCollide(sithThing *thing, sithThing *thing2, sithUnk3SearchEntry *searchEnt, int isSolid)
{
    int result; // eax
    float amount; // [esp+0h] [ebp-10h]
    float mass; // [esp+14h] [ebp+4h]

    float tmp = 0.0; // Added 0.0, original game overwrite &searchEnt...

    mass = thing->physicsParams.mass;

    if ( isSolid )
        return sithUnk3_DebrisDebrisCollide(thing, thing2, searchEnt, isSolid);

    if ( thing->move_type == MOVETYPE_PHYSICS )
        tmp = -(searchEnt->field_14.x * thing->physicsParams.vel.x
                               + searchEnt->field_14.y * thing->physicsParams.vel.y
                               + searchEnt->field_14.z * thing->physicsParams.vel.z);

    if (sithUnk3_DebrisDebrisCollide(thing, thing2, searchEnt, 0))
    {
        if ( tmp > 0.25 )
        {
            amount = mass * 0.30000001 * tmp;
            sithThing_Damage(thing2, thing, amount, 1);
        }
        return 1;
    }
    return 0;
}
