#include "sithUnk3.h"

#include "World/sithThing.h"
#include "World/sithWeapon.h"
#include "World/sithItem.h"
#include "World/sithUnk4.h"
#include "jk.h"

static int sithUnk3_initted = 0;

int sithUnk3_Startup()
{
    if ( sithUnk3_initted )
        return 0;

    _memset(sithUnk3_collisionHandlers, 0, sizeof(sithUnk3_collisionHandlers));
    _memset(sithUnk3_funcList, 0, sizeof(sithUnk3_funcList));
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

    sithUnk3_RegisterHitHandler(THINGTYPE_ACTOR, sithUnk4_sub_4ED1D0_ADDR);
    sithUnk3_RegisterHitHandler(THINGTYPE_WEAPON, sithWeapon_HitDebug);

    sithUnk3_initted = 1;
    return 1;
}

void sithUnk3_RegisterCollisionHandler(int idxA, int idxB, int func, int a4)
{
    int idx = idxB + 12 * idxA;
    sithUnk3_collisionHandlers[idx].handler = func;
    sithUnk3_collisionHandlers[idx].param = a4;
    sithUnk3_collisionHandlers[idx].inverse = 0;
    if ( idxA != idxB )
    {
        idx = idxA + 12 * idxB;
        sithUnk3_collisionHandlers[idx].handler = func;
        sithUnk3_collisionHandlers[idx].param = a4;
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
