#include "sithItem.h"

#include "Engine/sithTime.h"
#include "World/sithThing.h"
#include "Cog/sithCog.h"
#include "Engine/sithNet.h"
#include "Engine/sithCollision.h"
#include "World/jkPlayer.h"
#include "World/sithSector.h"
#include "Dss/sithDSSThing.h"
#include "jk.h"

int sithItem_Collide(sithThing *a1, sithThing *a2, sithCollisionSearchEntry *a4, int a5)
{
    if ( !sithNet_isMulti || (!(a2->thingflags & SITH_TF_INVULN)) )
    {
        if ( sithCollision_HasLos(a2, a1, 0) && a1->itemParams.respawnTime < sithTime_curMs )
        {
            sithCog_SendMessageFromThing(a1, a2, SITH_MESSAGE_TOUCHED);
            a1->itemParams.respawnTime = sithTime_curMs + 500;
        }
    }

    return 0;
}

void sithItem_New(sithThing *out)
{
    rdVector_Copy3(&out->itemParams.position, &out->position);
    out->itemParams.sector = out->sector;
}

void sithItem_Take(sithThing *item, sithThing *actor, int a3)
{
    if ( !sithNet_isMulti || a3 )
    {
        if ( actor == g_localPlayerThing )
        {
            sithCog_SendMessageFromThing(item, actor, SITH_MESSAGE_TAKEN);
        }

        if ( item->itemParams.typeflags & THING_TYPEFLAGS_FORCE && !sithNet_isMulti 
             || item->itemParams.typeflags & THING_TYPEFLAGS_1 && sithNet_isMulti )
        {
            item->thingflags |= SITH_TF_DISABLED;
            item->lifeLeftMs = (int)(item->itemParams.respawn * 1000.0);
        }
        else
        {
            sithThing_Destroy(item);
        }
    }
    else
    {
        sithDSSThing_SendTakeItem(item, actor, 255);
    }
}

void sithItem_Remove(sithThing *item)
{
    if ( sithNet_isMulti && !sithNet_isServer )
    {
        item->lifeLeftMs = 0;
        return;
    }

    // TODO verify this, it was kinda weird
    if ( !item->itemParams.sector
         || !sithNet_isMulti && !(item->itemParams.typeflags & THING_TYPEFLAGS_FORCE)
         || sithNet_isMulti && !(item->itemParams.typeflags & THING_TYPEFLAGS_1))
    {
        if ( item->isVisible + 1 == bShowInvisibleThings )
            item->lifeLeftMs = 3000;
        else
            sithThing_Destroy(item);
    }
    else
    {
        rdVector_Zero3(&item->physicsParams.vel);
        sithThing_LeaveSector(item);
        sithThing_SetPosAndRot(item, &item->itemParams.position, &item->lookOrientation);
        sithThing_MoveToSector(item, item->itemParams.sector, 1);
        item->lifeLeftMs = 0;
        item->thingflags = item->thingflags & ~SITH_TF_DISABLED;
        sithCog_SendMessageFromThing(item, item, SITH_MESSAGE_RESPAWN);
    }

    if ( sithCogVm_multiplayerFlags )
    {
        sithDSSThing_SendSyncThing(item, -1, 255);
        sithDSSThing_SendTeleportThing(item, -1, 1);
    }
}

int sithItem_LoadThingParams(stdConffileArg *arg, sithThing *thing, int paramIdx)
{
    if ( paramIdx == THINGPARAM_TYPEFLAGS )
    {
        int tmp;
        if ( _sscanf(arg->value, "%x", &tmp) == 1 )
        {
            thing->itemParams.typeflags = tmp;
            return 1;
        }
    }
    else if ( paramIdx == THINGPARAM_RESPAWN )
    {
        thing->itemParams.respawn = _atof(arg->value);
        return 1;
    }

    return 0;
}
