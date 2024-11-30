#include "sithItem.h"

#include "General/stdConffile.h"
#include "Gameplay/sithTime.h"
#include "World/sithThing.h"
#include "Cog/sithCog.h"
#include "Engine/sithCollision.h"
#include "World/jkPlayer.h"
#include "World/sithSector.h"
#include "Dss/sithDSSThing.h"
#include "Main/Main.h"
#include "jk.h"

int sithItem_Collide(sithThing *a1, sithThing *a2, sithCollisionSearchEntry *a4, int a5)
{
    if ( !sithNet_isMulti || (!(a2->thingflags & SITH_TF_INVULN)) )
    {
        // MOTS added
        if (Main_bMotsCompat && (a2->actorParams.typeflags & (THING_TYPEFLAGS_40000 | THING_TYPEFLAGS_8000000))) return 0;

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
#ifdef JKM_PARAMS
    out->itemParams.respawnFactor = 0.9;
#endif
    rdVector_Copy3(&out->itemParams.position, &out->position);
    out->itemParams.sector = out->sector;
}

void sithItem_Take(sithThing *item, sithThing *actor, int a3)
{
    if (sithNet_isMulti && !a3)
    {
        sithDSSThing_SendTakeItem(item, actor, 255);
        if (Main_bMotsCompat) {
            if (item->collide == SITH_COLLIDE_SPHERE) {
                item->collide = SITH_COLLIDE_NONE;
                item->thingflags = item->thingflags | SITH_TF_INVISIBLE;
                return;
            }
        }
        return;
    }

    if ( actor == sithPlayer_pLocalPlayerThing )
    {
        sithCog_SendMessageFromThing(item, actor, SITH_MESSAGE_TAKEN);
    }

    if ( (item->itemParams.typeflags & SITH_ITEM_RESPAWN_SP && !sithNet_isMulti) 
         || (item->itemParams.typeflags & SITH_ITEM_RESPAWN_MP && sithNet_isMulti) )
    {
        item->thingflags |= SITH_TF_DISABLED;

        // MOTS added
#ifdef JKM_PARAMS
        if (Main_bMotsCompat) {
            if (item->collide == SITH_COLLIDE_NONE) {
                item->collide = SITH_COLLIDE_SPHERE;
                item->thingflags &= ~SITH_TF_INVISIBLE;
                item->thingflags |= SITH_TF_DISABLED;
            }
            float val = item->itemParams.respawn;
            if (item->itemParams.respawnFactor != 1.0 && sithNet_isMulti) {
                for (int i = 0; i < jkPlayer_maxPlayers; i++) {
                    if ((jkPlayer_playerInfos[i].flags & 1) && (i != playerThingIdx)) {
                        val *= item->itemParams.respawnFactor;
                    }
                }
            }

            item->lifeLeftMs = (int)(val * 1000.0 * (_frand() + 0.75));
        }
        else 
#endif
        {
            item->lifeLeftMs = (int)(item->itemParams.respawn * 1000.0);
        }
    }
    else
    {
        sithThing_Destroy(item);
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
         || !sithNet_isMulti && !(item->itemParams.typeflags & SITH_ITEM_RESPAWN_SP)
         || sithNet_isMulti && !(item->itemParams.typeflags & SITH_ITEM_RESPAWN_MP))
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
        if (Main_bMotsCompat) {
            if (item->collide == SITH_COLLIDE_NONE) {
                item->collide = SITH_COLLIDE_SPHERE;
                item->thingflags &= ~SITH_TF_INVISIBLE;
                return;
            }
        }
        sithCog_SendMessageFromThing(item, item, SITH_MESSAGE_RESPAWN);
    }

    if ( sithComm_multiplayerFlags )
    {
        sithDSSThing_SendSyncThing(item, -1, 255);
        sithDSSThing_SendPos(item, -1, 1);
    }
}

// MOTS altered
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
#ifdef JKM_PARAMS
    else if ( paramIdx == THINGPARAM_RESPAWNFACTOR )
    {
        thing->itemParams.respawnFactor = _atof(arg->value);
        return 1;
    }
#endif

    return 0;
}
