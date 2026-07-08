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

int sithItem_PlayerCollisionHandler(SithThing *a1, SithThing *a2, SithCollision *a4, int a5)
{
    if ( !sithNet_isMulti || (!(a2->flags & SITH_TF_INVULN)) )
    {
        // MOTS added
        if (Main_bMotsCompat && (a2->actorParams.flags & (THING_TYPEFLAGS_40000 | THING_TYPEFLAGS_8000000))) return 0;

        if ( sithCollision_HasLOS(a2, a1, 0) && a1->itemParams.msecLastTouchTime < sithTime_g_msecGameTime )
        {
            sithCog_ThingSendMessage(a1, a2, SITH_MESSAGE_TOUCHED);
            a1->itemParams.msecLastTouchTime = sithTime_g_msecGameTime + 500;
        }
    }

    return 0;
}

void sithItem_Initialize(SithThing *out)
{
#ifdef JKM_PARAMS
    out->itemParams.respawnFactor = 0.9;
#endif
    rdVector_Copy3(&out->itemParams.position, &out->position);
    out->itemParams.sector = out->sector;
}

void sithItem_SetItemTaken(SithThing *item, SithThing *actor, int a3)
{
    if (sithNet_isMulti && !a3)
    {
        sithDSSThing_Take(item, actor, 255);
        if (Main_bMotsCompat) {
            if (item->collide == SITH_COLLIDE_SPHERE) {
                item->collide = SITH_COLLIDE_NONE;
                item->flags = item->flags | SITH_TF_10;
                return;
            }
        }
        return;
    }

    if ( actor == sithPlayer_g_pLocalPlayerThing )
    {
        sithCog_ThingSendMessage(item, actor, SITH_MESSAGE_TAKEN);
    }

    if ( (item->itemParams.flags & SITH_ITEM_RESPAWN_SP && !sithNet_isMulti) 
         || (item->itemParams.flags & SITH_ITEM_RESPAWN_MP && sithNet_isMulti) )
    {
        item->flags |= SITH_TF_DISABLED;

        // MOTS added
#ifdef JKM_PARAMS
        if (Main_bMotsCompat) {
            if (item->collide == SITH_COLLIDE_NONE) {
                item->collide = SITH_COLLIDE_SPHERE;
                item->flags &= ~SITH_TF_10;
                item->flags |= SITH_TF_DISABLED;
            }
            flex_t val = item->itemParams.secRespawnInterval;
            if (item->itemParams.respawnFactor != 1.0 && sithNet_isMulti) {
                for (int i = 0; i < jkPlayer_maxPlayers; i++) {
                    if ((jkPlayer_playerInfos[i].flags & 1) && (i != playerThingIdx)) {
                        val *= item->itemParams.respawnFactor;
                    }
                }
            }

            item->msecLifeLeft = (int)(val * 1000.0 * (_frand() + 0.75));
        }
        else 
#endif
        {
            item->msecLifeLeft = (int)(item->itemParams.secRespawnInterval * 1000.0);
        }
    }
    else
    {
        sithThing_DestroyThing(item);
    }
}

void sithItem_DestroyItem(SithThing *item)
{
    if ( sithNet_isMulti && !sithNet_isServer )
    {
        item->msecLifeLeft = 0;
        return;
    }

    // TODO verify this, it was kinda weird
    if ( !item->itemParams.sector
         || !sithNet_isMulti && !(item->itemParams.flags & SITH_ITEM_RESPAWN_SP)
         || sithNet_isMulti && !(item->itemParams.flags & SITH_ITEM_RESPAWN_MP))
    {
        if ( item->renderFrame + 1 == jkPlayer_currentTickIdx )
            item->msecLifeLeft = 3000;
        else
            sithThing_DestroyThing(item);
    }
    else
    {
        rdVector_Zero3(&item->physicsParams.vel);
        sithThing_ExitSector(item);
        sithThing_SetPositionAndOrient(item, &item->itemParams.position, &item->orient);
        sithThing_SetSector(item, item->itemParams.sector, 1);
        item->msecLifeLeft = 0;
        item->flags = item->flags & ~SITH_TF_DISABLED;
        if (Main_bMotsCompat) {
            if (item->collide == SITH_COLLIDE_NONE) {
                item->collide = SITH_COLLIDE_SPHERE;
                item->flags &= ~SITH_TF_10;
                return;
            }
        }
        sithCog_ThingSendMessage(item, item, SITH_MESSAGE_RESPAWN);
    }

    if ( sithMessage_g_outputstream )
    {
        sithDSSThing_UpdateState(item, -1, 255);
        sithDSSThing_Pos(item, -1, 1);
    }
}

// MOTS altered
int sithItem_ParseArg(StdConffileArg *arg, SithThing *thing, int paramIdx)
{
    if ( paramIdx == THINGPARAM_TYPEFLAGS )
    {
        int tmp;
        if ( _sscanf(arg->value, "%x", &tmp) == 1 )
        {
            thing->itemParams.flags = tmp;
            return 1;
        }
    }
    else if ( paramIdx == THINGPARAM_RESPAWN )
    {
        thing->itemParams.secRespawnInterval = _atof(arg->value);
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
