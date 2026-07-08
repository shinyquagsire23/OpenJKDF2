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

int sithItem_PlayerCollisionHandler(SithThing *pItem, SithThing *pPlayer, SithCollision *pCollision, int a5)
{
    if ( !sithNet_isMulti || (!(pPlayer->flags & SITH_TF_INVULN)) )
    {
        // MOTS added
        if (Main_bMotsCompat && (pPlayer->actorParams.flags & (THING_TYPEFLAGS_40000 | THING_TYPEFLAGS_8000000))) return 0;

        if ( sithCollision_HasLOS(pPlayer, pItem, 0) && pItem->itemParams.msecLastTouchTime < sithTime_g_msecGameTime )
        {
            sithCog_ThingSendMessage(pItem, pPlayer, SITH_MESSAGE_TOUCHED);
            pItem->itemParams.msecLastTouchTime = sithTime_g_msecGameTime + 500;
        }
    }

    return 0;
}

void sithItem_Initialize(SithThing *pThing)
{
#ifdef JKM_PARAMS
    pThing->itemParams.respawnFactor = 0.9;
#endif
    rdVector_Copy3(&pThing->itemParams.position, &pThing->position);
    pThing->itemParams.sector = pThing->sector;
}

void sithItem_SetItemTaken(SithThing *pItem, SithThing *pSrcThing, int bNoMultiSync)
{
    if (sithNet_isMulti && !bNoMultiSync)
    {
        sithDSSThing_Take(pItem, pSrcThing, 255);
        if (Main_bMotsCompat) {
            if (pItem->collide == SITH_COLLIDE_SPHERE) {
                pItem->collide = SITH_COLLIDE_NONE;
                pItem->flags = pItem->flags | SITH_TF_10;
                return;
            }
        }
        return;
    }

    if ( pSrcThing == sithPlayer_g_pLocalPlayerThing )
    {
        sithCog_ThingSendMessage(pItem, pSrcThing, SITH_MESSAGE_TAKEN);
    }

    if ( (pItem->itemParams.flags & SITH_ITEM_RESPAWN_SP && !sithNet_isMulti) 
         || (pItem->itemParams.flags & SITH_ITEM_RESPAWN_MP && sithNet_isMulti) )
    {
        pItem->flags |= SITH_TF_DISABLED;

        // MOTS added
#ifdef JKM_PARAMS
        if (Main_bMotsCompat) {
            if (pItem->collide == SITH_COLLIDE_NONE) {
                pItem->collide = SITH_COLLIDE_SPHERE;
                pItem->flags &= ~SITH_TF_10;
                pItem->flags |= SITH_TF_DISABLED;
            }
            flex_t val = pItem->itemParams.secRespawnInterval;
            if (pItem->itemParams.respawnFactor != 1.0 && sithNet_isMulti) {
                for (int i = 0; i < jkPlayer_maxPlayers; i++) {
                    if ((jkPlayer_playerInfos[i].flags & 1) && (i != playerThingIdx)) {
                        val *= pItem->itemParams.respawnFactor;
                    }
                }
            }

            pItem->msecLifeLeft = (int)(val * 1000.0 * (_frand() + 0.75));
        }
        else 
#endif
        {
            pItem->msecLifeLeft = (int)(pItem->itemParams.secRespawnInterval * 1000.0);
        }
    }
    else
    {
        sithThing_DestroyThing(pItem);
    }
}

void sithItem_DestroyItem(SithThing *pItem)
{
    if ( sithNet_isMulti && !sithNet_isServer )
    {
        pItem->msecLifeLeft = 0;
        return;
    }

    // TODO verify this, it was kinda weird
    if ( !pItem->itemParams.sector
         || !sithNet_isMulti && !(pItem->itemParams.flags & SITH_ITEM_RESPAWN_SP)
         || sithNet_isMulti && !(pItem->itemParams.flags & SITH_ITEM_RESPAWN_MP))
    {
        if ( pItem->renderFrame + 1 == jkPlayer_currentTickIdx )
            pItem->msecLifeLeft = 3000;
        else
            sithThing_DestroyThing(pItem);
    }
    else
    {
        rdVector_Zero3(&pItem->physicsParams.vel);
        sithThing_ExitSector(pItem);
        sithThing_SetPositionAndOrient(pItem, &pItem->itemParams.position, &pItem->orient);
        sithThing_SetSector(pItem, pItem->itemParams.sector, 1);
        pItem->msecLifeLeft = 0;
        pItem->flags = pItem->flags & ~SITH_TF_DISABLED;
        if (Main_bMotsCompat) {
            if (pItem->collide == SITH_COLLIDE_NONE) {
                pItem->collide = SITH_COLLIDE_SPHERE;
                pItem->flags &= ~SITH_TF_10;
                return;
            }
        }
        sithCog_ThingSendMessage(pItem, pItem, SITH_MESSAGE_RESPAWN);
    }

    if ( sithMessage_g_outputstream )
    {
        sithDSSThing_UpdateState(pItem, -1, 255);
        sithDSSThing_Pos(pItem, -1, 1);
    }
}

// MOTS altered
int sithItem_ParseArg(StdConffileArg *pArg, SithThing *pThing, int adjNum)
{
    if ( adjNum == THINGPARAM_TYPEFLAGS )
    {
        int tmp;
        if ( _sscanf(pArg->value, "%x", &tmp) == 1 )
        {
            pThing->itemParams.flags = tmp;
            return 1;
        }
    }
    else if ( adjNum == THINGPARAM_RESPAWN )
    {
        pThing->itemParams.secRespawnInterval = _atof(pArg->value);
        return 1;
    }
#ifdef JKM_PARAMS
    else if ( adjNum == THINGPARAM_RESPAWNFACTOR )
    {
        pThing->itemParams.respawnFactor = _atof(pArg->value);
        return 1;
    }
#endif

    return 0;
}
