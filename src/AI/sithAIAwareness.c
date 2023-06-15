#include "sithAIAwareness.h"

#include "AI/sithAI.h"
#include "Gameplay/sithEvent.h"
#include "World/sithWorld.h"
#include "World/sithSector.h"
#include "World/sithThing.h"
#include "Dss/sithMulti.h"
#include "jk.h"

int sithAIAwareness_Startup()
{
    sithAIAwareness_aSectors = (sithSectorAlloc *)pSithHS->alloc(sizeof(sithSectorAlloc) * sithWorld_pCurrentWorld->numSectors);
    if (sithAIAwareness_aSectors)
    {
        sithAIAwareness_numEntries = 0;
        if ( sithEvent_RegisterFunc(3, sithAIAwareness_Tick, 1000, SITHEVENT_TASKPERIODIC) )
        {
            sithAIAwareness_bInitted = 1;
            return 1;
        }
    }

    return 0;
}

void sithAIAwareness_Shutdown()
{
    pSithHS->free(sithAIAwareness_aSectors);
    sithAIAwareness_aSectors = 0;
    sithEvent_RegisterFunc(3, NULL, 0, SITHEVENT_TASKDISABLED);
    sithAIAwareness_bInitted = 0;
}

int sithAIAwareness_AddEntry(sithSector *sector, rdVector3 *pos, int a3, float a4, sithThing *thing)
{
    int v6; // ecx
    int v7; // eax

    if ( !sithAI_bOpened )
        return 0;
    v6 = sithAIAwareness_numEntries;
    if ( sithAIAwareness_numEntries == 32 )
        return 0;
    v7 = sithAIAwareness_numEntries;
    sithAIAwareness_aEntries[v7].sector = sector;
    sithAIAwareness_numEntries = v6 + 1;
    rdVector_Copy3(&sithAIAwareness_aEntries[v6].pos, pos);
    sithAIAwareness_aEntries[v7].field_14 = a3;
    sithAIAwareness_aEntries[v7].field_18 = a4;
    sithAIAwareness_aEntries[v7].thing = thing;

    return 1;
}

int sithAIAwareness_Tick(int a, sithEventInfo* b)
{
    // Added: co-op
    if (sithNet_isMulti && !sithNet_isServer)
        return 1;

    ++sithAIAwareness_timerTicks;
    if ( !sithAIAwareness_numEntries )
        return 1;

    for (size_t v1 = 0; v1 < sithAIAwareness_numEntries; v1++)
    {
        sithSectorEntry* v2 = &sithAIAwareness_aEntries[v1];
        // Added: potential crash maybe?
        sithAIAwareness_sub_4F2C30(v2, v2->sector, &v2->pos, &v2->pos, v2->field_18, v2->field_18, v2->thing);
    }
    
    // Added: fixed off-by-one in loop comparison
    for (size_t v3 = 0; v3 < sithAI_inittedActors; ++v3 )
    {
        // Added: prevent OOB access
        // TODO: define this maximum
        if (v3 >= 256) break;

        sithActor* i = &sithAI_actors[v3];

        if ( i->pAIClass )
        {
            if ( i->thing )
            {
                if ( (i->thing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
                {
                    sithSector* v6 = i->thing->sector;
                    if ( v6 )
                    {
                        if ( sithAIAwareness_aSectors[v6->id].field_0 == sithAIAwareness_timerTicks )
                            sithAI_SetActorFireTarget(i, SITHAI_MODE_ATTACKING, 0);
                    }
                }
            }
        }
    }
    sithAIAwareness_numEntries = 0;
    return 1;
}

void sithAIAwareness_sub_4F2C30(sithSectorEntry *pSectorEntry, sithSector *pSector, rdVector3 *pPos1, rdVector3 *pPos2, float a5, float a6, sithThing *pThing)
{
    // Added: potential crash maybe?
    OPENJKDF2_WARN_NULL_AND_RETURN(pSectorEntry);
    OPENJKDF2_WARN_NULL_AND_RETURN(pSector);
    OPENJKDF2_WARN_NULL_AND_RETURN(pPos1);
    OPENJKDF2_WARN_NULL_AND_RETURN(pPos2);

    sithSectorAlloc* pSectorAlloc = &sithAIAwareness_aSectors[pSector->id];
    if ( pSectorAlloc->field_0 != sithAIAwareness_timerTicks )
    {
        _memset(pSectorAlloc, 0, sizeof(sithSectorAlloc));
        pSectorAlloc->field_0 = sithAIAwareness_timerTicks;
    }

    if ( pSectorAlloc->field_4[pSectorEntry->field_14] < (double)a5 )
    {
        pSectorAlloc->field_4[pSectorEntry->field_14] = a5;
        pSectorAlloc->field_10[pSectorEntry->field_14] = *pPos1;
        pSectorAlloc->field_34[pSectorEntry->field_14] = *pPos2;
        pSectorAlloc->field_58[pSectorEntry->field_14] = pThing;
        if ( a6 > 0.0 )
        {
            for (sithAdjoin* i = pSector->adjoins; i; i = i->next )
            {
                float a6a = (i->mirror ? a6 - i->mirror->dist : a6);

                sithAIAwareness_sub_4F2C30(pSectorEntry, i->sector, pPos1, &i->field_1C, a6, a6a, pThing);
            }
        }
    }
}