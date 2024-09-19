#include "sithRagdoll.h"

#ifdef RAGDOLLS

#include "World/sithWorld.h"
#include "Primitives/rdRagdoll.h"
#include "General/stdHashTable.h"
#include "General/stdConffile.h"

#include "Primitives/rdVector.h"
#include "stdPlatform.h"

#include "jk.h"

#define SITHRAGDOLL_MAX_RAGDOLLS 64

static stdHashTable *sithRagdoll_alloc;

int sithRagdoll_Startup()
{
	sithRagdoll_alloc = stdHashTable_New(128);

    if (sithRagdoll_alloc)
        return 1;

    stdPrintf(pSithHS->errorPrint, ".\\Engine\\sithRagdoll.c", 66, "Failed to allocate memory for articulated figures.\n", 0, 0, 0, 0);
    return 0;
}

void sithRagdoll_Shutdown()
{
    if (sithRagdoll_alloc)
    {
        stdHashTable_Free(sithRagdoll_alloc);
		sithRagdoll_alloc = 0;
    }
}

rdRagdollSkeleton* sithRagdoll_LoadEntry(char *a1)
{
    if ( !sithWorld_pLoading->ragdolls )
    {
		sithWorld_pLoading->ragdolls = (rdRagdollSkeleton*)pSithHS->alloc(SITHRAGDOLL_MAX_RAGDOLLS * sizeof(rdRagdollSkeleton));
        if (sithWorld_pLoading->ragdolls)
        {
			sithWorld_pLoading->numRagdolls = SITHRAGDOLL_MAX_RAGDOLLS;
			sithWorld_pLoading->numRagdollsLoaded = 0;
            _memset(sithWorld_pLoading->ragdolls, 0, SITHRAGDOLL_MAX_RAGDOLLS * sizeof(rdRagdollSkeleton));
        }
    }
	
	rdRagdollSkeleton* result = (rdRagdollSkeleton*)stdHashTable_GetKeyVal(sithRagdoll_alloc, a1);
    if ( !result )
    {
		int idx = sithWorld_pLoading->numRagdollsLoaded;
        if (idx < sithWorld_pLoading->numRagdolls && sithWorld_pLoading->ragdolls)
        {
			rdRagdollSkeleton* skel = &sithWorld_pLoading->ragdolls[idx];
			
			char fpath[128];
			_sprintf(fpath, "%s%c%s", "misc\\af", '\\', a1);
            if ( rdRagdollSkeleton_LoadEntry(skel, fpath) )
            {
                stdHashTable_SetKeyVal(sithRagdoll_alloc, skel->name, skel);
                ++sithWorld_pLoading->numRagdollsLoaded;
                result = skel;
            }
			else
			{
				rdRagdollSkeleton_FreeEntry(skel);
			}
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

int sithRagdoll_Load(sithWorld *world, int numRagdolls)
{
	rdRagdollSkeleton* newRagdoll = (rdRagdollSkeleton*)pSithHS->alloc(sizeof(rdRagdollSkeleton) * numRagdolls);
    world->ragdolls = newRagdoll;
    if ( !newRagdoll)
        return 0;
    world->numRagdolls = numRagdolls;
    world->numRagdollsLoaded = 0;
    _memset(newRagdoll, 0, sizeof(rdRagdollSkeleton) * numRagdolls);
    return 1;
}

void sithRagdoll_Free(sithWorld *world)
{
    if (!world->numRagdollsLoaded)
		return;

    for (int i = 0; i < world->numRagdollsLoaded; i++)
    {
        stdHashTable_FreeKey(sithRagdoll_alloc, world->ragdolls[i].name);
        rdRagdollSkeleton_FreeEntry(&world->ragdolls[i]);
    }
    
    pSithHS->free(world->ragdolls);
    world->ragdolls = 0;
    world->numRagdolls = 0;
    world->numRagdollsLoaded = 0;
}

#endif
