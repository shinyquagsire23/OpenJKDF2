#include "rdPuppet.h"

#include "Engine/rdroid.h"
#include "stdPlatform.h"
#include "jk.h"

rdPuppet* rdPuppet_New(rdThing *thing)
{
    rdPuppet* puppet = (rdPuppet *)rdroid_pHS->alloc(sizeof(rdPuppet));

    if (!puppet )
        return NULL;

    // Added: Moved this memset after the nullptr check
    _memset(puppet, 0, sizeof(rdPuppet));

    puppet->paused = 0;
    puppet->rdthing = thing;

    for (int i = 0; i < 4; i++)
    {
        puppet->tracks[i].field_120 = 0.0;
        puppet->tracks[i].field_124 = 0.0;
        if ( puppet->tracks[i].callback )
        {
            puppet->tracks[i].callback(puppet->rdthing->parentSithThing, i, 0);
        }
        puppet->tracks[i].field_4 = 0;
        puppet->tracks[i].keyframe = NULL;
        puppet->tracks[i].callback = NULL;
    }
    thing->puppet = puppet;
    return puppet;
}

void rdPuppet_Free(rdPuppet *puppet)
{
    if ( puppet )
        rdroid_pHS->free(puppet);
}
