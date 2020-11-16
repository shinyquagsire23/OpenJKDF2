#include "jkPlayer.h"

#include "World/sithThing.h"
#include "World/sithPlayer.h"
#include "Engine/sithAnimclass.h"
#include "World/sithInventory.h"
#include "World/jkSaber.h"
#include "Primitives/rdMatrix.h"


void jkPlayer_renderSaberWeaponMesh(sithThing *thing)
{
    jkSaberInfo* saberInfo = thing->saberInfo;
    if (!saberInfo)
        return;

    if (!thing->animclass)
        return;

    rdMatrix34* primaryMat = &thing->rdthing.hierarchyNodeMatrices[thing->animclass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAP]];
        rdMatrix34* secondaryMat = &thing->rdthing.hierarchyNodeMatrices[thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP]];

    if (thing->jkFlags & JKFLAG_PERSUASION)
    {
        if ( g_selfPlayerInfo->iteminfo[SITHBIN_F_SEEING].state & ITEMSTATE_ACTIVATE )
        {
            thing->rdthing.geometryMode = thing->rdthing.geoMode;
            rdVector_Copy3(&thing->lookOrientation.scale, &thing->position);
            rdThing_Draw(&thing->rdthing, &thing->lookOrientation);

            thing->lookOrientation.scale.x = 0.0;
            thing->lookOrientation.scale.y = 0.0;
            thing->lookOrientation.scale.z = 0.0;
            thing->rdthing.geometryMode = thing->rdthing.geometryMode;

            if (saberInfo->rd_thing.model3)
                rdThing_Draw(&saberInfo->rd_thing, primaryMat);

            if (thing->jkFlags & JKFLAG_SABERON)
            {
                jkSaber_PolylineRand(&saberInfo->polylineThing);
                rdThing_Draw(&saberInfo->polylineThing, primaryMat);
                if ( thing->jkFlags & JKFLAG_DUALSABERS)
                    rdThing_Draw(&saberInfo->polylineThing, secondaryMat);
            }
        }
        else
        {
            jkPlayer_renderSaberTwinkle(thing);
        }
    }
    else if ( thing->rdthing.geometryMode > 0 )
    {
        if (saberInfo->rd_thing.model3)
            rdThing_Draw(&saberInfo->rd_thing, primaryMat);
        
        if (thing->jkFlags & JKFLAG_SABERON)
        {
            //jkSaber_PolylineRand(&saberInfo->polylineThing);
            rdThing_Draw(&saberInfo->polylineThing, primaryMat);
            if (thing->jkFlags & JKFLAG_DUALSABERS)
                rdThing_Draw(&saberInfo->polylineThing, secondaryMat);
        }
    }
}
