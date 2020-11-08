#include "jkSaber.h"

#include "jkPlayer.h"
#include "Engine/rdroid.h"
#include "Engine/rdPuppet.h"
#include "jk.h"

void jkSaber_PolylineRandidk(rdThing *thing)
{
    rdModel3* model = thing->model3;
    if ( model )
    {
        if ( !(bShowInvisibleThings & 0xF) )
            model->field_64 = 0.0;
        model->field_64 = ((double)_rand() * 0.000030518509 - 0.80000001) * 80.0 + model->field_64;
    }
}

void jkSaber_Draw(rdMatrix34 *posRotMat)
{
    if ( playerThings[playerThingIdx].spawnedSparks->jkFlags & JKFLAG_SABERON
      && playerThings[playerThingIdx].field_4C.model3
      && playerThings[playerThingIdx].polylineThing.model3 )
    {
        if ( playerThings[playerThingIdx].field_4C.frameTrue != rdroid_frameTrue )
        {
            rdPuppet_BuildJointMatrices(&playerThings[playerThingIdx].field_4C, posRotMat);
        }

        jkSaber_PolylineRandidk(&playerThings[playerThingIdx].polylineThing);
        rdThing_Draw(&playerThings[playerThingIdx].polylineThing, &playerThings[playerThingIdx].field_4C.hierarchyNodeMatrices[5]);
    }
}
