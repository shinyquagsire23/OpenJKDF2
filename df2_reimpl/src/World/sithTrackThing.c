#include "sithTrackThing.h"

#include "General/stdConffile.h"
#include "Engine/sithSoundClass.h"
#include "jk.h"

void sithTrackThing_MoveToFrame(sithThing *thing, int goalFrame, float a3)
{
    if ( goalFrame < thing->trackParams.loadedFrames )
    {
        thing->trackParams.field_C |= 4u;
        thing->trackParams.field_20 = a3;
        thing->goalframe = goalFrame;
        sithSoundClass_ThingPlaySoundclass4(thing, SITH_SC_STARTMOVE);
        sithSoundClass_ThingPlaySoundclass4(thing, SITH_SC_MOVING);
        sithTrackThing_Arrivedidk(thing);
    }
}

int sithTrackThing_LoadPathParams(stdConffileArg *arg, sithThing *thing, int param)
{
    sithThing *v4; // ebp
    int v5; // eax
    int v6; // ebx
    unsigned int v7; // esi
    sithThing *v8; // edi
    unsigned int v9; // esi
    sithThingFrame *v10; // eax
    rdVector3 v12; // [esp+10h] [ebp-Ch] BYREF
    rdVector3 v13;

    if ( param == THINGPARAM_FRAME )
    {
        v8 = thing;
        v9 = thing->trackParams.loadedFrames;
        if ( v9 < thing->trackParams.numFrames )
        {
            if ( _sscanf(arg->value, "(%f/%f/%f:%f/%f/%f)", &v12.x, &v12.y, &v12.z, &v13.x, &v13.y, &v13.z) != 6 )
                return 0;
            v10 = &v8->trackParams.frames[v9];
            v8->trackParams.loadedFrames = v9 + 1;
            rdVector_Copy3(&v10->pos, &v12);
            rdVector_Copy3(&v10->rot, &v13);
        }
        return 1;
    }
    if ( param != THINGPARAM_NUMFRAMES )
        return 0;
    v4 = thing;
    if ( thing->trackParams.numFrames )
        return 0;
    v5 = _atoi(arg->value);
    v6 = v5;
    if ( v5 < 1 )
        return 0;
    v7 = sizeof(sithThingFrame) * v5;
    v4->trackParams.frames = pSithHS->alloc(sizeof(sithThingFrame) * v5);
    if ( v4->trackParams.frames )
    {
        _memset(v4->trackParams.frames, 0, v7);
        v4->trackParams.numFrames = v6;
        v4->trackParams.loadedFrames = 0;
        return 1;
    }
    return 0;
}
