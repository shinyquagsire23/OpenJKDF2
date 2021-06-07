#include "sithActor.h"

#include "World/sithThing.h"
#include "World/sithSector.h"
#include "Engine/sithSoundClass.h"

void sithActor_Tick(sithThing *thing, int deltaMs)
{
    unsigned int v2; // eax
    unsigned int v3; // eax

    if ( (thing->actorParams.typeflags & THING_TYPEFLAGS_40) == 0 && (thing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
    {
        if ( (thing->trackParams.numFrames & PHYSFLAGS_MIDAIR) != 0 || (thing->sector->flags & SITH_SF_UNDERWATER) == 0 )
        {
            v3 = thing->actorParams.msUnderwater;
            if ( v3 )
            {
                if ( v3 <= 18000 )
                {
                    if ( v3 > 10000 )
                        sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_BREATH);
                }
                else
                {
                    sithSoundClass_ThingPlaySoundclass(thing, SITH_SC_GASP);
                }
                thing->actorParams.msUnderwater = 0;
            }
        }
        else
        {
            v2 = deltaMs + thing->actorParams.msUnderwater;
            thing->actorParams.msUnderwater = v2;
            if ( v2 > 20000 )
            {
                sithThing_Damage(thing, thing, 10.0, 32);
                thing->actorParams.msUnderwater -= 2000;
            }
        }
    }
}
