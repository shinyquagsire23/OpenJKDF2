#include "sithCorpse.h"

#include "World/sithThing.h"
#include "World/jkPlayer.h"

void sithCorpse_Remove(sithThing *corpse)
{
    if ( corpse->isVisible + 1 == bShowInvisibleThings )
        corpse->lifeLeftMs = 3000;
    else
        sithThing_Destroy(corpse);
}
