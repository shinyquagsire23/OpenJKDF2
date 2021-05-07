#include "sithSoundSys.h"

#include "Win95/stdMci.h"
#include "jk.h"

int sithSoundSys_Startup()
{
    if ( !stdMci_Startup() )
        return 1;

    if ( sithSoundSys_bInitted )
    {
        sithSoundSys_musicVolume = 1.0;
        stdMci_SetVolume(sithSoundSys_globalVolume);
    }

    sithSoundSys_bInitted = 1;
    return 1;
}
