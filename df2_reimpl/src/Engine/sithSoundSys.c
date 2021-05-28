#include "sithSoundSys.h"

#include "Engine/sithSound.h"
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

int sithSoundSys_Open()
{
    if ( sithSoundSys_bOpened )
        return 0;

    if ( !sithSound_bInit )
        return 0;
    
    _memset(sithSoundSys_aPlayingSounds, 0, sizeof(sithPlayingSound) * 32);
    for (int i = 0; i < 32; i++)
    {
        sithSoundSys_aPlayingSounds[i].idx = i;
    }

    sithSoundSys_numSoundsAvailable = 32;
    sithSoundSys_numSoundsAvailable2 = 32;

    // Someone please help whoever programmed this    
    for (int i = 31; i >= 0; i--)
    {
        // Setting the index?
        sithSoundSys_aPlayingSounds[i].idx = i;

        // Ok nvm clearing the struct
        _memset(&sithSoundSys_aPlayingSounds[i], 0, sizeof(sithPlayingSound));

        // but gotta set that index again
        sithSoundSys_aPlayingSounds[i].idx = i;
        sithSoundSys_aIdk[31 - i] = i;
    }

    sithSoundSys_dword_836BF8 = 0;
    sithSoundSys_dword_836BFC = 0;
    sithSoundSys_dword_836BF4 = 0;

    sithSoundSys_bOpened = 1;
    return 1;
}
