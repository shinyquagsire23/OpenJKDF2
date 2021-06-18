#include "sithSoundSys.h"

#include "Engine/sithSound.h"
#include "Win95/stdSound.h"
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

void sithSoundSys_FreeThing(sithThing *thing)
{
    int *v1; // esi
    int v2; // eax
    int v3; // eax
    int v5; // edx
    int v6; // eax
    IDirectSoundBuffer *v7; // [esp-10h] [ebp-18h]
    unsigned int v8; // [esp+4h] [ebp-4h]

    if (!sithSoundSys_bOpened)
        return;

    for (v8 = 0; v8 < sithSoundSys_numSoundsAvailable; v8++)
    {
        sithPlayingSound* playingSound = &sithSoundSys_aPlayingSounds[v8];
        
        if ( (playingSound->flags & 0x80u) != 0 && thing == playingSound->thing )
        {
            if ( (playingSound->flags & 1) != 0 )
            {
                if ( (playingSound->flags & 0x20000) != 0 )
                {
                    stdSound_BufferReset(playingSound->field_0);
                    v3 = sithSoundSys_dword_836BE8;
                    playingSound->flags &= ~0x20000u;
                    v7 = (IDirectSoundBuffer *)playingSound->field_0;
                    sithSoundSys_dword_836BE8 = v3 - 1;
                    stdSound_BufferRelease(v7);
                    playingSound->field_0 = 0;
                    --*(uint32_t*)(playingSound->vtable + 64);
                }

                if ( playingSound->field_0 )
                {
                    stdSound_BufferRelease(playingSound->field_0);
                    playingSound->field_0 = 0;
                }
                if ( playingSound->anonymous_0 )
                {
                    stdSound_BufferRelease_0(playingSound->anonymous_0);
                    playingSound->anonymous_0 = 0;
                }
                v5 = playingSound->idx;
                _memset(playingSound, 0, sizeof(sithPlayingSound));
                v6 = sithSoundSys_numSoundsAvailable2;
                playingSound->idx = v5;
                sithSoundSys_aIdk[v6] = v5;
                sithSoundSys_numSoundsAvailable2 = v6 + 1;
            }
            else
            {
                playingSound->idx &= ~0x80;
                playingSound->idx |= 0x40;
                rdVector_Copy3(&playingSound->pos, &thing->position);
            }
        }
    }
}

#ifdef LINUX
void sithSoundSys_Tick(float a1)
{
}

void sithSoundSys_ResumeMusic(int a1)
{
    
}

void sithSoundSys_StopAll()
{
}

void sithSoundSys_ResumeAll()
{
}

void sithSoundSys_sub_4DBF90()
{
}

void sithSoundSys_Close()
{
    sithSoundSys_bOpened = 0;
}

void sithSoundSys_StopSong()
{
}

int sithSoundSys_PlaySong(unsigned int trackTo, unsigned int trackFrom, unsigned int trackNum, int a4)
{
    return 1;
}

void sithSoundSys_SetMusicVol(float a1)
{
}
#endif
