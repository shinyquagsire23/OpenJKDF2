#include "sithSoundSys.h"

#include "Engine/sithControl.h"
#include "Engine/sithSound.h"
#include "Engine/sithTime.h"
#include "Engine/sithNet.h"
#include "Win95/stdSound.h"
#include "Win95/stdMci.h"
#include "World/sithSector.h"
#include "World/jkPlayer.h"
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

void sithSoundSys_Shutdown()
{
    if ( sithSoundSys_bInitted )
    {
        stdMci_Shutdown();
        sithSoundSys_bInitted = 0;
    }
}

int sithSoundSys_PlaySong(unsigned int trackTo, unsigned int trackFrom, unsigned int trackNum, int a4)
{
    unsigned int trackFrom_; // esi
    unsigned int trackTo_; // edi
    int result; // eax

    if ( sithSoundSys_bPlayingMci )
        stdMci_Stop();
    trackFrom_ = trackFrom;
    if ( trackFrom <= trackTo )
        trackFrom_ = trackTo;
    trackTo_ = trackNum;
    if ( trackNum < trackTo )
    {
        trackTo_ = trackTo;
    }
    else if ( trackNum > trackFrom_ )
    {
        trackTo_ = trackFrom_;
    }
    sithSoundSys_trackTo = trackTo;
    sithSoundSys_bPlayingMci = 1;
    sithSoundSys_trackFrom = trackFrom_;
    sithSoundSys_dword_835FCC = a4;
    if ( !sithSoundSys_bIsMuted )
    {
        if ( sithSoundSys_bInitted )
        {
            sithSoundSys_musicVolume = 1.0;
            stdMci_SetVolume(sithSoundSys_globalVolume);
        }

        if ( !stdMci_Play(trackTo_, trackFrom_) )
        {
            sithSoundSys_bPlayingMci = 0;
            return 0;
        }
        if ( a4 )
            sithSoundSys_flt_835FD8 = sithTime_curSeconds - -5.0;
    }
    return 1;
}

void sithSoundSys_StopSong()
{
    if ( sithSoundSys_bPlayingMci )
    {
        stdMci_Stop();
        sithSoundSys_bPlayingMci = 0;
    }
}

void sithSoundSys_UpdateMusicVolume(float musicVolume)
{
    float vol; // [esp+0h] [ebp-4h]

    if ( musicVolume < 0.0 )
    {
        sithSoundSys_globalVolume = 0.0;
    }
    else if ( musicVolume > 1.0 )
    {
        sithSoundSys_globalVolume = 1.0;
    }
    else
    {
        sithSoundSys_globalVolume = musicVolume;
    }
    if ( sithSoundSys_globalVolume == 0.0 )
    {
        sithSoundSys_bIsMuted = 1;
        if ( !sithSoundSys_bInitted )
            return;
        stdMci_Stop();
    }
    else
    {
        if ( !sithSoundSys_bInitted )
            return;
        sithSoundSys_bIsMuted = 0;
        if ( sithSoundSys_bPlayingMci )
        {
            if ( sithSoundSys_dword_835FCC )
            {
                sithSoundSys_flt_835FD8 = sithTime_curSeconds - -5.0;
                if ( !stdMci_CheckStatus() && !stdMci_Play(sithSoundSys_trackTo, sithSoundSys_trackFrom) )
                {
                    sithSoundSys_bPlayingMci = 0;
                    sithSoundSys_dword_835FCC = 0;
                }
            }
        }
    }
    
    sithSoundSys_SetMusicVol(sithSoundSys_musicVolume);
}

void sithSoundSys_SetMusicVol(float volume)
{
    if ( sithSoundSys_bInitted )
    {
        if ( volume < 0.0 )
        {
            sithSoundSys_musicVolume = 0.0;
        }
        else if ( volume > 1.0 )
        {
            sithSoundSys_musicVolume = 1.0;
        }
        else
        {
            sithSoundSys_musicVolume = volume;
        }

        stdMci_SetVolume(sithSoundSys_globalVolume * sithSoundSys_musicVolume);
    }
}

void sithSoundSys_ResumeMusic(int a1)
{
    if ( sithSoundSys_bPlayingMci
      && !sithSoundSys_bIsMuted
      && (a1 || sithControl_msIdle >= 0x7D0)
      && sithSoundSys_dword_835FCC
      && (a1 || sithSoundSys_flt_835FD8 <= (double)sithTime_curSeconds) )
    {
        sithSoundSys_flt_835FD8 = sithTime_curSeconds - -5.0;
        if ( !stdMci_CheckStatus() && !stdMci_Play(sithSoundSys_trackTo, sithSoundSys_trackFrom) )
        {
            sithSoundSys_bPlayingMci = 0;
            sithSoundSys_dword_835FCC = 0;
        }
    }
}

int sithSoundSys_Open()
{
    if ( sithSoundSys_bOpened )
        return 0;

    if ( !sithSound_bInit )
        return 0;
    
    sithSoundSys_ClearAll();

    sithSoundSys_bOpened = 1;
    return 1;
}

void sithSoundSys_Close()
{
    unsigned int v0; // ebp
    sithPlayingSound* soundIter;
    sithPlayingSound *v3; // edi

    if (!sithSoundSys_bOpened)
        return;

    v0 = 0;
    if ( sithSoundSys_numSoundsAvailable )
    {
        soundIter = &sithSoundSys_aPlayingSounds[0];
        do
        {
            if ( soundIter->sound )
            {
                if ( (soundIter->flags & SITHSOUNDFLAG_PLAYING) != 0 )
                {
                    stdSound_BufferReset(soundIter->pSoundBuf);
                    soundIter->flags &= ~SITHSOUNDFLAG_PLAYING;
                    sithSoundSys_dword_836BE8--;
                    stdSound_BufferRelease(soundIter->pSoundBuf);
                    soundIter->pSoundBuf = 0;
                    --soundIter->sound->field_40;
                }

                if ( soundIter->pSoundBuf )
                {
                    stdSound_BufferRelease(soundIter->pSoundBuf);
                    soundIter->pSoundBuf = 0;
                }
                if ( soundIter->p3DSoundObj )
                {
                    stdSound_3DBufferRelease(soundIter->p3DSoundObj);
                    soundIter->p3DSoundObj = 0;
                }

                int v4 = soundIter->idx;
                _memset(soundIter, 0, sizeof(sithPlayingSound));
                soundIter->idx = v4;
                sithSoundSys_aIdk[sithSoundSys_numSoundsAvailable2++] = v4;
            }
            ++v0;
            soundIter++;
        }
        while ( v0 < sithSoundSys_numSoundsAvailable );
    }
    sithSoundSys_pPlayingSoundIdk = 0;
    sithSoundSys_dword_836BFC = 0;
    sithSoundSys_pLastSectorSoundSector = 0;
    stdSound_IA3D_idk(0.0);
    sithSoundSys_dword_836C00 = 0;
    sithSoundSys_pLastSectorSoundSector = 0;
    sithSoundSys_pPlayingSoundIdk = 0;
    sithSoundSys_dword_836BFC = 0;
    sithSoundSys_bOpened = 0;
}

void sithSoundSys_ClearAll()
{
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
    sithSoundSys_pLastSectorSoundSector = 0;
}

void sithSoundSys_StopAll()
{
    unsigned int v0; // edi

    if ( !net_isMulti )
    {
        for (v0 = 0; v0 < sithSoundSys_numSoundsAvailable; v0++)
        {
            if ( (sithSoundSys_aPlayingSounds[v0].flags & SITHSOUNDFLAG_PLAYING) != 0 )
            {
                stdSound_BufferStop(sithSoundSys_aPlayingSounds[v0].pSoundBuf);
                sithSoundSys_aPlayingSounds[v0].flags |= SITHSOUNDFLAG_40000;
            }
        }
    }
}

void sithSoundSys_ResumeAll()
{
    unsigned int v0; // edi

    if ( !net_isMulti )
    {
        for (v0 = 0; v0 < sithSoundSys_numSoundsAvailable; v0++)
        {
            if ( (sithSoundSys_aPlayingSounds[v0].flags & SITHSOUNDFLAG_40000) != 0 )
            {
                if ( sithSoundSys_aPlayingSounds[v0].pSoundBuf )
                    stdSound_BufferPlay(sithSoundSys_aPlayingSounds[v0].pSoundBuf, sithSoundSys_aPlayingSounds[v0].flags & SITHSOUNDFLAG_LOOP);
                sithSoundSys_aPlayingSounds[v0].flags &= ~SITHSOUNDFLAG_40000;
            }
        }
    }
}

sithPlayingSound* sithSoundSys_PlayingSoundFromSound(sithSound *sound, int flags)
{
    sithPlayingSound *result; // eax
    int v3; // eax
    int v5; // edx

    if ( !sithSoundSys_bOpened )
        return 0;
    if ( sithSoundSys_numSoundsAvailable2 )
        v3 = sithSoundSys_aIdk[--sithSoundSys_numSoundsAvailable2];
    else
        v3 = -1;
    if ( v3 < 0 )
        return 0;

    result = &sithSoundSys_aPlayingSounds[v3];
    result->sound = sound;
    result->flags = flags;
    result->volumeVelocity = 1.0;
    result->pitch = 1.0;
    if ( sithSoundSys_nextSoundIdx == 0 )
        sithSoundSys_nextSoundIdx = 1;
    v5 = sithSoundSys_nextSoundIdx++ | ((playerThingIdx + 1) << 16);
    result->refid = v5;
    return result;
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
                    stdSound_BufferReset(playingSound->pSoundBuf);
                    v3 = sithSoundSys_dword_836BE8;
                    playingSound->flags &= ~0x20000u;
                    v7 = (IDirectSoundBuffer *)playingSound->pSoundBuf;
                    sithSoundSys_dword_836BE8 = v3 - 1;
                    stdSound_BufferRelease(v7);
                    playingSound->pSoundBuf = 0;
                    --playingSound->sound->field_40;
                }

                if ( playingSound->pSoundBuf )
                {
                    stdSound_BufferRelease(playingSound->pSoundBuf);
                    playingSound->pSoundBuf = 0;
                }
                if ( playingSound->p3DSoundObj )
                {
                    stdSound_3DBufferRelease(playingSound->p3DSoundObj);
                    playingSound->p3DSoundObj = 0;
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

void sithSoundSys_SectorSound(sithSector *sector, sithSound *sound, float vol)
{
    sector->sectorSound = sound;
    sector->sectorSoundVol = vol;
    if ( sithSoundSys_pLastSectorSoundSector == sector )
        sithSoundSys_pLastSectorSoundSector = 0;
}

#ifdef LINUX
void sithSoundSys_Tick(float a1)
{
}

void sithSoundSys_sub_4DBF90()
{
}

sithPlayingSound* sithSoundSys_GetSoundFromRef(int a1)
{
    return NULL;
}
#endif
