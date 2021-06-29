#include "sithSoundSys.h"

#include "Engine/sithControl.h"
#include "Engine/sithSound.h"
#include "Engine/sithTime.h"
#include "Engine/sithNet.h"
#include "Win95/stdSound.h"
#include "Win95/stdMci.h"
#include "Gui/jkGUISound.h"
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

sithPlayingSound* sithSoundSys_cog_playsound_internal(sithSound *sound, float volume, float pan, int flags)
{
    sithPlayingSound *result; // eax
    sithPlayingSound *v6; // ebx
    int v8; // ecx
    stdSound_buffer_t *v9; // eax
    stdSound_buffer_t *v10; // eax
    stdSound_buffer_t *v11; // eax
    double v12; // st7
    int v13; // ecx
    unsigned int v14; // ecx
    int v15; // esi
    sithPlayingSound* v16;
    sithPlayingSound *v17; // esi
    int v18; // ecx
    int v19; // ecx
    sithPlayingSound *v20; // esi
    int v21; // eax
    int v22; // eax
    int v23; // edx
    int v24; // eax
    float a2; // [esp+0h] [ebp-10h]
    float a2a; // [esp+0h] [ebp-10h]
    stdSound_buffer_t *a2b; // [esp+0h] [ebp-10h]
    stdSound_buffer_t *a2d; // [esp+0h] [ebp-10h]

    v6 = sithSoundSys_PlayingSoundFromSound(sound, flags);
    
    if ( !v6 )
        return 0;
    v9 = sithSound_LoadData(v6->sound);
    v6->pSoundBuf = v9;
    if ( !v9 )
        goto LABEL_50;
    ++v6->sound->field_40;
    a2 = v6->vol_2 * 0.75;
    stdSound_BufferSetVolume(v6->pSoundBuf, a2);
    if ( jkGuiSound_b3DSound )
    {
        v10 = (stdSound_buffer_t *)stdSound_BufferQueryInterface(v6->pSoundBuf);
        v6->p3DSoundObj = v10;
        if ( v10 )
            stdSound_BufferSetVolume(v6->pSoundBuf, v6->vol_2);
    }
    v11 = v6->p3DSoundObj;
    if ( v11 )
        stdSound_3DBufferIdk(v11, 2);
    if ( volume < 0.0 )
    {
        v12 = 0.0;
    }
    else if ( volume > 1.5 )
    {
        v12 = 1.5;
    }
    else
    {
        v12 = volume;
    }
    v6->vol_2 = v12;
    if ( v6->pSoundBuf )
    {
        v13 = v6->flags;
        if ( (v13 & SITHSOUNDFLAG_80000) != 0 || (v13 & (SITHSOUNDFLAG_FOLLOWSTHING|SITHSOUNDFLAG_ABSOLUTE)) == 0 )
        {
            a2a = v12 * 0.75;
            stdSound_BufferSetVolume(v6->pSoundBuf, a2a);
        }
    }
    stdSound_BufferSetPan(v6->pSoundBuf, pan);
    if ( sithSoundSys_dword_836BE8 >= (unsigned int)jkGuiSound_numChannels )
    {
        v14 = sithSoundSys_dword_836C04;
        v15 = 0;
        while ( v14 >= 0x20 )
        {
LABEL_35:
            if ( v15 )
                goto LABEL_46;
            v14 = 0;
            v15 = 1;
            sithSoundSys_dword_836C04 = 0;
        }

        v16 = &sithSoundSys_aPlayingSounds[v14];
        while ( (v16->flags & SITHSOUNDFLAG_PLAYING) == 0 || (v16->flags & (SITHSOUNDFLAG_200|SITHSOUNDFLAG_HIGHPRIO|SITHSOUNDFLAG_LOOP)) != 0 )
        {
            v16++;
            sithSoundSys_dword_836C04 = ++v14;
            if ( v16 >= &sithSoundSys_aPlayingSounds[32] )
                goto LABEL_35;
        }
        v17 = &sithSoundSys_aPlayingSounds[v14];
        stdSound_BufferReset(v17->pSoundBuf);
        v18 = sithSoundSys_dword_836BE8;
        v17->flags &= ~SITHSOUNDFLAG_PLAYING;
        a2b = v17->pSoundBuf;
        sithSoundSys_dword_836BE8 = v18 - 1;
        stdSound_BufferRelease(a2b);
        v19 = sithSoundSys_dword_836C04;
        v17->pSoundBuf = 0;
        --v17->sound->field_40;
        if ( (sithSoundSys_aPlayingSounds[v19].flags & SITHSOUNDFLAG_LOOP) == 0 )
        {
            v20 = &sithSoundSys_aPlayingSounds[v19];
            if ( (sithSoundSys_aPlayingSounds[v19].flags & SITHSOUNDFLAG_PLAYING) != 0 )
                sithSoundSys_PlayingSoundReset(v20);
            if ( v20->pSoundBuf )
            {
                stdSound_BufferRelease(v20->pSoundBuf);
                v20->pSoundBuf = 0;
            }
            if ( v20->p3DSoundObj )
            {
                stdSound_3DBufferRelease(v20->p3DSoundObj);
                v20->p3DSoundObj = 0;
            }
            sithSoundSys_FreePlayingSound(v20);
            v19 = sithSoundSys_dword_836C04;
        }
        sithSoundSys_dword_836C04 = v19 + 1;
    }
LABEL_46:
    if ( sithSoundSys_dword_836BE8 < (unsigned int)jkGuiSound_numChannels )
    {
        if ( jkGuiSound_b3DSound )
            stdSound_CommitDeferredSettings();
        stdSound_BufferPlay(v6->pSoundBuf, v6->flags & SITHSOUNDFLAG_LOOP);
        v21 = sithSoundSys_dword_836BE8 + 1;
        v6->flags |= SITHSOUNDFLAG_PLAYING;
        sithSoundSys_dword_836BE8 = v21;
        result = v6;
    }
    else
    {
LABEL_50:
        if ( (v6->flags & SITHSOUNDFLAG_PLAYING) != 0 )
        {
            sithSoundSys_PlayingSoundReset(v6);
        }
        if ( v6->pSoundBuf )
        {
            stdSound_BufferRelease(v6->pSoundBuf);
            v6->pSoundBuf = 0;
        }
        if ( v6->p3DSoundObj )
        {
            stdSound_3DBufferRelease(v6->p3DSoundObj);
            v6->p3DSoundObj = 0;
        }
        v23 = v6->idx;
        _memset(v6, 0, sizeof(sithPlayingSound));
        v24 = sithSoundSys_numSoundsAvailable2;
        v6->idx = v23;
        sithSoundSys_aIdk[v24] = v23;
        sithSoundSys_numSoundsAvailable2 = v24 + 1;
        result = 0;
    }
    return result;
}

void sithSoundSys_PlayingSoundReset(sithPlayingSound *sound)
{
    int v1; // eax
    stdSound_buffer_t *v2; // [esp-4h] [ebp-8h]

    stdSound_BufferReset(sound->pSoundBuf);
    v1 = sithSoundSys_dword_836BE8;
    sound->flags &= ~SITHSOUNDFLAG_PLAYING;
    v2 = sound->pSoundBuf;
    sithSoundSys_dword_836BE8 = v1 - 1;
    stdSound_BufferRelease(v2);
    sound->pSoundBuf = 0;
    --sound->sound->field_40;
}

void sithSoundSys_Reset()
{
    unsigned int v0; // ebp
    int v2; // eax
    sithPlayingSound *v3; // edi
    int v4; // edx
    int v5; // eax
    stdSound_buffer_t *v6; // [esp-Ch] [ebp-14h]

    v0 = 0;
    for (v0 = 0; v0 < sithSoundSys_numSoundsAvailable; v0++ )
    {
        sithPlayingSound* v1 = &sithSoundSys_aPlayingSounds[v0];
        if ( v1->sound )
        {
            if ( (v1->flags & SITHSOUNDFLAG_PLAYING) != 0 )
            {
                sithSoundSys_PlayingSoundReset(v1);
            }
            v3 = v1;
            if ( v1->pSoundBuf )
            {
                stdSound_BufferRelease(v1->pSoundBuf);
                v3->pSoundBuf = 0;
            }
            if ( v1->p3DSoundObj )
            {
                stdSound_3DBufferRelease(v1->p3DSoundObj);
                v1->p3DSoundObj = 0;
            }
            v4 = v1->idx;
            _memset(v3, 0, sizeof(sithPlayingSound));
            v5 = sithSoundSys_numSoundsAvailable2;
            v1->idx = v4;
            sithSoundSys_aIdk[v5] = v4;
            sithSoundSys_numSoundsAvailable2 = v5 + 1;
        }
    }
    sithSoundSys_pPlayingSoundIdk = 0;
    sithSoundSys_pLastSectorSoundSector = 0;
    sithSoundSys_dword_836BFC = 0;
}

void sithSoundSys_FreePlayingSound(sithPlayingSound *sound)
{
    int v1; // esi

    v1 = sound->idx;
    _memset(sound, 0, sizeof(sithPlayingSound));
    sound->idx = v1;
    sithSoundSys_aIdk[sithSoundSys_numSoundsAvailable2++] = v1;
}

void sithSoundSys_FreeThing(sithThing *thing)
{
    int *v1; // esi
    int v2; // eax
    int v3; // eax
    int v5; // edx
    int v6; // eax
    stdSound_buffer_t *v7; // [esp-10h] [ebp-18h]
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
                    v7 = (stdSound_buffer_t *)playingSound->pSoundBuf;
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

sithPlayingSound* sithSoundSys_GetSoundFromRef(int refid)
{
    unsigned int playingsound_idx; // ecx

    if ( !refid )
        return NULL;

    playingsound_idx = 0;
    for (int i = 0; i < 32; i++)
    {
        if ( sithSoundSys_aPlayingSounds[i].sound && sithSoundSys_aPlayingSounds[i].refid == refid )
            break;
        ++playingsound_idx;
    }

    if ( playingsound_idx < 0x20 )
        return &sithSoundSys_aPlayingSounds[playingsound_idx];
    else
        return NULL;
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
#endif
