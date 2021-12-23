#include "stdMci.h"

#include "jk.h"

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

#ifndef SDL2_RENDER

int stdMci_Startup()
{
    MCI_SET_PARMS setParams;
    MCI_OPEN_PARMS openParams;
    struct tagAUXCAPSA pac;

    openParams.lpstrDeviceType = "cdaudio";
    if (jk_mciSendCommandA(0, MCI_OPEN, MCI_OPEN_TYPE, &openParams))
        return 0;
    stdMci_mciId = openParams.wDeviceID;
    setParams.dwTimeFormat = MCI_FORMAT_TMSF;
    if (jk_mciSendCommandA(openParams.wDeviceID, MCI_SET, MCI_SET_TIME_FORMAT, &setParams))
    {
        jk_mciSendCommandA(stdMci_mciId, MCI_CLOSE, 0, 0);
        return 0;
    }

    for (int i = 0; i < jk_auxGetNumDevs(); i++)
    {
        _memset(&pac, 0, sizeof(pac));
        if (jk_auxGetDevCapsA(i, &pac, 48) >= 0 && pac.wTechnology == 1)
        {
            stdMci_uDeviceID = i;
            break;
        }
    }

    if (stdMci_uDeviceID >= 0)
        jk_auxGetVolume(stdMci_uDeviceID, &stdMci_dwVolume);
    stdMci_bInitted = 1;
    return 1;
}

void stdMci_Shutdown()
{
    if (stdMci_mciId)
    {
        jk_mciSendCommandA(stdMci_mciId, MCI_STOP, 0, NULL);
        jk_mciSendCommandA(stdMci_mciId, MCI_CLOSE, 0, NULL);
        stdMci_mciId = 0;
    }

    if (stdMci_uDeviceID >= 0)
        jk_auxSetVolume(stdMci_uDeviceID, stdMci_dwVolume);

    stdMci_bInitted = 0;
}

int stdMci_Play(uint8_t trackTo, uint8_t trackFrom)
{
    MCI_PLAY_PARMS playParams;

    if (!stdMci_bInitted)
        return 0;

    playParams.dwTo = (trackFrom + 1 <= trackTo) ? (trackTo + 1) : (trackFrom + 1);
    playParams.dwFrom = trackTo;
    if (!jk_mciSendCommandA(stdMci_mciId, MCI_PLAY, (MCI_TO|MCI_FROM), &playParams))
        return 1;
    if(!jk_mciSendCommandA(stdMci_mciId, MCI_PLAY, MCI_FROM, &playParams))
        return 1;
    return 0;
}

void stdMci_SetVolume(float vol)
{
    if (!stdMci_bInitted)
        return;

    uint16_t volQuantized = (uint16_t)(vol * 65535.0);
    if (stdMci_uDeviceID >= 0)
        jk_auxSetVolume(stdMci_uDeviceID, volQuantized | (volQuantized<<16));
}

void stdMci_Stop()
{
    if (stdMci_bInitted)
        jk_mciSendCommandA(stdMci_mciId, MCI_STOP, 0, 0);
}

int stdMci_CheckStatus()
{
    MCI_STATUS_PARMS statusParms;

    if (!stdMci_bInitted)
        return 0;

    statusParms.dwCallback = 0;
    statusParms.dwReturn = 0;
    statusParms.dwTrack = 0;
    statusParms.dwItem = MCI_STATUS_MODE;
    jk_mciSendCommandA(stdMci_mciId, MCI_STATUS, MCI_STATUS_ITEM, &statusParms);
    return statusParms.dwReturn != MCI_MODE_STOP;
}

double stdMci_GetTrackLength(int track)
{
    MCI_STATUS_PARMS statusParms;

    if (!stdMci_bInitted)
        return 0.0;

    statusParms.dwCallback = 0;
    statusParms.dwReturn = 0;
    statusParms.dwItem = MCI_STATUS_LENGTH;
    statusParms.dwTrack = track;
    jk_mciSendCommandA(stdMci_mciId, MCI_STATUS, 0x110u, &statusParms);

    return (double)((statusParms.dwReturn >> 16) & 0xFF) + (double)((statusParms.dwReturn >> 8) & 0xFF) * 60.0;
}

#else // LINUX
#ifdef NULL_SOUND

int stdMci_trackTo;
int stdMci_trackFrom;
int stdMci_trackCurrent;
int stdMci_music;

int stdMci_Startup()
{
    stdMci_uDeviceID = 0;

    stdMci_bInitted = 1;
    
    return 1;
}

void stdMci_Shutdown()
{
    stdMci_bInitted = 0;
}

void stdMci_trackFinished();
void stdMci_trackStart(int track)
{
    stdMci_music = 1;
}

void stdMci_trackFinished()
{
    stdMci_trackCurrent++;
    if (stdMci_trackCurrent >= stdMci_trackTo)
        stdMci_trackCurrent = stdMci_trackFrom;
    
    stdMci_trackStart(stdMci_trackCurrent);
}

int stdMci_Play(uint8_t trackTo, uint8_t trackFrom)
{
    stdMci_trackTo = trackTo;
    stdMci_trackFrom = trackFrom;
}

void stdMci_SetVolume(float vol)
{
}

void stdMci_Stop()
{
    printf("stdMci: stop music\n");
    
    if (stdMci_music) {
        stdMci_music = 0;
    }
}

int stdMci_CheckStatus()
{
    return stdMci_music;
}

double stdMci_GetTrackLength(int track)
{
    return 0.0;
}

#else // !NULL_SOUND

#include <SDL_mixer.h>

int stdMci_trackTo;
int stdMci_trackFrom;
int stdMci_trackCurrent;
Mix_Music* stdMci_music;

int stdMci_Startup()
{
    stdMci_uDeviceID = 0;

    stdMci_bInitted = 1;
    
    if (Mix_OpenAudio(48000, AUDIO_S16SYS, 2, 1024) < 0)
	    return 1;

	Mix_AllocateChannels(2);
    
    return 1;
}

void stdMci_Shutdown()
{
    stdMci_bInitted = 0;
    Mix_CloseAudio();
}

void stdMci_trackFinished();
void stdMci_trackStart(int track)
{
    char tmp[256];
    
    snprintf(tmp, 255, "MUSIC/Track%d.ogg", track);

#ifdef LINUX
    char *r = malloc(strlen(tmp) + 16);
    if (casepath(tmp, r))
    {
        strcpy(tmp, r);
    }
    free(r);
#endif

    if (stdMci_music)
        Mix_FreeMusic(stdMci_music);

    stdMci_music = Mix_LoadMUS(tmp);
            
    if (!stdMci_music) {
        printf("WARN: Failed to play music `%s'\n", tmp);
        return;
    }

    Mix_PlayMusic(stdMci_music, 0);
    Mix_HookMusicFinished(stdMci_trackFinished);
    printf("INFO: Playing music `%s'\n", tmp);
}

void stdMci_trackFinished()
{
    stdMci_trackCurrent++;
    if (stdMci_trackCurrent >= stdMci_trackTo)
        stdMci_trackCurrent = stdMci_trackFrom;
    
    stdMci_trackStart(stdMci_trackCurrent);
}

int stdMci_Play(uint8_t trackTo, uint8_t trackFrom)
{
    char tmp[256];
    
    printf("stdMci: play track %d to %d\n", trackTo, trackFrom);
    
    stdMci_trackTo = trackTo;
    stdMci_trackFrom = trackFrom;
    
    stdMci_trackStart(stdMci_trackTo);
}

void stdMci_SetVolume(float vol)
{
    printf("Set vol %f\n", vol);
    uint8_t volQuantized = (uint16_t)(vol * (double)MIX_MAX_VOLUME);
    Mix_VolumeMusic(volQuantized);
}

void stdMci_Stop()
{
    printf("stdMci: stop music\n");
    
    if (stdMci_music) {
        Mix_HaltMusic();
        Mix_FreeMusic(stdMci_music);
        stdMci_music = NULL;
    }
}

int stdMci_CheckStatus()
{
    return (stdMci_music != NULL);
}

double stdMci_GetTrackLength(int track)
{
    return 0.0;
}

#endif // else SDL2_RENDER
#endif // else NULL_SOUND
