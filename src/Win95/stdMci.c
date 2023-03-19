#include "stdMci.h"

#include "Main/jkMain.h"
#include "stdPlatform.h"
#include "jk.h"

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

// Added
int stdMci_bIsGOG = 1;

#ifndef SDL2_RENDER

int stdMci_Startup()
{
    // Added
    stdMci_bIsGOG = 1;

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

    // Added
    stdMci_bIsGOG = 1;
}

int stdMci_Play(uint8_t trackFrom, uint8_t trackTo)
{
    MCI_PLAY_PARMS playParams;

    if (!stdMci_bInitted)
        return 0;

    playParams.dwTo = (trackTo + 1 <= trackFrom) ? (trackFrom + 1) : (trackTo + 1);
    playParams.dwFrom = trackFrom;
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
#ifdef STDSOUND_NULL

int stdMci_trackFrom;
int stdMci_trackTo;
int stdMci_trackCurrent;
int stdMci_music;

int stdMci_Startup()
{
    stdMci_uDeviceID = 0;

    stdMci_bInitted = 1;

    // Added
    stdMci_bIsGOG = 1;
    
    return 1;
}

void stdMci_Shutdown()
{
    stdMci_bInitted = 0;

    // Added: Clean reset
    stdMci_trackFrom = 0;
    stdMci_trackTo = 0;
    stdMci_trackCurrent = 0;
    stdMci_music = 0;
    stdMci_bIsGOG = 1;
}

void stdMci_trackFinished();
void stdMci_trackStart(int track)
{
    stdMci_trackCurrent = track;
    stdMci_music = 1;
}

void stdMci_trackFinished()
{
    stdMci_trackCurrent++;
    if (stdMci_trackCurrent > stdMci_trackTo)
        stdMci_Stop();
    else
        stdMci_trackStart(stdMci_trackCurrent);
}

int stdMci_Play(uint8_t trackFrom, uint8_t trackTo)
{
    stdMci_trackFrom = trackFrom;
    stdMci_trackTo = trackTo;

    return 1;
}

void stdMci_SetVolume(float vol)
{
}

void stdMci_Stop()
{
    stdPlatform_Printf("stdMci: stop music\n");
    
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

#else // !STDSOUND_NULL

#include <SDL_mixer.h>

int stdMci_trackFrom;
int stdMci_trackTo;
int stdMci_trackCurrent;

Mix_Music* stdMci_music;

int stdMci_Startup()
{
    stdMci_uDeviceID = 0;
    stdMci_music = NULL;

    stdMci_bInitted = 1;
    
    if (Mix_OpenAudio(48000, AUDIO_S16SYS, 2, 1024) < 0)
	    return 1;

	Mix_AllocateChannels(2);

    // Added
    stdMci_bIsGOG = 1;
    
    return 1;
}

void stdMci_Shutdown()
{
    stdMci_bInitted = 0;
    Mix_CloseAudio();

    // Added: Clean reset
    stdMci_trackFrom = 0;
    stdMci_trackTo = 0;
    stdMci_trackCurrent = 0;
    stdMci_music = 0;
    stdMci_bIsGOG = 1;
}

int stdMci_TryPlay(const char* fpath) {
    char tmp[256];
    strncpy(tmp, fpath, 255);

#ifdef LINUX
    char *r = malloc(strlen(tmp) + 16);
    if (casepath(tmp, r))
    {
        strcpy(tmp, r);
    }
    free(r);
#endif

    stdMci_music = Mix_LoadMUS(tmp); 
    if (!stdMci_music) {
        //printf("INFO: Failed to play music `%s', trying alternate location...\n", tmp);
        stdPlatform_Printf("stdMci: Error in Mix_LoadMUS, %s\n", Mix_GetError());
    }

    if (stdMci_music)
        return 1;

    return 0;
}

void stdMci_trackFinished();
void stdMci_trackStart(int track)
{
    char tmp[256];
 
    if (stdMci_music) {
        Mix_HaltMusic();
        Mix_FreeMusic(stdMci_music);
    }

    int cdNum = 1;
    if(jkMain_pEpisodeEnt)
        cdNum = jkMain_pEpisodeEnt->cdNum;
    else if(jkMain_pEpisodeEnt2)
        cdNum = jkMain_pEpisodeEnt2->cdNum;

    // GOG only reports real track IDs, and does not have any disk 2s
    if (cdNum > 1 && stdMci_bIsGOG) {
        stdMci_bIsGOG = 0;
        stdPlatform_Printf("stdMci: Seeing CD number >1 (%u), assuming this is an OG disk install with offsetted tracks...\n", cdNum);
    }

    // If we're getting a >12 track number, it's definitely GOG
    if (track > 12 && !stdMci_bIsGOG) {
        stdPlatform_Printf("stdMci: Seeing a >12 track number (%u), assuming this is a GOG install with no offsets...\n", track);
        stdMci_bIsGOG = 1;
    }

    // Try and play disk-dumped music
    snprintf(tmp, 255, "MUSIC/%d/Track%d.ogg", cdNum, track);
    if (stdMci_TryPlay(tmp)) goto done;

    // Try and play disk-dumped music
    if (track < 10) {
        snprintf(tmp, 255, "MUSIC/%d/Track%02d.ogg", cdNum, track);
        if (stdMci_TryPlay(tmp)) goto done;
    }

    // If we are a GOG install, assume all tracks are as-is first
    if (stdMci_bIsGOG) {
        // GOG and Steam soundtrack location
        snprintf(tmp, 255, "MUSIC/Track%d.ogg", track);
        if (stdMci_TryPlay(tmp)) goto done;

        // GOG and Steam soundtrack location (00-09)
        if (track < 10) {
            snprintf(tmp, 255, "MUSIC/Track%02d.ogg", track);
            if (stdMci_TryPlay(tmp)) goto done;
        }
    }

    // Try and convert the OG track numbers to GOG/Steam
    if (!stdMci_music && track <= 12 && !Main_bMotsCompat)
    {
        int track_shifted = track;
        if (cdNum == 1)
        {
            track_shifted += 10;
        }
        else if (cdNum == 2)
        {
            track_shifted += 20;
        }

        // GOG and Steam soundtrack location
        snprintf(tmp, 255, "MUSIC/Track%d.ogg", track_shifted);
        if (stdMci_TryPlay(tmp)) goto done;
    }

    // Last chance to get it right...
    if (!stdMci_bIsGOG) {
        snprintf(tmp, 255, "MUSIC/Track%d.ogg", track);
        if (stdMci_TryPlay(tmp)) goto done;

        // GOG and Steam soundtrack location (00-09)
        if (track < 10) {
            snprintf(tmp, 255, "MUSIC/Track%02d.ogg", track);
            if (stdMci_TryPlay(tmp)) goto done;
        }
    }

done:
    if (!stdMci_music) {
        stdPlatform_Printf("stdMci: No music was loaded, must not have any music.\n");
        return;
    }

    stdMci_trackCurrent = track;
    Mix_HaltMusic();
    if (Mix_PlayMusic(stdMci_music, 0) < 0) {
        stdPlatform_Printf("stdMci: Error in Mix_PlayMusic, %s\n", Mix_GetError());
    }
    Mix_HookMusicFinished(stdMci_trackFinished);
    stdPlatform_Printf("stdMci: Playing music `%s'\n", tmp);
}

void stdMci_trackFinished()
{
    stdMci_trackCurrent++;
    if (stdMci_trackCurrent > stdMci_trackTo)
        stdMci_Stop();
    else
        stdMci_trackStart(stdMci_trackCurrent);
}

int stdMci_Play(uint8_t trackFrom, uint8_t trackTo)
{
    char tmp[256];
    
    stdPlatform_Printf("stdMci: play track %d to %d\n", trackFrom, trackTo);
    
    stdMci_trackFrom = trackFrom;
    stdMci_trackTo = trackTo;
    
    stdMci_trackStart(trackFrom);

    return 1;
}

void stdMci_SetVolume(float vol)
{
    stdPlatform_Printf("stdMci: Set vol %f\n", vol);
    uint8_t volQuantized = (uint16_t)(vol * (double)MIX_MAX_VOLUME);
    Mix_VolumeMusic(volQuantized);
}

void stdMci_Stop()
{
    stdPlatform_Printf("stdMci: stop music\n");
    
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
#endif // else STDSOUND_NULL
