#include "stdMci.h"

#include "Main/jkMain.h"
#include "stdPlatform.h"
#include "jk.h"

#ifdef TARGET_ANDROID
#include "Main/InstallHelper.h"
#endif

#ifdef FS_POSIX
#include "external/fcaseopen/fcaseopen.h"
#endif

#ifdef STDSOUND_DREAMCAST
#include <dc/cdrom.h>
#include <dc/syscalls.h>   // CD_STATUS_*
#include <dc/spu.h>        // spu_cdda_volume
#endif

// Added
int stdMci_bIsGOG = 1;

#if !defined(SDL2_RENDER) && defined(WIN32)

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

void stdMci_SetVolume(flex_t vol)
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

flex_d_t stdMci_GetTrackLength(int track)
{
    MCI_STATUS_PARMS statusParms;

    if (!stdMci_bInitted)
        return 0.0;

    statusParms.dwCallback = 0;
    statusParms.dwReturn = 0;
    statusParms.dwItem = MCI_STATUS_LENGTH;
    statusParms.dwTrack = track;
    jk_mciSendCommandA(stdMci_mciId, MCI_STATUS, 0x110u, &statusParms);

    return (flex_d_t)((statusParms.dwReturn >> 16) & 0xFF) + (flex_d_t)((statusParms.dwReturn >> 8) & 0xFF) * 60.0;
}

#else // LINUX
#if defined(STDSOUND_DREAMCAST)

// Dreamcast: stream the soundtrack as hardware CD Digital Audio (CDDA). The music
// tracks are authored onto the disc as Red Book audio tracks (see the mkdcdisc --cdda
// packaging), and the GD-ROM plays them directly into the AICA mix -- effectively free
// CPU-wise, unlike decoding Ogg/Vorbis in software. The engine's track numbers line up
// with the disc's audio track numbers (data is track 1, music starts at track 2).

int stdMci_dcFrom = 0;
int stdMci_dcTo = 0;
int stdMci_dcPlaying = 0;
int stdMci_dcVol = 15;   // AICA CDDA mix level, 0..15 (start at full)

// Map a GOG DF2 soundtrack track number to the physical CDDA track on our disc.
//
// GOG encodes the source CD in the tens digit: disk 1 is tracks 12-18, disk 2 is 22-32
// (18 songs total, with a gap). mkdcdisc authors the Oggs as audio tracks *before* the
// data track, in numeric filename order, so Track12.ogg..Track32.ogg become CD tracks
// 1..18 contiguously. This collapses the GOG numbering (and its gap) onto 1..18:
//   disk 1: 12..18 -> CD 1..7      (cd = gog - 11)
//   disk 2: 22..32 -> CD 8..18     (cd = gog - 14)
// Returns 0 for track numbers we don't ship (caller then plays nothing).
static int stdMci_dcCddaTrack(int gog)
{
    if (gog >= 12 && gog <= 18) return gog - 11;
    if (gog >= 22 && gog <= 32) return gog - 14;
    return 0;
}

int stdMci_Startup()
{
    stdMci_bInitted = 1;
    stdMci_bIsGOG = 1; // real track IDs, no CD-offset guessing needed on our disc
    // The GD-ROM is brought up by KOS (INIT_CDROM, part of INIT_DEFAULT); nothing else.
    return 1;
}

void stdMci_Shutdown()
{
    stdMci_Stop();
    stdMci_bInitted = 0;
    stdMci_dcFrom = stdMci_dcTo = 0;
    stdMci_bIsGOG = 1;
}

int stdMci_Play(uint8_t trackFrom, uint8_t trackTo)
{
    stdMci_dcFrom = trackFrom;
    stdMci_dcTo   = trackTo;

    int cdFrom = stdMci_dcCddaTrack(trackFrom);
    int cdTo   = stdMci_dcCddaTrack(trackTo);
    if (cdFrom == 0) {           // track we don't ship -> nothing to play
        stdMci_dcPlaying = 0;
        return 0;
    }
    if (cdTo == 0 || cdTo < cdFrom) cdTo = cdFrom;

    // Play the range once (loops=0); sithSoundMixer polls CheckStatus and re-issues
    // Play to loop the range, matching the other backends. CDDA_TRACKS = play by track.
    if (cdrom_cdda_play(cdFrom, cdTo, 0, CDDA_TRACKS) == ERR_OK) {
        // Re-assert the mix level -- snd/spu init can reset the CDDA registers, and the
        // engine may Play before its first SetVolume.
        spu_cdda_volume(stdMci_dcVol, stdMci_dcVol);
        stdMci_dcPlaying = 1;
        return 1;
    }
    stdMci_dcPlaying = 0;
    return 0;
}

void stdMci_SetVolume(flex_t vol)
{
    // Engine passes 0.0..1.0; the AICA CDDA mix level is 0..15 (spu_cdda_volume writes
    // the CDDA volume registers directly, so it persists across track changes).
    int v = (int)(vol * 15.0 + 0.5);
    if (v < 0) v = 0;
    if (v > 15) v = 15;
    stdMci_dcVol = v;
    spu_cdda_volume(v, v);
}

void stdMci_Stop()
{
    if (stdMci_dcPlaying) {
        cdrom_cdda_pause();
        stdMci_dcPlaying = 0;
    }
}

int stdMci_CheckStatus()
{
    if (!stdMci_dcPlaying)
        return 0;

    int status = 0, disc_type = 0;
    if (cdrom_get_status(&status, &disc_type) == ERR_OK && status == CD_STATUS_PLAYING)
        return 1;

    // Finished (or drive left the playing state) -> report idle so the mixer loops.
    stdMci_dcPlaying = 0;
    return 0;
}

flex_d_t stdMci_GetTrackLength(int track)
{
    return 0.0;
}

#elif defined(STDSOUND_NULL) || defined(STDSOUND_MAXMOD)

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

void stdMci_SetVolume(flex_t vol)
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

flex_d_t stdMci_GetTrackLength(int track)
{
    return 0.0;
}

#elif defined(SDL2_RENDER) // !STDSOUND_NULL

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
    
    if (Mix_OpenAudio(48000, AUDIO_S16SYS, 2, 1024) < 0) {
        stdPlatform_Printf("stdMci: Failed Mix_OpenAudio? %s\n", Mix_GetError());
        return 1;
    }

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

#ifdef FS_POSIX
    char *r = (char*)malloc(strlen(tmp) + 16);
    if (casepath(tmp, r))
    {
        strcpy(tmp, r);
    }
    free(r);
#endif

#ifdef TARGET_ANDROID
    char tmp2[512];
    getcwd(tmp2, sizeof(tmp2));
    //if (tmp[0] != '.') {
        strcat(tmp2, "/");
    //}
    strcat(tmp2, tmp);
    stdMci_music = Mix_LoadMUS(tmp2); 
#else
    stdMci_music = Mix_LoadMUS(tmp);
#endif
    
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

void stdMci_SetVolume(flex_t vol)
{
    stdPlatform_Printf("stdMci: Set vol %f\n", vol);
    uint8_t volQuantized = (uint16_t)(vol * (flex_d_t)MIX_MAX_VOLUME);
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

flex_d_t stdMci_GetTrackLength(int track)
{
    return 0.0;
}

#endif // else SDL2_RENDER
#endif // else STDSOUND_NULL
