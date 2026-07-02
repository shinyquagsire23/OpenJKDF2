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
#include <kos/thread.h>    // thd_sleep
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
#ifdef STDMCI_DC_CDDA

// Dreamcast (retired CDDA path, kept for reference behind STDMCI_DC_CDDA):
// stream the soundtrack as hardware CD Digital Audio. This turned out to be
// unusable in practice -- the GD drive can't serve data-sector reads while
// playing audio (any read stops playback, and reads racing a PLAY command
// return garbage that permanently poisons KOS's iso9660 sector cache), and this
// engine streams materials/sounds from disc constantly. See the ADPCM streaming
// implementation below instead.

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
    int playRc = cdrom_cdda_play(cdFrom, cdTo, 0, CDDA_TRACKS);

    // Issuing a PLAY command (even one that FAILS) can leave the drive delivering
    // mispositioned (audio) bytes -- or outright errors -- for data reads. KOS's
    // iso9660 layer DMAs every read into its persistent sector cache, so ONE bad
    // read during this window poisons that sector's cache block for the rest of
    // the session (this broke all GOB reads when music started mid-level-load).
    // Absorb the window with cache-bypassing scratch reads of the data session's
    // PVD until it verifies ("CD001"); if it never verifies, stop the music rather
    // than let the engine read garbage.
    int bReadsVerified = 0;
    {
        static uint8_t scratch[2048] __attribute__((aligned(32)));
        cd_toc_t toc;
        // false = low-density TOC: burned CD-Rs have no high-density area.
        if (cdrom_read_toc(&toc, false) == ERR_OK) {
            uint32_t fad = cdrom_locate_data_track(&toc);
            if (fad) {
                for (int tries = 0; tries < 100; tries++) {
                    if (cdrom_read_sectors_ex(scratch, fad + 16, 1, false) == ERR_OK &&
                        scratch[1] == 'C' && scratch[2] == 'D' &&
                        scratch[3] == '0' && scratch[4] == '0' && scratch[5] == '1') {
                        bReadsVerified = 1; // data reads position correctly again
                        break;
                    }
                    thd_sleep(10);
                }
            }
        }
    }

    if (playRc != ERR_OK || !bReadsVerified) {
        // No playback, or reads still wedged: make sure the drive isn't left in the
        // play state so the game survives without music.
        cdrom_cdda_pause();
        stdMci_dcPlaying = 0;
        return 0;
    }

    // Re-assert the mix level -- snd/spu init can reset the CDDA registers, and the
    // engine may Play before its first SetVolume.
    spu_cdda_volume(stdMci_dcVol, stdMci_dcVol);
    stdMci_dcPlaying = 1;
    return 1;
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

#else // !STDMCI_DC_CDDA: AICA ADPCM streaming from the data track

// Dreamcast: stream the soundtrack as AICA ADPCM files from the data track.
// The packaging converts each GOG Ogg (Track12.ogg, ...) to headerless 4-bit
// Yamaha AICA ADPCM at 44.1kHz stereo, nibble-interleaved for snd_stream
// (music/trackNN.adp on the disc; see plat_dreamcast.cmake + KOS wav2adpcm).
// The AICA decodes ADPCM in hardware, so this costs ~no SH4 time -- and unlike
// CDDA, the music data flows through normal file reads that interleave cleanly
// with the engine's constant material/sound streaming.
//
// A small pump thread keeps the stream fed even while the main thread is busy
// inside a level load (KOS's fs layer serializes concurrent disc access).

#include <dc/sound/stream.h>
#include <kos/thread.h>
#include <kos/mutex.h>

#define STDMCI_ADPCM_FREQ   44100
#define STDMCI_ADPCM_STEREO 1
#define STDMCI_CHUNK        (32 << 10)   // callback staging; >= any smp_req

static snd_stream_hnd_t stdMci_shnd = SND_STREAM_INVALID;
static FILE*   stdMci_fp = NULL;
static int     stdMci_trackCur = 0;   // GOG track number currently playing
static int     stdMci_trackEnd = 0;   // last GOG track of the requested range
static volatile int stdMci_bStreaming = 0;
static volatile int stdMci_bEnded = 0;
static int     stdMci_vol255 = 255;
static volatile int stdMci_bPumpRun = 0;
static kthread_t*   stdMci_pPumpThd = NULL;
static mutex_t stdMci_mtx = MUTEX_INITIALIZER;
static uint8_t stdMci_chunkBuf[STDMCI_CHUNK] __attribute__((aligned(32)));

// Open the .adp for a track number (NULL = not shipped / missing). Files are
// GOG-named (track12..18 = disc 1, track22..32 = disc 2). In-level requests
// already arrive GOG-numbered; jkCredits passes ORIGINAL CD track numbers
// (2..9), so mirror the SDL2 backend's fallback: +10/+20 by the episode's disc.
// Absolute paths: the game chdir's into the game-data subdir (/cd/jk1), but the
// soundtrack lives at the disc root (see plat_dreamcast.cmake).
static FILE* stdMci_dcOpenTrack(int track)
{
    char path[64];
    FILE* fp;

    snprintf(path, sizeof(path), "/cd/music/track%d.adp", track);
    if ((fp = fopen(path, "rb")))
        return fp;

    if (track <= 12) {
        int cdNum = 1;
        if (jkMain_pEpisodeEnt)       cdNum = jkMain_pEpisodeEnt->cdNum;
        else if (jkMain_pEpisodeEnt2) cdNum = jkMain_pEpisodeEnt2->cdNum;
        snprintf(path, sizeof(path), "/cd/music/track%d.adp",
                 track + (cdNum == 2 ? 20 : 10));
        if ((fp = fopen(path, "rb")))
            return fp;
    }
    return NULL;
}

// snd_stream data callback (called from the pump thread via snd_stream_poll).
// For 4-bit stereo nibble-interleaved ADPCM, one byte = one L+R sample pair,
// so bytes == samples requested. Advances across the track range on EOF.
static void* stdMci_dcStreamCb(snd_stream_hnd_t hnd, int smp_req, int* smp_recv)
{
    (void)hnd;
    int want = smp_req;                    // bytes (stereo 4-bit: 1 byte/sample pair)
    if (want > (int)sizeof(stdMci_chunkBuf)) want = (int)sizeof(stdMci_chunkBuf);
    // ADPCM transfers want whole 32-byte blocks; trailing partials are padded.
    int got = 0;
    while (got < want && stdMci_fp) {
        int r = (int)fread(stdMci_chunkBuf + got, 1, want - got, stdMci_fp);
        if (r > 0) { got += r; continue; }
        // EOF: advance to the next track in the range, else finish.
        fclose(stdMci_fp);
        stdMci_fp = NULL;
        if (stdMci_trackCur < stdMci_trackEnd) {
            stdMci_trackCur++;
            stdMci_fp = stdMci_dcOpenTrack(stdMci_trackCur);
        }
    }
    if (got <= 0) {
        stdMci_bEnded = 1;
        *smp_recv = 0;
        return NULL;   // stream starves out; CheckStatus reports idle -> mixer loops
    }
    // Zero-pad up to a 32-byte boundary so a short final read can't loop garbage.
    while ((got & 31) && got < (int)sizeof(stdMci_chunkBuf)) stdMci_chunkBuf[got++] = 0;
    *smp_recv = got;
    return stdMci_chunkBuf;
}

// Pump thread: keeps the AICA ring buffer fed. ~1.4s of audio fits in the ring
// (32KB/chan at 22KB/s/chan), so a 50ms cadence has lots of slack.
static void* stdMci_dcPumpThread(void* arg)
{
    (void)arg;
    while (stdMci_bPumpRun) {
        mutex_lock(&stdMci_mtx);
        if (stdMci_bStreaming && !stdMci_bEnded && stdMci_shnd != SND_STREAM_INVALID)
            snd_stream_poll(stdMci_shnd);
        mutex_unlock(&stdMci_mtx);
        thd_sleep(50);
    }
    return NULL;
}

int stdMci_Startup()
{
    // snd_stream_init implicitly snd_init()s; run it at startup, before any SPU
    // sfx are loaded, so it can't clobber them later.
    if (snd_stream_init() < 0) {
        stdPlatform_Printf("stdMci: snd_stream_init failed, no music\n");
        stdMci_bInitted = 0;
        return 0;
    }
    stdMci_shnd = snd_stream_alloc(stdMci_dcStreamCb, SND_STREAM_BUFFER_MAX_ADPCM);
    if (stdMci_shnd == SND_STREAM_INVALID) {
        stdPlatform_Printf("stdMci: snd_stream_alloc failed, no music\n");
        stdMci_bInitted = 0;
        return 0;
    }
    stdMci_bPumpRun = 1;
    stdMci_pPumpThd = thd_create(0, stdMci_dcPumpThread, NULL);
    stdMci_bInitted = 1;
    stdMci_bIsGOG = 1; // engine passes real GOG track IDs; files are named by them
    return 1;
}

void stdMci_Shutdown()
{
    stdMci_Stop();
    if (stdMci_pPumpThd) {
        stdMci_bPumpRun = 0;
        thd_join(stdMci_pPumpThd, NULL);
        stdMci_pPumpThd = NULL;
    }
    if (stdMci_shnd != SND_STREAM_INVALID) {
        snd_stream_destroy(stdMci_shnd);
        stdMci_shnd = SND_STREAM_INVALID;
    }
    stdMci_bInitted = 0;
}

int stdMci_Play(uint8_t trackFrom, uint8_t trackTo)
{
    if (stdMci_shnd == SND_STREAM_INVALID) return 0;

    mutex_lock(&stdMci_mtx);

    // Stop anything already going.
    if (stdMci_bStreaming) {
        snd_stream_stop(stdMci_shnd);
        stdMci_bStreaming = 0;
    }
    if (stdMci_fp) { fclose(stdMci_fp); stdMci_fp = NULL; }

    stdMci_trackCur = trackFrom;
    stdMci_trackEnd = (trackTo >= trackFrom) ? trackTo : trackFrom;
    stdMci_fp = stdMci_dcOpenTrack(stdMci_trackCur);
    if (!stdMci_fp) {
        // Track not shipped (GOG numbering has gaps) -> play nothing.
        mutex_unlock(&stdMci_mtx);
        return 0;
    }

    stdMci_bEnded = 0;
    snd_stream_start_adpcm(stdMci_shnd, STDMCI_ADPCM_FREQ, STDMCI_ADPCM_STEREO);
    snd_stream_volume(stdMci_shnd, stdMci_vol255);
    stdMci_bStreaming = 1;

    mutex_unlock(&stdMci_mtx);
    return 1;
}

void stdMci_SetVolume(flex_t vol)
{
    int v = (int)(vol * 255.0 + 0.5);
    if (v < 0) v = 0;
    if (v > 255) v = 255;
    stdMci_vol255 = v;
    mutex_lock(&stdMci_mtx);
    if (stdMci_bStreaming && stdMci_shnd != SND_STREAM_INVALID)
        snd_stream_volume(stdMci_shnd, v);
    mutex_unlock(&stdMci_mtx);
}

void stdMci_Stop()
{
    mutex_lock(&stdMci_mtx);
    if (stdMci_bStreaming && stdMci_shnd != SND_STREAM_INVALID)
        snd_stream_stop(stdMci_shnd);
    stdMci_bStreaming = 0;
    stdMci_bEnded = 0;
    if (stdMci_fp) { fclose(stdMci_fp); stdMci_fp = NULL; }
    mutex_unlock(&stdMci_mtx);
}

int stdMci_CheckStatus()
{
    // Playing as long as the stream is up and hasn't drained past the last track;
    // reporting idle makes sithSoundMixer re-issue Play (that's how looping works).
    return stdMci_bStreaming && !stdMci_bEnded;
}

flex_d_t stdMci_GetTrackLength(int track)
{
    return 0.0;
}

#endif // STDMCI_DC_CDDA

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
