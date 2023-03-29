#include "jkCutscene.h"

#include "General/stdStrTable.h"
#include "General/stdFont.h"
#include "Win95/Window.h"
#include "Win95/Video.h"
#include "Win95/stdDisplay.h"
#include "Win95/stdMci.h"
#include "World/jkPlayer.h"
#include "Main/jkMain.h"
#include "Main/Main.h"
#include "Main/jkStrings.h"
#include "Main/smack.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUISound.h"
#include "Win95/stdSound.h"
#include "Devices/sithSoundMixer.h"
#include "General/stdString.h"
#include "stdPlatform.h"
#include "Platform/std3D.h"

#include "smacker.h"
#include "smush.h"

#include "../jk.h"

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

static smush_ctx* jkCutscene_pSmush;
static smk jkCutscene_smk;
static int jkCutscene_bSmkValid = 0;
static double jkCutscene_smk_usf;
static unsigned long jkCutscene_smk_w, jkCutscene_smk_h, jkCutscene_smk_frames;
static stdVBuffer* jkCutscene_frameBuf = NULL;
static void* jkCutscene_palette = NULL;
//static void* jkCutscene_audioBuf = NULL;
static stdSound_buffer_t* jkCutscene_audio = NULL;
static stdSound_buffer_t* jkCutscene_audio2 = NULL;
static stdSound_buffer_t* jkCutscene_audio3 = NULL;
static stdSound_buffer_t* jkCutscene_audioFull = NULL;
static int jkCutscene_audioFlip = 0;

// TODO actually fill this in with an alternative Smack decoder

static double last_displayFrame = 0;
static double last_audioUs = 0;
static double extraUs = 0;
extern int openjkdf2_bIsKVM;

// Smush
#define AUDIO_QUEUE_DEPTH (128)
#define AUDIO_BUFS_DEPTH (0x800000)
#define AUDIO_MAXIMUM_ALLOWED_SLOP_BYTES (0x8000)

static double jkCutscene_audio_us;
static double jkCutscene_audio_us_slop;

static uint8_t* jkCutscene_audio_buf;
static uint8_t* jkCutscene_audio_pos;
static uint32_t jkCutscene_audio_len;

static uint8_t* jkCutscene_audio_queue[AUDIO_QUEUE_DEPTH] = {0};
static size_t jkCutscene_audio_queue_lens[AUDIO_QUEUE_DEPTH] = {0};
static int jkCutscene_audio_queue_read_idx = 0;
static int jkCutscene_audio_queue_write_idx = 0;

void smush_audio_callback(const uint8_t* data, size_t len)
{
    //printf("Callback %p %zx %x %x %x\n", data, len, jkCutscene_pSmush->cur_frame, jkCutscene_pSmush->audio_cur_frame, jkCutscene_audio_queue_write_idx);
    if (jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx]) {
        free(jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx]);
        jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx] = NULL;
    }

    jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx] = data;
    jkCutscene_audio_queue_lens[jkCutscene_audio_queue_write_idx++] = len;
    jkCutscene_audio_queue_write_idx = jkCutscene_audio_queue_write_idx % AUDIO_QUEUE_DEPTH;
}

// Added
void jkCutscene_CleanReset()
{
#ifdef SDL2_RENDER
    for (int i = 0; i < AUDIO_QUEUE_DEPTH; i++) {
        if (jkCutscene_audio_queue[i]) {
            free(jkCutscene_audio_queue[i]);
        }

        jkCutscene_audio_queue[i] = NULL;
        jkCutscene_audio_queue_lens[i] = 0;
    }
    if (jkCutscene_audio_buf) {
        free(jkCutscene_audio_buf);
        jkCutscene_audio_buf = NULL;
    }
    if (jkCutscene_audio) {
        stdSound_BufferRelease(jkCutscene_audio);
        jkCutscene_audio = NULL;
    }
    if (jkCutscene_audio2) {
        stdSound_BufferRelease(jkCutscene_audio2);
        jkCutscene_audio2 = NULL;
    }
    if (jkCutscene_audio3) {
        stdSound_BufferRelease(jkCutscene_audio3);
        jkCutscene_audio3 = NULL;
    }
    //stdSound_BufferRelease(jkCutscene_audio2);
    if (jkCutscene_audioFull) {
        stdSound_BufferRelease(jkCutscene_audioFull);
        jkCutscene_audioFull = NULL;
    }
    if (jkCutscene_pSmush) {
        smush_destroy(jkCutscene_pSmush);
        jkCutscene_pSmush = NULL;
    }
    if (jkCutscene_bSmkValid) {
        smk_close(jkCutscene_smk);
        jkCutscene_bSmkValid = 0;
    }

    if (jkCutscene_frameBuf) {
        stdDisplay_VBufferFree(jkCutscene_frameBuf);
        jkCutscene_frameBuf = NULL;
    }
#endif

    jkCutscene_pSmush = NULL;
    memset(&jkCutscene_smk, 0, sizeof(jkCutscene_smk));
    jkCutscene_bSmkValid = 0;
    jkCutscene_smk_usf = 0;
    jkCutscene_smk_w = 0;
    jkCutscene_smk_h = 0;
    jkCutscene_smk_frames = 0;
    jkCutscene_frameBuf = NULL;
    if (jkCutscene_palette) {
        free(jkCutscene_palette);
    }
    jkCutscene_palette = NULL;
    //jkCutscene_audioBuf = NULL;
    jkCutscene_audio = NULL;
    jkCutscene_audio2 = NULL;
    jkCutscene_audio3 = NULL;
    jkCutscene_audioFull = NULL;
    jkCutscene_audioFlip = 0;

    last_displayFrame = 0;
    last_audioUs = 0;
    extraUs = 0;

    jkCutscene_audio_us = 0.0;
    jkCutscene_audio_us_slop = 0.0;

    jkCutscene_audio_buf = NULL;
    jkCutscene_audio_pos = NULL;
    jkCutscene_audio_len = 0;

    memset(jkCutscene_audio_queue, 0, sizeof(jkCutscene_audio_queue));
    memset(jkCutscene_audio_queue_lens, 0, sizeof(jkCutscene_audio_queue_lens));
    jkCutscene_audio_queue_read_idx = 0;
    jkCutscene_audio_queue_write_idx = 0;
}

// MOTS altered
void jkCutscene_Startup(char *fpath)
{
    jkCutscene_CleanReset();

    stdStrTable_Load(&jkCutscene_strings, fpath); // MOTS removed
    jkCutscene_subtitlefont = stdFont_Load("ui\\sft\\subtitlefont.sft", 0, 0);
    
    if (Main_bMotsCompat) {
        jkCutscene_rect1.x = 10;
        jkCutscene_rect1.y = 400; // MoTS was 385?
        jkCutscene_rect1.width = 620;
        jkCutscene_rect1.height = 80; // MoTS was 95?
        jkCutscene_rect2.x = 0;
        jkCutscene_rect2.y = 10;
        jkCutscene_rect2.width = 640;
        jkCutscene_rect2.height = 40;
    }
    else {
        jkCutscene_rect1.x = 10;
        jkCutscene_rect1.y = 360;
        jkCutscene_rect1.width = 620;
        jkCutscene_rect1.height = 120;
        jkCutscene_rect2.x = 0;
        jkCutscene_rect2.y = 10;
        jkCutscene_rect2.width = 640;
        jkCutscene_rect2.height = 40;
    }

    jkCutscene_bInitted = 1;
}

// MOTS altered
void jkCutscene_Shutdown()
{
    if ( jkCutscene_subtitlefont )
    {
        stdFont_Free(jkCutscene_subtitlefont);
        jkCutscene_subtitlefont = 0;
    }
    stdStrTable_Free(&jkCutscene_strings); // MOTS removed

    // Added: Clean shutdown
#ifdef QOL_IMPROVEMENTS
    jkCutscene_CleanReset();
#endif

    jkCutscene_bInitted = 0;
}

int jkCutscene_sub_421310(char* fpath)
{
    // STUB
    if (!fpath) return 1;

#ifdef ARCH_WASM
    printf("vid skip %s\n", fpath);
    return 1;
#endif

    if (jkPlayer_setDisableCutscenes) {
        return 1;
    }

    char tmp[512];
    size_t len = _strlen(fpath);

    if (len > 512) {
        len = 512;
    }
    _strncpy(tmp, fpath, sizeof(tmp));

#ifdef LINUX
    for (int i = 0; i < len; i++)
    {
        if (tmp[i] == '\\') {
            tmp[i] = '/';
        }
    }
#endif
    
#if !defined(SDL2_RENDER)
    if (!openjkdf2_bIsKVM)
        return _jkCutscene_sub_421310(tmp);
#endif

#ifdef SDL2_RENDER
    sithSoundMixer_StopSong();
    stdMci_Stop();
    if (jkCutscene_palette) {
        free(jkCutscene_palette);
    }
    jkCutscene_palette = malloc(0x300);
    
    for (int i = 0; i < 0x300; i++)
    {
        *(uint8_t*)((char*)jkCutscene_palette+i) = i & 0xFF;
    }

#ifdef LINUX
    char *r = malloc(strlen(tmp) + 16);
    if (casepath(tmp, r))
    {
        strcpy(tmp, r);
    }
    free(r);
#endif

    jkCutscene_pSmush = smush_from_fpath(tmp);
    if (!jkCutscene_pSmush)
    {
        jkCutscene_bSmkValid = 0;
        jkCutscene_smk = smk_open_file(tmp, SMK_MODE_MEMORY);
        if (!jkCutscene_smk)
        {
            jk_printf("Failed to load file `%s`!\n", tmp);
            return 1;
        }

        jkCutscene_bSmkValid = 1;
        smk_info_all(jkCutscene_smk, NULL, &jkCutscene_smk_frames, &jkCutscene_smk_usf);
        smk_info_video(jkCutscene_smk, &jkCutscene_smk_w, &jkCutscene_smk_h, NULL);
        jk_printf("Opened file %s as SMK\nWidth: %lu\nHeight: %lu\nFrames: %lu\nFPS: %f\n", tmp, jkCutscene_smk_w, jkCutscene_smk_h, jkCutscene_smk_frames, 1000000.0 / jkCutscene_smk_usf);
        
        unsigned char   a_t, a_c[7], a_d[7];
        unsigned long   a_r[7];

        smk_info_audio(jkCutscene_smk, &a_t, a_c, a_d, a_r);
        //printf("%x\n", a_t);
        //printf("%x %x %x %x %x %x %x\n", a_c[0], a_c[1], a_c[2], a_c[3], a_c[4], a_c[5], a_c[6]);
        //printf("%x %x %x %x %x %x %x\n", a_d[0], a_d[1], a_d[2], a_d[3], a_d[4], a_d[5], a_d[6]);
        //printf("%x %x %x %x %x %x %x\n", a_r[0], a_r[1], a_r[2], a_r[3], a_r[4], a_r[5], a_r[6]);
        
        stdVBufferTexFmt texFmt;
        texFmt.width = jkCutscene_smk_w;
        texFmt.height = jkCutscene_smk_h;
        texFmt.format.bpp = 8;
        jkCutscene_frameBuf = stdDisplay_VBufferNew(&texFmt, 1, 0, (void*)1);
        stdDisplay_VBufferFill(jkCutscene_frameBuf, 0, NULL);
        
        smk_enable_video(jkCutscene_smk, 0);
        smk_enable_audio(jkCutscene_smk, 0, 1);
        smk_first(jkCutscene_smk);
        
        uint64_t totalAudioSize = 0;
        for (size_t i = 0; i < jkCutscene_smk_frames; i++)
        {
            totalAudioSize += smk_get_audio_size(jkCutscene_smk, 0);
            smk_next(jkCutscene_smk);
        }
        
        smk_first(jkCutscene_smk);

        unsigned long   cur_frame;
        smk_info_all(jkCutscene_smk, &cur_frame, NULL, NULL);
        
        // Start audio stuff
        jkCutscene_audioFull = stdSound_BufferCreate(a_c[0] == 2, a_r[0], a_d[0], totalAudioSize);
        int maxSize;
        void* audioBuf = stdSound_BufferSetData(jkCutscene_audioFull, totalAudioSize, &maxSize);
        uint64_t copiedSize = 0;
        for (size_t i = 0; i < jkCutscene_smk_frames; i++)
        {
            _memcpy((char*)audioBuf + copiedSize, smk_get_audio(jkCutscene_smk, 0), smk_get_audio_size(jkCutscene_smk, 0));
            copiedSize += smk_get_audio_size(jkCutscene_smk, 0);
            smk_next(jkCutscene_smk);
        }

        stdSound_BufferSetVolume(jkCutscene_audioFull, jkGuiSound_cutsceneVolume);
        stdSound_BufferUnlock(jkCutscene_audioFull, audioBuf, maxSize);
        stdSound_BufferPlay(jkCutscene_audioFull, 0);
        
        smk_enable_video(jkCutscene_smk, 1);
        smk_enable_audio(jkCutscene_smk, 0, 0);
        smk_enable_audio(jkCutscene_smk, 1, 1); // metadata track
        smk_first(jkCutscene_smk);
        
        //jkCutscene_audio = stdSound_BufferCreate(a_c[0] == 2, a_r[0], a_d[0], smk_get_audio_size(jkCutscene_smk, 0)*2);
        //jkCutscene_audio2 = stdSound_BufferCreate(a_c[0] == 2, a_r[0], a_d[0], smk_get_audio_size(jkCutscene_smk, 0)*2);
        // end audio
        
        // TODO kinda hacky
        //jkGui_SetModeMenu(smk_get_palette(jkCutscene_smk));
        jkGui_SetModeMenu(smk_get_palette(jkCutscene_smk));
    }
    else {
        jkCutscene_bSmkValid = 0;
        if (jkCutscene_audio_buf) {
            free(jkCutscene_audio_buf);
        }
        jkCutscene_audio_buf = NULL;
        jkCutscene_audio_pos = NULL;
        jkCutscene_audio_len = 0;

        jkCutscene_audio_queue_read_idx = 0;
        jkCutscene_audio_queue_write_idx = 0;

        for (int i = 0; i < AUDIO_QUEUE_DEPTH; i++) {
            if (jkCutscene_audio_queue[i]) {
                free(jkCutscene_audio_queue[i]);
            }
            jkCutscene_audio_queue[i] = NULL;
            jkCutscene_audio_queue_lens[i] = 0;
        }

        smush_set_debug(jkCutscene_pSmush, 0);
        smush_set_audio_buffer_size(jkCutscene_pSmush, AUDIO_BUFS_DEPTH);
        smush_set_audio_callback(jkCutscene_pSmush, smush_audio_callback);
        smush_frame(jkCutscene_pSmush);

        jkCutscene_smk_frames = smush_num_frames(jkCutscene_pSmush);
        jkCutscene_smk_w = smush_video_width(jkCutscene_pSmush);
        jkCutscene_smk_h = smush_video_height(jkCutscene_pSmush);
        jkCutscene_smk_usf = 1000000.0 / (double)smush_video_fps(jkCutscene_pSmush);

        jk_printf("Opened file %s as Smush\nWidth: %lu\nHeight: %lu\nFrames: %lu\nFPS: %f\n", tmp, jkCutscene_smk_w, jkCutscene_smk_h, jkCutscene_smk_frames, 1000000.0 / jkCutscene_smk_usf);

        stdVBufferTexFmt texFmt;
        texFmt.width = jkCutscene_smk_w;
        texFmt.height = jkCutscene_smk_h;
        texFmt.format.bpp = 8;
        jkCutscene_frameBuf = stdDisplay_VBufferNew(&texFmt, 1, 0, (void*)1);
        stdDisplay_VBufferFill(jkCutscene_frameBuf, 0, NULL);

        // Keep half of AUDIO_BUFS_DEPTH empty to allow time adjustments
        double audio_depth_us = ((double)(AUDIO_BUFS_DEPTH / 4) / 22050.0) * 1000000.0;
        jkCutscene_audio_us = 0.0; // audio_depth_us / 2.0
        jkCutscene_audio_us_slop = audio_depth_us / 4.0;
        
        int len;
        uint8_t* stream;

        jkCutscene_audio = stdSound_BufferCreate(1, 22050, 16, AUDIO_BUFS_DEPTH);
        stdSound_BufferSetVolume(jkCutscene_audio, jkGuiSound_cutsceneVolume);
        stream = (uint8_t*)stdSound_BufferSetData(jkCutscene_audio, AUDIO_BUFS_DEPTH, &len);
        memset(stream, 0, len);
        stdSound_BufferUnlock(jkCutscene_audio, stream, len);
        //stdSound_BufferPlay(jkCutscene_audio, 0);

        jkCutscene_audio2 = stdSound_BufferCreate(1, 22050, 16, AUDIO_BUFS_DEPTH);
        stdSound_BufferSetVolume(jkCutscene_audio2, jkGuiSound_cutsceneVolume);
        stream = (uint8_t*)stdSound_BufferSetData(jkCutscene_audio2, AUDIO_BUFS_DEPTH, &len);
        memset(stream, 0, len);
        stdSound_BufferUnlock(jkCutscene_audio2, stream, len);
        //stdSound_BufferPlay(jkCutscene_audio2, 0);

        jkCutscene_audio3 = stdSound_BufferCreate(1, 22050, 16, AUDIO_BUFS_DEPTH);
        stdSound_BufferSetVolume(jkCutscene_audio3, jkGuiSound_cutsceneVolume);
        stream = (uint8_t*)stdSound_BufferSetData(jkCutscene_audio3, AUDIO_BUFS_DEPTH, &len);
        memset(stream, 0, len);
        stdSound_BufferUnlock(jkCutscene_audio3, stream, len);
        //stdSound_BufferPlay(jkCutscene_audio3, 0);

        jkGui_SetModeMenu(smush_get_palette(jkCutscene_pSmush));
    }

    jkCutscene_55AA54 = 0;
    jkCutscene_audioFlip = 0;
    last_displayFrame = 0;
    last_audioUs = 0;
    extraUs = 0;
    //jkCutscene_audio_us = 0.0;
    //jkCutscene_audio_us_slop = 0.0;

    last_audioUs = Linux_TimeUs();

	stdDisplay_VBufferFill(Video_pMenuBuffer, 0, NULL);
	
	stdDisplay_VBufferLock(Video_pMenuBuffer);
	stdDisplay_VBufferCopy(Video_pMenuBuffer, jkCutscene_frameBuf, 0, 0, NULL, 0);
	stdDisplay_VBufferUnlock(Video_pMenuBuffer);
	
	Window_AddMsgHandler(jkCutscene_Handler);
	jkCutscene_isRendering = 1;
#endif
    // STUBBED
    return 1;
}

int jkCutscene_sub_421410()
{
#if !defined(SDL2_RENDER)
    if ( !jkCutscene_isRendering )
        return 0;
#endif
    Window_RemoveMsgHandler(jkCutscene_Handler);

#if !defined(SDL2_RENDER)
    if (!openjkdf2_bIsKVM)
        smack_sub_426940();
#endif

#ifdef SDL2_RENDER
    for (int i = 0; i < AUDIO_QUEUE_DEPTH; i++) {
        if (jkCutscene_audio_queue[i]) {
            free(jkCutscene_audio_queue[i]);
        }

        jkCutscene_audio_queue[i] = NULL;
        jkCutscene_audio_queue_lens[i] = 0;
    }
    if (jkCutscene_audio_buf) {
        free(jkCutscene_audio_buf);
        jkCutscene_audio_buf = NULL;
    }
    if (jkCutscene_audio) {
        stdSound_BufferRelease(jkCutscene_audio);
        jkCutscene_audio = NULL;
    }
    if (jkCutscene_audio2) {
        stdSound_BufferRelease(jkCutscene_audio2);
        jkCutscene_audio2 = NULL;
    }
    if (jkCutscene_audio3) {
        stdSound_BufferRelease(jkCutscene_audio3);
        jkCutscene_audio3 = NULL;
    }
    //stdSound_BufferRelease(jkCutscene_audio2);
    if (jkCutscene_audioFull) {
        stdSound_BufferRelease(jkCutscene_audioFull);
        jkCutscene_audioFull = NULL;
    }
    if (jkCutscene_pSmush) {
        smush_destroy(jkCutscene_pSmush);
        jkCutscene_pSmush = NULL;
    }
    
    if (jkCutscene_bSmkValid) {
        smk_close(jkCutscene_smk);
    }
    jkCutscene_bSmkValid = 0;

    if (jkCutscene_frameBuf) {
        stdDisplay_VBufferFree(jkCutscene_frameBuf);
        jkCutscene_frameBuf = NULL;
    }
#endif

    last_displayFrame = 0;
    last_audioUs = 0;
    extraUs = 0;

    jkCutscene_isRendering = 0;
    jk_ShowCursor(1);
    return 1;
}

// MOTS altered
int jkCutscene_smack_related_loops()
{
    signed int smack_finished; // esi
    int v2; // ecx

    smack_finished = 0;
    if ( !jkCutscene_isRendering )
        return 1;
    if ( !jkCutscene_55AA54 && g_app_suspended )
    {
#if !defined(SDL2_RENDER)
        if (!openjkdf2_bIsKVM)
            smack_finished = smack_process();
        else
            smack_finished = 1;
#else
        if (!jkCutscene_pSmush) {
            smack_finished = jkCutscene_smacker_process();
        }
        else {
            smack_finished = jkCutscene_smusher_process();
        }
        
#endif
        if ( smack_finished )
        {
            if ( jkCutscene_isRendering )
            {
                Window_RemoveMsgHandler(jkCutscene_Handler);
#if !defined(SDL2_RENDER)
                if (!openjkdf2_bIsKVM)
                    smack_sub_426940();
#endif
                jkCutscene_isRendering = 0;
                jk_ShowCursor(1);
            }
        }
        else if ( jkCutscene_dword_55B750 != jkCutscene_dword_55AA50 )
        {
            stdDisplay_VBufferFill(&Video_otherBuf, 0, &jkCutscene_rect1);

            if (jkCutscene_pSmush)
            {
                wchar_t* str = NULL;
                int uVar3 = jkCutscene_dword_55B750 & 0x7FFFFFFF;
                if (uVar3) {
                    int uVar4 = uVar3 % 10000;
                    int iVar2 = 0;
                    if (uVar3 / 10000 == 1) {
                      iVar2 = 7;
                    }
                    else {
                      iVar2 = (uVar3 / 10000 == 2) + 8;
                    }
                    if ((iVar2 == 8) && ((uVar4 == 166 || (uVar4 == 148)))) {
                      iVar2 = 5;
                    }

                    char key[32];
                    stdString_snprintf(key, 32, "COG_%05d", iVar2 * 10000 + uVar4);
                    str = jkStrings_GetUniStringWithFallback(key);
                }
                
                if (str) {
                    int forced = 0;
                    if (*str == '|') {
                        str++;
                        forced = 1;
                    }
                    if (jkPlayer_setFullSubtitles || forced) {
                        stdFont_Draw3(
                            &Video_otherBuf,
                            jkCutscene_subtitlefont,
                            jkCutscene_rect1.y,
                            &jkCutscene_rect1,
                            1,
                            str,
                            0);
                    }
                }
                jkCutscene_dword_55AA50 = jkCutscene_dword_55B750;
            }
            else {
                v2 = jkCutscene_dword_55B750;
                if ( (jkCutscene_dword_55B750 & 0x80000000 || jkPlayer_setFullSubtitles) && (jkCutscene_dword_55B750 & 0x7FFFFFFF) != 0 )
                {
                    stdFont_Draw3(
                        &Video_otherBuf,
                        jkCutscene_subtitlefont,
                        360,
                        &jkCutscene_rect1,
                        1,
                        jkCutscene_strings.msgs[jkCutscene_dword_55B750 & 0x7FFFFFFF].uniStr,
                        0);
                    v2 = jkCutscene_dword_55B750;
                }
                jkCutscene_dword_55AA50 = v2;
            }
            
        }
        if ( Main_bWindowGUI )
        {
            stdDisplay_DDrawGdiSurfaceFlip();
            return smack_finished;
        }
    }
#if defined(SDL2_RENDER)
    else
    {
        stdDisplay_DDrawGdiSurfaceFlip();
    }
#endif
    return smack_finished;
}

int jkCutscene_PauseShow(int unk)
{
    wchar_t *v0; // eax
    int result; // eax

    if ( jkCutscene_55AA54 )
    {
        v0 = jkStrings_GetUniStringWithFallback("GUI_PAUSED");
        stdFont_Draw4(&Video_otherBuf, jkCutscene_subtitlefont, 0, 10, 640, 40, 3, v0, 0);
    }
    else
    {
        stdDisplay_VBufferFill(&Video_otherBuf, 0, &jkCutscene_rect2);
    }

#if defined(SDL2_RENDER)
    stdDisplay_VBufferLock(Video_pMenuBuffer);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, jkCutscene_frameBuf, 0, 50, NULL, 0);
    stdDisplay_VBufferFill(Video_pMenuBuffer, 0, &jkCutscene_rect1);
    stdDisplay_VBufferFill(Video_pMenuBuffer, 0, &jkCutscene_rect2);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, &Video_otherBuf, jkCutscene_rect1.x, jkCutscene_rect1.y, &jkCutscene_rect1, 0);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, &Video_otherBuf, jkCutscene_rect2.x, jkCutscene_rect2.y, &jkCutscene_rect2, 0);
    stdDisplay_VBufferUnlock(Video_pMenuBuffer);
#endif

    result = Main_bWindowGUI;
#if !defined(SDL2_RENDER)
    if ( Main_bWindowGUI )
        result = stdDisplay_DDrawGdiSurfaceFlip();
#endif
    return result;
}

int jkCutscene_Handler(HWND a1, UINT a2, WPARAM a3, LPARAM a4, LRESULT *a5)
{
    wchar_t *v5; // eax

    switch ( a2 )
    {
        case WM_CLOSE:
#if !defined(SDL2_RENDER)
            if (!openjkdf2_bIsKVM)
                smack_sub_426940();
#endif
            break;
        case WM_SETCURSOR:
            jk_SetCursor(0);
            return 1;
        case WM_CHAR:
            if ( a3 == VK_ESCAPE )
            {
                if ( jkCutscene_isRendering )
                {
                    return jkCutscene_sub_421410();
                }
                return 1;
            }
            else if ( a3 == VK_SPACE )
            {
                jkCutscene_55AA54 = !jkCutscene_55AA54;
#if !defined(SDL2_RENDER)
                if (!openjkdf2_bIsKVM)
                    smack_off(jkCutscene_55AA54);
#endif

#if defined(SDL2_RENDER)
                if (jkCutscene_55AA54)
                {
                    if (jkCutscene_audioFull)
                        stdSound_BufferStop(jkCutscene_audioFull);
                    if (jkCutscene_audio)
                        stdSound_BufferStop(jkCutscene_audio);
                    if (jkCutscene_audio2)
                        stdSound_BufferStop(jkCutscene_audio2);
                    if (jkCutscene_audio3)
                        stdSound_BufferStop(jkCutscene_audio3);
                    last_displayFrame -= Linux_TimeUs();
                    last_audioUs -= Linux_TimeUs();
                }
                else
                {
                    if (jkCutscene_audioFull)
                        stdSound_BufferPlay(jkCutscene_audioFull, 0);
                    if (jkCutscene_audio)
                        stdSound_BufferPlay(jkCutscene_audio, 0);
                    if (jkCutscene_audio2)
                        stdSound_BufferPlay(jkCutscene_audio2, 0);
                    if (jkCutscene_audio3)
                        stdSound_BufferPlay(jkCutscene_audio3, 0);
                    last_displayFrame += Linux_TimeUs();
                    last_audioUs += Linux_TimeUs();
                }
#endif
                jkCutscene_PauseShow(0);
            }
            return 0;
    }
    return 0;
}

#ifdef SDL2_RENDER
int jkCutscene_smacker_process()
{
    if ( !jkCutscene_isRendering )
        return 0;
    if (!std3D_IsReady()) {
        return 0;
    }

    double cur_displayFrame = (double)Linux_TimeUs();

    double usPerFrame = jkCutscene_smk_usf;
    double delta = cur_displayFrame - last_displayFrame;
    if (delta <= usPerFrame) return 0;
    //printf("%f %f %f\n", delta, usPerFrame, extraUs);

    if (last_displayFrame)
        extraUs += (delta - usPerFrame);

    last_displayFrame = cur_displayFrame;

    // Get the video to catch up, if it misses frames
    last_displayFrame -= extraUs;
    extraUs = 0.0;

    unsigned long frame = 0;
    smk_info_all(jkCutscene_smk, &frame, NULL, NULL);

    uint32_t* subtitle_idx = smk_get_audio(jkCutscene_smk, 1);
    size_t s = smk_get_audio_size(jkCutscene_smk, 1);

    if (s == 4)
    {
        jkCutscene_dword_55B750 = *subtitle_idx;
    }

    _memcpy(stdDisplay_masterPalette, smk_get_palette(jkCutscene_smk), 0x300);
    
    stdDisplay_VBufferLock(jkCutscene_frameBuf);
	_memcpy(jkCutscene_frameBuf->surface_lock_alloc, smk_get_video(jkCutscene_smk), jkCutscene_smk_w*jkCutscene_smk_h);
	stdDisplay_VBufferUnlock(jkCutscene_frameBuf);
    
    stdDisplay_VBufferLock(Video_pMenuBuffer);
	stdDisplay_VBufferCopy(Video_pMenuBuffer, jkCutscene_frameBuf, 0, 50, NULL, 0);
    stdDisplay_VBufferFill(Video_pMenuBuffer, 0, &jkCutscene_rect1);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, &Video_otherBuf, jkCutscene_rect1.x, jkCutscene_rect1.y, &jkCutscene_rect1, 0);
	stdDisplay_VBufferUnlock(Video_pMenuBuffer);

#if 0	
	jkCutscene_audioFlip = !jkCutscene_audioFlip;
	stdSound_buffer_t* buf = jkCutscene_audio;
	if (jkCutscene_audioFlip)
	    buf = jkCutscene_audio2;
	
	stdSound_BufferReset(buf);

    int maxSize;
	void* audioBuf = stdSound_BufferSetData(buf, smk_get_audio_size(jkCutscene_smk, 0), &maxSize);
	_memcpy(audioBuf, smk_get_audio(jkCutscene_smk, 0), smk_get_audio_size(jkCutscene_smk, 0));
	stdSound_BufferUnlock(buf, audioBuf, maxSize);
    stdSound_BufferPlay(buf, 0);
#endif	
	
	if (smk_next(jkCutscene_smk) == SMK_DONE) {
        last_displayFrame = 0;
        extraUs = 0;
	    return 1;
    }

    return 0;
}

int jkCutscene_smusher_process()
{
    if ( !jkCutscene_isRendering )
        return 0;
    if (!std3D_IsReady()) {
        return 0;
    }

    double cur_displayFrame = (double)Linux_TimeUs();

    double usPerFrame = jkCutscene_smk_usf;
    double delta = cur_displayFrame - last_displayFrame;

    double cur_audioUs = (double)Linux_TimeUs();

    double slop = jkCutscene_audio_us - (cur_audioUs - last_audioUs);
    //printf("%f %f\n", slop, jkCutscene_audio_us_slop);

    if (cur_audioUs - last_audioUs >= jkCutscene_audio_us - jkCutscene_audio_us_slop) {

        double stutter_compensate = 0.0;
        double slop = jkCutscene_audio_us - (cur_audioUs - last_audioUs);
        //printf("next! %p %f %f %f %f\n", jkCutscene_audio_queue_read_idx, cur_audioUs - last_audioUs, slop, jkCutscene_audio_us, jkCutscene_audio_us_slop);

        
        if (slop > jkCutscene_audio_us_slop) {
            slop = jkCutscene_audio_us_slop;
        }
        else if (slop < 0) {
            if (jkCutscene_audio_us) {
                stutter_compensate = slop;
            }
            slop = 0;
        }

        int slop_bytes = (int)((slop * 22050.0 * 4.0) / 1000000.0);
        if (slop_bytes > AUDIO_BUFS_DEPTH / 4) {
            slop_bytes = AUDIO_BUFS_DEPTH / 4;
        }
        if (slop_bytes < 0) {
            slop_bytes = 0;
        }

        // We have to keep things aligned to 4 or the stereo switches sides
        if (slop_bytes & 3) {
            slop_bytes += 4;
        }
        slop_bytes &= ~3;
        
        if (slop_bytes > AUDIO_MAXIMUM_ALLOWED_SLOP_BYTES) {
            goto skip_audio;
        }
        //printf("slop bytes %x %x %x\n", slop_bytes, jkCutscene_audio_queue_read_idx, jkCutscene_audioFlip);

        if (jkCutscene_audio_len <= 0) {
            if (jkCutscene_audio_buf) {
                free(jkCutscene_audio_buf);
                jkCutscene_audio_buf = NULL;
            }
            jkCutscene_audio_buf = jkCutscene_audio_queue[jkCutscene_audio_queue_read_idx];
            jkCutscene_audio_len = jkCutscene_audio_queue_lens[jkCutscene_audio_queue_read_idx];
            jkCutscene_audio_pos = jkCutscene_audio_buf;

            if (jkCutscene_audio_buf) {
                jkCutscene_audio_queue[jkCutscene_audio_queue_read_idx] = NULL;
                jkCutscene_audio_queue_lens[jkCutscene_audio_queue_read_idx++] = 0;
                jkCutscene_audio_queue_read_idx = jkCutscene_audio_queue_read_idx % AUDIO_QUEUE_DEPTH;
            }
        }

        if (!jkCutscene_audio_pos || !jkCutscene_audio_len) {
            goto skip_audio;
        }

        jkCutscene_audioFlip++;
        jkCutscene_audioFlip %= 3;
        stdSound_buffer_t* buf = jkCutscene_audio;
        if (jkCutscene_audioFlip == 1) {
            buf = jkCutscene_audio2;
        }
        else if (jkCutscene_audioFlip == 2) {
             buf = jkCutscene_audio3;
        }

        stdSound_BufferReset(buf);
        int len = 0;
        uint8_t* stream = (uint8_t*)stdSound_BufferSetData(buf, AUDIO_BUFS_DEPTH, &len);
        uint8_t* stream_iter = stream;
        uint32_t stream_left = len;

        memset(stream, 0, len);
        stream_iter += (slop_bytes);
        
        int written_len = slop_bytes;
        stream_left -= written_len;
        while (written_len < (len/2) + (slop_bytes)) {
            if (jkCutscene_audio_len <= 0) {
                if (jkCutscene_audio_buf) {
                    free(jkCutscene_audio_buf);
                    jkCutscene_audio_buf = NULL;
                }
                jkCutscene_audio_buf = jkCutscene_audio_queue[jkCutscene_audio_queue_read_idx];
                jkCutscene_audio_len = jkCutscene_audio_queue_lens[jkCutscene_audio_queue_read_idx];
                jkCutscene_audio_pos = jkCutscene_audio_buf;

                if (jkCutscene_audio_buf) {
                    jkCutscene_audio_queue[jkCutscene_audio_queue_read_idx] = NULL;
                    jkCutscene_audio_queue_lens[jkCutscene_audio_queue_read_idx++] = 0;
                    jkCutscene_audio_queue_read_idx = jkCutscene_audio_queue_read_idx % AUDIO_QUEUE_DEPTH;
                }
            }

            if (!jkCutscene_audio_pos || !jkCutscene_audio_len) {
                break;
            }

            int to_write = (stream_left > jkCutscene_audio_len ? jkCutscene_audio_len : stream_left);
            if (to_write && jkCutscene_audio_pos) {
                memcpy(stream_iter, jkCutscene_audio_pos, to_write);
                stream_iter += to_write;
                stream_left -= to_write;
            }

            //printf("write %x %x %p %x\n", to_write, stream_left, jkCutscene_audio_pos, jkCutscene_audio_len);

            //SDL_MixAudio(stream, jkCutscene_audio_pos, len, SDL_MIX_MAXVOLUME);// mix from one buffer into another
            
            written_len += to_write;
            jkCutscene_audio_pos += to_write;
            jkCutscene_audio_len -= to_write;
        }
        //printf("Wrote %x\n", written_len);
        stdSound_BufferUnlock(buf, stream, len);
        stdSound_BufferPlay(buf, 0);

        jkCutscene_audio_us = ((double)(written_len / 4) / 22050.0) * 1000000.0;
        jkCutscene_audio_us += stutter_compensate; // If we were late...

        last_audioUs = Linux_TimeUs();
    }

skip_audio:
    if (delta <= usPerFrame) return 0;
    //printf("%f %f %f\n", delta, usPerFrame, extraUs);

    if (last_displayFrame)
        extraUs += (delta - usPerFrame);

    last_displayFrame = cur_displayFrame;

    // Get the video to catch up, if it misses frames
    last_displayFrame -= extraUs;
    extraUs = 0.0;

    unsigned long frame = smush_cur_frame(jkCutscene_pSmush);
    //smk_info_all(jkCutscene_smk, &frame, NULL, NULL);

    //uint32_t* subtitle_idx = smk_get_audio(jkCutscene_smk, 1);
    //size_t s = smk_get_audio_size(jkCutscene_smk, 1);

    //if (s == 4)
    {
        // TODO subtitles
        jkCutscene_dword_55B750 = smush_get_current_subtitle(jkCutscene_pSmush);
    }

    _memcpy(stdDisplay_masterPalette, smush_get_palette(jkCutscene_pSmush), 0x300);
    
    stdDisplay_VBufferLock(jkCutscene_frameBuf);
    _memcpy(jkCutscene_frameBuf->surface_lock_alloc, smush_get_video(jkCutscene_pSmush), jkCutscene_smk_w*jkCutscene_smk_h);
    stdDisplay_VBufferUnlock(jkCutscene_frameBuf);
    
    stdDisplay_VBufferLock(Video_pMenuBuffer);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, jkCutscene_frameBuf, 0, 50, NULL, 0);
    stdDisplay_VBufferFill(Video_pMenuBuffer, 0, &jkCutscene_rect1);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, &Video_otherBuf, jkCutscene_rect1.x, jkCutscene_rect1.y, &jkCutscene_rect1, 0);
    stdDisplay_VBufferUnlock(Video_pMenuBuffer);
    

#if 0
    if (jkCutscene_audio) {
        stdSound_BufferRelease(jkCutscene_audio);
    }

    // Start audio stuff
    jkCutscene_audio = stdSound_BufferCreate(1, 22050, 16, len);
    

    memcpy(audioBuf, data, len);

    stdSound_BufferSetVolume(jkCutscene_audio, jkGuiSound_cutsceneVolume);
    stdSound_BufferUnlock(jkCutscene_audio, audioBuf, maxSize);
    stdSound_BufferPlay(jkCutscene_audio, 0);
#endif

#if 0   
    jkCutscene_audioFlip = !jkCutscene_audioFlip;
    stdSound_buffer_t* buf = jkCutscene_audio;
    if (jkCutscene_audioFlip)
        buf = jkCutscene_audio2;
    
    stdSound_BufferReset(buf);

    int maxSize;
    void* audioBuf = stdSound_BufferSetData(buf, smk_get_audio_size(jkCutscene_smk, 0), &maxSize);
    _memcpy(audioBuf, smk_get_audio(jkCutscene_smk, 0), smk_get_audio_size(jkCutscene_smk, 0));
    stdSound_BufferUnlock(buf, audioBuf, maxSize);
    stdSound_BufferPlay(buf, 0);
#endif  
    
    smush_frame(jkCutscene_pSmush);
    if (smush_done(jkCutscene_pSmush)) {
        last_displayFrame = 0;
        last_audioUs = 0;
        extraUs = 0;
        return 1;
    }

    return 0;
}
#endif
