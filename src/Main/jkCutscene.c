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

#ifdef __cplusplus
extern "C" {
#endif
#include "smacker.h"
#include "smush.h"
#ifdef __cplusplus
}
#endif

#include "../jk.h"

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

// TODO read back the number of queued buffers instead of being wasteful
#define AUDIO_NUM_STDBUFS (32)

static smush_ctx* jkCutscene_pSmush;
static smk jkCutscene_smk;
static int jkCutscene_bSmkValid = 0;
static flex64_t jkCutscene_smk_usf;
static uint32_t jkCutscene_smk_w, jkCutscene_smk_h, jkCutscene_smk_frames;
static stdVBuffer* jkCutscene_frameBuf = NULL;
//static void* jkCutscene_audioBuf = NULL;
static stdSound_buffer_t* jkCutscene_audio[AUDIO_NUM_STDBUFS];

static stdSound_buffer_t* jkCutscene_lastAudio = NULL;
static stdSound_buffer_t* jkCutscene_currentAudio = NULL;
static uint8_t* jkCutscene_currentAudioBuf = NULL;
static int32_t jkCutscene_currentAudioBufSize = 0;
static int32_t jkCutscene_currentAudioWritten = 0;
static int jkCutscene_audioFlip = 0;

// TODO actually fill this in with an alternative Smack decoder

static flex64_t last_displayFrame = 0;
static flex64_t last_audioUs = 0;
static flex64_t extraUs = 0;
extern int openjkdf2_bIsKVM;

// Smush
#ifdef TARGET_TWL
#define AUDIO_BUFS_DEPTH (0x8000)
#define AUDIO_QUEUE_DEPTH (128)
#define AUDIO_MAXIMUM_ALLOWED_SLOP_BYTES (0x800)
#else
#define AUDIO_BUFS_DEPTH (0x8000)
#define AUDIO_QUEUE_DEPTH (128)
#define AUDIO_MAXIMUM_ALLOWED_SLOP_BYTES (0x800)
#endif

static flex64_t jkCutscene_audio_us;
static flex64_t jkCutscene_audio_us_slop;

static const uint8_t* jkCutscene_audio_buf;
static const uint8_t* jkCutscene_audio_pos;
static uint32_t jkCutscene_audio_len;

static const uint8_t* jkCutscene_audio_queue[AUDIO_QUEUE_DEPTH] = {0};
static size_t jkCutscene_audio_queue_lens[AUDIO_QUEUE_DEPTH] = {0};
static int32_t jkCutscene_audio_queue_read_idx = 0;
static int32_t jkCutscene_audio_queue_write_idx = 0;

void smush_audio_callback(const uint8_t* data, size_t len)
{
    //printf("Callback %p %zx %x %x %x\n", data, len, jkCutscene_pSmush->cur_frame, jkCutscene_pSmush->audio_cur_frame, jkCutscene_audio_queue_write_idx);
    if (jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx]) {
        free((void*)jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx]);
        jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx] = NULL;
    }

    jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx] = data;
    jkCutscene_audio_queue_lens[jkCutscene_audio_queue_write_idx++] = len;
    jkCutscene_audio_queue_write_idx = jkCutscene_audio_queue_write_idx % AUDIO_QUEUE_DEPTH;
}

void smack_audio_callback(const uint8_t* data, size_t len)
{
    //printf("Callback %p %zx %x %x %x\n", data, len, jkCutscene_pSmush->cur_frame, jkCutscene_pSmush->audio_cur_frame, jkCutscene_audio_queue_write_idx);
    if (jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx]) {
        free((void*)jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx]);
        jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx] = NULL;
    }

    void* queueAlloc = malloc(len);
    if (!queueAlloc) {
        return;
    }
    memcpy(queueAlloc, data, len);

    jkCutscene_audio_queue[jkCutscene_audio_queue_write_idx] = (const uint8_t*)queueAlloc;
    jkCutscene_audio_queue_lens[jkCutscene_audio_queue_write_idx++] = len;
    jkCutscene_audio_queue_write_idx = jkCutscene_audio_queue_write_idx % AUDIO_QUEUE_DEPTH;
}

// Added
void jkCutscene_CleanReset()
{
#if defined(SDL2_RENDER) || defined(TARGET_TWL)
    for (int32_t i = 0; i < AUDIO_QUEUE_DEPTH; i++) {
        if (jkCutscene_audio_queue[i]) {
            free((void*)jkCutscene_audio_queue[i]);
        }

        jkCutscene_audio_queue[i] = NULL;
        jkCutscene_audio_queue_lens[i] = 0;
    }
    if (jkCutscene_audio_buf) {
        free((void*)jkCutscene_audio_buf);
        jkCutscene_audio_buf = NULL;
    }
    for (int i = 0; i < AUDIO_NUM_STDBUFS; i++) {
        if (jkCutscene_audio[i]) {
            stdSound_BufferRelease(jkCutscene_audio[i]);
            jkCutscene_audio[i] = NULL;
        }
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
    //jkCutscene_audioBuf = NULL;
    jkCutscene_lastAudio = NULL;
    jkCutscene_currentAudio = NULL;
    jkCutscene_currentAudioBuf = NULL;
    jkCutscene_currentAudioWritten = 0;

    for (int i = 0; i < AUDIO_NUM_STDBUFS; i++) {
        jkCutscene_audio[i] = NULL;
    }
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
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);
    
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
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);

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

#if defined(ARCH_WASM)
    printf("vid skip %s\n", fpath);
    return 1;
#endif

#if defined(TARGET_TWL)
    // TODO: Find a way to make sure enough memory is free during cutscenes
    // (move them back to before the level load?)
    if (openjkdf2_bIsExtraLowMemoryPlatform /*&& Main_bMotsCompat*/) {
        printf("vid skip %s\n", fpath);
        return 1;
    }
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
    
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
    if (!openjkdf2_bIsKVM)
        return _jkCutscene_sub_421310(tmp);
#endif

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
    sithSoundMixer_StopSong();
    stdMci_Stop();

#ifdef LINUX
    char *r = (char*)malloc(strlen(tmp) + 16);
    if (casepath(tmp, r))
    {
        strcpy(tmp, r);
    }
    free((void*)r);
#endif

#ifdef TARGET_TWL
    pHS->suggestHeap(HEAP_FAST);
#endif

    jkCutscene_pSmush = smush_from_fpath(tmp);
    if (!jkCutscene_pSmush)
    {
        jkCutscene_bSmkValid = 0;
        jkCutscene_smk = smk_open_file(tmp, SMK_MODE_DISK);

#ifdef TARGET_TWL
        pHS->suggestHeap(HEAP_ANY);
#endif

        if (jkCutscene_audio_buf) {
            free((void*)jkCutscene_audio_buf);
        }
        jkCutscene_audio_buf = NULL;
        jkCutscene_audio_pos = NULL;
        jkCutscene_audio_len = 0;

        jkCutscene_audio_queue_read_idx = 0;
        jkCutscene_audio_queue_write_idx = 0;

        for (int32_t i = 0; i < AUDIO_QUEUE_DEPTH; i++) {
            if (jkCutscene_audio_queue[i]) {
                free((void*)jkCutscene_audio_queue[i]);
            }
            jkCutscene_audio_queue[i] = NULL;
            jkCutscene_audio_queue_lens[i] = 0;
        }

        if (!jkCutscene_smk)
        {
            stdPlatform_Printf("Failed to load file `%s`!\n", tmp);
#ifdef TARGET_TWL
            stdPlatform_PrintHeapStats();
            //while(1);
#endif
            return 1;
        }

        jkCutscene_bSmkValid = 1;
        smk_info_all(jkCutscene_smk, NULL, &jkCutscene_smk_frames, &jkCutscene_smk_usf);
        smk_info_video(jkCutscene_smk, &jkCutscene_smk_w, &jkCutscene_smk_h, NULL);
        stdPlatform_Printf("Opened file %s as SMK\nWidth: %lu\nHeight: %lu\nFrames: %lu\nFPS: %f\n", tmp, jkCutscene_smk_w, jkCutscene_smk_h, jkCutscene_smk_frames, 1000000.0 / jkCutscene_smk_usf);
        
        unsigned char   a_t, a_c[7], a_d[7];
        uint32_t   a_r[7];

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

        smk_enable_video(jkCutscene_smk, 1);
        smk_enable_audio(jkCutscene_smk, 0, 1);
        smk_enable_audio(jkCutscene_smk, 1, 1); // metadata track
        smk_first(jkCutscene_smk);

        int32_t len;
        uint8_t* stream;

        for (int i = 0; i < AUDIO_NUM_STDBUFS; i++) {
            jkCutscene_audio[i] = stdSound_BufferCreate(a_c[0] == 2, a_r[0], a_d[0], AUDIO_BUFS_DEPTH);
            stdSound_BufferSetVolume(jkCutscene_audio[i], jkGuiSound_cutsceneVolume);
            stream = (uint8_t*)stdSound_BufferSetData(jkCutscene_audio[i], AUDIO_BUFS_DEPTH, &len);
            memset(stream, 0, len);
            stdSound_BufferUnlock(jkCutscene_audio[i], stream, len);
            stdSound_BufferReset(jkCutscene_audio[i]);
        }

        // Keep half of AUDIO_BUFS_DEPTH empty to allow time adjustments
        flex64_t audio_depth_us = ((flex64_t)(AUDIO_BUFS_DEPTH / 4) / 22050.0) * 1000000.0;
        jkCutscene_audio_us = 0.0;//audio_depth_us / 2.0;
        jkCutscene_audio_us_slop = audio_depth_us / 4.0;
        
        // TODO kinda hacky
        //jkGui_SetModeMenu(smk_get_palette(jkCutscene_smk));
        jkGui_SetModeMenu(smk_get_palette(jkCutscene_smk));
    }
    else {
#ifdef TARGET_TWL
        pHS->suggestHeap(HEAP_ANY);
#endif
        jkCutscene_bSmkValid = 0;
        if (jkCutscene_audio_buf) {
            free((void*)jkCutscene_audio_buf);
        }
        jkCutscene_audio_buf = NULL;
        jkCutscene_audio_pos = NULL;
        jkCutscene_audio_len = 0;

        jkCutscene_audio_queue_read_idx = 0;
        jkCutscene_audio_queue_write_idx = 0;

        for (int32_t i = 0; i < AUDIO_QUEUE_DEPTH; i++) {
            if (jkCutscene_audio_queue[i]) {
                free((void*)jkCutscene_audio_queue[i]);
            }
            jkCutscene_audio_queue[i] = NULL;
            jkCutscene_audio_queue_lens[i] = 0;
        }

        smush_set_debug(jkCutscene_pSmush, 0);
        smush_set_audio_buffer_size(jkCutscene_pSmush, 0x1000);
        smush_set_audio_callback(jkCutscene_pSmush, smush_audio_callback);
        smush_frame(jkCutscene_pSmush);

        jkCutscene_smk_frames = smush_num_frames(jkCutscene_pSmush);
        jkCutscene_smk_w = smush_video_width(jkCutscene_pSmush);
        jkCutscene_smk_h = smush_video_height(jkCutscene_pSmush);
        jkCutscene_smk_usf = 1000000.0 / (flex64_t)smush_video_fps(jkCutscene_pSmush);

        stdPlatform_Printf("Opened file %s as Smush\nWidth: %lu\nHeight: %lu\nFrames: %lu\nFPS: %f\n", tmp, jkCutscene_smk_w, jkCutscene_smk_h, jkCutscene_smk_frames, 1000000.0 / jkCutscene_smk_usf);

        stdVBufferTexFmt texFmt;
        texFmt.width = jkCutscene_smk_w;
        texFmt.height = jkCutscene_smk_h;
        texFmt.format.bpp = 8;
        jkCutscene_frameBuf = stdDisplay_VBufferNew(&texFmt, 1, 0, (void*)1);
        stdDisplay_VBufferFill(jkCutscene_frameBuf, 0, NULL);

        // Keep half of AUDIO_BUFS_DEPTH empty to allow time adjustments
        flex64_t audio_depth_us = ((flex64_t)(AUDIO_BUFS_DEPTH / 4) / 22050.0) * 1000000.0;
        jkCutscene_audio_us = 0.0; // audio_depth_us / 2.0
        jkCutscene_audio_us_slop = audio_depth_us / 4.0;
        
        int32_t len;
        uint8_t* stream;

        for (int i = 0; i < AUDIO_NUM_STDBUFS; i++) {
            jkCutscene_audio[i] = stdSound_BufferCreate(1, 22050, 16, AUDIO_BUFS_DEPTH);
            stdSound_BufferSetVolume(jkCutscene_audio[i], jkGuiSound_cutsceneVolume);
            stream = (uint8_t*)stdSound_BufferSetData(jkCutscene_audio[i], AUDIO_BUFS_DEPTH, &len);
            memset(stream, 0, len);
            stdSound_BufferUnlock(jkCutscene_audio[i], stream, len);
            stdSound_BufferReset(jkCutscene_audio[i]);
        }

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
#ifdef TARGET_TWL
    stdDisplay_VBufferFill(Video_pMenuBuffer, 0, &jkCutscene_rect1);
#endif
	stdDisplay_VBufferUnlock(Video_pMenuBuffer);
	
	Window_AddMsgHandler(jkCutscene_Handler);
	jkCutscene_isRendering = 1;
#endif
    // STUBBED
    return 1;
}

int jkCutscene_sub_421410()
{
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);
    
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
    if ( !jkCutscene_isRendering )
        return 0;
#endif
    Window_RemoveMsgHandler(jkCutscene_Handler);

#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
    if (!openjkdf2_bIsKVM)
        smack_sub_426940();
#endif

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
    for (int32_t i = 0; i < AUDIO_QUEUE_DEPTH; i++) {
        if (jkCutscene_audio_queue[i]) {
            free((void*)jkCutscene_audio_queue[i]);
        }

        jkCutscene_audio_queue[i] = NULL;
        jkCutscene_audio_queue_lens[i] = 0;
    }
    if (jkCutscene_audio_buf) {
        free((void*)jkCutscene_audio_buf);
        jkCutscene_audio_buf = NULL;
    }

    for (int i = 0; i < AUDIO_NUM_STDBUFS; i++) {
        if (jkCutscene_audio[i]) {
            stdSound_BufferRelease(jkCutscene_audio[i]);
        }
        jkCutscene_audio[i] = NULL;
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

    jkCutscene_lastAudio = NULL;
    jkCutscene_currentAudio = NULL;
    jkCutscene_currentAudioBuf = NULL;
    jkCutscene_currentAudioWritten = 0;
    jkCutscene_currentAudioBufSize = 0;
#endif

    last_displayFrame = 0;
    last_audioUs = 0;
    extraUs = 0;

    jkCutscene_isRendering = 0;
    jkGui_SetModeGame(); // Added?
    jk_ShowCursor(1);
    return 1;
}

// MOTS altered
int jkCutscene_smack_related_loops()
{
    int32_t smack_finished; // esi
    int32_t v2; // ecx

    smack_finished = 0;
    if ( !jkCutscene_isRendering )
        return 1;
    if ( !jkCutscene_55AA54 && g_app_suspended )
    {
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
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
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
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
                int32_t uVar3 = jkCutscene_dword_55B750 & 0x7FFFFFFF;
                if (uVar3) {
                    int32_t uVar4 = uVar3 % 10000;
                    int32_t iVar2 = 0;
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
                    int32_t forced = 0;
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
#if defined(SDL2_RENDER) || defined(TARGET_TWL)
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

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
    stdDisplay_VBufferLock(Video_pMenuBuffer);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, jkCutscene_frameBuf, 0, 50, NULL, 0);
    stdDisplay_VBufferFill(Video_pMenuBuffer, 0, &jkCutscene_rect1);
    stdDisplay_VBufferFill(Video_pMenuBuffer, 0, &jkCutscene_rect2);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, &Video_otherBuf, jkCutscene_rect1.x, jkCutscene_rect1.y, &jkCutscene_rect1, 0);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, &Video_otherBuf, jkCutscene_rect2.x, jkCutscene_rect2.y, &jkCutscene_rect2, 0);
    stdDisplay_VBufferUnlock(Video_pMenuBuffer);
#endif

    result = Main_bWindowGUI;
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
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
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
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
#if !defined(SDL2_RENDER) && !defined(TARGET_TWL)
                if (!openjkdf2_bIsKVM)
                    smack_off(jkCutscene_55AA54);
#endif

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
                if (jkCutscene_55AA54)
                {
                    if (jkCutscene_audio[0])
                        stdSound_BufferStop(jkCutscene_audio[0]);

                    last_displayFrame -= Linux_TimeUs();
                    last_audioUs -= Linux_TimeUs();
                }
                else
                {
                    if (jkCutscene_audio[0])
                        stdSound_BufferPlay(jkCutscene_audio[0], 0);

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

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
void jkCutscene_smacker_process_audio()
{
    uint32_t frame = 0;
    smk_info_all(jkCutscene_smk, &frame, NULL, NULL);

    uint32_t* subtitle_idx = (uint32_t*)smk_get_audio(jkCutscene_smk, 1);
    size_t s = smk_get_audio_size(jkCutscene_smk, 1);

    if (s == 4)
    {
        jkCutscene_dword_55B750 = *subtitle_idx;
    }

    const uint8_t* audioBufBits = (const uint8_t*)smk_get_audio(jkCutscene_smk, 0);
    size_t s0 = smk_get_audio_size(jkCutscene_smk, 0);

    if (s0) {
        smack_audio_callback(audioBufBits, s0);
    }
}

void jkCutscene_smacker_smusher_audio_queue() {
    if (jkCutscene_audio_queue_read_idx != jkCutscene_audio_queue_write_idx || jkCutscene_audio_len || jkCutscene_currentAudioWritten < jkCutscene_currentAudioBufSize) {
        
        // If we ran through the queued samples, fetch new samples
        if (jkCutscene_audio_len <= 0) {
            if (jkCutscene_audio_buf) {
                free((void*)jkCutscene_audio_buf);
                jkCutscene_audio_buf = NULL;
            }
            jkCutscene_audio_buf = jkCutscene_audio_queue[jkCutscene_audio_queue_read_idx];
            jkCutscene_audio_len = jkCutscene_audio_queue_lens[jkCutscene_audio_queue_read_idx];
            jkCutscene_audio_pos = jkCutscene_audio_buf;

            if (jkCutscene_audio_buf) {
                jkCutscene_audio_queue[jkCutscene_audio_queue_read_idx] = NULL;
                jkCutscene_audio_queue_lens[jkCutscene_audio_queue_read_idx++] = 0;
                jkCutscene_audio_queue_read_idx = jkCutscene_audio_queue_read_idx % AUDIO_QUEUE_DEPTH;

                //stdPlatform_Printf("Next samples! %x\n", jkCutscene_audio_buf[0]);
            }
            else {
                return;
            }
        }

        if (!jkCutscene_audio_pos || !jkCutscene_audio_len) {
            return;
        }

        if (!jkCutscene_currentAudio) {
            //stdPlatform_Printf("Flip!\n");
            jkCutscene_audioFlip++;
            if (!jkCutscene_audioFlip) {
                jkCutscene_audioFlip++;
            }
            jkCutscene_audioFlip %= AUDIO_NUM_STDBUFS;
            jkCutscene_currentAudio = jkCutscene_audio[jkCutscene_audioFlip];

            if (!jkCutscene_lastAudio) {
                jkCutscene_lastAudio = jkCutscene_currentAudio;
            }
            jkCutscene_currentAudioWritten = 0;

            //stdSound_BufferReset(jkCutscene_currentAudio);
            jkCutscene_currentAudioBuf = (uint8_t*)stdSound_BufferSetData(jkCutscene_currentAudio, AUDIO_BUFS_DEPTH, &jkCutscene_currentAudioBufSize);
            memset(jkCutscene_currentAudioBuf, 0, jkCutscene_currentAudioBufSize);
        }

        

        int32_t len = 0;
        uint8_t* stream = jkCutscene_currentAudioBuf;
        uint8_t* stream_iter = stream + jkCutscene_currentAudioWritten;
        uint32_t stream_left = jkCutscene_currentAudioBufSize - jkCutscene_currentAudioWritten;
        
        int32_t written_len = 0;
        while (written_len < stream_left) {
            int32_t to_write = (stream_left > jkCutscene_audio_len ? jkCutscene_audio_len : stream_left);
            if (to_write > 0 && jkCutscene_audio_pos) {
                memcpy(stream_iter, jkCutscene_audio_pos, to_write);
                stream_iter += to_write;
                stream_left -= to_write;
            }

            //stdPlatform_Printf("write %x %x %p %x\n", to_write, stream_left, jkCutscene_audio_pos, jkCutscene_audio_len);

            written_len += to_write;
            jkCutscene_audio_pos += to_write;
            jkCutscene_audio_len -= to_write;
            jkCutscene_currentAudioWritten += to_write;
            //printf("%x %x %x %x\n", to_write, written_len, jkCutscene_audio_len, stream_left);

            // Just in case?
            if (to_write <= 0) break;
        }
        //stdPlatform_Printf("Wrote %x, %x of %x\n", written_len, jkCutscene_currentAudioWritten, jkCutscene_currentAudioBufSize);

        if (jkCutscene_currentAudioWritten >= jkCutscene_currentAudioBufSize) {
            //stdPlatform_Printf("Play!\n");
            stdSound_BufferUnlock(jkCutscene_currentAudio, stream, len);
            /*if (!stdSound_IsPlaying(jkCutscene_audio[0], NULL)) {
                stdSound_BufferReset(jkCutscene_audio[0]);
            }*/
            //stdSound_BufferReset(jkCutscene_audio[0]);
            stdSound_BufferQueueAfterAnother(jkCutscene_audio[0], jkCutscene_currentAudio);

            last_audioUs = Linux_TimeUs();

            jkCutscene_lastAudio = jkCutscene_currentAudio;
            jkCutscene_currentAudio = NULL;
            jkCutscene_currentAudioWritten = 0;
            jkCutscene_currentAudioBufSize = 0;
        }
    }
}

int jkCutscene_smacker_process()
{
    if ( !jkCutscene_isRendering )
        return 0;
    if (!std3D_IsReady()) {
        return 0;
    }

    flex64_t cur_displayFrame = (flex64_t)Linux_TimeUs();

    flex64_t usPerFrame = jkCutscene_smk_usf;
    flex64_t delta = cur_displayFrame - last_displayFrame;


    jkCutscene_smacker_smusher_audio_queue();

    if (delta <= usPerFrame) return 0;
    //printf("%f %f %f\n", delta, usPerFrame, extraUs);

    if (last_displayFrame)
        extraUs += (delta - usPerFrame);

    last_displayFrame = cur_displayFrame;

    // If the CPU is lagging, try and catch up by skipping video frames
    while (extraUs > usPerFrame) {
        //stdPlatform_Printf("Lagging behind?\n");
        /*if (smk_is_keyframe(jkCutscene_smk)) {
            printf("Keyframe\n");
        }*/
        smk_enable_video(jkCutscene_smk, smk_is_keyframe(jkCutscene_smk));
        jkCutscene_smacker_process_audio();
#ifdef TARGET_TWL
        //pHS->suggestHeap(HEAP_FAST);
#endif
        char smk_res = smk_next(jkCutscene_smk);
#ifdef TARGET_TWL
        //pHS->suggestHeap(HEAP_ANY);
#endif
        if (smk_res == SMK_DONE) {
            last_displayFrame = 0;
            extraUs = 0;
            return 1;
        }
        else if (smk_res < 0) {
            printf("smk_next failed?\n");
            while(1);
        }
        extraUs -= usPerFrame;
    }
    smk_enable_video(jkCutscene_smk, 1);

    // Get the video to catch up, if it misses frames
    last_displayFrame -= extraUs;
    extraUs = 0.0;

    jkCutscene_smacker_process_audio();

    _memcpy(stdDisplay_masterPalette, smk_get_palette(jkCutscene_smk), 0x300);

#ifdef TARGET_TWL
    /*stdDisplay_VBufferLock(jkCutscene_frameBuf);
    _memcpy(jkCutscene_frameBuf->surface_lock_alloc, smk_get_video(jkCutscene_smk), jkCutscene_smk_w*jkCutscene_smk_h);
    stdDisplay_VBufferUnlock(jkCutscene_frameBuf);*/
    
    stdDisplay_VBufferLock(Video_pMenuBuffer);
    _memcpy(Video_pMenuBuffer->surface_lock_alloc + (640*50), smk_get_video(jkCutscene_smk), jkCutscene_smk_w*jkCutscene_smk_h);
    //stdDisplay_VBufferCopy(Video_pMenuBuffer, jkCutscene_frameBuf, 0, 50, NULL, 0);
    //stdDisplay_VBufferFill(Video_pMenuBuffer, 0, &jkCutscene_rect1);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, &Video_otherBuf, jkCutscene_rect1.x, jkCutscene_rect1.y, &jkCutscene_rect1, 0);
    stdDisplay_VBufferUnlock(Video_pMenuBuffer);
#else
    stdDisplay_VBufferLock(jkCutscene_frameBuf);
    _memcpy(jkCutscene_frameBuf->surface_lock_alloc, smk_get_video(jkCutscene_smk), jkCutscene_smk_w*jkCutscene_smk_h);
    stdDisplay_VBufferUnlock(jkCutscene_frameBuf);
    
    stdDisplay_VBufferLock(Video_pMenuBuffer);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, jkCutscene_frameBuf, 0, 50, NULL, 0);
    stdDisplay_VBufferFill(Video_pMenuBuffer, 0, &jkCutscene_rect1);
    stdDisplay_VBufferCopy(Video_pMenuBuffer, &Video_otherBuf, jkCutscene_rect1.x, jkCutscene_rect1.y, &jkCutscene_rect1, 0);
    stdDisplay_VBufferUnlock(Video_pMenuBuffer);
#endif

#ifdef TARGET_TWL
    //pHS->suggestHeap(HEAP_FAST);
#endif
    char smk_res = smk_next(jkCutscene_smk);
#ifdef TARGET_TWL
    //pHS->suggestHeap(HEAP_ANY);
#endif
	if (smk_res == SMK_DONE) {
        last_displayFrame = 0;
        extraUs = 0;
	    return 1;
    }
    else if (smk_res < 0) {
        printf("smk_next failed?\n");
        while(1);
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

    flex64_t cur_displayFrame = (flex64_t)Linux_TimeUs();

    flex64_t usPerFrame = jkCutscene_smk_usf;
    flex64_t delta = cur_displayFrame - last_displayFrame;

    jkCutscene_smacker_smusher_audio_queue();

    if (delta <= usPerFrame) return 0;
    //printf("%f %f %f\n", delta, usPerFrame, extraUs);

    if (last_displayFrame)
        extraUs += (delta - usPerFrame);

    last_displayFrame = cur_displayFrame;

    // Get the video to catch up, if it misses frames
    last_displayFrame -= extraUs;
    extraUs = 0.0;

    uint32_t frame = smush_cur_frame(jkCutscene_pSmush);
    //smk_info_all(jkCutscene_smk, &frame, NULL, NULL);

    //uint32_t* subtitle_idx = (uint32_t*)smk_get_audio(jkCutscene_smk, 1);
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
    
    smush_frame(jkCutscene_pSmush);
    smush_audio_flush(jkCutscene_pSmush);
    if (smush_done(jkCutscene_pSmush)) {
        last_displayFrame = 0;
        last_audioUs = 0;
        extraUs = 0;
        return 1;
    }

    return 0;
}
#endif
