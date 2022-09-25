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
#include "Win95/stdSound.h"
#include "Devices/sithSoundMixer.h"
#include "stdPlatform.h"

#include "smacker.h"

#include "../jk.h"

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

static smk jkCutscene_smk;
static double jkCutscene_smk_usf;
static unsigned long jkCutscene_smk_w, jkCutscene_smk_h, jkCutscene_smk_frames;
static stdVBuffer* jkCutscene_frameBuf = NULL;
static void* jkCutscene_palette = NULL;
//static void* jkCutscene_audioBuf = NULL;
//static stdSound_buffer_t* jkCutscene_audio = NULL;
//static stdSound_buffer_t* jkCutscene_audio2 = NULL;
static stdSound_buffer_t* jkCutscene_audioFull = NULL;
//static int jkCutscene_audioFlip = 0;

// TODO actually fill this in with an alternative Smack decoder

static double last_displayFrame = 0;
static double extraUs = 0;
extern int openjkdf2_bIsKVM;

// MOTS altered
void jkCutscene_Startup(char *fpath)
{
    stdStrTable_Load(&jkCutscene_strings, fpath); // MOTS removed
    jkCutscene_subtitlefont = stdFont_Load("ui\\sft\\subtitlefont.sft", 0, 0);
    jkCutscene_rect1.x = 10;
    jkCutscene_rect1.y = 360;
    jkCutscene_rect1.width = 620;
    jkCutscene_rect1.height = 120;
    jkCutscene_rect2.x = 0;
    jkCutscene_rect2.y = 10;
    jkCutscene_rect2.width = 640;
    jkCutscene_rect2.height = 40;
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

    jkCutscene_smk = smk_open_file(tmp, SMK_MODE_MEMORY);
    if (!jkCutscene_smk)
    {
        jk_printf("Failed to load file `%s`!\n", tmp);
        return 1;
    }
    smk_info_all(jkCutscene_smk, NULL, &jkCutscene_smk_frames, &jkCutscene_smk_usf);
	smk_info_video(jkCutscene_smk, &jkCutscene_smk_w, &jkCutscene_smk_h, NULL);
	printf("Opened file %s\nWidth: %lu\nHeight: %lu\nFrames: %lu\nFPS: %f\n", tmp, jkCutscene_smk_w, jkCutscene_smk_h, jkCutscene_smk_frames, 1000000.0 / jkCutscene_smk_usf);
	
	unsigned char	a_t, a_c[7], a_d[7];
	unsigned long	a_r[7];

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

	unsigned long	cur_frame;
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
    if ( !jkCutscene_isRendering )
        return 0;
    Window_RemoveMsgHandler(jkCutscene_Handler);

#if !defined(SDL2_RENDER)
    if (!openjkdf2_bIsKVM)
        smack_sub_426940();
#endif

#ifdef SDL2_RENDER
    //stdSound_BufferRelease(jkCutscene_audio);
    //stdSound_BufferRelease(jkCutscene_audio2);
    stdSound_BufferRelease(jkCutscene_audioFull);
    smk_close(jkCutscene_smk);
    stdDisplay_VBufferFree(jkCutscene_frameBuf);
    jkCutscene_frameBuf = NULL;
#endif

    last_displayFrame = 0;
    extraUs = 0;

    jkCutscene_isRendering = 0;
    jk_ShowCursor(1);
    return 1;
}

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
        smack_finished = jkCutscene_smacker_process();
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
        v0 = jkStrings_GetText("GUI_PAUSED");
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
            if ( a3 != 0x1B )
            {
                if ( a3 == 0x20 )
                {
                    jkCutscene_55AA54 = !jkCutscene_55AA54;
#if !defined(SDL2_RENDER)
                    if (!openjkdf2_bIsKVM)
                        smack_off(jkCutscene_55AA54);
#endif

#if defined(SDL2_RENDER)
                    if (jkCutscene_55AA54)
                    {
                        stdSound_BufferStop(jkCutscene_audioFull);
                        last_displayFrame -= Linux_TimeUs();
                    }
                    else
                    {
                        stdSound_BufferPlay(jkCutscene_audioFull, 0);
                        last_displayFrame += Linux_TimeUs();
                    }
#endif
                    jkCutscene_PauseShow(0);
                }
                return 0;
            }
            if ( jkCutscene_isRendering )
            {
                return jkCutscene_sub_421410();
            }
            return 1;
    }
    return 0;
}

#ifdef SDL2_RENDER
int jkCutscene_smacker_process()
{
    if ( !jkCutscene_isRendering )
        return 0;

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
#endif
