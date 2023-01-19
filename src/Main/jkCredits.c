#include "jkCredits.h"

#include "General/stdStrTable.h"
#include "General/stdFont.h"
#include "Win95/stdDisplay.h"
#include "Win95/Window.h"
#include "Win95/stdMci.h"
#include "Main/jkRes.h"
#include "Main/jkMain.h"

#include "../jk.h"

// Added: Simulate Disk 1 in menu
int jkCredits_cdOverride = 0;

static stdVBuffer* jkCredits_pVbufferTmp;

void jkCredits_Startup(char *fpath)
{
    stdStrTable_Load(&jkCredits_table, fpath);
    jkCredits_fontLarge = stdFont_Load("ui\\sft\\creditlarge.sft", 0, 0);
    jkCredits_fontSmall = stdFont_Load("ui\\sft\\creditsmall.sft", 0, 0);
    jkCredits_bInitted = 1;
    jkCredits_cdOverride = 0; // Added: Simulate Disk 1 in menu
}

void jkCredits_Shutdown()
{
    if ( jkCredits_fontLarge )
    {
        stdFont_Free(jkCredits_fontLarge);
        jkCredits_fontLarge = 0;
    }
    if ( jkCredits_fontSmall )
    {
        stdFont_Free(jkCredits_fontSmall);
        jkCredits_fontSmall = 0;
    }
    stdStrTable_Free(&jkCredits_table);
    jkCredits_bInitted = 0;
    jkCredits_cdOverride = 0; // Added: Simulate Disk 1 in menu
}

// MOTS altered (songs?)
int jkCredits_Show()
{
    unsigned int v1; // esi
    int v2; // esi
    HWND v3; // eax
    int v4; // edi
    int v5; // edi
    int v6; // esi
    char *v7; // ecx
    int v8; // edx
    int v9; // edx
    int v10; // edi
    int v11; // esi
    char *v12; // ecx
    int v13; // edx
    int v14; // edx
    stdVBuffer *v15; // eax
    char *v16; // edx
    int v17; // edi
    char *v18; // ebp
    int v19; // ecx
    int v20; // esi
    int v21; // edx
    int whichCdInserted; // eax
    signed int result; // eax
    stdDeviceParams v24; // [esp+10h] [ebp-B4h] BYREF
    render_pair a1; // [esp+24h] [ebp-A0h] BYREF
    stdVBufferTexFmt v26; // [esp+78h] [ebp-4Ch] BYREF

    if ( jkCredits_dword_55AD94 )
        return 0;
    jkCredits_dword_55ADA0 = 0;
    jkCredits_dword_55ADA8 = 0;
    jk_ShowCursor(0);
    v24.field_0 = 1;
    v24.field_C = 1;
    if ( Main_bWindowGUI )
    {
        v24.field_10 = 0;
        v24.field_4 = 0;
    }
    else
    {
        v24.field_10 = 1;
        v24.field_4 = 1;
    }
    v24.field_8 = 0;
    a1.render_8bpp.bpp = 0;
    a1.render_8bpp.rBpp = 0x3F800000;
    a1.render_8bpp.width = 640;
    a1.render_8bpp.height = 480;
    a1.render_8bpp.palBytes = 0;
    a1.render_rgb.bpp = 8;
    v1 = stdDisplay_FindClosestDevice(&v24);
    if ( !stdDisplay_bOpen )
        goto LABEL_10;
    if ( Video_dword_866D78 != v1 )
    {
        if ( stdDisplay_bOpen )
            stdDisplay_Close();
LABEL_10:
        if ( !stdDisplay_Open(v1) )
        {
LABEL_36:
            jk_ShowCursor(1);
            return 0;
        }
        v2 = 1;
        goto LABEL_12;
    }
    v2 = 0;
LABEL_12:
    v3 = stdGdi_GetHwnd();
    jk_SetFocus(v3);
    memset(jkCredits_aPalette, 0, sizeof(jkCredits_aPalette));
    v4 = stdDisplay_FindClosestMode(&a1, Video_renderSurface, stdDisplay_numVideoModes);
    if ( v2 )
        goto LABEL_16;
    if ( !stdDisplay_bModeSet )
        goto LABEL_18;
    if ( v4 != Video_curMode || stdDisplay_bPaged == 1 )
    {
LABEL_16:
        if ( stdDisplay_bModeSet )
            stdDisplay_ClearRect(&Video_otherBuf, 0, 0);
LABEL_18:
        if ( stdDisplay_SetMode(v4, jkCredits_aPalette, 1) )
            goto LABEL_19;
        goto LABEL_36;
    }
LABEL_19:
    stdDisplay_ClearRect(&Video_otherBuf, 0, 0);
    if ( Main_bWindowGUI )
        Window_ShowCursorUnwindowed(0);
    else
        Window_ShowCursorUnwindowed(1);
    Window_AddMsgHandler(jkCredits_Handler);
    v5 = 0;
    v6 = 0;
    v7 = &jkCredits_aPalette[7];
    do
    {
        v7 += 3;
        v8 = (uint64_t)(2510300521 * v6) >> 32;
        v6 += 4;
        *(v7 - 4) = (v8 >> 7 < 0) + (v8 >> 7);
        *(v7 - 3) = 0;
        v9 = (int)((uint64_t)(2510300521 * v5) >> 32) >> 7;
        v5 += 183;
        *(v7 - 2) = (v9 < 0) + v9;
    }
    while ( (intptr_t)v7 < (intptr_t)&jkCredits_aPalette[0x29B] );
    v10 = 0;
    v11 = 0;
    v12 = &jkCredits_aPalette[0x2A0];
    do
    {
        v13 = (uint64_t)(2216757315 * v11) >> 32;
        v11 += 4;
        *(v12) = (v13 >> 4 < 0) + (v13 >> 4);
        *(v12 + 1) = 0;
        v14 = (int)((uint64_t)(2216757315 * v10) >> 32) >> 4;
        v10 += 183;
        *(v12 + 2) = (v14 < 0) + v14;

        v12 += 3;
    }
    while ( (intptr_t)v12 < (intptr_t)&jkCredits_aPalette[0x300] );
    stdDisplay_SetMasterPalette(jkCredits_aPalette);
    v15 = stdDisplay_VBufferNew(&Video_menuBuffer.format, 1, 1, jkCredits_aPalette);
    _memcpy(&v26, &Video_menuBuffer.format, sizeof(v26));
    jkCredits_pVbuffer = v15;
    v26.height = 64;
    jkCredits_pVbuffer2 = stdDisplay_VBufferNew(&v26, 1, 1, jkCredits_aPalette);
    stdDisplay_ClearRect(jkCredits_pVbuffer2, 0, 0);
    v16 = (char *)pHS->alloc(0x2000);
    memset(v16, 0, 0x2000u);
    jkCredits_aIdk = v16;
    v17 = 0;
    v18 = v16 + 0xE0;
    do
    {
        v19 = 0;
        v20 = 0;
        do
        {
            v21 = (uint64_t)(2288265615 * v20) >> 32;
            v20 += v17;
            v18[v19++] = (v21 >> 9 < 0) + (v21 >> 9) + 2;
        }
        while ( v19 < 32 );
        v17 += 220;
        v18 += 256;
    }
    while ( v17 < 0x1B80 );

    // MOTS added: CD tracks
    if (!Main_bMotsCompat)
    {
        // Added: Discern the CD number from the episode.
        whichCdInserted = 0;
        if(jkMain_pEpisodeEnt)
            whichCdInserted = jkMain_pEpisodeEnt->cdNum;
        else if(jkMain_pEpisodeEnt2)
            whichCdInserted = jkMain_pEpisodeEnt2->cdNum;

        // Added: GOG doesn't report CD 2.
        if (stdMci_bIsGOG) {
            whichCdInserted = 2;
        }

        // Added: Simulate disk 1 in menu for jkCredits
        if (jkCredits_cdOverride) {
            whichCdInserted = jkCredits_cdOverride;
            jkCredits_cdOverride = 0;
            jkMain_pEpisodeEnt = NULL;
            jkMain_pEpisodeEnt2 = NULL;
        }

        //whichCdInserted = jkRes_ReadKey() - 1; // Removed: Discern the CD number from the episode.
        if ( whichCdInserted )
        {
            if ( whichCdInserted == 1 )
                stdMci_Play(6u, 7);
            else
                stdMci_Play(2u, 3);
        }
        else
        {
            stdMci_Play(4u, 5);
        }
    }
    else {
        stdMci_Play(6, 9);
    }
    

    jkCredits_startMs = pHS->getTimerTick();
    result = 1;
    jkCredits_dword_55AD68 = 0;
    jkCredits_dword_55AD84 = 0;
    jkCredits_dword_55AD64 = 0;
    jkCredits_strIdx = 0;
    jkCredits_dword_55AD94 = 1;

    // Added
    jkCredits_pVbufferTmp = stdDisplay_VBufferNew(&Video_menuBuffer.format, 1, 1, jkCredits_aPalette);
    return result;
}

int jkCredits_Tick()
{
    signed int v0; // edi
    signed int v1; // eax
    signed int v2; // edx
    int v4; // ecx
    char *v5; // eax
    stdFont *v6; // ebx
    wchar_t *v7; // esi
    uint8_t *v8; // esi
    char *pAIdk; // ecx
    uint8_t *v10; // edx
    int v11; // ebp
    unsigned int v12; // eax
    int v13; // edx
    unsigned int v14; // eax
    int v15; // ebx
    unsigned int v16; // eax
    int v17; // edx
    unsigned int v18; // eax
    int v19; // ebx
    int v21; // [esp+10h] [ebp-40h]
    char *v22; // [esp+14h] [ebp-3Ch]
    char *v23; // [esp+18h] [ebp-38h]
    int v24; // [esp+1Ch] [ebp-34h]
    rdRect v25; // [esp+20h] [ebp-30h] BYREF
    rdRect a4; // [esp+30h] [ebp-20h] BYREF
    rdRect v27; // [esp+40h] [ebp-10h] BYREF

    if (!jkCredits_dword_55AD94 || !g_app_suspended)
        return jkCredits_dword_55ADA8;

    //pHS->some_float = 60.0;

    v0 = -jkCredits_dword_55AD68 - (int64_t)((double)(pHS->getTimerTick() - jkCredits_startMs) * (1.0 / pHS->some_float) * -40.0);
    jkCredits_dword_55AD68 += v0;
    if ( v0 )
    {
        a4.x = 0;
        a4.width = 640;
        a4.y = v0;
        a4.height = 480 - v0;
#ifdef SDL2_RENDER
        stdDisplay_VBufferLock(jkCredits_pVbufferTmp);
        stdDisplay_VBufferFill(jkCredits_pVbufferTmp, 0, NULL);
        stdDisplay_VBufferCopy(jkCredits_pVbufferTmp, &Video_menuBuffer, 0, 0, NULL, 0);
        stdDisplay_VBufferUnlock(jkCredits_pVbufferTmp);

        stdDisplay_VBufferLock(&Video_menuBuffer);
        
        stdDisplay_VBufferCopy(&Video_menuBuffer, jkCredits_pVbufferTmp, 0, 0, &a4, 0);
        stdDisplay_VBufferUnlock(&Video_menuBuffer);
#else
        stdDisplay_VBufferCopy(&Video_menuBuffer, &Video_otherBuf, 0, 0, &a4, 0);
#endif
        v25.width = 640;
        v25.x = 0;
        if ( v0 < 32 )
        {
            v25.y = v0;
            v25.height = 32 - v0;
            stdDisplay_VBufferCopy(&Video_menuBuffer, jkCredits_pVbuffer2, 0, 0, &v25, 0);
        }
        if ( v0 < 448 )
        {
            v25.y = 32;
            v25.height = 32;
            stdDisplay_VBufferCopy(&Video_menuBuffer, jkCredits_pVbuffer2, 0, 448 - v0, &v25, 0);
        }
        v1 = jkCredits_dword_55AD84;
        v2 = jkCredits_dword_55AD64;
        do
        {
            if ( v1 )
            {
                a4.y = v2;
                a4.height = v0;
                if ( v0 >= v1 )
                    a4.height = v1;
                stdDisplay_VBufferCopy(&Video_menuBuffer, jkCredits_pVbuffer, 0, 480 - v0, &a4, 0);
                v1 = jkCredits_dword_55AD84 - a4.height;
                v0 -= a4.height;
                v2 = a4.height + jkCredits_dword_55AD64;
                int v3 = jkCredits_dword_55AD84 == a4.height;
                jkCredits_dword_55AD84 -= a4.height;
                jkCredits_dword_55AD64 += a4.height;
                if ( !v3 )
                    continue;
            }
            a4.y = 0;
            a4.height = v2;
            if ( !v2 )
                a4.height = 480;
            stdDisplay_ClearRect(jkCredits_pVbuffer, 0, &a4);
            v4 = jkCredits_strIdx;
            if ( jkCredits_strIdx >= jkCredits_table.numMsgs )
            {
                v1 = 480;
                jkCredits_dword_55AD84 = 480;
                if ( jkCredits_strIdx != jkCredits_table.numMsgs )
                    jkCredits_dword_55ADA8 = 1;
            }
            else
            {
                v5 = _strstr(jkCredits_table.msgs[jkCredits_strIdx].key, "big");
                v6 = jkCredits_fontLarge;
                if ( !v5 )
                    v6 = jkCredits_fontSmall;
                a4.y = 0;
                a4.height = 480;
                v7 = jkCredits_table.msgs[jkCredits_strIdx].uniStr;
                if ( !v7 )
                    v7 = L" ";
#ifdef SDL2_RENDER
                stdDisplay_VBufferLock(jkCredits_pVbuffer);
#endif
                stdFont_Draw3(jkCredits_pVbuffer, v6, 0, &a4, 1, v7, 0);
#ifdef SDL2_RENDER
                stdDisplay_VBufferUnlock(jkCredits_pVbuffer2);
#endif
                v1 = stdFont_sub_4357C0(v6, v7, &a4);
                v4 = jkCredits_strIdx;
                jkCredits_dword_55AD84 = v1;
            }
            v2 = 0;
            jkCredits_dword_55AD64 = 0;
            jkCredits_strIdx = v4 + 1;
        }
        while ( v0 );
        stdDisplay_VBufferUnlock(&Video_menuBuffer);
        v27.x = 0;
        v27.width = 640;
        v27.y = 0;
        v27.height = 32;
#ifdef SDL2_RENDER
        stdDisplay_VBufferLock(jkCredits_pVbuffer2);
#endif
        stdDisplay_VBufferCopy(jkCredits_pVbuffer2, &Video_menuBuffer, 0, 0, &v27, 0);
        v27.y = 448;
        stdDisplay_VBufferCopy(jkCredits_pVbuffer2, &Video_menuBuffer, 0, 32, &v27, 0);
#ifdef SDL2_RENDER
        stdDisplay_VBufferUnlock(jkCredits_pVbuffer2);
#endif

        if ( stdDisplay_VBufferLock(&Video_menuBuffer) )
        {
            v8 = Video_menuBuffer.surface_lock_alloc;
            pAIdk = jkCredits_aIdk;
            v25.x = -Video_menuBuffer.format.width_in_bytes;
            v23 = Video_menuBuffer.surface_lock_alloc;
            v24 = 32;
            v10 = &Video_menuBuffer.surface_lock_alloc[479 * Video_menuBuffer.format.width_in_bytes];
            v22 = v10;
            do
            {
                v21 = 160;
                v11 = v10 - v8;
                do
                {
                    v12 = *(uint32_t *)v8;
                    if ( v12 )
                    {
                        v13 = (uint8_t)v12;
                        v14 = v12 >> 8;
                        v15 = (uint8_t)pAIdk[v13];
                        v13 = (v13 & 0xFFFFFF00) | 0;
                        v13 = (v13 & 0xFFFF00FF) | (pAIdk[(uint8_t)v14] << 8);
                        *(uint32_t*)v8 = ((uint8_t)pAIdk[(v14 >> 8) & 0xFF] << 16) | (uint16_t)v13 | v15 | ((uint8_t)pAIdk[(v14 >> 16) & 0xFF] << 24);
                    }
                    v16 = *(uint32_t *)&v8[v11];
                    if ( v16 )
                    {
                        v17 = (uint8_t)v16;
                        v18 = v16 >> 8;
                        v19 = (uint8_t)pAIdk[v17];
                        v17 = (v17 & 0xFFFFFF00) | 0;
                        v17 = (v17 & 0xFFFF00FF) | (pAIdk[(uint8_t)v18] << 8);
                        *(uint32_t *)&v8[v11] = ((uint8_t)pAIdk[(v18 >> 8) & 0xFF] << 16) | (uint16_t)v17 | v19 | ((uint8_t)pAIdk[(v18 >> 16) & 0xFF] << 24);
                    }
                    v8 += 4;
                    --v21;
                }
                while ( v21 );
                pAIdk += 256;
                v10 = &v22[v25.x];
                v8 = &v23[Video_menuBuffer.format.width_in_bytes];
                v22 += v25.x;
                v23 += Video_menuBuffer.format.width_in_bytes;
                --v24;
            }
            while (v24 != 1);
            stdDisplay_VBufferUnlock(&Video_menuBuffer);
        }
        stdDisplay_DDrawGdiSurfaceFlip();
    }
    return jkCredits_dword_55ADA8;
}

int jkCredits_Skip()
{
    if ( !jkCredits_dword_55AD94 )
        return 0;
    Window_RemoveMsgHandler(jkCredits_Handler);
    jkCredits_dword_55AD94 = 0;
    jk_ShowCursor(1);
    if ( jkCredits_pVbuffer )
        stdDisplay_VBufferFree(jkCredits_pVbuffer);
    jkCredits_pVbuffer = 0;
    if ( jkCredits_pVbuffer2 )
        pHS->free(jkCredits_pVbuffer2);
    jkCredits_pVbuffer2 = 0;
    if ( jkCredits_aIdk )
        pHS->free(jkCredits_aIdk);
    jkCredits_aIdk = 0;

    // Added
    if (jkCredits_pVbufferTmp)
        stdDisplay_VBufferFree(jkCredits_pVbufferTmp);

    stdMci_Stop();
    return 1;
}

int jkCredits_Handler(HWND a1, UINT a2, WPARAM a3, HWND a4, LRESULT *a5)
{
    signed int result; // eax

    result = 0;
    switch ( a2 )
    {
        case 0x10u:
            jkCredits_dword_55ADA8 = 1;
            break;
        case 0x20u:
            jk_SetCursor(0);
            result = 1;
            break;
        case 0x102u:
            if ( a3 == 27 )
            {
                result = 1;
                jkCredits_dword_55ADA8 = 1;
            }
            else if ( a3 == 32 )
            {
                jkCredits_dword_55ADA0 = jkCredits_dword_55ADA0 == 0;
            }
            break;
    }
    return result;
}