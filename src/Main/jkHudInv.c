#include "jkHudInv.h"

#include "Win95/Windows.h"
#include "Win95/stdDisplay.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdString.h"
#include "Devices/sithControl.h"
#include "stdPlatform.h"
#include "Cog/sithCog.h"
#include "Gameplay/sithInventory.h"
#include "Main/Main.h"
#include "Platform/std3D.h"
#include "World/jkPlayer.h"
#include "jk.h"

void jkHudInv_DrawGPU();

// MOTS added
flex_t jkHud_aBinMaxAmt[SITHBIN_NUMBINS] = {0};

// MOTS altered
int jkHudInv_ItemDatLoad(char *fpath)
{
    unsigned int binNum; // esi
    unsigned int v3; // ebp
    sithCog *cog_; // eax
    sithCog *cog; // [esp+10h] [ebp-10h]
    flex_t max; // [esp+18h] [ebp-8h]
    flex_t min; // [esp+1Ch] [ebp-4h]
    int flags;

    if (!stdConffile_OpenRead(fpath))
        return 0;

    while ( stdConffile_ReadArgs() )
    {
        flags = 0;
        cog = 0;
        if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
            break;
        if ( stdConffile_entry.numArgs < 4u || (binNum = _atoi(stdConffile_entry.args[1].value), binNum >= 0xC8) )
        {
            stdConffile_Close();
            return 0;
        }
        min = _atof(stdConffile_entry.args[2].value);
        max = _atof(stdConffile_entry.args[3].value);
        _sscanf(stdConffile_entry.args[4].value, "%x", &flags);

        for (v3 = 5; v3 < stdConffile_entry.numArgs; v3++)
        {
            if ( !_strcmp(stdConffile_entry.args[v3].key, "cog") )
            {
                cog_ = sithCog_LoadCogscript(stdConffile_entry.args[v3].value);
                if ( cog_ )
                    cog_->flags |= SITH_COG_LOCAL;
                cog = cog_;
            }
        }
        sithInventory_NewEntry(binNum, cog, stdConffile_entry.args[0].value, min, max, flags);
        jkHud_aBinMaxAmt[binNum] = max; // MOTS added
    }
    stdConffile_Close();
    return 1;
}

void jkHudInv_ClearRects()
{
    int v0; // esi
    signed int v1; // edi
    rdRect a4; // [esp+8h] [ebp-10h] BYREF

    if ( jkHudInv_scroll.field_C && Video_pCanvas->widthMinusOne < (signed int)(jkHudInv_scroll.blitX + 24) )
    {
        v0 = jkHudInv_scroll.field_10;
        a4.x = jkHudInv_scroll.blitX;
        a4.y = 0;
        a4.width = 24;
        a4.height = 24;
        if ( jkHudInv_scroll.field_10 <= jkHudInv_scroll.rendIdx )
        {
            v1 = 28 * jkHudInv_scroll.field_10 + 8;
            do
            {
                a4.y = v1;
                stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, &a4);
                ++v0;
                v1 += 28;
            }
            while ( v0 <= jkHudInv_scroll.rendIdx );
        }
        if ( !--jkHudInv_scroll.field_C )
        {
            jkHudInv_scroll.field_10 = 0;
            jkHudInv_scroll.rendIdx = 0;
        }
    }
    if ( jkHudInv_info.field_28 )
    {
        if ( Video_pCanvas->heightMinusOne < jkHudInv_info.field_3C )
        {
            stdDisplay_VBufferFill(Video_pMenuBuffer, Video_fillColor, &jkHudInv_info.drawRect);
            --jkHudInv_info.field_28;
        }
    }
}

void jkHudInv_Draw()
{
    sithThing *player; // ebx MAPDST
    int v1; // edi
    int v2; // ebp
    int i; // esi
    stdBitmap *v4; // eax
    int j; // ebp
    sithItemDescriptor *v6; // ebx
    stdBitmap *v7; // eax
    int curItem; // edi
    int curPower; // ebp
    unsigned int time_msec; // esi
    int v11; // ecx
    int v12; // eax
    int v13; // edx
    stdBitmap *v14; // edi
    unsigned int v15; // ebp
    sithItemDescriptor *v16; // ebx
    stdBitmap *v17; // edi
    int v18; // esi
    int v19; // edi
    unsigned int v20; // ebx
    int v22; // eax
    signed int v23; // eax
    int v24; // ebp
    sithItemDescriptor *v25; // ebx
    stdBitmap *v26; // esi
    int v27; // edi
    int v28; // ebx
    unsigned int v29; // esi
    int v31; // eax
    sithItemDescriptor *v32; // ebx
    stdBitmap *v33; // edi
    int v34; // esi
    int v35; // ebp
    int v36; // edi
    unsigned int v38; // ebp
    int v39; // eax
    int a2; // [esp+14h] [ebp-2Ch]
    int idx; // [esp+18h] [ebp-28h]
    int v43; // [esp+1Ch] [ebp-24h] BYREF
    char v44[4]; // [esp+20h] [ebp-20h] BYREF
    wchar_t a6[3]; // [esp+28h] [ebp-18h] BYREF
    wchar_t v48[3]; // [esp+30h] [ebp-10h] BYREF
    wchar_t v50[3]; // [esp+38h] [ebp-8h] BYREF

#ifdef SDL2_RENDER
    jkHudInv_DrawGPU();
    return;
#endif

    player = sithWorld_pCurrentWorld->playerThing;
    if ( player->type != SITH_THING_PLAYER ) {
        return;
    }

    v1 = 0;
    v2 = 0;
    for ( i = 8; v2 < jkHudInv_numItems; ++v2 )
    {
        if ( v1 >= jkHudInv_scroll.scroll )
            break;
        if ( sithInventory_GetActivate(player, jkHudInv_aItems[v2]) )
        {
            v4 = sithInventory_GetItemDesc(player, jkHudInv_aItems[v2])->hudBitmap;
            if ( v4 )
            {
                stdDisplay_VBufferCopy(Video_pMenuBuffer, *v4->mipSurfaces, jkHudInv_scroll.blitX, i, 0, 1);
                i += 28;
                ++v1;
            }
        }
    }

    for ( j = 0; j < SITHBIN_NUMBINS; ++j )
    {
        if ( v1 >= jkHudInv_scroll.scroll )
            break;
        v6 = sithInventory_GetBinByIdx(j);
        if (v6->flags & ITEMINFO_ITEM)
        {
            if ( sithInventory_GetActivate(player, j) )
            {
                v7 = v6->hudBitmap;
                if ( v7 )
                {
                    stdDisplay_VBufferCopy(Video_pMenuBuffer, *v7->mipSurfaces, jkHudInv_scroll.blitX, i, 0, 1);
                    i += 28;
                    ++v1;
                }
            }
        }
    }

    if ( v1 < jkHudInv_scroll.maxItemRend )
    {
        jkHudInv_scroll.field_C = 2;
        jkHudInv_scroll.field_10 = v1;
        if ( jkHudInv_scroll.rendIdx <= jkHudInv_scroll.maxItemRend - 1 )
            jkHudInv_scroll.rendIdx = jkHudInv_scroll.maxItemRend - 1;
    }
    jkHudInv_scroll.maxItemRend = v1;
    curItem = sithInventory_GetCurItem(player);
    curPower = sithInventory_GetCurPower(player);
    time_msec = stdPlatform_GetTimeMsec();
    v11 = 0;
    if ( sithInventory_bRendIsHidden )
    {
        sithInventory_bRendIsHidden = 0;
        jkHudInv_info.rend_timeout_5secs = time_msec + 5000;
        jkHudInv_rend_isshowing_maybe = 1;
        jkHudInv_dword_553F94 = 0;
    }
    else if ( sithInventory_8339F4 )
    {
        sithInventory_8339F4 = 0;
        jkHudInv_info.rend_timeout_5secs = time_msec + 5000;
        jkHudInv_dword_553F94 = 1;
        jkHudInv_rend_isshowing_maybe = 0;
    }
    if ( time_msec > jkHudInv_info.rend_timeout_5secs || sithInventory_8339EC == 1 )
    {
        if ( jkHudInv_info.field_24 )
        {
            jkHudInv_info.field_28 = 2;
            jkHudInv_info.field_24 = 0;
        }
        jkHudInv_rend_isshowing_maybe = 0;
        jkHudInv_dword_553F94 = 0;
    }
    else
    {
        jkHudInv_info.field_24 = 1;
        if ( jkHudInv_rend_isshowing_maybe && curItem )
        {
            v12 = 2;
        }
        else
        {
            if ( !jkHudInv_dword_553F94 || !curPower )
                return;
            v12 = 8;
        }
        jkHudInv_flags = v12;
        if ( v12 == jkHudInv_dword_553F64 )
        {
            v13 = jkHudInv_info.field_18;
        }
        else
        {
            v13 = 0;
            jkHudInv_info.field_1C = time_msec + 100;
            jkHudInv_dword_553F64 = v12;
            jkHudInv_info.field_28 = 2;
            jkHudInv_info.field_18 = 0;
            v11 = 0;
        }
        if ( v12 == 8 )
        {
            a2 = curPower;
            v11 = 1;
        }
        else
        {
            a2 = curItem;
        }
        v14 = jkHudInv_aBitmaps[v11];
        if ( v14 )
        {
            v15 = v14->numMips;
            if ( v15 > 1 && time_msec > jkHudInv_info.field_1C )
            {
                v13 = (v13 + 1) % v15;
                jkHudInv_info.field_1C = time_msec + 100;
                jkHudInv_info.field_18 = v13;
            }
            stdDisplay_VBufferCopy(Video_pMenuBuffer, v14->mipSurfaces[v13], jkHudInv_info.field_8[v11], jkHudInv_info.field_10[v11], 0, 1);
        }
        v16 = sithInventory_GetItemDesc(player, a2);
        v17 = v16->hudBitmap;
        if ( v17 || (v17 = jkHudInv_aBitmaps[2]) != 0 )
        {
            v18 = (__int64)sithInventory_GetBinAmount(player, a2);
            if ( v18 <= 0 )
            {
                jkHudInv_rend_isshowing_maybe = 0;
                jkHudInv_dword_553F94 = 0;
                return;
            }
            stdDisplay_VBufferCopy(Video_pMenuBuffer, *v17->mipSurfaces, jkHudInv_info.field_0, jkHudInv_info.field_4, 0, 1);
            if (v16->flags & ITEMINFO_ITEM)
            {
                char tmpChars[4];
                v19 = jkHudInv_info.field_4;
                v20 = jkHudInv_info.field_0;
                stdString_snprintf(tmpChars, 4, "%d", v18);
                stdString_CharToWchar(a6, tmpChars, 3);
                v22 = 99;
                if ( v18 <= 99 )
                    v22 = v18;
                if ( v22 <= 9 )
                {
                    if ( v22 > 1 )
                        stdFont_Draw1(Video_pMenuBuffer, jkHudInv_font, v20 + 18, v19 + 2, 640, a6, 1);
                }
                else
                {
                    stdFont_Draw1(Video_pMenuBuffer, jkHudInv_font, v20 + 14, v19 + 2, 640, a6, 1);
                }
            }
        }
        v23 = a2;
        v24 = 32;
        idx = a2;
        v43 = 32;
        while ( 1 )
        {
            if ( v23 >= 0 )
                idx = sithInventory_GetNumBinsWithFlagRev(player, v23, jkHudInv_flags);
            if ( idx == a2 )
                break;
            if ( idx >= 0 )
            {
                v25 = sithInventory_GetItemDesc(player, idx);
                v26 = v25->hudBitmap;
                if ( v26 || (v26 = jkHudInv_aBitmaps[2]) != 0 )
                {
                    v27 = (__int64)sithInventory_GetBinAmount(player, idx);
                    if ( v27 <= 0 )
                        goto LABEL_84;
                    stdDisplay_VBufferCopy(Video_pMenuBuffer, *v26->mipSurfaces, jkHudInv_info.field_0 - v24, jkHudInv_info.field_4, 0, 1);
                    if (v25->flags & ITEMINFO_ITEM)
                    {
                        v28 = jkHudInv_info.field_4;
                        v29 = jkHudInv_info.field_0 - v24;
                        stdString_snprintf(v44, 4, "%d", v27);
                        stdString_CharToWchar(v48, v44, 3);
                        v31 = 99;
                        if ( v27 <= 99 )
                            v31 = v27;
                        if ( v31 <= 9 )
                        {
                            if ( v31 > 1 )
                                stdFont_Draw1(Video_pMenuBuffer, jkHudInv_font, v29 + 18, v28 + 2, 640, v48, 1);
                        }
                        else
                        {
                            stdFont_Draw1(Video_pMenuBuffer, jkHudInv_font, v29 + 14, v28 + 2, 640, v48, 1);
                        }
                    }
                }
            }
            if ( a2 >= 0 )
                a2 = sithInventory_GetNumBinsWithFlag(player, a2, jkHudInv_flags);
            if ( idx == a2 )
                return;
            if ( a2 >= 0 )
            {
                v32 = sithInventory_GetItemDesc(player, a2);
                v33 = v32->hudBitmap;
                if ( v33 || (v33 = jkHudInv_aBitmaps[2]) != 0 )
                {
                    v34 = (__int64)sithInventory_GetBinAmount(player, a2);
                    if ( v34 <= 0 )
                    {
LABEL_84:
                        jkHudInv_rend_isshowing_maybe = 0;
                        jkHudInv_dword_553F94 = 0;
                        return;
                    }
                    v35 = v43;
                    stdDisplay_VBufferCopy(Video_pMenuBuffer, *v33->mipSurfaces, v43 + jkHudInv_info.field_0, jkHudInv_info.field_4, 0, 1);
                    if (v32->flags & ITEMINFO_ITEM)
                    {
                        char tmpChars[4];
                        v36 = jkHudInv_info.field_4;
                        v38 = jkHudInv_info.field_0 + v35;
                        stdString_snprintf(tmpChars, 4, "%d", v34);
                        stdString_CharToWchar(v50, tmpChars, 3);
                        v39 = 99;
                        if ( v34 <= 99 )
                            v39 = v34;
                        if ( v39 <= 9 )
                        {
                            if ( v39 > 1 )
                                stdFont_Draw1(Video_pMenuBuffer, jkHudInv_font, v38 + 18, v36 + 2, 640, v50, 1);
                        }
                        else
                        {
                            stdFont_Draw1(Video_pMenuBuffer, jkHudInv_font, v38 + 14, v36 + 2, 640, v50, 1);
                        }
                    }
                }
            }
            v24 = v43 + 32;
            v43 += 32;
            if ( v43 >= 96 )
                return;
            v23 = idx;
        }
    }
}

void jkHudInv_DrawGPU()
{
    sithThing *player; // ebx MAPDST
    int v1; // edi
    int v2; // ebp
    int i; // esi
    stdBitmap *v4; // eax
    int j; // ebp
    sithItemDescriptor *v6; // ebx
    stdBitmap *v7; // eax
    int curItem; // edi
    int curPower; // ebp
    unsigned int time_msec; // esi
    int v11; // ecx
    int v12; // eax
    int v13; // edx
    stdBitmap *v14; // edi
    unsigned int v15; // ebp
    sithItemDescriptor *v16; // ebx
    stdBitmap *v17; // edi
    int v18; // esi
    int v19; // edi
    unsigned int v20; // ebx
    int v22; // eax
    signed int v23; // eax
    int v24; // ebp
    sithItemDescriptor *v25; // ebx
    stdBitmap *v26; // esi
    int v27; // edi
    int v28; // ebx
    unsigned int v29; // esi
    int v31; // eax
    sithItemDescriptor *v32; // ebx
    stdBitmap *v33; // edi
    int v34; // esi
    int v35; // ebp
    int v36; // edi
    unsigned int v38; // ebp
    int v39; // eax
    int a2; // [esp+14h] [ebp-2Ch]
    int idx; // [esp+18h] [ebp-28h]
    int v43; // [esp+1Ch] [ebp-24h] BYREF
    char v44[4]; // [esp+20h] [ebp-20h] BYREF
    wchar_t a6[3]; // [esp+28h] [ebp-18h] BYREF
    wchar_t v48[3]; // [esp+30h] [ebp-10h] BYREF
    wchar_t v50[3]; // [esp+38h] [ebp-8h] BYREF

    player = sithWorld_pCurrentWorld->playerThing;
    if ( player->type != SITH_THING_PLAYER ) {
        return;
    }

    v1 = 0;
    v2 = 0;
    for ( i = 8; v2 < jkHudInv_numItems; ++v2 )
    {
        if ( v1 >= jkHudInv_scroll.scroll )
            break;
        if ( sithInventory_GetActivate(player, jkHudInv_aItems[v2]) )
        {
            v4 = sithInventory_GetItemDesc(player, jkHudInv_aItems[v2])->hudBitmap;
            if ( v4 )
            {
                std3D_DrawUIBitmap(v4, 0, jkHudInv_scroll.blitX, i, NULL, jkPlayer_hudScale, 1);
                //stdDisplay_VBufferCopy(Video_pMenuBuffer, *v4->mipSurfaces, jkHudInv_scroll.blitX, i, 0, 1);
                i += HUD_SCALED(28);
                ++v1;
            }
        }
    }

    for ( j = 0; j < SITHBIN_NUMBINS; ++j )
    {
        if ( v1 >= jkHudInv_scroll.scroll )
            break;
        v6 = sithInventory_GetBinByIdx(j);
        if (v6->flags & ITEMINFO_ITEM)
        {
            if ( sithInventory_GetActivate(player, j) )
            {
                v7 = v6->hudBitmap;
                if ( v7 )
                {
                    std3D_DrawUIBitmap(v7, 0, jkHudInv_scroll.blitX, i, NULL, jkPlayer_hudScale, 1);
                    //stdDisplay_VBufferCopy(Video_pMenuBuffer, *v7->mipSurfaces, jkHudInv_scroll.blitX, i, 0, 1);
                    i += HUD_SCALED(28);
                    ++v1;
                }
            }
        }
    }

    if ( v1 < jkHudInv_scroll.maxItemRend )
    {
        jkHudInv_scroll.field_C = 2;
        jkHudInv_scroll.field_10 = v1;
        if ( jkHudInv_scroll.rendIdx <= jkHudInv_scroll.maxItemRend - 1 )
            jkHudInv_scroll.rendIdx = jkHudInv_scroll.maxItemRend - 1;
    }
    jkHudInv_scroll.maxItemRend = v1;
    curItem = sithInventory_GetCurItem(player);
    curPower = sithInventory_GetCurPower(player);
    time_msec = stdPlatform_GetTimeMsec();
    v11 = 0;
    if ( sithInventory_bRendIsHidden )
    {
        sithInventory_bRendIsHidden = 0;
        jkHudInv_info.rend_timeout_5secs = time_msec + 5000;
        jkHudInv_rend_isshowing_maybe = 1;
        jkHudInv_dword_553F94 = 0;
    }
    else if ( sithInventory_8339F4 )
    {
        sithInventory_8339F4 = 0;
        jkHudInv_info.rend_timeout_5secs = time_msec + 5000;
        jkHudInv_dword_553F94 = 1;
        jkHudInv_rend_isshowing_maybe = 0;
    }
    if ( time_msec > jkHudInv_info.rend_timeout_5secs || sithInventory_8339EC == 1 )
    {
        if ( jkHudInv_info.field_24 )
        {
            jkHudInv_info.field_28 = 2;
            jkHudInv_info.field_24 = 0;
        }
        jkHudInv_rend_isshowing_maybe = 0;
        jkHudInv_dword_553F94 = 0;
    }
    else
    {
        jkHudInv_info.field_24 = 1;
        if ( jkHudInv_rend_isshowing_maybe && curItem )
        {
            v12 = 2;
        }
        else
        {
            if ( !jkHudInv_dword_553F94 || !curPower )
                return;
            v12 = 8;
        }
        jkHudInv_flags = v12;
        if ( v12 == jkHudInv_dword_553F64 )
        {
            v13 = jkHudInv_info.field_18;
        }
        else
        {
            v13 = 0;
            jkHudInv_info.field_1C = time_msec + 100;
            jkHudInv_dword_553F64 = v12;
            jkHudInv_info.field_28 = 2;
            jkHudInv_info.field_18 = 0;
            v11 = 0;
        }
        if ( v12 == 8 )
        {
            a2 = curPower;
            v11 = 1;
        }
        else
        {
            a2 = curItem;
        }
        v14 = jkHudInv_aBitmaps[v11];
        if ( v14 )
        {
            v15 = v14->numMips;
            if ( v15 > 1 && time_msec > jkHudInv_info.field_1C )
            {
                v13 = (v13 + 1) % v15;
                jkHudInv_info.field_1C = time_msec + 100;
                jkHudInv_info.field_18 = v13;
            }
            //stdDisplay_VBufferCopy(Video_pMenuBuffer, v14->mipSurfaces[v13], jkHudInv_info.field_8[v11], jkHudInv_info.field_10[v11], 0, 1);
            std3D_DrawUIBitmap(v14, v13, jkHudInv_info.field_8[v11], jkHudInv_info.field_10[v11], NULL, jkPlayer_hudScale, 1);
        }
        v16 = sithInventory_GetItemDesc(player, a2);
        v17 = v16->hudBitmap;
        if ( v17 || (v17 = jkHudInv_aBitmaps[2]) != 0 )
        {
            v18 = (__int64)sithInventory_GetBinAmount(player, a2);
            if ( v18 <= 0 )
            {
                jkHudInv_rend_isshowing_maybe = 0;
                jkHudInv_dword_553F94 = 0;
                return;
            }
            //stdDisplay_VBufferCopy(Video_pMenuBuffer, *v17->mipSurfaces, jkHudInv_info.field_0, jkHudInv_info.field_4, 0, 1);
            std3D_DrawUIBitmap(v17, 0, jkHudInv_info.field_0, jkHudInv_info.field_4, NULL, jkPlayer_hudScale, 1);
            if (v16->flags & ITEMINFO_ITEM)
            {
                char tmpChars[4];
                v19 = jkHudInv_info.field_4;
                v20 = jkHudInv_info.field_0;
                stdString_snprintf(tmpChars, 4, "%d", v18);
                stdString_CharToWchar(a6, tmpChars, 3);

                int width = stdFont_Draw1Width(jkHudInv_font, 0, 0, 640, a6, 1, jkPlayer_hudScale);

                // Added: allow displaying all numbers.
                if ( v18 > 1 )
                    stdFont_Draw1GPU(jkHudInv_font, v20 + HUD_SCALED(v17->mipSurfaces[0]->format.width) - width - HUD_SCALED(2), v19 + HUD_SCALED(2), 640, a6, 1, jkPlayer_hudScale);
#if 0
                v22 = 99;
                if ( v18 <= 99 )
                    v22 = v18;
                if ( v22 <= 9 )
                {
                    if ( v22 > 1 )
                        stdFont_Draw1GPU(jkHudInv_font, v20 + HUD_SCALED(18), v19 + 2, 640, a6, 1, jkPlayer_hudScale);
                }
                else
                {
                    stdFont_Draw1GPU(jkHudInv_font, v20 + HUD_SCALED(14), v19 + 2, 640, a6, 1, jkPlayer_hudScale);
                }
#endif
            }
        }
        v23 = a2;
        v24 = HUD_SCALED(32);
        idx = a2;
        v43 = HUD_SCALED(32);
        while ( 1 )
        {
            if ( v23 >= 0 )
                idx = sithInventory_GetNumBinsWithFlagRev(player, v23, jkHudInv_flags);
            if ( idx == a2 )
                break;
            if ( idx >= 0 )
            {
                v25 = sithInventory_GetItemDesc(player, idx);
                v26 = v25->hudBitmap;
                if ( v26 || (v26 = jkHudInv_aBitmaps[2]) != 0 )
                {
                    v27 = (__int64)sithInventory_GetBinAmount(player, idx);
                    if ( v27 <= 0 )
                        goto LABEL_84;
                    //stdDisplay_VBufferCopy(Video_pMenuBuffer, *v26->mipSurfaces, jkHudInv_info.field_0 - v24, jkHudInv_info.field_4, 0, 1);
                    std3D_DrawUIBitmap(v26, 0, jkHudInv_info.field_0 - v24, jkHudInv_info.field_4, NULL, jkPlayer_hudScale, 1);
                    if (v25->flags & ITEMINFO_ITEM)
                    {
                        v28 = jkHudInv_info.field_4;
                        v29 = jkHudInv_info.field_0 - v24;
                        stdString_snprintf(v44, 4, "%d", v27);
                        stdString_CharToWchar(v48, v44, 3);

                        int width = stdFont_Draw1Width(jkHudInv_font, 0, 0, 640, v48, 1, jkPlayer_hudScale);

                        // Added: allow displaying all numbers.
                        if ( v27 > 1 )
                            stdFont_Draw1GPU(jkHudInv_font, v29 + HUD_SCALED(v26->mipSurfaces[0]->format.width) - width - HUD_SCALED(2), v28 + HUD_SCALED(2), 640, v48, 1, jkPlayer_hudScale);

#if 0
                        v31 = 99;
                        if ( v27 <= 99 )
                            v31 = v27;
                        if ( v31 <= 9 )
                        {
                            if ( v31 > 1 )
                                stdFont_Draw1GPU(jkHudInv_font, v29 + 18, v28 + 2, 640, v48, 1, jkPlayer_hudScale);
                        }
                        else
                        {
                            stdFont_Draw1GPU(jkHudInv_font, v29 + 14, v28 + 2, 640, v48, 1, jkPlayer_hudScale);
                        }
#endif
                    }
                }
            }
            if ( a2 >= 0 )
                a2 = sithInventory_GetNumBinsWithFlag(player, a2, jkHudInv_flags);
            if ( idx == a2 )
                return;
            if ( a2 >= 0 )
            {
                v32 = sithInventory_GetItemDesc(player, a2);
                v33 = v32->hudBitmap;
                if ( v33 || (v33 = jkHudInv_aBitmaps[2]) != 0 )
                {
                    v34 = (__int64)sithInventory_GetBinAmount(player, a2);
                    if ( v34 <= 0 )
                    {
LABEL_84:
                        jkHudInv_rend_isshowing_maybe = 0;
                        jkHudInv_dword_553F94 = 0;
                        return;
                    }
                    v35 = v43;
                    //stdDisplay_VBufferCopy(Video_pMenuBuffer, *v33->mipSurfaces, v43 + jkHudInv_info.field_0, jkHudInv_info.field_4, 0, 1);
                    std3D_DrawUIBitmap(v33, 0, v43 + jkHudInv_info.field_0, jkHudInv_info.field_4, NULL, jkPlayer_hudScale, 1);
                    
                    if (v32->flags & ITEMINFO_ITEM)
                    {
                        char tmpChars[4];
                        v36 = jkHudInv_info.field_4;
                        v38 = jkHudInv_info.field_0 + v35;
                        stdString_snprintf(tmpChars, 4, "%d", v34);
                        stdString_CharToWchar(v50, tmpChars, 3);

                        int width = stdFont_Draw1Width(jkHudInv_font, 0, 0, 640, v50, 1, jkPlayer_hudScale);

                        // Added: allow displaying all numbers.
                        if ( v34 > 1 )
                            stdFont_Draw1GPU(jkHudInv_font, v38 + HUD_SCALED(v33->mipSurfaces[0]->format.width) - width - HUD_SCALED(2), v36 + HUD_SCALED(2), 640, v50, 1, jkPlayer_hudScale);


#if 0
                        v39 = 99;
                        if ( v34 <= 99 )
                            v39 = v34;
                        if ( v39 <= 9 )
                        {
                            if ( v39 > 1 )
                                stdFont_Draw1GPU(jkHudInv_font, v38 + 18, v36 + 2, 640, v50, 1, jkPlayer_hudScale);
                        }
                        else
                        {
                            stdFont_Draw1GPU(jkHudInv_font, v38 + 14, v36 + 2, 640, v50, 1, jkPlayer_hudScale);
                        }
#endif
                    }
                }
            }
            v24 = v43 + HUD_SCALED(32);
            v43 += HUD_SCALED(32);
            if ( v43 >= HUD_SCALED(96) )
                return;
            v23 = idx;
        }
    }
}

void jkHudInv_InputInit()
{
    // TODO: what is the second param, DIK?
    sithControl_MapFunc(INPUT_FUNC_CAMERAMODE, DIK_F1, 0);
    sithControl_MapFunc(INPUT_FUNC_ACTIVATE16, DIK_F2, 0);
    sithControl_MapFunc(INPUT_FUNC_ACTIVATE15, DIK_F3, 0);
    sithControl_MapFunc(INPUT_FUNC_ACTIVATE14, DIK_F4, 0);
    sithControl_MapFunc(INPUT_FUNC_ACTIVATE0, DIK_F5, 0);
    sithControl_MapFunc(INPUT_FUNC_ACTIVATE1, DIK_F6, 0);
    sithControl_MapFunc(INPUT_FUNC_ACTIVATE2, DIK_F7, 0);
    sithControl_MapFunc(INPUT_FUNC_ACTIVATE3, DIK_F8, 0);
}

int jkHudInv_InitItems()
{
    int v1; // ecx
    sithItemDescriptor *v2; // eax
    int *v3; // edx
    int v4; // ecx
    sithItemDescriptor *v5; // eax

    _sprintf(std_genBuffer, "misc\\%s", "items.dat");
    if (!jkHudInv_ItemDatLoad(std_genBuffer))
        return 0;

    sithInventory_KeybindInit();
    v1 = 0;
    v2 = sithInventory_aDescriptors;
    jkHudInv_numItems = 0;
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        if ( (v2->flags & ITEMINFO_POWER) != 0 )
            ++v1;
        ++v2;
    }

    jkHudInv_numItems = v1;
    if ( v1 > 0 )
    {
        jkHudInv_aItems = (int*)pHS->alloc(sizeof(int) * v1);
        if (!jkHudInv_aItems)
        {
            jkHudInv_numItems = 0;
            return 0;
        }
        v3 = jkHudInv_aItems;
        v4 = 0;
        v5 = sithInventory_aDescriptors;
        for (int i = 0; i < SITHBIN_NUMBINS; i++)
        {
            if ( (v5->flags & ITEMINFO_POWER) != 0 )
                *v3++ = v4;
            ++v5;
            ++v4;
        }
    }
    return 1;
}

void jkHudInv_LoadItemRes()
{
    int v0; // ebp
    stdBitmap *v1; // eax
    stdBitmap *v2; // eax
    stdBitmap *v4; // eax
    unsigned int v6; // ebp
    int v7; // ebx
    signed int v8; // edx
    signed int v9; // ecx
    int i; // esi
    stdBitmap *v11; // eax
    stdVBuffer *v12; // eax
    uint32_t v13; // ecx
    signed int v14; // eax
    int v15; // ecx
    int v16; // edi
    char a1[32]; // [esp+10h] [ebp-A0h] BYREF
    char v18[128]; // [esp+30h] [ebp-80h] BYREF

#ifndef SDL2_RENDER
    v0 = stdDisplay_pCurVideoMode->format.format.bpp;
#else
    v0 = 16;
#endif
    jkHudInv_rend_isshowing_maybe = 0;
    jkHudInv_dword_553F94 = 0;
    if ( _memcmp(&Video_format.format, &jkHudInv_itemTexfmt, sizeof(rdTexformat)) || std3D_bReinitHudElements) // Added: std3D_bReinitHudElements
    {
        std3D_bReinitHudElements = 0;
        _memcpy(&jkHudInv_itemTexfmt, &Video_format.format, sizeof(jkHudInv_itemTexfmt));
        if ( jkHudInv_aBitmaps[0] )
        {
            stdBitmap_Free(jkHudInv_aBitmaps[0]);
            jkHudInv_aBitmaps[0] = 0;
        }
        if ( jkHudInv_aBitmaps[1] )
        {
            stdBitmap_Free(jkHudInv_aBitmaps[1]);
            jkHudInv_aBitmaps[1] = 0;
        }

        if ( v0 == 8 )
            v1 = stdBitmap_Load("ui\\bm\\icBrack8.bm", 0, 0);
        else
            v1 = stdBitmap_Load("ui\\bm\\icBrack16.bm", 0, 0);
        jkHudInv_aBitmaps[0] = v1;
        stdBitmap_ConvertColorFormat(&Video_format.format, v1);
        if ( v0 == 8 )
            v2 = stdBitmap_Load("ui\\bm\\forceBrack8.bm", 0, 0);
        else
            v2 = stdBitmap_Load("ui\\bm\\forceBrack16.bm", 0, 0);
        jkHudInv_aBitmaps[1] = v2;
        stdBitmap_ConvertColorFormat(&Video_format.format, v2);
        if ( jkHudInv_aBitmaps[2] )
        {
            stdBitmap_Free(jkHudInv_aBitmaps[2]);
            jkHudInv_aBitmaps[2] = 0;
        }
        if ( v0 == 8 )
            stdString_snprintf(std_genBuffer, 1024, "ui\\bm\\%s", "IcDefau8.bm");
        else
            stdString_snprintf(std_genBuffer, 1024, "ui\\bm\\%s", "IcDefau16.bm");
        jkHudInv_aBitmaps[2] = stdBitmap_Load(std_genBuffer, 0, 0);
        stdBitmap_ConvertColorFormat(&Video_format.format, jkHudInv_aBitmaps[2]);
        for (int j = 0; j < SITHBIN_NUMBINS; j++)
        {
            if ( (sithInventory_aDescriptors[j].flags & (ITEMINFO_POWER|ITEMINFO_ITEM)) != 0 )
            {
                if ( sithInventory_aDescriptors[j].hudBitmap )
                    stdBitmap_Free(sithInventory_aDescriptors[j].hudBitmap);
                sithInventory_aDescriptors[j].hudBitmap = NULL;
                stdString_snprintf(a1, 32, "ui\\bm\\ic%.5s%d.bm", sithInventory_aDescriptors[j].fpath, v0);
                v4 = stdBitmap_Load(a1, 0, 0);
                sithInventory_aDescriptors[j].hudBitmap = v4;
                stdBitmap_ConvertColorFormat(&Video_format.format, v4);
            }
        }
    }
    if ( v0 == 8 )
        _sprintf(v18, "ui\\sft\\%s", "HelthNum.sft");
    else
        _sprintf(v18, "ui\\sft\\%s", "HelthNum16.sft");
    
    // Added: fix memleak
    if (jkHudInv_font) {
        stdFont_Free(jkHudInv_font);
        jkHudInv_font = NULL;
    }

    jkHudInv_font = stdFont_Load(v18, 0, 0);
    if ( !jkHudInv_font )
        Windows_GameErrorMsgbox("ERR_CANNOT_LOAD_FILE %s", v18);
    stdBitmap_ConvertColorFormat(&Video_format.format, jkHudInv_font->bitmap);
    v6 = Video_format.width;
    _memset(&jkHudInv_info, 0, sizeof(jkHudInvInfo));
    v7 = Video_format.height;
    _memset(&jkHudInv_scroll, 0, sizeof(jkHudInvScroll));
    v8 = Video_format.height - HUD_SCALED(36);
    jkHudInv_info.field_0 = (Video_format.width - HUD_SCALED(24)) >> 1;
    jkHudInv_info.drawRect.x = jkHudInv_info.field_0 - HUD_SCALED(64);
    v9 = HUD_SCALED(24);
    jkHudInv_info.field_4 = Video_format.height - HUD_SCALED(36);
    jkHudInv_info.drawRect.y = Video_format.height - HUD_SCALED(36);
    jkHudInv_info.drawRect.width = HUD_SCALED(184);
    jkHudInv_info.drawRect.height = HUD_SCALED(24);
    if ( jkHudInv_aBitmaps[0] )
    {
        for ( i = 0; i < 2; ++i )
        {
            v11 = jkHudInv_aBitmaps[i];
            if ( v11 )
            {
                v12 = *v11->mipSurfaces;
                v13 = HUD_SCALED(v12->format.height);
                jkHudInv_info.field_8[i] = (v6 - HUD_SCALED(v12->format.width)) >> 1;
                v14 = v7 - ((v13 - HUD_SCALED(24)) >> 1) - HUD_SCALED(36);
                jkHudInv_info.field_10[i] = v14;
                v8 = jkHudInv_info.drawRect.y;
                v15 = v14 + v13;
                v16 = jkHudInv_info.drawRect.y + jkHudInv_info.drawRect.height;
                if ( jkHudInv_info.drawRect.y > v14 )
                {
                    v8 = v14;
                    jkHudInv_info.drawRect.y = v14;
                }
                if ( v16 <= v15 )
                    v9 = v15 - v8;
                else
                    v9 = v16 - v8;
                jkHudInv_info.drawRect.height = HUD_SCALED(v9);
            }
        }
    }
    jkHudInv_info.field_3C = v9 + v8;
    jkHudInv_scroll.blitX = v6 - HUD_SCALED(32);
    jkHudInv_scroll.scroll = (v7 - HUD_SCALED(76)) / HUD_SCALED(28u);
}

void jkHudInv_Close()
{
    stdFont_Free(jkHudInv_font);
    jkHudInv_font = 0;
}

int jkHudInv_Startup()
{
    _memset(&jkHudInv_itemTexfmt, 0, sizeof(rdTexformat)); // sizeof(jkHudInv_itemTexfmt)
    return 1;
}

int jkHudInv_Shutdown()
{
    jkHudInv_Close(); // Added: memleak

    if ( jkHudInv_aItems )
        pHS->free(jkHudInv_aItems);

    if ( jkHudInv_aBitmaps[0] )
    {
        stdBitmap_Free(jkHudInv_aBitmaps[0]);
        jkHudInv_aBitmaps[0] = 0;
    }

    if ( jkHudInv_aBitmaps[1] )
    {
        stdBitmap_Free(jkHudInv_aBitmaps[1]);
        jkHudInv_aBitmaps[1] = 0;
    }

    if ( jkHudInv_aBitmaps[2] )
    {
        stdBitmap_Free(jkHudInv_aBitmaps[2]);
        jkHudInv_aBitmaps[2] = 0;
    }

    for (int i = 0; i < 100; i++)
    {
        if ( (sithInventory_aDescriptors[i].flags & 0xA) != 0 && sithInventory_aDescriptors[i].hudBitmap )
        {
            stdBitmap_Free(sithInventory_aDescriptors[i].hudBitmap);
            sithInventory_aDescriptors[i].hudBitmap = NULL;
        }
    }
    return 1;
}

// MOTS added
void jkHudInv_FixAmmoMaximums()
{
    for (int i = 0; i < SITHBIN_NUMBINS; i++)
    {
        sithInventory_aDescriptors[i].ammoMax = jkHud_aBinMaxAmt[i];
    }
}
