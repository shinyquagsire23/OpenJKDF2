#include "jkEpisode.h"

#include "World/sithThing.h"
#include "Gameplay/jkSaber.h"
#include "stdPlatform.h"
#include "Main/jkRes.h"
#include "Main/Main.h"
#include "Main/jkStrings.h"
#include "General/stdFileUtil.h"
#include "General/stdFnames.h"
#include "General/stdString.h"
#include "Win95/Windows.h"
#include "Win95/stdMci.h"
#include "Cog/jkCog.h"
#include "World/jkPlayer.h"

#include "../jk.h"

#ifdef JKM_DSS
int jkEpisode_numBubbles = 0;
#endif

// MOTS altered
int jkEpisode_Startup()
{
    sithThing_SetHandler(jkEpisode_UpdateExtra);
    jkEpisode_numBubbles = 0;
    return 1;
}

void jkEpisode_Shutdown()
{
#ifdef JKM_DSS
    for (int i = 0; i < 64; i++) {
        jkPlayer_aBubbleInfo[i].pThing = 0;
    }
    jkEpisode_numBubbles = 0; // Added
#endif
}

int jkEpisode_LoadVerify()
{
    stdFileSearch *v0; // ebp
    unsigned int v2; // esi
    jkEpisode *v3; // edi
    stdFileSearch *v5; // ebp
    unsigned int v7; // esi
    jkEpisode *v8; // edi
    stdFileSearch *v10; // ebp
    unsigned int v12; // esi
    jkEpisode *v13; // edi
    int result; // eax
    jkEpisode *v16; // ebx
    int v17; // eax
    int v19; // edi
    char *i; // ecx
    char v21; // al
    wchar_t *v22; // eax
    int v24; // edi
    char *j; // ecx
    char v26; // al
    wchar_t *v27; // eax
    unsigned int v28; // [esp+10h] [ebp-1D0h]
    char v29[64]; // [esp+14h] [ebp-1CCh] BYREF
    stdFileSearchResult v30; // [esp+54h] [ebp-18Ch] BYREF
    char v31[64]; // [esp+160h] [ebp-80h] BYREF
    char v32[64]; // [esp+1A0h] [ebp-40h] BYREF

    if ( Windows_installType < 1 )
        jkRes_LoadCD(0);
    jkRes_UnhookHS();
    jkEpisode_var2 = 0;
    v0 = stdFileUtil_NewFind("episode", 2, "*");
    while ( stdFileUtil_FindNext(v0, &v30) )
    {
        if ( v30.fpath[0] != '.' )
        {
            if ( v30.is_subdirectory )
            {
                if ( jkEpisode_var2 < 0x40 )
                {
                    v2 = 0;
                    if ( jkEpisode_var2 )
                    {
                        v3 = jkEpisode_aEpisodes;
                        while ( __strnicmp(v30.fpath, v3->name, 0x20u) )
                        {
                            ++v2;
                            ++v3;
                            if ( v2 >= jkEpisode_var2 )
                                goto LABEL_11;
                        }
                    }
                    else
                    {
LABEL_11:
                        _strncpy(jkEpisode_aEpisodes[jkEpisode_var2].name, v30.fpath, 0x1Fu);
                        jkEpisode_aEpisodes[jkEpisode_var2].name[31] = 0;
                        jkEpisode_var2++;
                    }
                }
            }
        }
    }
    stdFileUtil_DisposeFind(v0);
    v5 = stdFileUtil_NewFind("episode", 3, JKRES_GOB_EXT);
    while ( stdFileUtil_FindNext(v5, &v30) )
    {
        if ( v30.fpath[0] != '.' )
        {
            stdFnames_StripExtAndDot(v30.fpath);
            if ( jkEpisode_var2 < 0x40 )
            {
                v7 = 0;
                if ( jkEpisode_var2 )
                {
                    v8 = jkEpisode_aEpisodes;
                    while ( __strnicmp(v30.fpath, v8->name, 0x20u) )
                    {
                        ++v7;
                        ++v8;
                        if ( v7 >= jkEpisode_var2 )
                            goto LABEL_20;
                    }
                }
                else
                {
LABEL_20:
                    _strncpy(jkEpisode_aEpisodes[jkEpisode_var2].name, v30.fpath, 0x1Fu);
                    jkEpisode_aEpisodes[jkEpisode_var2].name[31] = 0;
                    jkEpisode_var2++;
                }
            }
        }
    }
    stdFileUtil_DisposeFind(v5);
    if ( jkRes_curDir[0] )
    {
        _sprintf(jkEpisode_var5, "%s\\gamedata\\episode", jkRes_curDir);
        v10 = stdFileUtil_NewFind(jkEpisode_var5, 3, JKRES_GOB_EXT);
        while ( stdFileUtil_FindNext(v10, &v30) )
        {
            if ( v30.fpath[0] != '.' )
            {
                stdFnames_StripExtAndDot(v30.fpath);
                if ( jkEpisode_var2 < 0x40 )
                {
                    v12 = 0;
                    if ( jkEpisode_var2 )
                    {
                        v13 = jkEpisode_aEpisodes;
                        while ( __strnicmp(v30.fpath, v13->name, 0x20u) )
                        {
                            ++v12;
                            ++v13;
                            if ( v12 >= jkEpisode_var2 )
                                goto LABEL_30;
                        }
                    }
                    else
                    {
LABEL_30:
                        _strncpy(jkEpisode_aEpisodes[jkEpisode_var2].name, v30.fpath, 0x1Fu);
                        jkEpisode_aEpisodes[jkEpisode_var2].name[31] = 0;
                        jkEpisode_var2++;
                    }
                }
            }
        }
        stdFileUtil_DisposeFind(v10);
    }
    jkRes_HookHS();
    result = jkEpisode_var2;
    v28 = 0;
    if ( jkEpisode_var2 )
    {
        v16 = jkEpisode_aEpisodes;
        do
        {
            jkRes_LoadGob(v16->name);
            v17 = pHS->fileOpen("episode.jk", "rt");
            if ( v17 )
            {
                v19 = 0;
                pHS->fileGets(v17, v29, 64);
                if ( !pHS->feof(v17) )
                {
                    while ( 1 )
                    {
                        if ( !_strchr(v29, '\n') )
                        {
                            do
                                pHS->fileGets(v17, v31, 64);
                            while ( !_strchr(v31, '\n') );
                        }
                        for ( i = v29; *i == ' ' || *i == '\t'; ++i )
                            ;
                        v21 = *i;
                        if ( *i != '#' && v21 && v21 != '\r' && v21 != '\n' )
                            v19 = 1;
                        if ( v19 )
                            break;
                        pHS->fileGets(v17, v29, 64);
                        if ( pHS->feof(v17) )
                            goto LABEL_50;
                    }
                    stdString_GetQuotedStringContents(v29, jkEpisode_var4, 128);
                    v22 = jkStrings_GetUniStringWithFallback(jkEpisode_var4);
                    _wcsncpy(v16->unistr, v22, 0x40u);
                    v16->type = JK_EPISODE_SINGLEPLAYER;
                    v24 = 0;
                    pHS->fileGets(v17, v29, 64);
                    if ( !pHS->feof(v17) )
                    {
                        while ( 1 )
                        {
                            if ( !_strchr(v29, '\n') )
                            {
                                do
                                    pHS->fileGets(v17, v32, 64);
                                while ( !_strchr(v32, '\n') );
                            }
                            for ( j = v29; *j == ' ' || *j == '\t'; ++j )
                                ;
                            v26 = *j;
                            if ( *j != '#' && v26 && v26 != '\r' && v26 != '\n' )
                                v24 = 1;
                            if ( v24 )
                                break;
                            pHS->fileGets(v17, v29, 64);
                            if ( pHS->feof(v17) )
                                goto LABEL_50;
                        }
                        _sscanf(v29, "TYPE %d", &v16->type);
                    }
                }
LABEL_50:
                pHS->fileClose((intptr_t)v17);
            }
            else
            {
                v27 = jkStrings_GetUniStringWithFallback("ERR_INVALID_EPISODE %s");
                jk_snwprintf(v16->unistr, 0x40u, v27, v16);
            }
            result = v28 + 1;
            ++v16;
            ++v28;
        }
        while ( v28 < jkEpisode_var2 );
    }
    return result;
}

int jkEpisode_Load(jkEpisodeLoad *a1)
{
    int v2; // eax
    int v4; // esi
    char *i; // ecx
    char v6; // al
    int v7; // esi
    char *j; // ecx
    char v9; // al
    int v11; // esi
    char *k; // ecx
    char v13; // al
    unsigned int aEnts_size; // esi
    jkEpisodeEntry *aEnts; // edi
    int v16; // ebx
    int v17; // edi
    int v18; // edi
    jkEpisodeEntry *v19; // esi
    char *l; // ecx
    char v21; // al
    int v22; // esi
    char *m; // ecx
    char v24; // al
    char *v25; // eax
    int numSeq; // [esp+10h] [ebp-148h] BYREF
    int v27; // [esp+14h] [ebp-144h]
    char a1a[128]; // [esp+18h] [ebp-140h] BYREF
    char sType[64]; // [esp+98h] [ebp-C0h] BYREF
    char sFile[64]; // [esp+D8h] [ebp-80h] BYREF
    char v31[64]; // [esp+118h] [ebp-40h] BYREF

    numSeq = 0;
    a1->numSeq = 0;
    a1->field_8 = 0;

    // Added: memleak
    if (a1->paEntries) {
        pHS->free(a1->paEntries);
    }

    a1->paEntries = 0;
    v2 = pHS->fileOpen("episode.jk", "rt");
    if ( !v2 )
        return 0;
    v4 = 0;
    pHS->fileGets(v2, a1a, 128);
    while ( !pHS->feof(v2) )
    {
        if ( !_strchr(a1a, '\n') )
        {
            do
                pHS->fileGets(v2, sType, 64);
            while ( !_strchr(sType, '\n') );
        }
        for ( i = a1a; *i == ' ' || *i == '\t'; ++i )
            ;
        v6 = *i;
        if ( *i != '#' && v6 && v6 != '\r' && v6 != '\n' )
            v4 = 1;
        if ( v4 )
            break;
        pHS->fileGets(v2, a1a, 128);
    }
    v7 = 0;
    pHS->fileGets(v2, a1a, 128);
    if ( pHS->feof(v2) )
        goto LABEL_30;
    while ( 1 )
    {
        if ( !_strchr(a1a, '\n') )
        {
            do
                pHS->fileGets(v2, sType, 64);
            while ( !_strchr(sType, '\n') );
        }
        for ( j = a1a; *j == ' ' || *j == '\t'; ++j )
            ;
        v9 = *j;
        if ( *j != '#' && v9 && v9 != '\r' && v9 != '\n' )
            v7 = 1;
        if ( v7 )
            break;
        pHS->fileGets(v2, a1a, 128);
        if ( pHS->feof(v2) )
            goto LABEL_30;
    }
    if ( _sscanf(a1a, "TYPE %d", &a1->type) != 1 )
    {
LABEL_30:
        pHS->fileClose((intptr_t)v2);
        stdPrintf(pHS->errorPrint, ".\\Main\\jkEpisode.c", 105, "Bad 'TYPE n' line in sequence list 'episode.jkl'\n");
        return 0;
    }
    v11 = 0;
    pHS->fileGets(v2, a1a, 128);
    if ( pHS->feof(v2) )
        goto LABEL_47;
    while ( 1 )
    {
        if ( !_strchr(a1a, '\n') )
        {
            do
                pHS->fileGets(v2, sType, 64);
            while ( !_strchr(sType, '\n') );
        }
        for ( k = a1a; *k == ' ' || *k == '\t'; ++k )
            ;
        v13 = *k;
        if ( *k != '#' && v13 && v13 != '\r' && v13 != '\n' )
            v11 = 1;
        if ( v11 )
            break;
        pHS->fileGets(v2, a1a, 128);
        if ( pHS->feof(v2) )
            goto LABEL_47;
    }
    if ( _sscanf(a1a, "SEQ %d", &numSeq) != 1 )
    {
LABEL_47:
        pHS->fileClose((intptr_t)v2);
        stdPrintf(pHS->errorPrint, ".\\Main\\jkEpisode.c", 114, "Bad 'SEQ n' line in sequence list 'episode.jkl'\n", 0, 0, 0, 0);
        return 0;
    }
    aEnts_size = (numSeq + 1) * sizeof(jkEpisodeEntry);

    aEnts = (jkEpisodeEntry *)pHS->alloc(aEnts_size);
    a1->paEntries = aEnts;
    if ( !aEnts )
        Windows_GameErrorMsgbox("ERR_OUT_OF_MEMORY");
    _memset(aEnts, 0, aEnts_size);
    v16 = 0;
    v17 = 1;
    v27 = 0;
    do
    {
        if ( v27 >= numSeq )
            break;
        v18 = 0;
        v19 = &a1->paEntries[v16];
        pHS->fileGets(v2, a1a, 128);
        if ( pHS->feof(v2) )
        {
LABEL_67:
            v17 = 0;
        }
        else
        {
            while ( 1 )
            {
                if ( !_strchr(a1a, '\n') )
                {
                    do
                        pHS->fileGets(v2, v31, 64);
                    while ( !_strchr(v31, '\n') );
                }
                for ( l = a1a; *l == ' ' || *l == '\t'; ++l )
                    ;
                v21 = *l;
                if ( *l != '#' && v21 && v21 != '\r' && v21 != '\n' )
                    v18 = 1;
                if ( v18 )
                    break;
                pHS->fileGets(v2, a1a, 128);
                if ( pHS->feof(v2) )
                    goto LABEL_67;
            }
            v17 = 1;
            if ( !__strnicmp(a1a, "end", 3u) )
            {
                pHS->fileClose((intptr_t)v2);
                stdPrintf(pHS->errorPrint, ".\\Main\\jkEpisode.c", 153, "Premature 'end' found in episode file 'episode.jkl' after %d lines.\n", v27);
                return 0;
            }
            if ( _sscanf(
                     a1a,
                     " %d: %d %d %s %s %d %d %d %d",
                     &v19->lineNum,
                     &v19->cdNum,
                     &v19->level,
                     sType,
                     sFile,
                     &v19->lightpow,
                     &v19->darkpow,
                     &v19->gotoA,
                     &v19->gotoB) != 9 )
            {
                stdPrintf(
                    pHS->errorPrint,
                    ".\\Main\\jkEpisode.c",
                    171,
                    "Bad line or wrong number of messages in 'episode.jkl'.  Check 'SEQ xxx' header.\n",
                    0,
                    0,
                    0,
                    0);
                v17 = 0;
            }

            // Added: GOG detection for soundtracks
            if (v19->cdNum > 1 && stdMci_bIsGOG) {
                stdMci_bIsGOG = 0;
                stdPlatform_Printf("jkEpisode_Load: Seeing CD number >1 (%u), assuming this is an OG disk install with offsetted tracks...\n", v19->cdNum);
            }

            if ( _string_modify_idk(sType[0]) == 'L' )
                v19->type = 0; // LEVEL = 0
            else
                v19->type = _string_modify_idk(sType[0]) == 'C' ? 1 : 2; // CUT = 1, other = 2
            _strncpy(v19->fileName, sFile, 0x1Fu);
            v19->fileName[31] = 0;
        }
        ++v16;
        ++v27;
    }
    while ( v17 );
    if ( v17 )
    {
        a1a[0] = 0;
        v22 = 0;
        pHS->fileGets(v2, a1a, 128);
        while ( !pHS->feof(v2) )
        {
            if ( !_strchr(a1a, '\n') )
            {
                do
                    pHS->fileGets(v2, sFile, 64);
                while ( !_strchr(sFile, '\n') );
            }
            for ( m = a1a; *m == ' ' || *m == '\t'; ++m )
                ;
            v24 = *m;
            if ( *m != '#' && v24 && v24 != '\r' && v24 != '\n' )
                v22 = 1;
            if ( v22 )
                break;
            pHS->fileGets(v2, a1a, 128);
        }
        v25 = _strtok(a1a, " \t\n\r");
        if ( !v25 || __strcmpi(v25, "end") )
            stdPrintf(pHS->errorPrint, ".\\Main\\jkEpisode.c", 200, "'END' not found in 'episode.jkl'.  Check number in 'MSG xxx' header.\n", 0, 0, 0, 0);
        a1->numSeq = numSeq;
    }
    jkCog_StringsInit();
    pHS->fileClose((intptr_t)v2);
    return a1->paEntries != 0;
}

jkEpisodeEntry* jkEpisode_idk1(jkEpisodeLoad *a1)
{
    return &a1->paEntries[a1->field_8];
}

jkEpisodeEntry* jkEpisode_idk2(jkEpisodeLoad *pLoad, int bIsAPath)
{
    int v4; // edi
    int v5; // edx
    int v6; // eax
    jkEpisodeEntry *v7; // ecx

    if ( bIsAPath )
        v4 = pLoad->paEntries[pLoad->field_8].gotoA;
    else
        v4 = pLoad->paEntries[pLoad->field_8].gotoB;
    if ( v4 == -1 )
        return 0;
    v5 = pLoad->numSeq;
    v6 = 0;
    if ( v5 <= 0 )
LABEL_9:
        Windows_GameErrorMsgbox("ERR_BAD_EPISODE_FILE %d %d", pLoad->field_8, v4);
    v7 = pLoad->paEntries;
    while ( v7->lineNum != v4 )
    {
        ++v6;
        ++v7;
        if ( v6 >= v5 )
            goto LABEL_9;
    }
    pLoad->field_8 = v6;
    return &pLoad->paEntries[v6];
}

int jkEpisode_EndLevel(jkEpisodeLoad *pEpisode, int levelNum)
{
    int v2; // eax
    int v3; // edx
    int *i; // ecx

    v2 = 0;
    v3 = pEpisode->numSeq;
    if ( v3 <= 0 )
        return 0;
    for ( i = &pEpisode->paEntries->level; *i != levelNum; i += 16 )
    {
        if ( ++v2 >= v3 )
            return 0;
    }
    pEpisode->field_8 = v2;
    return 1;
}

// MOTS altered TODO verify
int jkEpisode_UpdateExtra(sithThing *pPlayerThing)
{
    // HACK: Sometimes when the player is killed, the blade isn't restored?
    if (sithInventory_GetCurWeapon(pPlayerThing) == SITHBIN_LIGHTSABER && !(pPlayerThing->jkFlags & JKFLAG_SABERON)) {
        pPlayerThing->jkFlags |= JKFLAG_SABERON;
    }

    // Removed: I want more logic in jkSaber_UpdateLength
    //if (pPlayerThing->jkFlags & JKFLAG_SABERON)
    //    jkSaber_UpdateLength(pPlayerThing);

    // Added: I want more logic in jkSaber_UpdateLength
    jkSaber_UpdateLength(pPlayerThing);

#ifdef JKM_DSS
    if (Main_bMotsCompat && pPlayerThing == sithPlayer_pLocalPlayerThing) {
        uint32_t uVar1;
        int iVar3;
        int iVar4;
        uint32_t uVar5;
        sithCog **ppsVar6;
        uint32_t bubbleType;
        int local_14;
        int bHasBubble;
        float bubbleRadSqrd;

        sithThing* pBubbleThing = NULL;
        bHasBubble = jkEpisode_GetBubbleInfo(pPlayerThing,&bubbleType,&pBubbleThing,&bubbleRadSqrd);
        iVar4 = 0;
        if (bHasBubble == 0) {
            if (playerThings[playerThingIdx].jkmUnk4 != 0) {
                sithCog_SendMessageFromThingEx(pPlayerThing, NULL, SITH_MESSAGE_EXITBUBBLE,(float)playerThings[playerThingIdx].jkmUnk5,0.0,0.0,0.0);

                for (int binIdx = 0; binIdx < SITHBIN_NUMBINS; binIdx++) 
                {
                    if (sithInventory_GetAvailable(pPlayerThing, binIdx) && (sithInventory_aDescriptors[binIdx].flags & 8) && sithInventory_aDescriptors[binIdx].cog) {
                        sithCog_SendMessageEx(sithInventory_aDescriptors[binIdx].cog, SITH_MESSAGE_EXITBUBBLE, SENDERTYPE_THING, pPlayerThing->thingIdx, 0,-1,0,(float)playerThings[playerThingIdx].jkmUnk5,0.0,0.0,0.0);
                    }
                }
            }
        }
        else if (playerThings[playerThingIdx].jkmUnk4 == 0) {
            sithCog_SendMessageFromThingEx(pPlayerThing,pBubbleThing,SITH_MESSAGE_ENTERBUBBLE,(float)bubbleType,0.0,0.0,0.0);
            if (!pBubbleThing) {
                uVar5 = 0xffffffff;
                iVar4 = 0;
            }
            else {
                uVar5 = pBubbleThing->thingIdx;
                iVar4 = 3;
            }

            for (int binIdx = 0; binIdx < SITHBIN_NUMBINS; binIdx++) 
            {
                if (sithInventory_GetAvailable(pPlayerThing, binIdx) && (sithInventory_aDescriptors[binIdx].flags & 8) && sithInventory_aDescriptors[binIdx].cog) {
                    sithCog_SendMessageEx(sithInventory_aDescriptors[binIdx].cog, SITH_MESSAGE_ENTERBUBBLE, SENDERTYPE_THING, pPlayerThing->thingIdx, iVar4,uVar5,0,(float)playerThings[playerThingIdx].jkmUnk5,0.0,0.0,0.0);
                }
            }
        }
        else {
            if ((float)playerThings[playerThingIdx].jkmUnk5 != (float)bubbleType) 
            {
                sithCog_SendMessageFromThingEx(pPlayerThing, NULL, SITH_MESSAGE_EXITBUBBLE,(float)playerThings[playerThingIdx].jkmUnk5,0.0,0.0,0.0);
                
                for (int binIdx = 0; binIdx < SITHBIN_NUMBINS; binIdx++) 
                {
                    if (sithInventory_GetAvailable(pPlayerThing, binIdx) && (sithInventory_aDescriptors[binIdx].flags & 8) && sithInventory_aDescriptors[binIdx].cog) {
                        sithCog_SendMessageEx(sithInventory_aDescriptors[binIdx].cog, SITH_MESSAGE_EXITBUBBLE, SENDERTYPE_THING, pPlayerThing->thingIdx, 0,-1,0,(float)playerThings[playerThingIdx].jkmUnk5,0.0,0.0,0.0);
                    }
                }

                sithCog_SendMessageFromThingEx(pPlayerThing,pBubbleThing,SITH_MESSAGE_ENTERBUBBLE,(float)bubbleType,0.0,0.0,0.0);
                
                if (!pBubbleThing) {
                    uVar5 = 0xffffffff;
                    iVar4 = 0;
                }
                else {
                    uVar5 = pBubbleThing->thingIdx;
                    iVar4 = 3;
                }

                for (int binIdx = 0; binIdx < SITHBIN_NUMBINS; binIdx++) 
                {
                    if (sithInventory_GetAvailable(pPlayerThing, binIdx) && (sithInventory_aDescriptors[binIdx].flags & 8) && sithInventory_aDescriptors[binIdx].cog) {
                        sithCog_SendMessageEx(sithInventory_aDescriptors[binIdx].cog, SITH_MESSAGE_ENTERBUBBLE, SENDERTYPE_THING, pPlayerThing->thingIdx, iVar4,uVar5,0,(float)playerThings[playerThingIdx].jkmUnk5,0.0,0.0,0.0);
                    }
                }
            }
        }
        playerThings[playerThingIdx].jkmUnk4 = bHasBubble;
        playerThings[playerThingIdx].jkmUnk5 = bubbleType;
        playerThings[playerThingIdx].jkmUnk6 = bubbleRadSqrd;
    }
#endif
    return 1;
}

int jkEpisode_idk4(jkEpisodeLoad *pEpisodeLoad, char *pEpisodeName)
{
    int v2; // edi
    int i; // ebx

    v2 = 0;
    if ( pEpisodeLoad->numSeq <= 0 )
        return 0;
    for ( i = 0; __strcmpi(pEpisodeLoad->paEntries[i].fileName, pEpisodeName); ++i )
    {
        if ( ++v2 >= pEpisodeLoad->numSeq )
            return 0;
    }
    pEpisodeLoad->field_8 = v2;
    return 1;
}


int jkEpisode_idk6(const char *pName)
{
    int v1; // eax
    int result; // eax
    unsigned int v3; // esi
    jkEpisode *v4; // edi
    int v5; // edx

    v1 = jkEpisode_var2;
    if ( (unsigned int)jkEpisode_var2 >= 0x40 )
        return 0;
    v3 = 0;
    if ( jkEpisode_var2 )
    {
        v4 = jkEpisode_aEpisodes;
        while ( __strnicmp(pName, v4->name, 0x20u) )
        {
            v1 = jkEpisode_var2;
            ++v3;
            ++v4;
            if ( v3 >= jkEpisode_var2 )
                goto LABEL_7;
        }
        result = 0;
    }
    else
    {
LABEL_7:
        _strncpy(jkEpisode_aEpisodes[v1].name, pName, 0x1Fu);
        v5 = jkEpisode_var2;
        result = ++jkEpisode_var2;
        jkEpisode_aEpisodes[v5].name[31] = 0;
    }
    return result;
}

// MOTS added
void jkEpisode_CreateBubble(sithThing *pThing,float radius,uint32_t type)
{
    int iVar1;
    jkBubbleInfo *pjVar2;
    int iVar3;
    
    jkEpisode_DestroyBubble(pThing);

    iVar3 = jkEpisode_numBubbles + 1;
    iVar1 = jkEpisode_numBubbles;
    if (iVar3 != jkEpisode_numBubbles) {
        pjVar2 = jkPlayer_aBubbleInfo + iVar3;
        do {
            if (&jkPlayer_aBubbleInfo[64] < pjVar2) {
                iVar3 = iVar3 - 64;
                pjVar2 = pjVar2 - 64;
            }
            iVar1 = iVar3;
            if (!pjVar2->pThing) break;
            iVar3 = iVar3 + 1;
            pjVar2 = pjVar2 + 1;
            iVar1 = jkEpisode_numBubbles;
        } while (iVar3 != jkEpisode_numBubbles);
    }

    jkEpisode_numBubbles = iVar1;
    if (!jkPlayer_aBubbleInfo[iVar3].pThing) {
        jkPlayer_aBubbleInfo[iVar3].pThing = pThing;
        jkPlayer_aBubbleInfo[iVar3].radiusSquared = radius * radius;
        jkPlayer_aBubbleInfo[iVar3].type = type;
        pThing->jkFlags |= JKFLAG_100;
    }
}

// MOTS added
void jkEpisode_DestroyBubble(sithThing *pThing)
{
    for (int i = 0; i < 64; i++) {
        if (jkPlayer_aBubbleInfo[i].pThing == pThing)
            jkPlayer_aBubbleInfo[i].pThing = 0;
    }

    pThing->jkFlags &= ~JKFLAG_100;
}

// MOTS added
int jkEpisode_GetBubbleInfo(sithThing *pThing,uint32_t *pTypeOut,sithThing **pThingOut,float *pOut)
{
    sithThing *psVar1;
    float fVar3;
    float fVar4;
    jkBubbleInfo *pjVar7;
    int iVar8;
    jkBubbleInfo *pjVar9;
    int local_4;
    
    fVar3 = 1e+12;
    iVar8 = 0;
    pjVar9 = jkPlayer_aBubbleInfo;
    local_4 = 0x40;
    do {
        psVar1 = pjVar9->pThing;
        if (psVar1 != (sithThing *)0x0) {
            if (psVar1->type == 0) {
                jkEpisode_DestroyBubble(psVar1);
            }
            else {
                if ((psVar1->jkFlags & JKFLAG_100) == 0) {
                    jkEpisode_DestroyBubble(psVar1);
                }
                else {
                    fVar4 = rdVector_DistSquared3(&psVar1->position, &pThing->position);
                    if ((fVar4 < pjVar9->radiusSquared) && (fVar4 < fVar3)) 
                    {
                        if (pTypeOut) {
                            *pTypeOut = pjVar9->type;
                        }
                        if (pThingOut) {
                            *pThingOut = psVar1;
                        }
                        if (pOut) { // Added: fix it to actually compare the ptr
                            *pOut = fVar4;
                        }
                        iVar8 = 1;
                        fVar3 = fVar4;
                    }
                }
            }
        }
        pjVar9 = pjVar9 + 1;
        local_4 = local_4 + -1;
    } while (local_4 != 0);
    return iVar8;
}

