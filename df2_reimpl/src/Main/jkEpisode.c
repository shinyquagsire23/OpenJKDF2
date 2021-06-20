#include "jkEpisode.h"

#include "World/sithThing.h"
#include "World/jkSaber.h"
#include "stdPlatform.h"
#include "Main/jkRes.h"
#include "Main/Main.h"
#include "Main/jkStrings.h"
#include "General/stdFileUtil.h"
#include "General/stdFnames.h"
#include "General/stdString.h"
#include "Win95/Windows.h"
#include "Cog/jkCog.h"

#include "../jk.h"

int jkEpisode_Startup()
{
    sithThing_SetHandler(jkEpisode_UpdateExtra);
    return 1;
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
    int v14; // ecx
    int result; // eax
    jkEpisode *v16; // ebx
    int v17; // eax
    char *v18; // esi
    int v19; // edi
    char *i; // ecx
    char v21; // al
    wchar_t *v22; // eax
    common_functions *v23; // edx
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
    v5 = stdFileUtil_NewFind("episode", 3, "gob");
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
        v10 = stdFileUtil_NewFind(jkEpisode_var5, 3, "gob");
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
            v18 = (char *)v17;
            if ( v17 )
            {
                v19 = 0;
                pHS->fileGets(v17, v29, 64);
                if ( !pHS->feof(v18) )
                {
                    while ( 1 )
                    {
                        if ( !_strchr(v29, '\n') )
                        {
                            do
                                pHS->fileGets((int)v18, v31, 64);
                            while ( !_strchr(v31, '\n') );
                        }
                        for ( i = v29; *i == ' ' || *i == '\t'; ++i )
                            ;
                        v21 = *i;
                        if ( *i != '#' && v21 && v21 != '\r' && v21 != '\n' )
                            v19 = 1;
                        if ( v19 )
                            break;
                        pHS->fileGets((int)v18, v29, 64);
                        if ( pHS->feof(v18) )
                            goto LABEL_50;
                    }
                    stdString_GetQuotedStringContents(v29, jkEpisode_var4, 128);
                    v22 = jkStrings_GetText(jkEpisode_var4);
                    _wcsncpy(v16->unistr, v22, 0x40u);
                    v23 = pHS;
                    v16->field_A0 = 1;
                    v24 = 0;
                    v23->fileGets((int)v18, v29, 64);
                    if ( !pHS->feof(v18) )
                    {
                        while ( 1 )
                        {
                            if ( !_strchr(v29, '\n') )
                            {
                                do
                                    pHS->fileGets((int)v18, v32, 64);
                                while ( !_strchr(v32, '\n') );
                            }
                            for ( j = v29; *j == ' ' || *j == '\t'; ++j )
                                ;
                            v26 = *j;
                            if ( *j != '#' && v26 && v26 != '\r' && v26 != '\n' )
                                v24 = 1;
                            if ( v24 )
                                break;
                            pHS->fileGets((int)v18, v29, 64);
                            if ( pHS->feof(v18) )
                                goto LABEL_50;
                        }
                        _sscanf(v29, "TYPE %d", &v16->field_A0);
                    }
                }
LABEL_50:
                pHS->fileClose((intptr_t)v18);
            }
            else
            {
                v27 = jkStrings_GetText("ERR_INVALID_EPISODE %s");
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
    common_functions *v1; // eax
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

    v1 = pHS;
    numSeq = 0;
    a1->numSeq = 0;
    a1->field_8 = 0;
    a1->paEntries = 0;
    v2 = v1->fileOpen("episode.jk", "rt");
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
    if ( _sscanf(a1a, "TYPE %d", a1) != 1 )
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
    aEnts_size = (numSeq + 1) << 6;
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
    int v2; // ebp
    jkEpisodeEntry *v3; // ebx
    int v4; // edi
    int v5; // edx
    int v6; // eax
    jkEpisodeEntry *v7; // ecx

    v2 = pLoad->field_8;
    v3 = pLoad->paEntries;
    if ( bIsAPath )
        v4 = v3[v2].gotoA;
    else
        v4 = v3[v2].gotoB;
    if ( v4 == -1 )
        return 0;
    v5 = pLoad->numSeq;
    v6 = 0;
    if ( v5 <= 0 )
LABEL_9:
        Windows_GameErrorMsgbox("ERR_BAD_EPISODE_FILE %d %d", v2, v4);
    v7 = pLoad->paEntries;
    while ( v7->lineNum != v4 )
    {
        ++v6;
        ++v7;
        if ( v6 >= v5 )
            goto LABEL_9;
    }
    pLoad->field_8 = v6;
    return &v3[v6];
}

void jkEpisode_UpdateExtra(sithThing *thing)
{
    if ( (thing->jkFlags & 1) != 0 )
        jkSaber_UpdateLength(thing);
}
