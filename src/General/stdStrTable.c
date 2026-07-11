#include "stdStrTable.h"

#include "stdPlatform.h"
#include "General/stdString.h"
#include "jk.h"

static char16_t stdStrTable_tmpBuf[64];

int stdStrTable_Load(stdStrTable *pStrTable, char *pFilename)
{
    int v2; // edi
    int hGobFile; // ebp
    char *i; // esi
    char v6; // al
    int v11; // ebx
    int v12; // edi
    char *j; // esi
    char v15; // al
    int v16; // eax
    char *v17; // ebp
    char *v18; // edx
    stdStrMsg *v19; // edi
    char *v20; // esi
    int v21; // edi
    char *k; // esi
    char v24; // al
    char *v25; // eax
    int numMsgs; // [esp+10h] [ebp-250h] BYREF
    stdStrMsg *value; // [esp+14h] [ebp-24Ch]
    int v30; // [esp+18h] [ebp-248h]
    char v32[64]; // [esp+20h] [ebp-240h] BYREF
    char a1a[256]; // [esp+60h] [ebp-200h] BYREF
    char v34[256]; // [esp+160h] [ebp-100h] BYREF

    pStrTable->numMsgs = 0;
    v2 = 0;
    pStrTable->msgs = 0;
    numMsgs = 0;
    pStrTable->pHashtbl = 0;
    pStrTable->magic_sTbl = 0;
    hGobFile = std_g_pHS->fileOpen(pFilename, "rt");

    if ( !hGobFile )
        return 0;

    do
    {
        std_g_pHS->fileGets(hGobFile, a1a, 255);
        if ( !_strchr(a1a, 10) )
        {
            do
            {
                std_g_pHS->fileGets(hGobFile, v32, 64);
            }
            while ( !_strchr(v32, '\n') );
        }
        for ( i = a1a; __isspace(*i); ++i )
            ;
        v6 = *i;
        if ( *i != '#' && v6 && v6 != '\r' && v6 != '\n' )
            v2 = 1;
    }
    while ( !v2 );

    if ( _sscanf(a1a, "MSGS %d", &numMsgs) != 1 )
    {
        std_g_pHS->fileClose(hGobFile);
        std_g_pHS->errorPrint("Bad 'MSG n' line in string table file '%s'\n", pFilename);
        return 0;
    }
    pStrTable->numMsgs = numMsgs;
    { TWL_EXTRAM_SUGGEST(std_g_pHS); // Added: msg table is word-safe (ptrs/ints)
    pStrTable->msgs = (stdStrMsg*)STD_ALLOC(sizeof(stdStrMsg) * numMsgs);
    TWL_EXTRAM_RESTORE(std_g_pHS); }
    if ( !pStrTable->msgs )
        std_g_pHS->assert("Out of memory--cannot load string table", ".\\General\\stdStrTable.c", 120);
    stdPlatform_Memzero32(pStrTable->msgs, sizeof(stdStrMsg) * numMsgs); // Added: word-safe
    pStrTable->pHashtbl = stdHashtbl_New(numMsgs + (numMsgs/2));
    if ( !pStrTable->pHashtbl )
        std_g_pHS->assert("Out of memory--cannot load string table", ".\\General\\stdStrTable.c", 126);
    v11 = 1;
    v30 = 0;
    value = pStrTable->msgs;
    do
    {
        if ( v30 >= numMsgs )
            break;
        v12 = 0;
        do
        {
            std_g_pHS->fileGets(hGobFile, a1a, 255);
            if ( !_strchr(a1a, '\n') )
            {
                do
                    std_g_pHS->fileGets(hGobFile, v32, 64);
                while ( !_strchr(v32, '\n') );
            }
            for ( j = a1a; __isspace(*j); ++j )
                ;
            v15 = *j;
            if ( *j != '#' && v15 && v15 != '\r' && v15 != '\n' )
                v12 = 1;
        }
        while ( !v12 );
        v11 = 1;
        if ( !__strnicmp(a1a, "end", 3u) )
        {
            v16 = v30;
            pStrTable->numMsgs = v30;
            v11 = 0;
            std_g_pHS->errorPrint("Premature 'END' found after only %d lines in '%s'.  Check number in 'MSG xxx' header.\n", v16, pFilename);
        }
        if ( v11 )
        {
            v17 = stdString_GetQuotedStringContents(a1a, v34, 256);
            if ( v17 )
            {
                { TWL_EXTRAM_SUGGEST(std_g_pHS); // Added: keys are read-only after insert
                v18 = (char *)STD_ALLOC(_strlen(v34) + 1);
                TWL_EXTRAM_RESTORE(std_g_pHS); }
                stdPlatform_Memcpy32(v18, v34, _strlen(v34) + 1); // Added: word-safe
                v19 = value;
                value->key = v18;
                v20 = stdString_CopyBetweenDelimiter(v17, v34, 256, " \t");
                if ( v20 )
                {
                    v19->field_8 = _atoi(v34);
                    stdString_GetQuotedStringContents(v20, v34, 256);
                    v19->uniStr = stdString_CstrCopy(v34);
                    if ( !stdHashtbl_Add(pStrTable->pHashtbl, v19->key, v19) )
                        stdPrintf(
                            std_g_pHS->errorPrint,
                            ".\\General\\stdStrTable.c",
                            177,
                            "The key '%s' is in the string table '%s' more than once.\n   >>>%s\n",
                            value->key,
                            pFilename,
                            a1a);
                }
                else
                {
                    stdPrintf(
                        std_g_pHS->errorPrint,
                        ".\\General\\stdStrTable.c",
                        164,
                        "Cannot understand this line in string table '%s'.\n   >>> %s\n",
                        pFilename,
                        a1a);
                }
            }
            else
            {
                stdPrintf(
                    std_g_pHS->errorPrint,
                    ".\\General\\stdStrTable.c",
                    155,
                    "Cannot understand this line in string table '%s'.\n   >>> %s\n",
                    pFilename,
                    a1a);
            }
        }
        ++v30;
        ++value;
    }
    while ( v11 );
    if ( v11 )
    {
        a1a[0] = 0;
        v21 = 0;
        do
        {
            std_g_pHS->fileGets(hGobFile, a1a, 255);
            if ( !_strchr(a1a, '\n') )
            {
                do
                    std_g_pHS->fileGets(hGobFile, v32, 64);
                while ( !_strchr(v32, '\n') );
            }
            for ( k = a1a; __isspace(*k); ++k )
                ;
            v24 = *k;
            if ( *k != '#' && v24 && v24 != '\r' && v24 != '\n' )
                v21 = 1;
        }
        while ( !v21 );
        v25 = _strtok(a1a, " \t\n\r");
        if ( __strcmpi(v25, "end") )
        {
            v11 = 0;
            std_g_pHS->errorPrint("'END' not found in '%s'.  Enlarge number in 'MSG xxx' header.\n", pFilename);
        }
    }
    pStrTable->magic_sTbl = 0x7354626C;
    std_g_pHS->fileClose(hGobFile);
    return v11;
}

void stdStrTable_Free(stdStrTable* pStrTable)
{
    stdStrMsg *msgs; // ebp
    stdStrMsg *msg; // esi

    if ( pStrTable->magic_sTbl == 0x7354626C )
    {
        pStrTable->magic_sTbl = 0;
        // Added: Moved
        //pTable->numMsgs = 0;
        //pTable->msgs = 0;
        stdHashtbl_Free(pStrTable->pHashtbl);
        if ( pStrTable->msgs )
        {
            for (int i = 0; i < pStrTable->numMsgs; i++)
            {
                if ( pStrTable->msgs[i].uniStr )
                    STD_FREE((void*)pStrTable->msgs[i].uniStr);
                if ( pStrTable->msgs[i].key )
                    STD_FREE((void*)pStrTable->msgs[i].key);
            }
            STD_FREE(pStrTable->msgs);
        }

        // Added: Moved
        pStrTable->numMsgs = 0;
        pStrTable->msgs = 0;
    }
    else
    {
        //stdPlatform_Printf("OpenJKDF2: Tried to free bad stdStrTable %p? magic==%x\n", pTable, pTable->magic_sTbl);
    }
}

char16_t* stdStrTable_GetValue(stdStrTable* pStrTable, const char *pKey)
{
    stdStrMsg *v2; // eax
    char16_t *result; // eax

    if ( pStrTable->numMsgs && (v2 = (stdStrMsg *)stdHashtbl_Find(pStrTable->pHashtbl, pKey)) != 0 )
        result = v2->uniStr;
    else
        result = 0;
    return result;
}

int stdStrTable_ReadLine(stdFile_t fh, char *pStr, int size)
{
    int found;
    char *p;
    char tmpBuf[64];

    found = 0;
    do
    {
        std_g_pHS->fileGets(fh, pStr, size);
        if ( !_strchr(pStr, '\n') )
        {
            do
                std_g_pHS->fileGets(fh, tmpBuf, 64);
            while ( !_strchr(tmpBuf, '\n') );
        }
        for ( p = pStr; __isspace(*p); ++p )
            ;
        if ( *p != '#' && *p && *p != '\r' && *p != '\n' )
            found = 1;
    }
    while ( !found );
    return 1;
}

int stdStrTable_ParseUniLine(stdFile_t hGobFile, char16_t *buf)
{
    int found;
    char16_t *p;
    char16_t tmpBuf[64];

    found = 0;
    do
    {
        std_g_pHS->fileGetws(hGobFile, buf, 10);
        if ( !__wcschr(buf, u'\n') )
        {
            do
                std_g_pHS->fileGetws(hGobFile, tmpBuf, 10);
            while ( !__wcschr(tmpBuf, u'\n') );
        }
        for ( p = buf; _iswspace(*p); ++p )
            ;
        if ( *p != u'#' && *p && *p != u'\r' && *p != u'\n' )
            found = 1;
    }
    while ( !found );
    return 1;
}

char16_t* stdStrTable_GetValueOrKey(stdStrTable* pStrTable, const char *pKey)
{
    stdStrMsg *v2; // eax
    char16_t *result; // eax

    // Added: nullptr fallback
    if (!pKey) {
        return u"(NULL)";
    }

    if ( pStrTable->numMsgs && (v2 = (stdStrMsg *)stdHashtbl_Find(pStrTable->pHashtbl, pKey)) != 0 )
        result = v2->uniStr;
    else
        result = 0;
    if ( !result )
    {
        stdString_CharToWchar(stdStrTable_tmpBuf, pKey, 63);
        stdStrTable_tmpBuf[63] = 0;
        result = stdStrTable_tmpBuf;
    }
    return result;
}
