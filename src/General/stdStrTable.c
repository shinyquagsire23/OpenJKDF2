#include "stdStrTable.h"

#include "stdPlatform.h"
#include "General/stdString.h"
#include "jk.h"

static wchar_t stdStrTable_tmpBuf[64];

int stdStrTable_Load(stdStrTable *strtable, char *fpath)
{
    int v2; // edi
    int fhand; // ebp
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

    strtable->numMsgs = 0;
    v2 = 0;
    strtable->msgs = 0;
    numMsgs = 0;
    strtable->hashtable = 0;
    strtable->magic_sTbl = 0;
    fhand = std_pHS->fileOpen(fpath, "rt");

    if ( !fhand )
        return 0;

    do
    {
        std_pHS->fileGets(fhand, a1a, 255);
        if ( !_strchr(a1a, 10) )
        {
            do
            {
                std_pHS->fileGets(fhand, v32, 64);
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
        std_pHS->fileClose(fhand);
        std_pHS->errorPrint("Bad 'MSG n' line in string table file '%s'\n", fpath);
        return 0;
    }
    strtable->numMsgs = numMsgs;
    strtable->msgs = std_pHS->alloc(sizeof(stdStrMsg) * numMsgs);
    if ( !strtable->msgs )
        std_pHS->assert("Out of memory--cannot load string table", ".\\General\\stdStrTable.c", 120);
    _memset(strtable->msgs, 0, sizeof(stdStrMsg) * numMsgs);
    strtable->hashtable = stdHashTable_New(numMsgs + (numMsgs/2));
    if ( !strtable->hashtable )
        std_pHS->assert("Out of memory--cannot load string table", ".\\General\\stdStrTable.c", 126);
    v11 = 1;
    v30 = 0;
    value = strtable->msgs;
    do
    {
        if ( v30 >= numMsgs )
            break;
        v12 = 0;
        do
        {
            std_pHS->fileGets(fhand, a1a, 255);
            if ( !_strchr(a1a, '\n') )
            {
                do
                    std_pHS->fileGets(fhand, v32, 64);
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
            strtable->numMsgs = v30;
            v11 = 0;
            std_pHS->errorPrint("Premature 'END' found after only %d lines in '%s'.  Check number in 'MSG xxx' header.\n", v16, fpath);
        }
        if ( v11 )
        {
            v17 = stdString_GetQuotedStringContents(a1a, v34, 256);
            if ( v17 )
            {
                v18 = (char *)std_pHS->alloc(_strlen(v34) + 1);
                _strcpy(v18, v34);
                v19 = value;
                value->key = v18;
                v20 = stdString_CopyBetweenDelimiter(v17, v34, 256, " \t");
                if ( v20 )
                {
                    v19->field_8 = _atoi(v34);
                    stdString_GetQuotedStringContents(v20, v34, 256);
                    v19->uniStr = stdString_CstrCopy(v34);
                    if ( !stdHashTable_SetKeyVal(strtable->hashtable, v19->key, v19) )
                        stdPrintf(
                            std_pHS->errorPrint,
                            ".\\General\\stdStrTable.c",
                            177,
                            "The key '%s' is in the string table '%s' more than once.\n   >>>%s\n",
                            value->key,
                            fpath,
                            a1a);
                }
                else
                {
                    stdPrintf(
                        std_pHS->errorPrint,
                        ".\\General\\stdStrTable.c",
                        164,
                        "Cannot understand this line in string table '%s'.\n   >>> %s\n",
                        fpath,
                        a1a);
                }
            }
            else
            {
                stdPrintf(
                    std_pHS->errorPrint,
                    ".\\General\\stdStrTable.c",
                    155,
                    "Cannot understand this line in string table '%s'.\n   >>> %s\n",
                    fpath,
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
            std_pHS->fileGets(fhand, a1a, 255);
            if ( !_strchr(a1a, '\n') )
            {
                do
                    std_pHS->fileGets(fhand, v32, 64);
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
            std_pHS->errorPrint("'END' not found in '%s'.  Enlarge number in 'MSG xxx' header.\n", fpath);
        }
    }
    strtable->magic_sTbl = 0x7354626C;
    std_pHS->fileClose(fhand);
    return v11;
}

void stdStrTable_Free(stdStrTable* pTable)
{
    stdStrMsg *msgs; // ebp
    stdStrMsg *msg; // esi

    if ( pTable->magic_sTbl == 0x7354626C )
    {
        pTable->magic_sTbl = 0;
        // Added: Moved
        //pTable->numMsgs = 0;
        //pTable->msgs = 0;
        stdHashTable_Free(pTable->hashtable);
        if ( pTable->msgs )
        {
            for (int i = 0; i < pTable->numMsgs; i++)
            {
                if ( pTable->msgs[i].uniStr )
                    std_pHS->free((void*)pTable->msgs[i].uniStr);
                if ( pTable->msgs[i].key )
                    std_pHS->free((void*)pTable->msgs[i].key);
            }
            std_pHS->free(pTable->msgs);
        }

        // Added: Moved
        pTable->numMsgs = 0;
        pTable->msgs = 0;
    }
    else
    {
        //stdPlatform_Printf("OpenJKDF2: Tried to free bad stdStrTable %p? magic==%x\n", pTable, pTable->magic_sTbl);
    }
}

wchar_t* stdStrTable_GetUniString(stdStrTable* pTable, const char *key)
{
    stdStrMsg *v2; // eax
    wchar_t *result; // eax

    if ( pTable->numMsgs && (v2 = (stdStrMsg *)stdHashTable_GetKeyVal(pTable->hashtable, key)) != 0 )
        result = v2->uniStr;
    else
        result = 0;
    return result;
}

wchar_t* stdStrTable_GetStringWithFallback(stdStrTable* pTable, char *key)
{
    stdStrMsg *v2; // eax
    wchar_t *result; // eax

    if ( pTable->numMsgs && (v2 = (stdStrMsg *)stdHashTable_GetKeyVal(pTable->hashtable, key)) != 0 )
        result = v2->uniStr;
    else
        result = 0;
    if ( !result )
    {
        stdString_CharToWchar(stdStrTable_tmpBuf, key, 63);
        stdStrTable_tmpBuf[63] = 0;
        result = stdStrTable_tmpBuf;
    }
    return result;
}
