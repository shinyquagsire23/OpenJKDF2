#include "stdStrTable.h"

#include "stdPlatform.h"
#include "General/stdString.h"

static wchar_t stdStrTable_tmpBuf[64];

void stdStrTable_Free(stdStrTable *table)
{
    stdStrMsg *msgs; // ebp
    stdStrMsg *msg; // esi

    if ( table->magic_sTbl == 0x7354626C )
    {
        table->magic_sTbl = 0;
        table->numMsgs = 0;
        table->msgs = 0;
        stdHashTable_Free(table->hashtable);
        if ( table->msgs )
        {
            for (int i = 0; i < table->numMsgs; i++)
            {
                if ( table->msgs[i].uniStr )
                    std_pHS->free(table->msgs[i].uniStr);
                if ( table->msgs[i].field_0 )
                    std_pHS->free(table->msgs[i].field_0);
            }
            std_pHS->free(table->msgs);
        }
    }
}

wchar_t* stdStrTable_GetUniString(stdStrTable *table, const char *key)
{
    stdStrMsg *v2; // eax
    wchar_t *result; // eax

    if ( table->numMsgs && (v2 = (stdStrMsg *)stdHashTable_GetKeyVal(table->hashtable, key)) != 0 )
        result = v2->uniStr;
    else
        result = 0;
    return result;
}

wchar_t* stdStrTable_GetString(stdStrTable *table, char *key)
{
    stdStrMsg *v2; // eax
    wchar_t *result; // eax

    if ( table->numMsgs && (v2 = (stdStrMsg *)stdHashTable_GetKeyVal(table->hashtable, key)) != 0 )
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
