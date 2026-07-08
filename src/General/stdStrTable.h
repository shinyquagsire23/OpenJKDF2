#ifndef _STDSTRTABLE_H
#define _STDSTRTABLE_H

#include <stddef.h>
#include "General/stdHashtbl.h"

#define stdStrTable_Load_ADDR (0x004359B0)
#define stdStrTable_Free_ADDR (0x00435F30)
#define stdStrTable_GetValue_ADDR (0x00435FB0)
#define stdStrTable_GetValueOrKey_ADDR (0x00435FE0)
#define stdStrTable_ReadLine_ADDR (0x00436030)
#define stdStrTable_ParseUniLine_ADDR (0x00436100)

typedef struct stdStrMsg
{
    const char* key;
    wchar_t* uniStr;
    uint32_t field_8;
} stdStrMsg;

typedef struct stdStrTable
{
    uint32_t numMsgs;
    stdStrMsg* msgs;
    tHashTable* pHashtbl;
    uint32_t magic_sTbl;
} stdStrTable;

int stdStrTable_Load(stdStrTable *strtable, char *fpath);
void stdStrTable_Free(stdStrTable* pTable);
wchar_t* stdStrTable_GetValue(stdStrTable* pTable, const char *key);
wchar_t* stdStrTable_GetValueOrKey(stdStrTable* pTable, const char *key);
int stdStrTable_ReadLine(stdFile_t hGobFile, char *buf, int bufLen);
int stdStrTable_ParseUniLine(stdFile_t hGobFile, wchar_t *buf);

//static int (__cdecl *stdStrTable_Load)(stdStrTable *strtable, char *fpath) = (void*)stdStrTable_Load_ADDR;


#endif // _STDSTRTABLE_H
