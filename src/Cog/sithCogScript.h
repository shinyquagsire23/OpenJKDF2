#ifndef _SITHCOGSCRIPT_H
#define _SITHCOGSCRIPT_H

#include "types.h"

typedef struct sithCogTrigger
{
    uint32_t trigId;
    uint32_t trigPc;
    uint32_t field_8;
} sithCogTrigger;

typedef struct cogSymbol
{
    int32_t type;
    cog_int_t val;
    cogSymbolFunc_t func;
} cogSymbol;

typedef struct sithCogSymbol
{
  int32_t symbol_id;
  sithCogStackvar val;
#if 0
  int32_t symbol_type;
  union
  {
    char *symbol_name;
    cogSymbolFunc_t func;
    cog_flex_t as_float;
    cog_flex_t as_flex;
    cog_int_t as_int;
    void* as_data;
    sithAIClass* as_aiclass;
    rdVector3 as_vec3;
    intptr_t as_intptrs[3];
  };
#endif
  int32_t field_14;
  char* field_18;
} sithCogSymbol;

typedef struct sithCogSymboltable
{
    sithCogSymbol* buckets;
    stdHashTable* hashtable;
    uint32_t entry_cnt;
    uint32_t max_entries;
    uint32_t bucket_idx;
    uint32_t unk_14;
} sithCogSymboltable;

typedef struct sithCogReference
{
    int type;
    int flags;
    int linkid;
    int mask;
    int hash;
    char* desc;
    char value[32];
} sithCogReference;

typedef struct sithCogScript
{
    sithCogFlags_t cogFlags;
    char cog_fpath[32];
    int* script_program;
    uint32_t codeSize;
    sithCogSymboltable *pSymbolTable;
    uint32_t num_triggers;
    sithCogTrigger triggers[32];
    sithCogReference aIdk[128];
    uint32_t numIdk;
} sithCogScript;

#endif // _SITHCOGSCRIPT_H
