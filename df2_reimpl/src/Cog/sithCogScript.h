#ifndef _SITHCOGSCRIPT_H
#define _SITHCOGSCRIPT_H

#include "types.h"

typedef struct sithCogTrigger
{
    uint32_t trigId;
    uint32_t trigPc;
    uint32_t field_8;
} sithCogTrigger;

typedef struct sithCog sithCog;
typedef void (__cdecl *cogSymbolFunc_t)(sithCog *);

typedef struct cogSymbol
{
    int type;
    int val;
    cogSymbolFunc_t func;
} cogSymbol;

typedef struct sithCogSymbol
{
  int symbol_id;
  int symbol_type;
  union
  {
    char *symbol_name;
    cogSymbolFunc_t func;
  };
  int field_C;
  int field_10;
  int field_14;
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

typedef struct sithCogScript
{
    uint32_t debug_maybe;
    char cog_fpath[32];
    int* script_program;
    uint32_t program_pc_max;
    sithCogSymboltable *symboltable_hashmap;
    uint32_t num_triggers;
    sithCogTrigger triggers[4];
    uint32_t field_64;
    uint32_t field_68;
    uint32_t field_6C;
    uint32_t field_70;
    uint32_t field_74[1872];
    uint32_t field_1DB4;
} sithCogScript;

#endif // _SITHCOGSCRIPT_H
