#ifndef _SITHCOGSCRIPT_H
#define _SITHCOGSCRIPT_H

typedef struct sithCogTrigger
{
    uint32_t trigId;
    uint32_t trigPc;
    uint32_t field_8;
} sithCogTrigger;

typedef struct sithCogSymboltable
{
    uint32_t hashmap_buckets_maybe;
    uint32_t hashmap_idk_amt_twice;
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
