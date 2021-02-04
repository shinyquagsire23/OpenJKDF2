#include "sithCogParse.h"

#include <stdlib.h>

#include "Cog/y.tab.h"
#include "Cog/sithCogYACC.h"
#include "General/stdHashTable.h"
#include "stdPlatform.h"

#include "jk.h"

// For progress tracking script...
void sithCogYACC_yyerror(){}
void sithCogYACC_yyparse(){}
void sithCogYACC_yylex(){}
void sithCogYACC_yy_get_next_buffer(){}
void sithCogYACC_yyrestart(){}
void sithCogYACC_yy_switch_to_buffer(){}
void sithCogYACC_yy_load_buffer_state(){}
void sithCogYACC_yy_create_buffer(){}
void sithCogYACC_yy_delete_buffer(){}
void sithCogYACC_yy_init_buffer(){}

#define yyin (*(int*)0x00855D90)
#define yyout (*(int*)0x00855D94)

void sithCogParse_Reset()
{
    if ( cogparser_nodes_alloc )
    {
        pSithHS->free(cogparser_nodes_alloc);
        cogparser_num_nodes = 0;
        cogparser_current_nodeidx = 0;
    }
}

int sithCogParse_Load(char *cog_fpath, sithCogScript *cogscript, int unk)
{
    int result; // eax
    const char *v4; // eax
    sithCogSymboltable *symboltable; // eax
    unsigned int v6; // ecx
    int *v7; // eax
    int v8; // edx

    result = stdConffile_OpenRead(cog_fpath);
    if ( result )
    {
        memset(cogscript, 0, sizeof(sithCogScript));
        v4 = stdFileFromPath(cog_fpath);
        _strncpy(cogscript->cog_fpath, v4, 0x1Fu);
        memset(cog_parser_node_stackpos, 0xFFu, sizeof(cog_parser_node_stackpos));
        cogscript->cog_fpath[31] = 0;
        cog_yacc_loop_depth = 1;
        if ( !stdConffile_ReadArgs() )
            goto LABEL_54;
        if ( !_strcmp(stdConffile_entry.args[0].key, "flags") )
        {
            _sscanf(stdConffile_entry.args[0].value, "%x", cogscript);
            if ( !stdConffile_ReadArgs() )
                goto LABEL_54;
        }
        if ( _strcmp(stdConffile_entry.args[0].value, "symbols") )
            goto LABEL_54;
        symboltable = sithCogParse_NewSymboltable(256);
        cogscript->symboltable_hashmap = symboltable;
        if ( !symboltable )
            goto LABEL_54;
        while ( stdConffile_ReadArgs() )
        {
            if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
                break;
            if ( cogscript->symboltable_hashmap->entry_cnt < (unsigned int)cogscript->symboltable_hashmap->max_entries )
            {
                if ( !_strcmp(stdConffile_entry.args[0].value, "thing") )
                {
                    sithCogParse_ParseSymbol(cogscript, 3, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "surface") )
                {
                    sithCogParse_ParseSymbol(cogscript, 6, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "sector") )
                {
                    sithCogParse_ParseSymbol(cogscript, 5, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "sound") )
                {
                    sithCogParse_ParseSymbol(cogscript, 8, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "template") )
                {
                    sithCogParse_ParseSymbol(cogscript, 4, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "model") )
                {
                    sithCogParse_ParseSymbol(cogscript, 12, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "keyframe") )
                {
                    sithCogParse_ParseSymbol(cogscript, 7, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "cog") )
                {
                    sithCogParse_ParseSymbol(cogscript, 9, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "message") )
                {
                    sithCogParse_ParseMessage(cogscript);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "material") )
                {
                    sithCogParse_ParseSymbol(cogscript, 10, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "flex") || !_strcmp(stdConffile_entry.args[0].value, "float") )
                {
                    sithCogParse_ParseFlex(cogscript, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "int") )
                {
                    sithCogParse_ParseInt(cogscript, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "vector") )
                {
                    sithCogParse_ParseVector(cogscript, unk);
                }
                else if ( !_strcmp(stdConffile_entry.args[0].value, "ai") )
                {
                    sithCogParse_ParseSymbol(cogscript, 13, unk);
                }
            }
        }
        if ( stdConffile_ReadArgs() && !_strcmp(stdConffile_entry.args[0].value, "code") && sithCogParse_LoadEntry(cogscript) )
        {
            v6 = 0;
            if ( cogscript->num_triggers )
            {
                v7 = &cogscript->triggers[0].trigPc;
                do
                {
                    v8 = v7[1];
                    ++v6;
                    v7 += 3;
                    *(v7 - 3) = cog_parser_node_stackpos[v8];
                }
                while ( v6 < cogscript->num_triggers );
            }
            stdConffile_Close();
            result = 1;
        }
        else
        {
LABEL_54:
            if ( cogscript->symboltable_hashmap )
            {
                sithCogParse_FreeSymboltable(cogscript->symboltable_hashmap);
                cogscript->symboltable_hashmap = 0;
            }
            if ( cogparser_topnode )
            {
                cogparser_current_nodeidx = 0;
                cogparser_topnode = 0;
            }
            stdConffile_Close();
            result = 0;
        }
    }
    return result;
}

int sithCogParse_LoadEntry(sithCogScript *script)
{
    FILE *fhand; // eax
    sith_cog_parser_node *v2; // eax
    sith_cog_parser_node *v3; // esi
    sith_cog_parser_node *v4; // eax
    int v5; // eax
    int v6; // eax
    int *script_program; // eax
    signed int result; // eax
    sith_cog_parser_node *cur_instr; // esi
    int script_prog_curidx; // ecx
    int *script_prog_next; // edx
    sith_cog_parser_node *node_parent; // eax
    int op; // eax
    int stack_pos; // ecx
    int v15; // eax
    int *v17; // edx
    int next_stackpos; // ecx

    fhand = stdConffile_GetFileHandle();
    parsing_script = script;
    yyin = (int)fhand;
    sithCogParse_symbolTable = script->symboltable_hashmap;
    if ( parsing_script_idk )
        parsing_script_idk = 0;
    else
        sithCogYACC_yyrestart(fhand);
    yacc_linenum = 1;
    if (yyparse())
    {
LABEL_19:
        if ( cogparser_topnode )
        {
            cogparser_current_nodeidx = 0;
            cogparser_topnode = 0;
        }
        cogvm_stackpos = 0;
        result = 0;
    }
    else
    {
        v2 = cogparser_topnode;
        cogvm_stackpos = 0;
        v3 = cogparser_topnode;
        if ( cogparser_topnode->child_loop_depth )
            cog_parser_node_stackpos[cogparser_topnode->child_loop_depth] = 0;
        v4 = v2->parent;
        if ( v4 )
            sithCogParse_RecurseStackdepth(v4);
        if ( v3->child )
            sithCogParse_RecurseStackdepth(v3->child);
        switch ( v3->opcode )
        {
            case COG_OPCODE_NOP:
                goto LABEL_16;
            case COG_OPCODE_PUSHINT:
            case COG_OPCODE_PUSHFLOAT:
            case COG_OPCODE_PUSHSYMBOL:
            case COG_OPCODE_GOFALSE:
            case COG_OPCODE_GOTRUE:
            case COG_OPCODE_GO:
            case COG_OPCODE_CALL:
                v5 = cogvm_stackpos + 2;
                goto LABEL_15;
            case COG_OPCODE_PUSHVECTOR:
                v5 = cogvm_stackpos + 4;
                goto LABEL_15;
            default:
                v5 = cogvm_stackpos + 1;
LABEL_15:
                cogvm_stackpos = v5;
LABEL_16:
                v6 = v3->parent_loop_depth;
                if ( v6 )
                    cog_parser_node_stackpos[v6] = cogvm_stackpos;
                script_program = (int *)pSithHS->alloc(4 * cogvm_stackpos + 4);
                script->script_program = script_program;
                if ( !script_program )
                    goto LABEL_19;
                cur_instr = cogparser_topnode;
                script_prog_curidx = 0;
                script->program_pc_max = cogvm_stackpos + 1;
                script_prog_next = script_program;
                node_parent = cur_instr->parent;
                cogvm_stackpos = 0;
                cogvm_stack = script_prog_next;
                if ( node_parent )
                {
                    sithCogParse_RecurseWrite(node_parent);
                    script_prog_curidx = cogvm_stackpos;
                    script_prog_next = cogvm_stack;
                }
                if ( cur_instr->child )
                {
                    sithCogParse_RecurseWrite(cur_instr->child);
                    script_prog_curidx = cogvm_stackpos;
                    script_prog_next = cogvm_stack;
                }
                op = cur_instr->opcode;
                if ( op )
                {
                    script_prog_next[script_prog_curidx] = op;
                    stack_pos = script_prog_curidx + 1;
                    cogvm_stackpos = stack_pos;
                    switch ( op )
                    {
                        case COG_OPCODE_PUSHINT:
                        case COG_OPCODE_PUSHFLOAT:
                        case COG_OPCODE_PUSHSYMBOL:
                            v15 = cur_instr->value;
                            goto LABEL_31;
                        case COG_OPCODE_PUSHVECTOR:
                            v17 = &script_prog_next[stack_pos];
                            next_stackpos = stack_pos + 3;
                            _memcpy(v17, &cur_instr->vector, sizeof(rdVector3));
                            goto LABEL_32;
                        case COG_OPCODE_GOFALSE:
                        case COG_OPCODE_GOTRUE:
                        case COG_OPCODE_GO:
                        case COG_OPCODE_CALL:
                            v15 = cog_parser_node_stackpos[cur_instr->value];
LABEL_31:
                            script_prog_next[stack_pos] = v15;
                            next_stackpos = stack_pos + 1;
LABEL_32:
                            cogvm_stackpos = next_stackpos;
                            break;
                        default:
                            break;
                    }
                }
                script->script_program[script->program_pc_max - 1] = 29;
                cogparser_current_nodeidx = 0;
                cogparser_topnode = 0;
                result = 1;
                break;
        }
    }
    return result;
}

sithCogSymboltable* sithCogParse_CopySymboltable(sithCogSymboltable *table)
{
    int entry_cnt; // ebp
    sithCogSymboltable *newTable; // ebx
    struct common_functions *v3; // edx
    sithCogSymbol *buckets; // eax
    sithCogSymboltable *result; // eax

    entry_cnt = table->entry_cnt;
    newTable = (sithCogSymboltable *)pSithHS->alloc(24);
    if ( !newTable )
        return 0;
    v3 = pSithHS;
    _memset(newTable, 0, sizeof(sithCogSymboltable));
    buckets = (sithCogSymbol *)v3->alloc(sizeof(sithCogSymbol) * entry_cnt);
    newTable->buckets = buckets;
    if ( !buckets )
        return 0;
    _memcpy(buckets, table->buckets, 4 * ((sizeof(sithCogSymbol) * entry_cnt) >> 2));
    result = newTable;
    newTable->max_entries = entry_cnt;
    newTable->entry_cnt = entry_cnt;
    newTable->unk_14 = 1;
    return result;
}

sithCogSymboltable* sithCogParse_NewSymboltable(int amt)
{
    sithCogSymboltable *newTable; // esi
    stdHashTable *newHashtable; // eax
    sithCogSymbol *buckets; // edi
    sithCogSymboltable *result; // eax

    newTable = (sithCogSymboltable *)pSithHS->alloc(24);
    if ( newTable
      && (memset(newTable, 0, sizeof(sithCogSymboltable)),
          newTable->buckets = (sithCogSymbol *)pSithHS->alloc(sizeof(sithCogSymbol) * amt),
          newHashtable = stdHashTable_New(2 * amt),
          buckets = newTable->buckets,
          newTable->hashtable = newHashtable,
          newTable->buckets)
      && newHashtable )
    {
        memset(buckets, 0, sizeof(sithCogSymbol) * amt);
        newTable->max_entries = amt;
        newTable->entry_cnt = 0;
        newTable->unk_14 = 0;
        result = newTable;
    }
    else
    {
        stdPrintf((int)pSithHS->errorPrint, ".\\Cog\\sithCogParse.c", 421, "Failed to create memory for symbol table.\n", 0, 0, 0, 0);
        if ( newTable )
        {
            if ( newTable->buckets )
                pSithHS->free(newTable->buckets);
            if ( newTable->hashtable )
                stdHashTable_Free(newTable->hashtable);
            pSithHS->free(newTable);
        }
        result = 0;
    }
    return result;
}

int sithCogParse_ReallocSymboltable(sithCogSymboltable *table)
{
    unsigned int amt; // eax
    sithCogSymbol *reallocBuckets; // eax
    int reallocAmt; // ecx
    unsigned int result; // eax
    unsigned int i_; // ebx
    sithCogSymbol *buckets; // ecx
    int i; // esi

    if ( table->hashtable )
    {
        stdHashTable_Free(table->hashtable);
        table->hashtable = 0;
    }
    amt = table->entry_cnt;
    if ( table->max_entries > amt )
    {
        reallocBuckets = (sithCogSymbol *)pSithHS->realloc(table->buckets, sizeof(sithCogSymbol) * amt);
        reallocAmt = table->entry_cnt;
        table->buckets = reallocBuckets;
        table->max_entries = reallocAmt;
    }
    result = table->max_entries;
    i_ = 0;
    if ( result )
    {
        buckets = table->buckets;
        i = 0;
        do
        {
            if ( buckets[i].field_18 )
            {
                pSithHS->free(buckets[i].field_18);
                buckets = table->buckets;
                table->buckets[i].field_18 = 0;
            }
            result = table->max_entries;
            ++i_;
            ++i;
        }
        while ( i_ < result );
    }
    return result;
}

void sithCogParse_FreeSymboltable(sithCogSymboltable *table)
{
    sithCogSymbol *v1; // eax
    unsigned int v2; // ebx
    int v3; // esi
    char *v4; // eax

    if ( table->hashtable )
    {
        stdHashTable_Free(table->hashtable);
        table->hashtable = 0;
    }
    v1 = table->buckets;
    if ( table->buckets )
    {
        if ( !table->unk_14 )
        {
            v2 = 0;
            if ( table->max_entries )
            {
                v3 = 0;
                do
                {
                    v4 = v1[v3].field_18;
                    if ( v4 )
                        pSithHS->free(v4);
                    v1 = table->buckets;
                    if ( table->buckets[v3].symbol_type == 4 )
                    {
                        pSithHS->free(v1[v3].symbol_name);
                        v1 = table->buckets;
                        table->buckets[v3].symbol_name = 0;
                    }
                    ++v2;
                    ++v3;
                }
                while ( v2 < table->max_entries );
            }
        }
        pSithHS->free(table->buckets);
        table->buckets = 0;
    }
    pSithHS->free(table);
}

sithCogSymbol* sithCogParse_AddSymbol(sithCogSymboltable *table, const char *symbolName)
{
    if ( table->max_entries > table->entry_cnt )
    {
        sithCogSymbol* symbol = &table->buckets[table->entry_cnt];
        table->entry_cnt++;
        if ( symbolName )
        {
            char* key = (char *)pSithHS->alloc(_strlen(symbolName) + 1);
            _strcpy(key, symbolName);
            symbol->field_18 = key;
            if ( table->hashtable )
                stdHashTable_SetKeyVal(table->hashtable, key, symbol);
        }
        symbol->field_14 = cog_yacc_loop_depth;
        cog_yacc_loop_depth++;
        symbol->symbol_id = table->bucket_idx + symbol - table->buckets;
        return symbol;
    }
    else
    {
        stdPrintf((int)pSithHS->errorPrint, ".\\Cog\\sithCogParse.c", 573, "No space for COG symbol %s.\n", symbolName);
        return NULL;
    }
}

void* sithCogParse_GetSymbolVal(sithCogSymboltable *symbolTable, char *a2)
{
    void *result; // eax

    if ( (!symbolTable->hashtable || (result = stdHashTable_GetKeyVal(symbolTable->hashtable, a2)) == 0)
      && (!g_cog_symboltable_hashmap
       || symbolTable == g_cog_symboltable_hashmap
       || (g_cog_symboltable_hashmap->hashtable) == 0
       || (result = stdHashTable_GetKeyVal(g_cog_symboltable_hashmap->hashtable, a2)) == 0) )
    {
        result = 0;
    }
    return result;
}

sithCogSymbol* sithCogParse_GetSymbol(sithCogSymboltable *table, unsigned int idx)
{
    unsigned int idx_; // eax
    sithCogSymboltable *symbolTable; // ecx
    sithCogSymbol *result; // eax

    idx_ = idx;
    if ( idx < 0x100 )
    {
        symbolTable = table;
    }
    else
    {
        symbolTable = g_cog_symboltable_hashmap;
        idx_ = idx - 256;
    }
    if ( symbolTable && idx_ < symbolTable->entry_cnt )
        result = &symbolTable->buckets[idx_];
    else
        result = 0;
    return result;
}

int sithCogParse_GetSymbolScriptIdx(unsigned int idx)
{
    unsigned int idx_; // ecx
    sithCogSymboltable *table; // eax
    int result; // eax

    idx_ = idx;
    table = sithCogParse_symbolTable;
    if ( idx >= 0x100 )
    {
        table = g_cog_symboltable_hashmap;
        idx_ = idx - 256;
    }
    if ( table && idx_ < table->entry_cnt )
        result = table->buckets[idx_].field_14;
    else
        result = table->buckets[0].field_14; // ????
    return result;
}

sith_cog_parser_node* sithCogParse_AddLeaf(int op, int val)
{
    return sithCogParse_AddLinkingNode(NULL, NULL, op, (int)val);
}

sith_cog_parser_node* sithCogParse_AddLeafVector(int opcode, rdVector3* vector)
{
    if (!cogparser_nodes_alloc)
    {
        cogparser_nodes_alloc = (sith_cog_parser_node *)malloc(8096 * sizeof(sith_cog_parser_node));
        cogparser_num_nodes = 8096;
    }
    
    if ( cogparser_current_nodeidx == cogparser_num_nodes )
    {
        cogparser_nodes_alloc = (sith_cog_parser_node*)realloc(cogparser_nodes_alloc, 2 * cogparser_num_nodes * sizeof(sith_cog_parser_node));
        cogparser_num_nodes *= 2;
    }
    
    sith_cog_parser_node* node = &cogparser_nodes_alloc[cogparser_current_nodeidx++];
    _memset(node, 0, sizeof(sith_cog_parser_node));
    node->opcode = opcode;
    node->vector = *vector;
    
    cogparser_topnode = node;
    //printf("Add node %p w/ op %x, %p %p\n", node, opcode, parent, child);
    
    return node;
}

sith_cog_parser_node* sithCogParse_AddLinkingNode(sith_cog_parser_node* parent, sith_cog_parser_node* child, int opcode, int val)
{
    if (!cogparser_nodes_alloc)
    {
        cogparser_nodes_alloc = (sith_cog_parser_node *)malloc(8096 * sizeof(sith_cog_parser_node));
        cogparser_num_nodes = 8096;
    }
    
    if ( cogparser_current_nodeidx == cogparser_num_nodes )
    {
        cogparser_nodes_alloc = (sith_cog_parser_node*)realloc(cogparser_nodes_alloc, 2 * cogparser_num_nodes * sizeof(sith_cog_parser_node));
        cogparser_num_nodes *= 2;
    }
    
    sith_cog_parser_node* node = &cogparser_nodes_alloc[cogparser_current_nodeidx++];
    _memset(node, 0, sizeof(sith_cog_parser_node));
    node->opcode = opcode;
    node->value = val;
    node->parent = parent;
    node->child = child;
    
    cogparser_topnode = node;
    //printf("Add node %p w/ op %x, %p %p\n", node, opcode, parent, child);
    
   return node;
}

int sithCogParse_IncrementLoopdepth()
{
    return cog_yacc_loop_depth++;
}

void sithCogParse_LexGetSym(char *symName)
{
    sithCogSymbol *v6; // ecx
    unsigned int v9; // ecx
    sithCogSymbol *v11; // ebx
    stdHashTable *v12; // ecx
    sithCogSymbol *v13; // edi
    int v14; // eax
    int v15; // [esp+18h] [ebp-8h]
    int v16; // [esp+1Ch] [ebp-4h]
    char *lpSrcStra; // [esp+24h] [ebp+4h]

    _strtolower(symName);
    v6 = sithCogParse_GetSymbolVal(sithCogParse_symbolTable, symName);

    if ( v6 )
    {
        yylval.as_int = v6->symbol_id;
    }
    else
    {
        v9 = sithCogParse_symbolTable->entry_cnt;
        if ( sithCogParse_symbolTable->max_entries > v9 )
        {
            v11 = &sithCogParse_symbolTable->buckets[v9];
            sithCogParse_symbolTable->entry_cnt = v9 + 1;
            if ( symName )
            {
                lpSrcStra = (char *)pSithHS->alloc(_strlen(symName) + 1);
                _strcpy(lpSrcStra, symName);
                v12 = sithCogParse_symbolTable->hashtable;
                v11->field_18 = lpSrcStra;
                if ( v12 )
                    stdHashTable_SetKeyVal(v12, lpSrcStra, v11);
            }
            v13 = sithCogParse_symbolTable->buckets;
            v14 = cog_yacc_loop_depth + 1;
            v11->field_14 = cog_yacc_loop_depth;
            cog_yacc_loop_depth = v14;
            v11->symbol_id = sithCogParse_symbolTable->bucket_idx + v11 - v13;
        }
        else
        {
            stdPrintf((int)pSithHS->errorPrint, ".\\Cog\\sithCogParse.c", 573, "No space for COG symbol %s.\n", symName);
            v11 = 0;
        }
        if ( v11 )
        {
            v11->symbol_type = 2;
            v11->symbol_name = 0;
            v11->field_C = 0;//v15;
            yylval.as_int = v11->symbol_id;
            v11->field_10 = 0;//v16;
        }
    }
}

void sithCogParse_LexAddSymbol(const char *symName)
{
    sithCogSymboltable *v1; // edi
    unsigned int v2; // eax
    sithCogSymbol *symbol; // esi
    sithCogSymbol *v5; // ecx
    int v6; // eax
    unsigned int v7; // edx
    char *name; // edx

    v1 = sithCogParse_symbolTable;
    v2 = sithCogParse_symbolTable->entry_cnt;
    if ( sithCogParse_symbolTable->max_entries > v2 )
    {
        sithCogParse_symbolTable->entry_cnt = v2 + 1;
        v5 = &sithCogParse_symbolTable->buckets[v2];
        v6 = cog_yacc_loop_depth + 1;
        v5->field_14 = cog_yacc_loop_depth;
        cog_yacc_loop_depth = v6;
        symbol = v5;
        v7 = (int)((uint64_t)(2454267027 * ((char *)v5 - (char *)sithCogParse_symbolTable->buckets)) >> 32) >> 4;
        v5->symbol_id = v1->bucket_idx + (v7 >> 31) + v7;
    }
    else
    {
        stdPrintf((int)pSithHS->errorPrint, ".\\Cog\\sithCogParse.c", 573, "No space for COG symbol %s.\n", 0);
        symbol = 0;
    }
    if ( symbol )
    {
        symbol->symbol_type = COG_VARTYPE_STR;
        name = (char *)pSithHS->alloc(_strlen(symName) - 1);
        symbol->symbol_name = name;
        _strncpy(name, symName + 1, _strlen(symName) - 2);
        symbol->symbol_name[_strlen(symName) - 2] = 0;
        yylval.as_int = symbol->symbol_id;
    }
}

void sithCogParse_LexScanVector3(char* text)
{
    rdVector3 scan_in;
    _sscanf(text, "'%f %f %f'", &scan_in.x, &scan_in.y, &scan_in.z);
    yylval.as_vector = scan_in;
}

int sithCogParse_RecurseStackdepth(sith_cog_parser_node *node)
{
    int result; // eax
    int v2; // esi

    if ( node->child_loop_depth )
        cog_parser_node_stackpos[node->child_loop_depth] = cogvm_stackpos;

    if ( node->parent )
        sithCogParse_RecurseStackdepth(node->parent);

    if ( node->child )
        sithCogParse_RecurseStackdepth(node->child);

    result = node->opcode;
    switch ( result )
    {
        case COG_OPCODE_NOP:
            goto LABEL_12;
        case COG_OPCODE_PUSHINT:
        case COG_OPCODE_PUSHFLOAT:
        case COG_OPCODE_PUSHSYMBOL:
        case COG_OPCODE_GOFALSE:
        case COG_OPCODE_GOTRUE:
        case COG_OPCODE_GO:
        case COG_OPCODE_CALL:
            result = cogvm_stackpos + 2;
            goto LABEL_11;
        case COG_OPCODE_PUSHVECTOR:
            result = cogvm_stackpos + 4;
            goto LABEL_11;
        default:
            result = cogvm_stackpos + 1;
LABEL_11:
            cogvm_stackpos = result;
LABEL_12:
            v2 = node->parent_loop_depth;
            if ( v2 )
            {
                result = cogvm_stackpos;
                cog_parser_node_stackpos[v2] = cogvm_stackpos;
            }
            return result;
    }
}

void sithCogParse_RecurseWrite(sith_cog_parser_node *node)
{
    if ( node->parent )
        sithCogParse_RecurseWrite(node->parent);

    if ( node->child )
        sithCogParse_RecurseWrite(node->child);

    if (!node->opcode )
        return;

    cogvm_stack[cogvm_stackpos] = node->opcode;
    cogvm_stackpos++;
    switch ( node->opcode )
    {
        case COG_OPCODE_PUSHINT:
        case COG_OPCODE_PUSHFLOAT:
        case COG_OPCODE_PUSHSYMBOL:
            cogvm_stack[cogvm_stackpos] = node->value;
            cogvm_stackpos++;
            break;
        case COG_OPCODE_PUSHVECTOR:
            _memcpy(&cogvm_stack[cogvm_stackpos], &node->vector, sizeof(rdVector3));
            cogvm_stackpos += 3;
            break;
        case COG_OPCODE_GOFALSE:
        case COG_OPCODE_GOTRUE:
        case COG_OPCODE_GO:
        case COG_OPCODE_CALL:
            cogvm_stack[cogvm_stackpos++] = cog_parser_node_stackpos[node->value];
            break;
        default:
            return;
    }
}
