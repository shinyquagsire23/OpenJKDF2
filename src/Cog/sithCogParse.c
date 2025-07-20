#include "sithCogParse.h"

#include <stdlib.h>

#include "Cog/y.tab.h"
#include "Cog/sithCogYACC.h"
#include "General/stdHashTable.h"
#include "stdPlatform.h"
#include "Win95/std.h"
#include "General/stdConffile.h"
#include "General/stdString.h"

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

extern int yyparse();

// Added: debug
char* sithCogParse_lastParsedFile = "INVALID";

void sithCogParse_Reset()
{
    if ( cogparser_nodes_alloc )
    {
        pSithHS->free(cogparser_nodes_alloc);
        cogparser_num_nodes = 0;
        cogparser_current_nodeidx = 0;
    }

    // Added
    sithCogParse_lastParsedFile = "INVALID";
}

int sithCogParse_Load(char *cog_fpath, sithCogScript *cogscript, int unk)
{
    sithCogSymboltable *symboltable; // eax
    unsigned int v6; // ecx
    int v8; // edx

    if (!stdConffile_OpenRead(cog_fpath))
        return 0;

    //printf("%s\n", cog_fpath);

    // Added
    sithCogParse_lastParsedFile = cog_fpath;

    _memset(cogscript, 0, sizeof(sithCogScript));
#ifdef STDHASHTABLE_CRC32_KEYS
    const char* fname = stdFileFromPath(cog_fpath);
    cogscript->pathCrc = stdCrc32(fname, strlen(fname));
#else
    stdString_SafeStrCopy(cogscript->cog_fpath, stdFileFromPath(cog_fpath), 32);
#endif
    _memset(cog_parser_node_stackpos, 0xFFu, sizeof(cog_parser_node_stackpos));
    cog_yacc_loop_depth = 1;

    if ( !stdConffile_ReadArgs() )
        goto fail_cleanup;

    if ( !_strcmp(stdConffile_entry.args[0].key, "flags") )
    {
        _sscanf(stdConffile_entry.args[0].value, "%x", cogscript);
        if ( !stdConffile_ReadArgs() )
            goto fail_cleanup;
    }

    if ( _strcmp(stdConffile_entry.args[0].value, "symbols") )
        goto fail_cleanup;

    symboltable = sithCogParse_NewSymboltable(SITHCOG_LINKED_SYMBOL_LIMIT);
    cogscript->pSymbolTable = symboltable;
    if ( !symboltable )
        goto fail_cleanup;

    while ( stdConffile_ReadArgs() )
    {
        //printf("%s\n", stdConffile_entry.args[0].value);
        if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
            break;
        if ( cogscript->pSymbolTable->entry_cnt < (unsigned int)cogscript->pSymbolTable->max_entries )
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
        for (v6 = 0; v6 < cogscript->num_triggers; v6++)
        {
            v8 = cogscript->triggers[v6].field_8;
            cogscript->triggers[v6].trigPc = cog_parser_node_stackpos[v8];
        }
        stdConffile_Close();
        return 1;
    }
    else
    {
        goto fail_cleanup;
    }

fail_cleanup:
    if ( cogscript->pSymbolTable )
    {
        sithCogParse_FreeSymboltable(cogscript->pSymbolTable);
        cogscript->pSymbolTable = 0;
    }
    if ( cogparser_topnode )
    {
        cogparser_current_nodeidx = 0;
        cogparser_topnode = 0;
    }
    stdConffile_Close();
    return 0;
}

int sithCogParse_LoadEntry(sithCogScript *script)
{
    stdFile_t fhand; // eax
    sith_cog_parser_node *v2; // eax
    sith_cog_parser_node *v3; // esi
    int v5; // eax
    int v6; // eax
    int32_t *script_program; // eax
    signed int result; // eax
    sith_cog_parser_node *cur_instr; // esi
    int script_prog_curidx; // ecx
    int32_t *script_prog_next; // edx
    sith_cog_parser_node *node_parent; // eax
    int op; // eax
    int stack_pos; // ecx
    int v15; // eax
    int32_t *v17; // edx
    int next_stackpos; // ecx

    fhand = stdConffile_GetFileHandle();
    parsing_script = script;
    yyin = (stdFile_t)fhand;
    sithCogParse_pSymbolTable = script->pSymbolTable;
    if ( parsing_script_idk )
        parsing_script_idk = 0;
    else
        yyrestart((FILE*)fhand);
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
        if ( v2->parent )
            sithCogParse_RecurseStackdepth(v2->parent);
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
                script_program = (int32_t *)pSithHS->alloc(sizeof(int32_t) * cogvm_stackpos + sizeof(int32_t));
                script->script_program = script_program;
                if ( !script_program )
                    goto LABEL_19;
                cur_instr = cogparser_topnode;
                script_prog_curidx = 0;
                script->codeSize = cogvm_stackpos + 1;
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
                            _memcpy(v17, &cur_instr->vector, sizeof(cog_flex_t)*3);
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
                script->script_program[script->codeSize - 1] = 29;
                cogparser_current_nodeidx = 0;
                cogparser_topnode = 0;
                result = 1;
                break;
        }
    }

#ifdef QOL_IMPROVEMENTS
    if (yynerrs) {
#ifdef SITH_DEBUG_STRUCT_NAMES
        jk_printf("OpenJKDF2: PARSER error was in file: %s\n", script->cog_fpath);
#endif
    }
#endif

    return result;
}

sithCogSymboltable* sithCogParse_CopySymboltable(sithCogSymboltable *table)
{
    int entry_cnt; // ebp
    sithCogSymboltable *newTable; // ebx
    sithCogSymbol *buckets; // eax
    sithCogSymboltable *result; // eax

    entry_cnt = table->entry_cnt;
    newTable = (sithCogSymboltable *)pSithHS->alloc(sizeof(sithCogSymboltable));
    if ( !newTable )
        return 0;
    _memset(newTable, 0, sizeof(sithCogSymboltable));
    buckets = (sithCogSymbol *)pSithHS->alloc(sizeof(sithCogSymbol) * entry_cnt);
    newTable->buckets = buckets;
    if ( !buckets )
        return 0;
    _memcpy(buckets, table->buckets, sizeof(sithCogSymbol) * entry_cnt);
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

    newTable = (sithCogSymboltable *)pSithHS->alloc(sizeof(sithCogSymboltable));
    if ( newTable
      && (_memset(newTable, 0, sizeof(sithCogSymboltable)),
          newTable->buckets = (sithCogSymbol *)pSithHS->alloc(sizeof(sithCogSymbol) * amt),
          newHashtable = stdHashTable_New(2 * amt),
          buckets = newTable->buckets,
          newTable->hashtable = newHashtable,
          newTable->buckets)
      && newHashtable )
    {
        _memset(buckets, 0, sizeof(sithCogSymbol) * amt);
        newTable->max_entries = amt;
        newTable->entry_cnt = 0;
        newTable->unk_14 = 0;
        result = newTable;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCogParse.c", 421, "Failed to create memory for symbol table.\n", 0, 0, 0, 0);
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

    // Added: nullptr checks
    if (!table) {
        return 0;
    }

    if ( table->hashtable )
    {
        stdHashTable_Free(table->hashtable);
        table->hashtable = 0;
    }
    amt = table->entry_cnt;
    if ( table->max_entries > amt )
    {
        reallocBuckets = (sithCogSymbol *)pSithHS->realloc(table->buckets, sizeof(sithCogSymbol) * amt);
        // Added: nullptr checks
        if (!reallocBuckets) {
            table->max_entries = 0;
            return 0;
        }
        reallocAmt = table->entry_cnt;
        table->buckets = reallocBuckets;
        table->max_entries = reallocAmt;
    }
    result = table->max_entries;
#ifndef COG_CRC32_SYMBOL_NAMES
    i_ = 0;
    if ( result )
    {
        buckets = table->buckets;
        i = 0;
        do
        {
            if ( buckets[i].pName )
            {
                pSithHS->free(buckets[i].pName);
                buckets = table->buckets;
                table->buckets[i].pName = 0;
            }
            result = table->max_entries;
            ++i_;
            ++i;
        }
        while ( i_ < result );
    }
#endif
    return result;
}

void sithCogParse_FreeSymboltable(sithCogSymboltable *table)
{
    sithCogSymbol *v1; // eax
    unsigned int v2; // ebx
    int v3; // esi

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
#ifndef COG_CRC32_SYMBOL_NAMES
                    if ( v1[v3].pName )
                        pSithHS->free(v1[v3].pName);
#endif
                    v1 = table->buckets;
                    if ( table->buckets[v3].val.type == 4 )
                    {
                        pSithHS->free(v1[v3].val.dataAsName);
                        v1 = table->buckets;
                        table->buckets[v3].val.dataAsName = 0;
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
#if !defined(COG_CRC32_SYMBOL_NAMES)
            char* key = (char *)pSithHS->alloc(_strlen(symbolName) + 1);
            _strcpy(key, symbolName);
            symbol->pName = key;
            if ( table->hashtable )
                stdHashTable_SetKeyVal(table->hashtable, key, symbol);
#else
            symbol->nameCrc = stdCrc32(symbolName, strlen(symbolName));
            if ( table->hashtable )
                stdHashTable_SetKeyVal(table->hashtable, symbolName, symbol);
#endif
            
        }
        symbol->field_14 = cog_yacc_loop_depth;
        cog_yacc_loop_depth++;
        symbol->symbol_id = table->bucket_idx + symbol - table->buckets;
        //v7 = ((((char *)v5 - (char *)sithCogParse_pSymbolTable->buckets) * 4) / 7) >> 4; ??
        
        return symbol;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCogParse.c", 573, "No space for COG symbol %s.\n", symbolName);
        return NULL;
    }
}

void sithCogParse_SetSymbolVal(sithCogSymbol *a1, sithCogStackvar *a2)
{
    // TODO ehhhhhh
    //*(sithCogStackvar *)&a1->val.type = *a2;
    a1->val.type = a2->type;
    _memcpy(a1->val.dataAsPtrs, a2->dataAsPtrs, sizeof(a1->val.dataAsPtrs));
}

sithCogSymbol* sithCogParse_GetSymbolVal(sithCogSymboltable *pSymbolTable, char *a2)
{
    sithCogSymbol *result; // eax

    if (!pSymbolTable->hashtable)
        return NULL;
    
    if (result = (sithCogSymbol*)stdHashTable_GetKeyVal(pSymbolTable->hashtable, a2))
        return result;

    if (pSymbolTable == sithCog_pSymbolTable) {
        //jk_printf("OpenJKDF2: Missing symbol `%s` in `%s`!\n", a2, sithCogParse_lastParsedFile);
        return NULL;
    }

    return sithCogParse_GetSymbolVal(sithCog_pSymbolTable, a2);
}

sithCogSymbol* sithCogParse_GetSymbol(sithCogSymboltable *table, unsigned int idx)
{
    sithCogSymbol *result; // eax

    if ( idx >= 0x100 )
    {
        table = sithCog_pSymbolTable;
        idx -= 256;
    }

    if ( table && idx < table->entry_cnt )
        result = &table->buckets[idx];
    else
        result = NULL;

    return result;
}

int sithCogParse_GetSymbolScriptIdx(unsigned int idx)
{
    // aaaaaaaaaaaaa this will dereference a nullptr
    return sithCogParse_GetSymbol(sithCogParse_pSymbolTable, idx)->field_14;
}

sith_cog_parser_node* sithCogParse_AddLeaf(int op, int val)
{
    return sithCogParse_AddLinkingNode(NULL, NULL, op, (int)val);
}

sith_cog_parser_node* sithCogParse_AddLeafVector(int opcode, cog_flex_t* vector)
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
    node->vector[0] = vector[0];
    node->vector[1] = vector[1];
    node->vector[2] = vector[2];
    
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

    _strtolower(symName);
    v6 = sithCogParse_GetSymbolVal(sithCogParse_pSymbolTable, symName);

    if ( v6 )
    {
        yylval.as_int = v6->symbol_id;
    }
    else
    {
        v6 = sithCogParse_AddSymbol(sithCogParse_pSymbolTable, symName);

        if ( v6 )
        {
            v6->val.type = 2;
            v6->val.dataAsPtrs[0] = 0;
            v6->val.dataAsPtrs[1] = 0;
            v6->val.dataAsPtrs[2] = 0;
            v6->val.dataAsName = 0;
            yylval.as_int = v6->symbol_id;
        }
    }
}

void sithCogParse_LexAddSymbol(const char *symName)
{
    sithCogSymbol *symbol; // esi

    symbol = sithCogParse_AddSymbol(sithCogParse_pSymbolTable, symName);
    
    if ( symbol )
    {
        symbol->val.type = COG_VARTYPE_STR;
        symbol->val.dataAsName = (char *)pSithHS->alloc(_strlen(symName) - 1);
        _strncpy(symbol->val.dataAsName, symName + 1, _strlen(symName) - 2);
        symbol->val.dataAsName[_strlen(symName) - 2] = 0;
        yylval.as_int = symbol->symbol_id;
    }
}

void sithCogParse_LexScanVector3(char* text)
{
    // Added: flex_t
    flex32_t scan_x = 0.0;
    flex32_t scan_y = 0.0;
    flex32_t scan_z = 0.0;

    _sscanf(text, "'%f %f %f'", &scan_x, &scan_y, &scan_z);

    // Added: flex_t
    yylval.as_vector[0] = scan_x;
    yylval.as_vector[1] = scan_y;
    yylval.as_vector[2] = scan_z;
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
            _memcpy(&cogvm_stack[cogvm_stackpos], &node->vector, sizeof(cog_flex_t)*3);
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

int sithCogParse_ParseSymbol(sithCogScript *cogScript, int a2, int unk)
{
    sithCogReference *cogIdk;

    if ( cogScript->numIdk >= 0x80u )
        return 0;
    if ( stdConffile_entry.numArgs < 2u )
        return 0;
    
    sithCogSymbol* symbol = sithCogParse_AddSymbol(cogScript->pSymbolTable, stdConffile_entry.args[1].key);
    
    if ( !symbol )
        return 0;

    // Added: remove undef stuff
    symbol->val.type = COG_VARTYPE_INT;
    symbol->val.dataAsPtrs[0] = 0;
    symbol->val.dataAsPtrs[1] = 0;
    symbol->val.dataAsPtrs[2] = 0;
    symbol->val.dataAsName = 0;

#ifdef COG_DYNAMIC_IDK
    cogScript->aIdk = (sithCogReference*)pSithHS->realloc(cogScript->aIdk, sizeof(sithCogReference) * (cogScript->numIdk+1));
#endif
    
    cogIdk = &cogScript->aIdk[cogScript->numIdk];
    _memset(cogIdk, 0, sizeof(sithCogReference));
    cogIdk->type = a2;
    cogIdk->mask = 0x401;
    cogIdk->hash = symbol->symbol_id;
        
    for (unsigned int i = 2; i < stdConffile_entry.numArgs; i++)
    {
        stdConffileArg* arg = &stdConffile_entry.args[i];
        if ( !_strcmp(arg->key, "local") )
        {
            cogIdk->flags |= 1;
        }
        else if ( unk && !_strcmp(arg->key, "desc"))
        {
            if ( cogIdk->desc )
                pSithHS->free(cogIdk->desc);
            cogIdk->desc = (char *)pSithHS->alloc(_strlen(arg->value) + 1);
            _strcpy(cogIdk->desc, arg->value);
        }
        else if ( !_strcmp(arg->key, "mask") )
        {
            _sscanf(arg->value, "%x", &cogIdk->mask);
        }
        else if ( !_strcmp(arg->key, "linkid") )
        {
            cogIdk->linkid = _atoi(arg->value);
        }
        else if ( !_strcmp(arg->key, "nolink") )
        {
            cogIdk->linkid = -1;
        }
    }
    if ( stdConffile_entry.args[1].value )
    {
        if ( stdConffile_entry.args[1].value != stdConffile_entry.args[1].key )
        {
            stdString_SafeStrCopy(cogScript->aIdk[cogScript->numIdk].value, stdConffile_entry.args[1].value, 32);
        }
    }
    ++cogScript->numIdk;
    return 1;
}

int sithCogParse_ParseFlex(sithCogScript *cogScript, int a2)
{
    char* v20 = 0;

    if ( cogScript->numIdk >= 0x80u ) // added
        return 0;

    sithCogSymbol* symbol = sithCogParse_AddSymbol(cogScript->pSymbolTable, stdConffile_entry.args[1].key);
    
    if ( !symbol )
        return 0;

    // Added: remove undef stuff
    symbol->val.type = COG_VARTYPE_FLEX;
    symbol->val.dataAsPtrs[0] = 0;
    symbol->val.dataAsPtrs[1] = 0;
    symbol->val.dataAsPtrs[2] = 0;
    symbol->val.dataAsFloat[0] = _atof(stdConffile_entry.args[1].value);
    
    for (int i = 2; i < stdConffile_entry.numArgs; i++)
    {
        stdConffileArg* arg = &stdConffile_entry.args[i];
        
        if ( !_strcmp(arg->key, "local") )
        {
            return 1;
        }

        if ( a2 && !_strcmp(arg->key, "desc"))
        {
            v20 = _strcpy((char *)pSithHS->alloc(_strlen(arg->value) + 1), arg->value);
        }
    }
    
#ifdef COG_DYNAMIC_IDK
    cogScript->aIdk = (sithCogReference*)pSithHS->realloc(cogScript->aIdk, sizeof(sithCogReference) * (cogScript->numIdk+1));
#endif

    sithCogReference* cogIdk = &cogScript->aIdk[cogScript->numIdk];
    _memset(cogIdk, 0, sizeof(sithCogReference)); // added
    cogIdk->type = COG_TYPE_FLEX; // hmm
    cogIdk->linkid = -1;
    cogIdk->hash = symbol->symbol_id;
    cogIdk->desc = v20;

    ++cogScript->numIdk;
    return 1;
}

int sithCogParse_ParseInt(sithCogScript *cogScript, int a2)
{
    char* v20 = 0;

    if ( cogScript->numIdk >= 0x80u ) // added
        return 0;

    sithCogSymbol* symbol = sithCogParse_AddSymbol(cogScript->pSymbolTable, stdConffile_entry.args[1].key);
    
    if ( !symbol )
        return 0;

    // Added: remove undef stuff
    symbol->val.type = COG_VARTYPE_INT;
    symbol->val.dataAsPtrs[0] = 0;
    symbol->val.dataAsPtrs[1] = 0;
    symbol->val.dataAsPtrs[2] = 0;
    symbol->val.data[0] = _atoi(stdConffile_entry.args[1].value);
    
    for (int i = 2; i < stdConffile_entry.numArgs; i++)
    {
        stdConffileArg* arg = &stdConffile_entry.args[i];
        
        if ( !_strcmp(arg->key, "local") )
        {
            return 1;
        }

        if ( a2 && !_strcmp(arg->key, "desc"))
        {
            v20 = _strcpy((char *)pSithHS->alloc(_strlen(arg->value) + 1), arg->value);
        }
    }
    
#ifdef COG_DYNAMIC_IDK
    cogScript->aIdk = (sithCogReference*)pSithHS->realloc(cogScript->aIdk, sizeof(sithCogReference) * (cogScript->numIdk+1));
#endif

    sithCogReference* cogIdk = &cogScript->aIdk[cogScript->numIdk];
    _memset(cogIdk, 0, sizeof(sithCogReference)); // added
    cogIdk->type = COG_TYPE_INT; // hmmm
    cogIdk->linkid = -1;
    cogIdk->hash = symbol->symbol_id;
    cogIdk->desc = v20;

    ++cogScript->numIdk;
    return 1;
}

int sithCogParse_ParseVector(sithCogScript *cogScript, int a2)
{
    char* v20 = 0;

    if ( cogScript->numIdk >= 0x80u ) // added
        return 0;

    sithCogSymbol* symbol = sithCogParse_AddSymbol(cogScript->pSymbolTable, stdConffile_entry.args[1].key);
    
    if ( !symbol )
        return 0;

    // Added: remove undef stuff
    symbol->val.type = COG_VARTYPE_VECTOR;
    symbol->val.dataAsPtrs[0] = 0;
    symbol->val.dataAsPtrs[1] = 0;
    symbol->val.dataAsPtrs[2] = 0;
    symbol->val.data[0] = 0;
    
    for (int i = 2; i < stdConffile_entry.numArgs; i++)
    {
        stdConffileArg* arg = &stdConffile_entry.args[i];
        
        if ( !_strcmp(arg->key, "local") )
        {
            return 1;
        }

        if ( a2 && !_strcmp(arg->key, "desc"))
        {
            v20 = _strcpy((char *)pSithHS->alloc(_strlen(arg->value) + 1), arg->value);
        }
    }

#ifdef COG_DYNAMIC_IDK
    cogScript->aIdk = (sithCogReference*)pSithHS->realloc(cogScript->aIdk, sizeof(sithCogReference) * (cogScript->numIdk+1));
#endif
    
    sithCogReference* cogIdk = &cogScript->aIdk[cogScript->numIdk];
    _memset(cogIdk, 0, sizeof(sithCogReference)); // added
    cogIdk->type = COG_TYPE_VECTOR; // TODO hmmmm
    cogIdk->linkid = -1;
    cogIdk->hash = symbol->symbol_id;
    cogIdk->desc = v20;

    ++cogScript->numIdk;
    return 1;
}

int sithCogParse_ParseMessage(sithCogScript *cogScript)
{
    if ( cogScript->num_triggers == 32 )
        return 0;

    sithCogSymbol* symbolGet = sithCogParse_GetSymbolVal(sithCog_pSymbolTable, stdConffile_entry.args[1].value);
    if (!symbolGet) return 0;

    sithCogSymbol* symbol = sithCogParse_AddSymbol(cogScript->pSymbolTable, stdConffile_entry.args[1].key);
    if (!symbol) return 0;
    
    //printf("Add message? %x %x %s\n", symbolGet->val.data[0], symbol->field_14, stdConffile_entry.args[1].value);
    
#ifdef COG_DYNAMIC_TRIGGERS
    cogScript->triggers = (sithCogTrigger*)pSithHS->realloc(cogScript->triggers, sizeof(sithCogTrigger) * (cogScript->num_triggers+1));
#endif

    symbol->val.dataAsName = symbolGet->val.dataAsName;
    symbol->val.type = COG_TYPE_INT;
    cogScript->triggers[cogScript->num_triggers].trigId = symbolGet->val.data[0];
    cogScript->triggers[cogScript->num_triggers].field_8 = symbol->field_14;
    
    cogScript->num_triggers++;
    return 1;
}
