#include "sithCogParse.h"

#include <stdlib.h>

#include "Cog/y.tab.h"
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
            v11 = (sithCogSymbol *)&sithCogParse_symbolTable->buckets[v9];
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
            v13 = (sithCogSymbol *)sithCogParse_symbolTable->buckets;
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
    sithCogSymboltableBucket *v4; // edx
    sithCogSymbol *v5; // ecx
    int v6; // eax
    unsigned int v7; // edx
    char *name; // edx

    v1 = sithCogParse_symbolTable;
    v2 = sithCogParse_symbolTable->entry_cnt;
    if ( sithCogParse_symbolTable->max_entries > v2 )
    {
        v4 = sithCogParse_symbolTable->buckets;
        sithCogParse_symbolTable->entry_cnt = v2 + 1;
        v5 = (sithCogSymbol *)&v4[v2];
        v6 = cog_yacc_loop_depth + 1;
        v5->field_14 = cog_yacc_loop_depth;
        cog_yacc_loop_depth = v6;
        symbol = v5;
        v7 = (int)((uint64_t)(2454267027 * ((char *)v5 - (char *)v4)) >> 32) >> 4;
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

#if 0
int cogparser_recurse_stackdepth(sith_cog_parser_node* node)
{
    if ( node->child_loop_depth )
        cog_parser_node_stackpos[node->child_loop_depth] = 0;

    //printf("op %x\n", node->opcode);

    if (node->parent)
        cogparser_recurse_stackdepth(node->parent);
    if (node->child)
        cogparser_recurse_stackdepth(node->child);
    switch ( node->opcode )
    {
        case COG_OPCODE_NOP:
            break;
        case COG_OPCODE_PUSHINT:
        case COG_OPCODE_PUSHFLOAT:
        case COG_OPCODE_PUSHSYMBOL:
        case COG_OPCODE_GOFALSE:
        case COG_OPCODE_GOTRUE:
        case COG_OPCODE_GO:
        case COG_OPCODE_CALL:
            cogvm_stackpos += 2;
            break;
        case COG_OPCODE_PUSHVECTOR:
            cogvm_stackpos += 4;
            break;
        default:
            cogvm_stackpos += 1;
            break;
    }

    if (node->parent_loop_depth)
        cog_parser_node_stackpos[node->parent_loop_depth] = cogvm_stackpos;

    return cogvm_stackpos;
}

int cogparser_recurse_write(sith_cog_parser_node* node)
{
    if (node->parent)
    {
        cogparser_recurse_write(node->parent);
    }
    if (node->child)
    {
        cogparser_recurse_write(node->child);
    }
    
    if (node->opcode)
    {
      cogvm_stack[cogvm_stackpos++] = node->opcode;
      switch (node->opcode)
      {
        case COG_OPCODE_PUSHINT:
        case COG_OPCODE_PUSHFLOAT:
        case COG_OPCODE_PUSHSYMBOL:
          cogvm_stack[cogvm_stackpos++] = node->value;
        case COG_OPCODE_PUSHVECTOR:
        {
          rdVector3* vec = &cogvm_stack[cogvm_stackpos];
          cogvm_stackpos += 3;
          vec->x = node->vector.x;
          vec->y = node->vector.y;
          vec->z = node->vector.z;
          break;
        }
        case COG_OPCODE_GOFALSE:
        case COG_OPCODE_GOTRUE:
        case COG_OPCODE_GO:
        case COG_OPCODE_CALL:
          cogvm_stack[cogvm_stackpos++] = cog_parser_node_stackpos[node->value];
          cogvm_stackpos += 1;
          break;
        default:
          break;
      }
    }
}

int cog_parsescript()
{
    //linenum = 1;
    //if (yyparse())
        goto error;
    
    //printf("Performing second pass...\n");
    cogvm_stackpos = 0;
    
    cogparser_recurse_stackdepth(cogparser_topnode);
    //printf("Stack max: %x\n", cogvm_stackpos);
    
    int* script_program = malloc(4 * (cogvm_stackpos + 1));
    //script->script_program = script_program;
    if (!script_program)
    {
        goto error;
    }
    
    cogvm_stackpos = 0;
    //script->program_pc_max = cogvm_stackpos + 1;
    cogvm_stack = script_program;
    cogparser_recurse_write(cogparser_topnode);
    
    //script->script_program[script->program_pc_max - 1] = COG_OPCODE_RETURN;
    cogparser_current_nodeidx = 0;
    cogparser_topnode = 0;
    
    //printf("Done with second pass\n");
    for (int i = 0; i < cogvm_stackpos; i++)
    {
        //printf("%08x: %08x\n", i, script_program[i]);
    }
    
    return 1;

error:
    //printf("Error while parsing line %u\n", linenum);
    if (cogparser_topnode)
    {
        cogparser_current_nodeidx = 0;
        cogparser_topnode = 0;
    }
    cogvm_stackpos = 0;
    return 0;
}
#endif
