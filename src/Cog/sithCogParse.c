#include "sithCogParse.h"

#include <stdlib.h>

#include "Cog/y.tab.h"
#include "Cog/sithCogYACC.h"
#include "General/stdHashtbl.h"
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

void sithCogParse_FreeParseTree()
{
    if ( cogparser_nodes_alloc )
    {
        SITH_FREE(cogparser_nodes_alloc);
        cogparser_num_nodes = 0;
        cogparser_current_nodeidx = 0;
    }

    // Added
    sithCogParse_lastParsedFile = "INVALID";
}

int sithCogParse_Load(char *pFilename, SithCogScript *pScript, int bParseDescription)
{
    SithCogSymbolTable *symboltable; // eax
    unsigned int v6; // ecx
    int v8; // edx

    if (!stdConffile_Open(pFilename))
        return 0;

    //printf("%s\n", aName);

    // Added
    sithCogParse_lastParsedFile = pFilename;

    _memset(pScript, 0, sizeof(SithCogScript));
#ifdef STDHASHTABLE_CRC32_KEYS
    const char* fname = stdFileFromPath(pFilename);
    pScript->pathCrc = stdCrc32(fname, strlen(fname));
#endif
#ifdef SITH_DEBUG_STRUCT_NAMES
    stdString_SafeStrCopy(pScript->aName, stdFileFromPath(pFilename), 32);
#endif
    _memset(cog_parser_node_stackpos, 0xFFu, sizeof(cog_parser_node_stackpos));
    cog_yacc_loop_depth = 1;

    if ( !stdConffile_ReadArgs() )
        goto fail_cleanup;

    if ( !_strcmp(stdConffile_g_entry.aArgs[0].key, "flags") )
    {
        _sscanf(stdConffile_g_entry.aArgs[0].value, "%x", pScript);
        if ( !stdConffile_ReadArgs() )
            goto fail_cleanup;
    }

    if ( _strcmp(stdConffile_g_entry.aArgs[0].value, "symbols") )
        goto fail_cleanup;

    symboltable = sithCogParse_AllocSymbolTable(SITHCOG_LINKED_SYMBOL_LIMIT);
    pScript->pSymbolTable = symboltable;
    if ( !symboltable )
        goto fail_cleanup;

    while ( stdConffile_ReadArgs() )
    {
        //printf("%s\n", stdConffile_g_entry.aArgs[0].value);
        if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "end") )
            break;
        if ( pScript->pSymbolTable->numUsedSymbols < (unsigned int)pScript->pSymbolTable->tableSize )
        {
            if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "thing") )
            {
                sithCogParse_ParseSymbolRef(pScript, 3, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "surface") )
            {
                sithCogParse_ParseSymbolRef(pScript, 6, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "sector") )
            {
                sithCogParse_ParseSymbolRef(pScript, 5, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "sound") )
            {
                sithCogParse_ParseSymbolRef(pScript, 8, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "template") )
            {
                sithCogParse_ParseSymbolRef(pScript, 4, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "model") )
            {
                sithCogParse_ParseSymbolRef(pScript, 12, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "keyframe") )
            {
                sithCogParse_ParseSymbolRef(pScript, 7, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "cog") )
            {
                sithCogParse_ParseSymbolRef(pScript, 9, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "message") )
            {
                sithCogParse_ParseMessage(pScript);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "material") )
            {
                sithCogParse_ParseSymbolRef(pScript, 10, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "flex") || !_strcmp(stdConffile_g_entry.aArgs[0].value, "float") )
            {
                sithCogParse_ParseFlex(pScript, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "int") )
            {
                sithCogParse_ParseInt(pScript, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "vector") )
            {
                sithCogParse_ParseVector(pScript, bParseDescription);
            }
            else if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "ai") )
            {
                sithCogParse_ParseSymbolRef(pScript, 13, bParseDescription);
            }
        }
    }
    if ( stdConffile_ReadArgs() && !_strcmp(stdConffile_g_entry.aArgs[0].value, "code") && sithCogParse_ParseSectionCode(pScript) )
    {
        for (v6 = 0; v6 < pScript->numHandlers; v6++)
        {
            v8 = pScript->aHandlers[v6].field_8;
            pScript->aHandlers[v6].trigPc = cog_parser_node_stackpos[v8];
        }
#ifdef COG_SEAL_SYMBOLTABLES
        // Added: seal the table (free parse-time pHashtbl, trim aSymbols); see
        // engine_config.h. Guarded: an empty table would realloc to 0 bytes.
        if ( pScript->pSymbolTable && pScript->pSymbolTable->numUsedSymbols )
            sithCogParse_ReallocSymbolTable(pScript->pSymbolTable);
#endif
        stdConffile_Close();
        return 1;
    }
    else
    {
        goto fail_cleanup;
    }

fail_cleanup:
    if ( pScript->pSymbolTable )
    {
        sithCogParse_FreeSymbolTable(pScript->pSymbolTable);
        pScript->pSymbolTable = 0;
    }
    if ( cogparser_topnode )
    {
        cogparser_current_nodeidx = 0;
        cogparser_topnode = 0;
    }
    stdConffile_Close();
    return 0;
}

int sithCogParse_ParseSectionCode(SithCogScript *pScript)
{
    stdFile_t hGobFile; // eax
    sith_cog_parser_node *v2; // eax
    sith_cog_parser_node *v3; // esi
    int v5; // eax
    int v6; // eax
    int32_t *pCode; // eax
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

    hGobFile = stdConffile_GetFileHandle();
    parsing_script = pScript;
    yyin = (stdFile_t)hGobFile;
    sithCogParse_pSymbolTable = pScript->pSymbolTable;
    if ( parsing_script_idk )
        parsing_script_idk = 0;
    else
        yyrestart((FILE*)hGobFile);
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
            sithCogParse_GenerateLabelTable(v2->parent);
        if ( v3->child )
            sithCogParse_GenerateLabelTable(v3->child);
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
#ifdef TARGET_RETRO_HOMEBREW
                // Added: bytecode is written as pure 32-bit stores by codegen and
                // read per-opcode at execution -- word-safe and cool enough for
                // word-addressable-only memory.
                {
                    int prevSuggest = pSithHS->suggestHeap(HEAP_WORD_ADDRESSABLE);
                    pCode = (int32_t *)SITH_ALLOC(sizeof(int32_t) * cogvm_stackpos + sizeof(int32_t));
                    pSithHS->suggestHeap(prevSuggest);
                }
#else
                pCode = (int32_t *)SITH_ALLOC(sizeof(int32_t) * cogvm_stackpos + sizeof(int32_t));
#endif
                pScript->pCode = pCode;
                if ( !pCode )
                    goto LABEL_19;
                cur_instr = cogparser_topnode;
                script_prog_curidx = 0;
                pScript->codeSize = cogvm_stackpos + 1;
                script_prog_next = pCode;
                node_parent = cur_instr->parent;
                cogvm_stackpos = 0;
                cogvm_stack = script_prog_next;
                if ( node_parent )
                {
                    sithCogParse_GenerateCode(node_parent);
                    script_prog_curidx = cogvm_stackpos;
                    script_prog_next = cogvm_stack;
                }
                if ( cur_instr->child )
                {
                    sithCogParse_GenerateCode(cur_instr->child);
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
                            stdPlatform_Memcpy32(v17, &cur_instr->vector, sizeof(cog_flex_t)*3); // Added: word-safe (program may be word-addressable-only)
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
                pScript->pCode[pScript->codeSize - 1] = 29;
                cogparser_current_nodeidx = 0;
                cogparser_topnode = 0;
                result = 1;
                break;
        }
    }

#ifdef QOL_IMPROVEMENTS
    if (yynerrs) {
#ifdef SITH_DEBUG_STRUCT_NAMES
        jk_printf("OpenJKDF2: PARSER error was in file: %s\n", pScript->aName);
#endif
    }
#endif

    return result;
}

SithCogSymbolTable* sithCogParse_DuplicateSymbolTable(SithCogSymbolTable *pSource)
{
    int numUsedSymbols; // ebp
    SithCogSymbolTable *newTable; // ebx
    SithCogSymbol *aSymbols; // eax
    SithCogSymbolTable *result; // eax

    numUsedSymbols = pSource->numUsedSymbols;
    newTable = (SithCogSymbolTable *)SITH_ALLOC(sizeof(SithCogSymbolTable));
    if ( !newTable )
        return 0;
    _memset(newTable, 0, sizeof(SithCogSymbolTable));
#ifdef TARGET_RETRO_HOMEBREW
    int prevSuggest = pSithHS->suggestHeap(HEAP_WORD_ADDRESSABLE); // Added: see NewSymboltable
#endif
    aSymbols = (SithCogSymbol *)SITH_ALLOC(sizeof(SithCogSymbol) * numUsedSymbols);
#ifdef TARGET_RETRO_HOMEBREW
    pSithHS->suggestHeap(prevSuggest);
#endif
    newTable->aSymbols = aSymbols;
    if ( !aSymbols )
        return 0;
    stdPlatform_Memcpy32(aSymbols, pSource->aSymbols, sizeof(SithCogSymbol) * numUsedSymbols); // Added: word-safe both sides
    result = newTable;
    newTable->tableSize = numUsedSymbols;
    newTable->numUsedSymbols = numUsedSymbols;
    newTable->unk_14 = 1;
    return result;
}

SithCogSymbolTable* sithCogParse_AllocSymbolTable(int numElements)
{
    SithCogSymbolTable *newTable; // esi
    tHashTable *newHashtable; // eax
    SithCogSymbol *aSymbols; // edi
    SithCogSymbolTable *result; // eax

    newTable = (SithCogSymbolTable *)SITH_ALLOC(sizeof(SithCogSymbolTable));
#ifdef TARGET_RETRO_HOMEBREW
    // Added: symbol aSymbols are word-safe (32-bit fields; 16-bit stackvar type
    // writes are fine on word-addressable memory) -- suggest the arena.
    int prevSuggest = pSithHS->suggestHeap(HEAP_WORD_ADDRESSABLE);
#endif
    if ( newTable
      && (_memset(newTable, 0, sizeof(SithCogSymbolTable)),
          newTable->aSymbols = (SithCogSymbol *)SITH_ALLOC(sizeof(SithCogSymbol) * numElements),
          newHashtable = stdHashtbl_New(2 * numElements),
          aSymbols = newTable->aSymbols,
          newTable->pHashtbl = newHashtable,
          newTable->aSymbols)
      && newHashtable )
    {
#ifdef TARGET_RETRO_HOMEBREW
        pSithHS->suggestHeap(prevSuggest);
#endif
        stdPlatform_Memzero32(aSymbols, sizeof(SithCogSymbol) * numElements); // Added: word-safe
        newTable->tableSize = numElements;
        newTable->numUsedSymbols = 0;
        newTable->unk_14 = 0;
        result = newTable;
    }
    else
    {
#ifdef TARGET_RETRO_HOMEBREW
        pSithHS->suggestHeap(prevSuggest); // Added
#endif
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCogParse.c", 421, "Failed to create memory for symbol table.\n", 0, 0, 0, 0);
        if ( newTable )
        {
            if ( newTable->aSymbols )
                SITH_FREE(newTable->aSymbols);
            if ( newTable->pHashtbl )
                stdHashtbl_Free(newTable->pHashtbl);
            SITH_FREE(newTable);
        }
        result = 0;
    }
    return result;
}

int sithCogParse_ReallocSymbolTable(SithCogSymbolTable *pTable)
{
    unsigned int amt; // eax
    SithCogSymbol *reallocBuckets; // eax
    int reallocAmt; // ecx
    unsigned int result; // eax
    unsigned int i_; // ebx
    SithCogSymbol *aSymbols; // ecx
    int i; // esi

    // Added: nullptr checks
    if (!pTable) {
        return 0;
    }

    if ( pTable->pHashtbl )
    {
        stdHashtbl_Free(pTable->pHashtbl);
        pTable->pHashtbl = 0;
    }
    amt = pTable->numUsedSymbols;
    if ( pTable->tableSize > amt )
    {
#ifdef TARGET_RETRO_HOMEBREW
        int prevSuggest = pSithHS->suggestHeap(HEAP_WORD_ADDRESSABLE); // Added: keep the trim in the arena
#endif
        reallocBuckets = (SithCogSymbol *)SITH_REALLOC(pTable->aSymbols, sizeof(SithCogSymbol) * amt);
#ifdef TARGET_RETRO_HOMEBREW
        pSithHS->suggestHeap(prevSuggest);
#endif
        // Added: nullptr checks
        if (!reallocBuckets) {
            pTable->tableSize = 0;
            return 0;
        }
        reallocAmt = pTable->numUsedSymbols;
        pTable->aSymbols = reallocBuckets;
        pTable->tableSize = reallocAmt;
    }
    result = pTable->tableSize;
#ifndef COG_CRC32_SYMBOL_NAMES
    i_ = 0;
    if ( result )
    {
        aSymbols = pTable->aSymbols;
        i = 0;
        do
        {
            if ( aSymbols[i].pName )
            {
                SITH_FREE(aSymbols[i].pName);
                aSymbols = pTable->aSymbols;
                pTable->aSymbols[i].pName = 0;
            }
            result = pTable->tableSize;
            ++i_;
            ++i;
        }
        while ( i_ < result );
    }
#endif
    return result;
}

void sithCogParse_FreeSymbolTable(SithCogSymbolTable *pTable)
{
    SithCogSymbol *v1; // eax
    unsigned int v2; // ebx
    int v3; // esi

    if ( pTable->pHashtbl )
    {
        stdHashtbl_Free(pTable->pHashtbl);
        pTable->pHashtbl = 0;
    }
    v1 = pTable->aSymbols;
    if ( pTable->aSymbols )
    {
        if ( !pTable->unk_14 )
        {
            v2 = 0;
            if ( pTable->tableSize )
            {
                v3 = 0;
                do
                {
#ifndef COG_CRC32_SYMBOL_NAMES
                    if (v1[v3].pName) {
                        SITH_FREE(v1[v3].pName);
                    }
#endif

#ifdef COG_COMPRESS_VAR_SIZE
                    if (v1[v3].val.type == SITHCOG_VALUE_VECTOR)
                    {
                        if (v1[v3].val.dataAsPtrs[0]) {
                            SITH_FREE((void*)v1[v3].val.dataAsPtrs[0]);
                        }
                        v1[v3].val.dataAsPtrs[0] = 0;
                    }
#endif
                    v1 = pTable->aSymbols;
                    if (pTable->aSymbols[v3].val.type == SITHCOG_VALUE_STRING)
                    {
                        SITH_FREE(v1[v3].val.dataAsName);
                        v1 = pTable->aSymbols;
                        pTable->aSymbols[v3].val.dataAsName = 0;
                    }
                    ++v2;
                    ++v3;
                }
                while ( v2 < pTable->tableSize );
            }
        }
        SITH_FREE(pTable->aSymbols);
        pTable->aSymbols = 0;
    }
    SITH_FREE(pTable);
}

SithCogSymbol* sithCogParse_AddSymbol(SithCogSymbolTable *pTable, const char *pName)
{
    if ( pTable->tableSize > pTable->numUsedSymbols )
    {
        SithCogSymbol* symbol = &pTable->aSymbols[pTable->numUsedSymbols];
        pTable->numUsedSymbols++;
        if ( pName )
        {
#if !defined(COG_CRC32_SYMBOL_NAMES)
            char* key = (char *)SITH_ALLOC(_strlen(pName) + 1);
            _strcpy(key, pName);
            symbol->pName = key;
            if ( pTable->pHashtbl )
                stdHashtbl_Add(pTable->pHashtbl, key, symbol);
#else
            symbol->nameCrc = stdCrc32(pName, strlen(pName));
            if ( pTable->pHashtbl )
                stdHashtbl_Add(pTable->pHashtbl, pName, symbol);
#endif
            
        }
        symbol->field_14 = cog_yacc_loop_depth;
        cog_yacc_loop_depth++;
        symbol->id = pTable->firstId + symbol - pTable->aSymbols;
        //v7 = ((((char *)v5 - (char *)sithCogParse_pSymbolTable->aSymbols) * 4) / 7) >> 4; ??
        
        return symbol;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCogParse.c", 573, "No space for COG symbol %s.\n", pName);
        return NULL;
    }
}

void sithCogParse_SetSymbolValue(SithCogSymbol *pSymbol, SithCogSymbolValue *pValue)
{
    // TODO ehhhhhh
    //*(SithCogSymbolValue *)&a1->val = *a2;
    pSymbol->val.type = pValue->type;
    // Added: word stores -- symbol tables may live in word-addressable-only
    // memory, and a tiny _memcpy compiles to a byte loop (dropped by the bus).
    for (size_t i = 0; i < sizeof(pSymbol->val.dataAsPtrs)/sizeof(pSymbol->val.dataAsPtrs[0]); i++)
        pSymbol->val.dataAsPtrs[i] = pValue->dataAsPtrs[i];
}

SithCogSymbol* sithCogParse_GetSymbol(SithCogSymbolTable *pLocal, char *pName)
{
    SithCogSymbol *result; // eax

    if (!pLocal->pHashtbl)
        return NULL;
    
    if (result = (SithCogSymbol*)stdHashtbl_Find(pLocal->pHashtbl, pName))
        return result;

    if (pLocal == sithCog_g_pSymbolTable) {
        //jk_printf("OpenJKDF2: Missing symbol `%s` in `%s`!\n", a2, sithCogParse_lastParsedFile);
        return NULL;
    }

    return sithCogParse_GetSymbol(sithCog_g_pSymbolTable, pName);
}

SithCogSymbol* sithCogParse_GetSymbolByID(SithCogSymbolTable *pTable, unsigned int symbolId)
{
    SithCogSymbol *result; // eax

    if ( symbolId >= 0x100 )
    {
        pTable = sithCog_g_pSymbolTable;
        symbolId -= 256;
    }

    if ( pTable && symbolId < pTable->numUsedSymbols )
        result = &pTable->aSymbols[symbolId];
    else
        result = NULL;

    return result;
}

int sithCogParse_GetSymbolLabel(unsigned int symbolId)
{
    // aaaaaaaaaaaaa this will dereference a nullptr
    return sithCogParse_GetSymbolByID(sithCogParse_pSymbolTable, symbolId)->field_14;
}

sith_cog_parser_node* sithCogParse_MakeLeafNode(int opcode, int symbolId)
{
    return sithCogParse_MakeNode(NULL, NULL, opcode, (int)symbolId);
}

sith_cog_parser_node* sithCogParse_MakeVectorLeafNode(int opcode, cog_flex_t* pVect)
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
    node->vector[0] = pVect[0];
    node->vector[1] = pVect[1];
    node->vector[2] = pVect[2];
    
    cogparser_topnode = node;
    //printf("Add node %p w/ op %x, %p %p\n", node, opcode, parent, child);
    
    return node;
}

sith_cog_parser_node* sithCogParse_MakeNode(sith_cog_parser_node* pLeft, sith_cog_parser_node* pRight, int opcode, int value)
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
    node->value = value;
    node->parent = pLeft;
    node->child = pRight;
    
    cogparser_topnode = node;
    //printf("Add node %p w/ op %x, %p %p\n", node, opcode, parent, child);
    
   return node;
}

int sithCogParse_GetNextLabel()
{
    return cog_yacc_loop_depth++;
}

void sithCogParse_LexerSetSymbol(char *pName)
{
    SithCogSymbol *v6; // ecx

    _strtolower(pName);
    v6 = sithCogParse_GetSymbol(sithCogParse_pSymbolTable, pName);

    if ( v6 )
    {
        yylval.as_int = v6->id;
    }
    else
    {
        v6 = sithCogParse_AddSymbol(sithCogParse_pSymbolTable, pName);

        if ( v6 )
        {
            v6->val.type = 2;
            v6->val.dataAsPtrs[0] = 0;
#ifndef COG_COMPRESS_VAR_SIZE
            v6->val.dataAsPtrs[1] = 0;
            v6->val.dataAsPtrs[2] = 0;
#endif
            v6->val.dataAsName = 0;
            yylval.as_int = v6->id;
        }
    }
}

void sithCogParse_LexerSetString(const char *pString)
{
    SithCogSymbol *symbol; // esi

    symbol = sithCogParse_AddSymbol(sithCogParse_pSymbolTable, pString);
    
    if ( symbol )
    {
        symbol->val.type = SITHCOG_VALUE_STRING;
        symbol->val.dataAsName = (char *)SITH_ALLOC(_strlen(pString) - 1);
        _strncpy(symbol->val.dataAsName, pString + 1, _strlen(pString) - 2);
        symbol->val.dataAsName[_strlen(pString) - 2] = 0;
        yylval.as_int = symbol->id;
    }
}

void sithCogParse_LexerSetVector(char* pString)
{
    // Added: flex_t
    flex32_t scan_x = 0.0;
    flex32_t scan_y = 0.0;
    flex32_t scan_z = 0.0;

    _sscanf(pString, "'%f %f %f'", &scan_x, &scan_y, &scan_z);

    // Added: flex_t
    yylval.as_vector[0] = scan_x;
    yylval.as_vector[1] = scan_y;
    yylval.as_vector[2] = scan_z;
}

int sithCogParse_GenerateLabelTable(sith_cog_parser_node *pRoot)
{
    int result; // eax
    int v2; // esi

    if ( pRoot->child_loop_depth )
        cog_parser_node_stackpos[pRoot->child_loop_depth] = cogvm_stackpos;

    if ( pRoot->parent )
        sithCogParse_GenerateLabelTable(pRoot->parent);

    if ( pRoot->child )
        sithCogParse_GenerateLabelTable(pRoot->child);

    result = pRoot->opcode;
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
            v2 = pRoot->parent_loop_depth;
            if ( v2 )
            {
                result = cogvm_stackpos;
                cog_parser_node_stackpos[v2] = cogvm_stackpos;
            }
            return result;
    }
}

void sithCogParse_GenerateCode(sith_cog_parser_node *pNode)
{
    if ( pNode->parent )
        sithCogParse_GenerateCode(pNode->parent);

    if ( pNode->child )
        sithCogParse_GenerateCode(pNode->child);

    if (!pNode->opcode )
        return;

    cogvm_stack[cogvm_stackpos] = pNode->opcode;
    cogvm_stackpos++;
    switch ( pNode->opcode )
    {
        case COG_OPCODE_PUSHINT:
        case COG_OPCODE_PUSHFLOAT:
        case COG_OPCODE_PUSHSYMBOL:
            cogvm_stack[cogvm_stackpos] = pNode->value;
            cogvm_stackpos++;
            break;
        case COG_OPCODE_PUSHVECTOR:
            _memcpy(&cogvm_stack[cogvm_stackpos], &pNode->vector, sizeof(cog_flex_t)*3);
            cogvm_stackpos += 3;
            break;
        case COG_OPCODE_GOFALSE:
        case COG_OPCODE_GOTRUE:
        case COG_OPCODE_GO:
        case COG_OPCODE_CALL:
            cogvm_stack[cogvm_stackpos++] = cog_parser_node_stackpos[pNode->value];
            break;
        default:
            return;
    }
}

int sithCogParse_ParseSymbolRef(SithCogScript *pScript, int symbolType, int bParseDescription)
{
    SithCogSymbolRef *cogIdk;

    if ( pScript->numSymbolRefs >= 0x80u )
        return 0;
    if ( stdConffile_g_entry.numArgs < 2u )
        return 0;
    
    SithCogSymbol* symbol = sithCogParse_AddSymbol(pScript->pSymbolTable, stdConffile_g_entry.aArgs[1].key);
    
    if ( !symbol )
        return 0;

    // Added: remove undef stuff
    symbol->val.type = SITHCOG_VALUE_INT;
    symbol->val.dataAsPtrs[0] = 0;
#ifndef COG_COMPRESS_VAR_SIZE
    symbol->val.dataAsPtrs[1] = 0;
    symbol->val.dataAsPtrs[2] = 0;
#endif
    symbol->val.dataAsName = 0;

#ifdef COG_DYNAMIC_IDK
    pScript->aSymRefs = (SithCogSymbolRef*)SITH_REALLOC(pScript->aSymRefs, sizeof(SithCogSymbolRef) * (pScript->numSymbolRefs+1));
#endif
    
    cogIdk = &pScript->aSymRefs[pScript->numSymbolRefs];
    _memset(cogIdk, 0, sizeof(SithCogSymbolRef));
    cogIdk->type = symbolType;
    cogIdk->mask = 0x401;
    cogIdk->hash = symbol->id;
        
    for (unsigned int i = 2; i < stdConffile_g_entry.numArgs; i++)
    {
        StdConffileArg* arg = &stdConffile_g_entry.aArgs[i];
        if ( !_strcmp(arg->key, "local") )
        {
            cogIdk->flags |= 1;
        }
        else if ( bParseDescription && !_strcmp(arg->key, "desc"))
        {
            if ( cogIdk->desc )
                SITH_FREE(cogIdk->desc);
            cogIdk->desc = (char *)SITH_ALLOC(_strlen(arg->value) + 1);
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
    if ( stdConffile_g_entry.aArgs[1].value )
    {
        if ( stdConffile_g_entry.aArgs[1].value != stdConffile_g_entry.aArgs[1].key )
        {
            stdString_SafeStrCopy(pScript->aSymRefs[pScript->numSymbolRefs].value, stdConffile_g_entry.aArgs[1].value, 32);
        }
    }
    ++pScript->numSymbolRefs;
    return 1;
}

int sithCogParse_ParseFlex(SithCogScript *pScript, int bParseDescription)
{
    char* v20 = 0;

    if ( pScript->numSymbolRefs >= 0x80u ) // added
        return 0;

    SithCogSymbol* symbol = sithCogParse_AddSymbol(pScript->pSymbolTable, stdConffile_g_entry.aArgs[1].key);
    
    if ( !symbol )
        return 0;

    // Added: remove undef stuff
    symbol->val.type = SITHCOG_VALUE_FLOAT;
    symbol->val.dataAsPtrs[0] = 0;
#ifndef COG_COMPRESS_VAR_SIZE
    symbol->val.dataAsPtrs[1] = 0;
    symbol->val.dataAsPtrs[2] = 0;
#endif
    symbol->val.dataAsFloat[0] = _atof(stdConffile_g_entry.aArgs[1].value);
    
    for (int i = 2; i < stdConffile_g_entry.numArgs; i++)
    {
        StdConffileArg* arg = &stdConffile_g_entry.aArgs[i];
        
        if ( !_strcmp(arg->key, "local") )
        {
            return 1;
        }

        if ( bParseDescription && !_strcmp(arg->key, "desc"))
        {
            v20 = _strcpy((char *)SITH_ALLOC(_strlen(arg->value) + 1), arg->value);
        }
    }
    
#ifdef COG_DYNAMIC_IDK
    pScript->aSymRefs = (SithCogSymbolRef*)SITH_REALLOC(pScript->aSymRefs, sizeof(SithCogSymbolRef) * (pScript->numSymbolRefs+1));
#endif

    SithCogSymbolRef* cogIdk = &pScript->aSymRefs[pScript->numSymbolRefs];
    _memset(cogIdk, 0, sizeof(SithCogSymbolRef)); // added
    cogIdk->type = SITHCOG_SYM_REF_FLEX; // hmm
    cogIdk->linkid = -1;
    cogIdk->hash = symbol->id;
    cogIdk->desc = v20;

    ++pScript->numSymbolRefs;
    return 1;
}

int sithCogParse_ParseInt(SithCogScript *pScript, int bParseDescription)
{
    char* v20 = 0;

    if ( pScript->numSymbolRefs >= 0x80u ) // added
        return 0;

    SithCogSymbol* symbol = sithCogParse_AddSymbol(pScript->pSymbolTable, stdConffile_g_entry.aArgs[1].key);
    
    if ( !symbol )
        return 0;

    // Added: remove undef stuff
    symbol->val.type = SITHCOG_VALUE_INT;
    symbol->val.dataAsPtrs[0] = 0;
#ifndef COG_COMPRESS_VAR_SIZE
    symbol->val.dataAsPtrs[1] = 0;
    symbol->val.dataAsPtrs[2] = 0;
#endif
    symbol->val.data[0] = _atoi(stdConffile_g_entry.aArgs[1].value);
    
    for (int i = 2; i < stdConffile_g_entry.numArgs; i++)
    {
        StdConffileArg* arg = &stdConffile_g_entry.aArgs[i];
        
        if ( !_strcmp(arg->key, "local") )
        {
            return 1;
        }

        if ( bParseDescription && !_strcmp(arg->key, "desc"))
        {
            v20 = _strcpy((char *)SITH_ALLOC(_strlen(arg->value) + 1), arg->value);
        }
    }
    
#ifdef COG_DYNAMIC_IDK
    pScript->aSymRefs = (SithCogSymbolRef*)SITH_REALLOC(pScript->aSymRefs, sizeof(SithCogSymbolRef) * (pScript->numSymbolRefs+1));
#endif

    SithCogSymbolRef* cogIdk = &pScript->aSymRefs[pScript->numSymbolRefs];
    _memset(cogIdk, 0, sizeof(SithCogSymbolRef)); // added
    cogIdk->type = COG_TYPE_INT; // hmmm
    cogIdk->linkid = -1;
    cogIdk->hash = symbol->id;
    cogIdk->desc = v20;

    ++pScript->numSymbolRefs;
    return 1;
}

int sithCogParse_ParseVector(SithCogScript *pScript, int bParseDescription)
{
    char* v20 = 0;

    if ( pScript->numSymbolRefs >= 0x80u ) // added
        return 0;

    SithCogSymbol* symbol = sithCogParse_AddSymbol(pScript->pSymbolTable, stdConffile_g_entry.aArgs[1].key);
    
    if ( !symbol )
        return 0;

    // Added: remove undef stuff
    symbol->val.type = SITHCOG_VALUE_VECTOR;
    symbol->val.dataAsPtrs[0] = 0;
#ifndef COG_COMPRESS_VAR_SIZE
    symbol->val.dataAsPtrs[1] = 0;
    symbol->val.dataAsPtrs[2] = 0;
#endif
    symbol->val.data[0] = 0;
    
    for (int i = 2; i < stdConffile_g_entry.numArgs; i++)
    {
        StdConffileArg* arg = &stdConffile_g_entry.aArgs[i];
        
        if ( !_strcmp(arg->key, "local") )
        {
            return 1;
        }

        if ( bParseDescription && !_strcmp(arg->key, "desc"))
        {
            v20 = _strcpy((char *)SITH_ALLOC(_strlen(arg->value) + 1), arg->value);
        }
    }

#ifdef COG_DYNAMIC_IDK
    pScript->aSymRefs = (SithCogSymbolRef*)SITH_REALLOC(pScript->aSymRefs, sizeof(SithCogSymbolRef) * (pScript->numSymbolRefs+1));
#endif
    
    SithCogSymbolRef* cogIdk = &pScript->aSymRefs[pScript->numSymbolRefs];
    _memset(cogIdk, 0, sizeof(SithCogSymbolRef)); // added
    cogIdk->type = SITHCOG_SYM_REF_VECTOR; // TODO hmmmm
    cogIdk->linkid = -1;
    cogIdk->hash = symbol->id;
    cogIdk->desc = v20;

    ++pScript->numSymbolRefs;
    return 1;
}

int sithCogParse_ParseMessage(SithCogScript *pScript)
{
    if ( pScript->numHandlers == 32 )
        return 0;

    SithCogSymbol* symbolGet = sithCogParse_GetSymbol(sithCog_g_pSymbolTable, stdConffile_g_entry.aArgs[1].value);
    if (!symbolGet) return 0;

    SithCogSymbol* symbol = sithCogParse_AddSymbol(pScript->pSymbolTable, stdConffile_g_entry.aArgs[1].key);
    if (!symbol) return 0;
    
    //printf("Add message? %x %x %s\n", symbolGet->val.data[0], symbol->field_14, stdConffile_g_entry.aArgs[1].value);
    
#ifdef COG_DYNAMIC_TRIGGERS
    pScript->aHandlers = (sithCogTrigger*)SITH_REALLOC(pScript->aHandlers, sizeof(sithCogTrigger) * (pScript->numHandlers+1));
#endif

    symbol->val.dataAsName = symbolGet->val.dataAsName;
    symbol->val.type = COG_TYPE_INT;
    pScript->aHandlers[pScript->numHandlers].trigId = symbolGet->val.data[0];
    pScript->aHandlers[pScript->numHandlers].field_8 = symbol->field_14;
    
    pScript->numHandlers++;
    return 1;
}
