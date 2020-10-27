#ifndef _SITHCOGPARSE_H
#define _SITHCOGPARSE_H

#include "Primitives/rdVector.h"
#include "sithCogVm.h"

#define sithCogParse_Reset_ADDR (0x004FC9A0)
#define sithCogParse_Load_ADDR (0x004FC9D0)
#define sithCogParse_LoadEntry_ADDR (0x004FCD70)
#define sithCogParse_copy_symboltable_ADDR (0x004FCFD0)
#define sithCogParse_alloc_symboltable_ADDR (0x004FD050)
#define sithCogParse_Free_ADDR (0x004FD130)
#define sithCogParse_free_symboltable_ADDR (0x004FD1C0)
#define sithCogParse_AddSymbol_ADDR (0x004FD260)
#define sithCogParse_SetSymbolVal_ADDR (0x004FD350)
#define sithCogParse_GetSymbolVal_ADDR (0x004FD380)
#define sithCogParse_GetSymbol_ADDR (0x004FD3D0)
#define sithCogParse_GetSymbolScriptIdx_ADDR (0x004FD410)
#define sithCogParse_AddLeaf_ADDR (0x004FD450)
#define sithCogParse_AddLeafVector_ADDR (0x004FD4F0)
#define sithCogParse_AddLinkingNode_ADDR (0x004FD5A0)
#define sithCogParse_LexGetSym_ADDR (0x004FD650)
#define sithCogParse_LexAddSymbol_ADDR (0x004FD7F0)
#define sithCogParse_LexScanVector3_ADDR (0x004FD8E0)
#define sithCogParse_IncrementLoopdepth_ADDR (0x004FD930)
#define sithCogParse_recurse_stackdepth_ADDR (0x004FD940)
#define sithCogParse_recurse_write_ADDR (0x004FDA00)
#define sithCogParse_ParseSymbol_ADDR (0x004FDAE0)
#define sithCogParse_ParseFlex_ADDR (0x004FDE10)
#define sithCogParse_ParseInt_ADDR (0x004FE040)
#define sithCogParse_ParseVector_ADDR (0x004FE280)
#define sithCogParse_ParseMessage_ADDR (0x004FE4D0)

typedef struct cogSymbol
{
    int type;
    int val;
    int func;
} cogSymbol;

typedef struct sith_cog_parser_node sith_cog_parser_node;

typedef struct sith_cog_parser_node 
{
    int child_loop_depth;
    int parent_loop_depth;
    sith_cog_parser_node* parent;
    sith_cog_parser_node* child;
    int opcode;
    int value;
    rdVector3 vector;
} sith_cog_parser_node;

//sith_cog_parser_node* sithCogParse_AddLinkingNode(sith_cog_parser_node* parent, sith_cog_parser_node* child, int opcode, int val);
//sith_cog_parser_node* sithCogParse_AddLeafVector(int op, rdVector3* vector);
//sith_cog_parser_node* sithCogParse_AddLeaf(int op, int val);

static cogSymbol* (__cdecl *sithCogParse_GetSymbol)(sithCogSymboltable *a1, unsigned int a2) = (void*)sithCogParse_GetSymbol_ADDR;

static sith_cog_parser_node* (*sithCogParse_AddLeaf)(int op, int val) = (void*)sithCogParse_AddLeaf_ADDR;
static sith_cog_parser_node* (*sithCogParse_AddLeafVector)(int op, rdVector3* vector) = (void*)sithCogParse_AddLeafVector_ADDR;
static sith_cog_parser_node* (*sithCogParse_AddLinkingNode)(sith_cog_parser_node* parent, sith_cog_parser_node* child, int opcode, int val) = (void*)sithCogParse_AddLinkingNode_ADDR;

int cog_parsescript();

#endif // _SITHCOGPARSE_H
