#ifndef _SITHCOGPARSE_H
#define _SITHCOGPARSE_H

#include "Primitives/rdVector.h"
#include "Cog/sithCogVm.h"
#include "Cog/sithCogYACC.h"

#define sithCogParse_Reset_ADDR (0x004FC9A0)
#define sithCogParse_Load_ADDR (0x004FC9D0)
#define sithCogParse_LoadEntry_ADDR (0x004FCD70)
#define sithCogParse_CopySymboltable_ADDR (0x004FCFD0)
#define sithCogParse_NewSymboltable_ADDR (0x004FD050)
#define sithCogParse_ReallocSymboltable_ADDR (0x004FD130)
#define sithCogParse_FreeSymboltable_ADDR (0x004FD1C0)
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
#define sithCogParse_RecurseStackdepth_ADDR (0x004FD940)
#define sithCogParse_RecurseWrite_ADDR (0x004FDA00)
#define sithCogParse_ParseSymbol_ADDR (0x004FDAE0)
#define sithCogParse_ParseFlex_ADDR (0x004FDE10)
#define sithCogParse_ParseInt_ADDR (0x004FE040)
#define sithCogParse_ParseVector_ADDR (0x004FE280)
#define sithCogParse_ParseMessage_ADDR (0x004FE4D0)

typedef struct sith_cog_parser_node sith_cog_parser_node;

typedef struct sith_cog_parser_node 
{
    int child_loop_depth;
    int parent_loop_depth;
    sith_cog_parser_node *parent;
    sith_cog_parser_node *child;
    int opcode;
    int value;
    rdVector3 vector;
} sith_cog_parser_node;

void sithCogParse_Reset();
int sithCogParse_Load(char *cog_fpath, sithCogScript *cogscript, int unk);
int sithCogParse_LoadEntry(sithCogScript *script);
sithCogSymboltable* sithCogParse_CopySymboltable(sithCogSymboltable *table);
sithCogSymboltable* sithCogParse_NewSymboltable(int amt);
int sithCogParse_ReallocSymboltable(sithCogSymboltable *table);
void sithCogParse_FreeSymboltable(sithCogSymboltable *table);
sithCogSymbol* sithCogParse_AddSymbol(sithCogSymboltable *table, const char *symbolName);
void* sithCogParse_GetSymbolVal(sithCogSymboltable *symbolTable, char *a2);
sithCogSymbol* sithCogParse_GetSymbol(sithCogSymboltable *table, unsigned int idx);
int sithCogParse_GetSymbolScriptIdx(unsigned int idx);
sith_cog_parser_node* sithCogParse_AddLeaf(int op, int val);
sith_cog_parser_node* sithCogParse_AddLeafVector(int op, rdVector3* vector);
sith_cog_parser_node* sithCogParse_AddLinkingNode(sith_cog_parser_node* parent, sith_cog_parser_node* child, int opcode, int val);
void sithCogParse_LexGetSym(char *symName);
void sithCogParse_LexAddSymbol(const char *symName);
void sithCogParse_LexScanVector3(char *inStr);
int sithCogParse_IncrementLoopdepth();
int sithCogParse_RecurseStackdepth(sith_cog_parser_node *node);
void sithCogParse_RecurseWrite(sith_cog_parser_node *node);

//sith_cog_parser_node* sithCogParse_AddLinkingNode(sith_cog_parser_node* parent, sith_cog_parser_node* child, int opcode, int val);
//sith_cog_parser_node* sithCogParse_AddLeafVector(int op, rdVector3* vector);
//sith_cog_parser_node* sithCogParse_AddLeaf(int op, int val);

//static cogSymbol* (__cdecl *sithCogParse_GetSymbol)(sithCogSymboltable *a1, unsigned int a2) = (void*)sithCogParse_GetSymbol_ADDR;
//static int (*sithCogParse_RecurseWrite)(sith_cog_parser_node *node) = (void*)sithCogParse_RecurseWrite_ADDR;
static int (*sithCogParse_ParseSymbol)(sithCogScript *a1, int a2, int a3) = (void*)sithCogParse_ParseSymbol_ADDR;
static int (*sithCogParse_ParseFlex)(sithCogScript *a1, int a2) = (void*)sithCogParse_ParseFlex_ADDR;
static int (*sithCogParse_ParseInt)(sithCogScript *a1, int a2) = (void*)sithCogParse_ParseInt_ADDR;
static int (*sithCogParse_ParseVector)(sithCogScript *a1, int a2) = (void*)sithCogParse_ParseVector_ADDR;
static int (*sithCogParse_ParseMessage)(sithCogScript *a1) = (void*)sithCogParse_ParseMessage_ADDR;

#define sithCogParse_symbolTable (*(sithCogSymboltable**)0x008554C0)
#define yacc_linenum (*(int*)0x00889F0C)
#define cog_yacc_loop_depth (*(int*)0x0054C850)
#define cog_parser_node_stackpos ((int*)0x008554C8)
#define cogvm_stackpos (*(int*)0x00855CD8)
#define cogparser_nodes_alloc (*(sith_cog_parser_node**)0x00855CD0)
#define cogparser_topnode (*(sith_cog_parser_node**)0x00855CCC)
#define cogvm_stack (*(int**)0x00855CC8)
#define cogparser_num_nodes (*(int*)0x00855CE0)
#define cogparser_current_nodeidx (*(int*)0x00855CDC)
#define parsing_script (*(int*)0x00855CD4)
#define parsing_script_idk (*(int*)0x0054C854)

int cog_parsescript();

#endif // _SITHCOGPARSE_H
