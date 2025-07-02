#ifndef _SITHCOGPARSE_H
#define _SITHCOGPARSE_H

#include "types.h"
#include "globals.h"

#include "Cog/sithCogExec.h"
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

void sithCogParse_Reset();
int sithCogParse_Load(char *cog_fpath, sithCogScript *cogscript, int unk);
int sithCogParse_LoadEntry(sithCogScript *script);
sithCogSymboltable* sithCogParse_CopySymboltable(sithCogSymboltable *table);
sithCogSymboltable* sithCogParse_NewSymboltable(int amt);
int sithCogParse_ReallocSymboltable(sithCogSymboltable *table);
void sithCogParse_FreeSymboltable(sithCogSymboltable *table);
sithCogSymbol* sithCogParse_AddSymbol(sithCogSymboltable *table, const char *symbolName);
void sithCogParse_SetSymbolVal(sithCogSymbol *a1, sithCogStackvar *a2);
sithCogSymbol* sithCogParse_GetSymbolVal(sithCogSymboltable *pSymbolTable, char *a2);
sithCogSymbol* sithCogParse_GetSymbol(sithCogSymboltable *table, unsigned int idx);
int sithCogParse_GetSymbolScriptIdx(unsigned int idx);
sith_cog_parser_node* sithCogParse_AddLeaf(int op, int val);
sith_cog_parser_node* sithCogParse_AddLeafVector(int op, cog_flex_t* vector);
sith_cog_parser_node* sithCogParse_AddLinkingNode(sith_cog_parser_node* parent, sith_cog_parser_node* child, int opcode, int val);
void sithCogParse_LexGetSym(char *symName);
void sithCogParse_LexAddSymbol(const char *symName);
void sithCogParse_LexScanVector3(char *inStr);
int sithCogParse_IncrementLoopdepth();
int sithCogParse_RecurseStackdepth(sith_cog_parser_node *node);
void sithCogParse_RecurseWrite(sith_cog_parser_node *node);
int sithCogParse_ParseSymbol(sithCogScript *cogScript, int a2, int unk);
int sithCogParse_ParseFlex(sithCogScript *cogScript, int a2);
int sithCogParse_ParseInt(sithCogScript *cogScript, int a2);
int sithCogParse_ParseVector(sithCogScript *cogScript, int a2);
int sithCogParse_ParseMessage(sithCogScript *cogScript);

//sith_cog_parser_node* sithCogParse_AddLinkingNode(sith_cog_parser_node* parent, sith_cog_parser_node* child, int opcode, int val);
//sith_cog_parser_node* sithCogParse_AddLeafVector(int op, cog_flex_t* vector);
//sith_cog_parser_node* sithCogParse_AddLeaf(int op, int val);

//static sithCogSymbol* (__cdecl *sithCogParse_GetSymbol_)(sithCogSymboltable *a1, unsigned int a2) = (void*)sithCogParse_GetSymbol_ADDR;
//static int (*sithCogParse_RecurseWrite)(sith_cog_parser_node *node) = (void*)sithCogParse_RecurseWrite_ADDR;

int cog_parsescript();

#endif // _SITHCOGPARSE_H
