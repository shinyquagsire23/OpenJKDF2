#ifndef _SITHCOGPARSE_H
#define _SITHCOGPARSE_H

#include "types.h"
#include "globals.h"

#include "Cog/sithCogExec.h"
#include "Cog/sithCogYACC.h"

#define sithCogParse_FreeParseTree_ADDR (0x004FC9A0)
#define sithCogParse_Load_ADDR (0x004FC9D0)
#define sithCogParse_ParseSectionCode_ADDR (0x004FCD70)
#define sithCogParse_DuplicateSymbolTable_ADDR (0x004FCFD0)
#define sithCogParse_AllocSymbolTable_ADDR (0x004FD050)
#define sithCogParse_ReallocSymbolTable_ADDR (0x004FD130)
#define sithCogParse_FreeSymbolTable_ADDR (0x004FD1C0)
#define sithCogParse_AddSymbol_ADDR (0x004FD260)
#define sithCogParse_SetSymbolValue_ADDR (0x004FD350)
#define sithCogParse_GetSymbol_ADDR (0x004FD380)
#define sithCogParse_GetSymbolByID_ADDR (0x004FD3D0)
#define sithCogParse_GetSymbolLabel_ADDR (0x004FD410)
#define sithCogParse_MakeLeafNode_ADDR (0x004FD450)
#define sithCogParse_MakeVectorLeafNode_ADDR (0x004FD4F0)
#define sithCogParse_MakeNode_ADDR (0x004FD5A0)
#define sithCogParse_LexerSetSymbol_ADDR (0x004FD650)
#define sithCogParse_LexerSetString_ADDR (0x004FD7F0)
#define sithCogParse_LexerSetVector_ADDR (0x004FD8E0)
#define sithCogParse_GetNextLabel_ADDR (0x004FD930)
#define sithCogParse_GenerateLabelTable_ADDR (0x004FD940)
#define sithCogParse_GenerateCode_ADDR (0x004FDA00)
#define sithCogParse_ParseSymbolRef_ADDR (0x004FDAE0)
#define sithCogParse_ParseFlex_ADDR (0x004FDE10)
#define sithCogParse_ParseInt_ADDR (0x004FE040)
#define sithCogParse_ParseVector_ADDR (0x004FE280)
#define sithCogParse_ParseMessage_ADDR (0x004FE4D0)

void sithCogParse_FreeParseTree();
int sithCogParse_Load(char *pFilename, SithCogScript *pScript, int bParseDescription);
int sithCogParse_ParseSectionCode(SithCogScript *pScript);
SithCogSymbolTable* sithCogParse_DuplicateSymbolTable(SithCogSymbolTable *pSource);
SithCogSymbolTable* sithCogParse_AllocSymbolTable(int numElements);
int sithCogParse_ReallocSymbolTable(SithCogSymbolTable *pTable);
void sithCogParse_FreeSymbolTable(SithCogSymbolTable *pTable);
SithCogSymbol* sithCogParse_AddSymbol(SithCogSymbolTable *pTable, const char *pName);
void sithCogParse_SetSymbolValue(SithCogSymbol *pSymbol, SithCogSymbolValue *pValue);
SithCogSymbol* sithCogParse_GetSymbol(SithCogSymbolTable *pLocal, char *pName);
SithCogSymbol* sithCogParse_GetSymbolByID(SithCogSymbolTable *pTable, unsigned int symbolId);
int sithCogParse_GetSymbolLabel(unsigned int symbolId);
sith_cog_parser_node* sithCogParse_MakeLeafNode(int opcode, int symbolId);
sith_cog_parser_node* sithCogParse_MakeVectorLeafNode(int op, cog_flex_t* pVect);
sith_cog_parser_node* sithCogParse_MakeNode(sith_cog_parser_node* pLeft, sith_cog_parser_node* pRight, int opcode, int value);
void sithCogParse_LexerSetSymbol(char *pName);
void sithCogParse_LexerSetString(const char *pString);
void sithCogParse_LexerSetVector(char *inStr);
int sithCogParse_GetNextLabel();
int sithCogParse_GenerateLabelTable(sith_cog_parser_node *pRoot);
void sithCogParse_GenerateCode(sith_cog_parser_node *pNode);
int sithCogParse_ParseSymbolRef(SithCogScript *pScript, int symbolType, int bParseDescription);
int sithCogParse_ParseFlex(SithCogScript *pScript, int bParseDescription);
int sithCogParse_ParseInt(SithCogScript *pScript, int bParseDescription);
int sithCogParse_ParseVector(SithCogScript *pScript, int bParseDescription);
int sithCogParse_ParseMessage(SithCogScript *pScript);

//sith_cog_parser_node* sithCogParse_MakeNode(sith_cog_parser_node* parent, sith_cog_parser_node* child, int opcode, int val);
//sith_cog_parser_node* sithCogParse_MakeVectorLeafNode(int op, cog_flex_t* vector);
//sith_cog_parser_node* sithCogParse_MakeLeafNode(int op, int val);

//static SithCogSymbol* (__cdecl *sithCogParse_GetSymbol_)(SithCogSymbolTable *a1, unsigned int a2) = (void*)sithCogParse_GetSymbolByID_ADDR;
//static int (*sithCogParse_GenerateCode)(sith_cog_parser_node *node) = (void*)sithCogParse_GenerateCode_ADDR;

int cog_parsescript();

#endif // _SITHCOGPARSE_H
