#ifndef _SITHCOGPARSE_H
#define _SITHCOGPARSE_H

#include "rdVector.h"

#define COG_OPCODE_NOP   (0)
#define COG_OPCODE_PUSHINT  (1)
#define COG_OPCODE_PUSHFLOAT  (2)
#define COG_OPCODE_PUSHSYMBOL  (3)
#define COG_OPCODE_ARRAYINDEX  (4)
#define COG_OPCODE_CALLFUNC  (5)
#define COG_OPCODE_ASSIGN  (6)
#define COG_OPCODE_PUSHVECTOR  (7)
#define COG_OPCODE_ADD   (8)
#define COG_OPCODE_SUB   (9)
#define COG_OPCODE_MUL   (10)
#define COG_OPCODE_DIV   (11)
#define COG_OPCODE_MOD   (12)
#define COG_OPCODE_CMPFALSE  (13)
#define COG_OPCODE_NEG   (14)
#define COG_OPCODE_CMPGT  (15)
#define COG_OPCODE_CMPLS  (16)
#define COG_OPCODE_CMPEQ  (17)
#define COG_OPCODE_CMPLE  (18)
#define COG_OPCODE_CMPGE  (19)
#define COG_OPCODE_CMPAND  (20)
#define COG_OPCODE_CMPOR  (21)
#define COG_OPCODE_CMPNE  (22)
#define COG_OPCODE_ANDI  (23)
#define COG_OPCODE_ORI   (24)
#define COG_OPCODE_XORI  (25)
#define COG_OPCODE_GOFALSE  (26)
#define COG_OPCODE_GOTRUE  (27)
#define COG_OPCODE_GO    (28)
#define COG_OPCODE_RET   (29)
#define COG_OPCODE_UNK30  (30)
#define COG_OPCODE_CALL  (31)

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

static sith_cog_parser_node* (*sithCogParse_AddLeaf)(int op, int val) = (void*)0x004FD450;
static sith_cog_parser_node* (*sithCogParse_AddLeafVector)(int op, rdVector3* vector) = (void*)0x004FD4F0;
static sith_cog_parser_node* (*sithCogParse_AddLinkingNode)(sith_cog_parser_node* parent, sith_cog_parser_node* child, int opcode, int val) = (void*)0x004FD5A0;

int cog_parsescript();

#endif // _SITHCOGPARSE_H
