#include "sithCogParse.h"
#include "y.tab.h"

#include <stdlib.h>

//int loopdepth = 0;
sith_cog_parser_node* cogparser_topnode;
sith_cog_parser_node* cogparser_nodes_alloc = 0;
int cogparser_num_nodes = 0;
int cogparser_current_nodeidx;

int yyparse();
extern int linenum;

int* cogvm_stack;
int cogvm_stackpos = 0;
int cog_parser_node_stackpos[512];

//void (*sithCogParse_GetSymbolScriptIdx)(sith_cog* ctx) = (void*)0x004FD410;
//void (*sithCogParse_LexAddSymbol)(char* str) = (void*)0x004FD7F0;
//void (*sithCogParse_LexGetSym)(char* str) = (void*)0x004FD650;
//void (*sithCogParse_LexScanVector3)(sith_cog* ctx) = (void*)0x004FD8E0;
//sith_cog_parser_node* (*sithCogParse_AddLeaf)(int op, int val) = (void*)0x004FD450;
//sith_cog_parser_node* (*sithCogParse_AddLeafVector)(int op, rdVector3* vector) = (void*)0x004FD4F0;
//sith_cog_parser_node* (*sithCogParse_AddLinkingNode)(sith_cog_parser_node* parent, sith_cog_parser_node* child, int opcode, int val) = (void*)0x004FD5A0;

#if 0
sith_cog_parser_node* sithCogParse_AddLeaf(int op, int val)
{
    returnsithCogParse_AddLinkingNode(NULL, NULL, op, (int)val);
}

sith_cog_parser_node* sithCogParse_AddLeafVector(int op, rdVector3* vector)
{
    return sithCogParse_AddLinkingNode(NULL, NULL, op, (int)vector);
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
    memset(node, 0, sizeof(sith_cog_parser_node));
    node->opcode = opcode;
    node->value = val;
    node->parent = parent;
    node->child = child;
    
    cogparser_topnode = node;
    //printf("Add node %p w/ op %x, %p %p\n", node, opcode, parent, child);
    
   return node;
}
#endif

int sithCogParse_IncrementLoopdepth()
{
	void (*func)(void) = (void*)0x4FD930; //TODO impl
    func();
    //return loopdepth++;
}

int sithCogParse_GetSymbolScriptIdx(int symbol)
{
	int (*func)(int ctx) = (void*)0x004FD410; //TODO impl
    return func(symbol);
}

int sithCogParse_LexGetSym(char* text)
{
	int (*func)(char* a) = (void*)0x004FD650; //TODO impl
    return func(text);
    //printf("Get sym %s\n", text);
    //yylval.as_int = *(int*)text;
    //return yylval.as_int;
}

void sithCogParse_LexAddSymbol(char* text)
{
	void (*func)(char* a) = (void*)0x004FD7F0; //TODO impl
    func(text);
    
    //printf("Add sym %s\n", text);
}

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
    linenum = 1;
    if (yyparse())
        goto error;
    
    printf("Performing second pass...\n");
    cogvm_stackpos = 0;
    
    cogparser_recurse_stackdepth(cogparser_topnode);
    printf("Stack max: %x\n", cogvm_stackpos);
    
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
    
    printf("Done with second pass\n");
    for (int i = 0; i < cogvm_stackpos; i++)
    {
        printf("%08x: %08x\n", i, script_program[i]);
    }
    
    return 1;

error:
    printf("Error while parsing line %u\n", linenum);
    if (cogparser_topnode)
    {
        cogparser_current_nodeidx = 0;
        cogparser_topnode = 0;
    }
    cogvm_stackpos = 0;
    return 0;
}
