%{
#include <stdio.h>
#include "rdVector.h"
#include "sithCogParse.h"
%}

%token IDENTIFIER CONSTANT_INT CONSTANT_FLOAT STRING_LITERAL VECTOR_LITERAL
%token LE_OP GE_OP EQ_OP NE_OP
%token AND_OP OR_OP
%token TYPE_NAME

%token UNK_269

%token IF ELSE SWITCH WHILE DO FOR GOTO CONTINUE BREAK RETURN CALL

%union {
    rdVector3 as_vector;
    float as_float;
    int as_int;
    sith_cog_parser_node* as_node;
}

%start statement_list
%%

primary_expression
    : IDENTIFIER         { $$.as_node = sithCogParse_AddLeaf(COG_OPCODE_PUSHSYMBOL, $1.as_int); }
    | CONSTANT_INT       { $$.as_node = sithCogParse_AddLeaf(COG_OPCODE_PUSHINT, $1.as_int); }
    | CONSTANT_FLOAT     { $$.as_node = sithCogParse_AddLeaf(COG_OPCODE_PUSHFLOAT, $1.as_float); }
    | STRING_LITERAL     { $$.as_node = sithCogParse_AddLeaf(COG_OPCODE_PUSHSYMBOL, $1.as_int); }
    | VECTOR_LITERAL     { $$.as_node = sithCogParse_AddLeafVector(COG_OPCODE_PUSHVECTOR, &$1.as_vector); }
    | '(' expression ')' { $$.as_node = $2.as_node; }
    ;

postfix_expression
    : primary_expression
    | postfix_expression '[' expression ']'                 { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_ARRAYINDEX, 0); }
    | postfix_expression '(' ')'                            { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, 0, COG_OPCODE_CALLFUNC, 0); }
    | postfix_expression '(' argument_expression_list ')'   { $$.as_node = sithCogParse_AddLinkingNode($3.as_node, $1.as_node, COG_OPCODE_CALLFUNC, 0); }
    ;

argument_expression_list
    : assignment_expression
    | argument_expression_list ',' assignment_expression    { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_NOP, 0); }
    ;

unary_operator
    : '-'                                                   { $$.as_node = sithCogParse_AddLeaf(COG_OPCODE_NEG, 0); }
    | '!'                                                   { $$.as_node = sithCogParse_AddLeaf(COG_OPCODE_CMPFALSE, 0); }
    ;

unary_expression
    : postfix_expression
    | unary_operator unary_expression                       { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $2.as_node, COG_OPCODE_NOP, 0); }
    ;

multiplicative_expression
    : unary_expression
    | multiplicative_expression '*' unary_expression        { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_MUL, 0); }
    | multiplicative_expression '/' unary_expression        { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_DIV, 0); }
    | multiplicative_expression '%' unary_expression        { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_MOD, 0); }
    ;

additive_expression
    : multiplicative_expression
    | additive_expression '+' multiplicative_expression     { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_ADD, 0); }
    | additive_expression '-' multiplicative_expression     { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_SUB, 0); }
    ;

relational_expression
    : additive_expression
    | relational_expression '<' additive_expression         { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_CMPLS, 0); }
    | relational_expression '>' additive_expression         { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_CMPGT, 0); }
    | relational_expression LE_OP additive_expression       { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_CMPLE, 0); }
    | relational_expression GE_OP additive_expression       { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_CMPGE, 0); }
    ;

equality_expression
    : relational_expression
    | equality_expression EQ_OP relational_expression       { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_CMPEQ, 0); }
    | equality_expression NE_OP relational_expression       { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_CMPNE, 0); }
    ;

and_expression
    : equality_expression
    | and_expression '&' equality_expression                { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_ANDI, 0); }
    ;

exclusive_or_expression
    : and_expression
    | exclusive_or_expression '^' and_expression            { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_XORI, 0); }
    ;

inclusive_or_expression
    : exclusive_or_expression
    | inclusive_or_expression '|' exclusive_or_expression   { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_ORI, 0); }
    ;

logical_and_expression
    : inclusive_or_expression
    | logical_and_expression AND_OP inclusive_or_expression { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_CMPAND, 0); }
    ;

logical_or_expression
    : logical_and_expression
    | logical_or_expression OR_OP logical_and_expression    { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_CMPOR, 0); }
    ;

assignment_expression
    : logical_or_expression
    | unary_expression '=' assignment_expression            { $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_ASSIGN, 0); }
    ;

expression
    : assignment_expression
    | expression ',' assignment_expression                  { printf("expr\n");$$.as_node = sithCogParse_AddLinkingNode($1.as_node, $3.as_node, COG_OPCODE_NOP, 0); }
    ;

statement
    : labeled_statement
    | compound_statement
    | expression_statement
    | selection_statement
    | iteration_statement
    | jump_statement
    ;

labeled_statement
    : IDENTIFIER ':' statement                              { 
                                                            $$.as_node = sithCogParse_AddLinkingNode($3.as_node, 0, COG_OPCODE_NOP, 0); 
                                                            $$.as_node->child_loop_depth = sithCogParse_GetSymbolScriptIdx($1.as_node);
                                                            }
    ;

compound_statement
    : '{' '}'                                               { $$.as_node = sithCogParse_AddLeaf(COG_OPCODE_NOP, 0); }
    | '{' statement_list '}'                                { $$.as_node = $2.as_node; }
    ;

statement_list
    : statement
    | statement_list statement                              { printf("statement list\n"); $$.as_node = sithCogParse_AddLinkingNode($1.as_node, $2.as_node, COG_OPCODE_NOP, 0);  }
    ;

expression_statement
    : ';'                                                   { $$.as_node = sithCogParse_AddLeaf(COG_OPCODE_NOP, 0); }
    | expression ';'                                        { /* expression ; */ }
    ;

selection_statement
    : IF '(' expression ')' statement                       {
                                                            sith_cog_parser_node* tmp = sithCogParse_AddLinkingNode($3.as_node, 0, 0, 0);
                                                            tmp->parent_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            sith_cog_parser_node* tmp2 = sithCogParse_AddLinkingNode($1.as_node, 0, COG_OPCODE_GOFALSE, tmp->parent_loop_depth);
                                                            $$.as_node = sithCogParse_AddLinkingNode(tmp2, tmp, 0, 0);
                                                            }
    | IF '(' expression ')' statement ELSE statement        {
                                                            sith_cog_parser_node* tmp = sithCogParse_AddLinkingNode($7.as_node, 0, 0, 0);
                                                            tmp->child_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            tmp->parent_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            sith_cog_parser_node* tmp2 = sithCogParse_AddLinkingNode($3.as_node, 0, COG_OPCODE_GOFALSE, tmp->child_loop_depth);
                                                            tmp2 = sithCogParse_AddLinkingNode(tmp2, $5.as_node, COG_OPCODE_GO, tmp->parent_loop_depth);
                                                            $$.as_node = sithCogParse_AddLinkingNode(tmp2, tmp, 0, 0);
                                                            }
    ;

iteration_statement
    : WHILE '(' expression ')' statement                    {
                                                            sith_cog_parser_node* tmp = sithCogParse_AddLinkingNode($3.as_node, 0, COG_OPCODE_GOFALSE, 0);// expression (cond)
                                                            $$.as_node = sithCogParse_AddLinkingNode(tmp, $5.as_node, COG_OPCODE_GO, 0);
                                                            $$.as_node->parent_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            $$.as_node->child_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            tmp->value = $$.as_node->parent_loop_depth;
                                                            $$.as_node->value = $$.as_node->child_loop_depth;
                                                            }
    | DO statement WHILE '(' expression ')' ';'             {
                                                            $$.as_node = sithCogParse_AddLinkingNode($2.as_node, $5.as_node, COG_OPCODE_GOTRUE, 0);
                                                            $$.as_node->child_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            $$.as_node->value = $$.as_node->child_loop_depth;
                                                            }
    | FOR '(' expression_statement expression_statement expression ')' statement {
                                                                                 sith_cog_parser_node* tmp = sithCogParse_AddLinkingNode($7.as_node, 0, 0, 0);
                                                                                 tmp->parent_loop_depth = sithCogParse_IncrementLoopdepth();
                                                                                 
                                                                                 sith_cog_parser_node* tmp2 = sithCogParse_AddLinkingNode($4.as_node, 0, COG_OPCODE_GOFALSE, tmp->parent_loop_depth);
                                                                                 tmp2->child_loop_depth = sithCogParse_IncrementLoopdepth();
                                                                                 $$.as_node = sithCogParse_AddLinkingNode(tmp, $5.as_node, COG_OPCODE_GO, tmp2->child_loop_depth);
                                                                                 tmp2->value = sithCogParse_IncrementLoopdepth();
                                                                                 $$.as_node->parent_loop_depth = tmp2->value;
                                                                                 sith_cog_parser_node* tmp3 = sithCogParse_AddLinkingNode($3.as_node, tmp2, 0, 0);
                                                                                 $$.as_node = sithCogParse_AddLinkingNode(tmp3, $$.as_node, 0, 0);
                                                                                 }
    ;

jump_statement
    : GOTO IDENTIFIER ';'       { $$.as_node = sithCogParse_AddLeaf(COG_OPCODE_GO, sithCogParse_GetSymbolScriptIdx($2.as_node)); }
    | CALL IDENTIFIER ';'       { $$.as_node = sithCogParse_AddLeaf(COG_OPCODE_CALL, sithCogParse_GetSymbolScriptIdx($2.as_node)); }
    | RETURN ';'                { $$.as_node = sithCogParse_AddLeaf(COG_OPCODE_RET, 0); }
    ;

%%
#include <stdio.h>

extern char yytext[];
extern int linenum;

yyerror(s)
char *s;
{
    fflush(stdout);
    printf("PARSER %s: line %d.\n", s, linenum);
}
