#ifndef _SITHCOGYACC_H
#define _SITHCOGYACC_H

#include "types.h"

#define sithCogYACC_yyerror_ADDR (0x0050BF10)
#define sithCogYACC_yyparse_ADDR (0x0050BF50)
#define sithCogYACC_yylex_ADDR (0x0050C9C0)
#define sithCogYACC_yy_get_next_buffer_ADDR (0x0050D260)
#define sithCogYACC_yyrestart_ADDR (0x0050D430)
#define sithCogYACC_yy_switch_to_buffer_ADDR (0x0050D490)
#define sithCogYACC_yy_load_buffer_state_ADDR (0x0050D500)
#define sithCogYACC_yy_create_buffer_ADDR (0x0050D530)
#define sithCogYACC_yy_delete_buffer_ADDR (0x0050D620)
#define sithCogYACC_yy_init_buffer_ADDR (0x0050D650)

typedef struct sith_cog_parser_node sith_cog_parser_node;
//typedef YYSTYPE sith_cog_yacc_yystype;
typedef struct yy_buffer_state *YY_BUFFER_STATE;

extern int yynerrs;

extern void yyerror(char* s);
extern int yylex();
extern void yyrestart (FILE *input_file);
extern void yy_switch_to_buffer (YY_BUFFER_STATE new_buffer);
extern void yy_load_buffer_state (void);
extern YY_BUFFER_STATE yy_create_buffer (FILE *file, int size );
extern void yy_delete_buffer (YY_BUFFER_STATE b);
extern void yy_init_buffer (YY_BUFFER_STATE b, FILE *file );

#endif // _SITHCOGYACC_H
