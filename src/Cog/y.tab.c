#ifndef lint
char yysccsid[] = "@(#)yaccpar	1.4 (Berkeley) 02/25/90";
#endif
#line 2 "cog.y"
#include <stdio.h>
#include "sithCogParse.h"
#include "stdPlatform.h"

#define printf(...) _printf(__VA_ARGS__)
#define fwrite(x,y,z,w) _fwrite(x,y,z,w)
#define atoi(x) _atoi(x)
#define exit(x) jk_exit(x)
#define malloc(x) _malloc(x)
#define free(x) _free(x)
#define memcpy(x,y,z) _memcpy(x,y,z)
#define strlen(x) _strlen(x)
#define strcpy(x,y) _strcpy(x,y)
#line 26 "cog.y"
typedef union {
    cog_flex_t as_vector[3];
    float as_float;
    int as_int;
    sith_cog_parser_node* as_node;
} YYSTYPE;
#line 26 "y.tab.c"
#define IDENTIFIER 257
#define CONSTANT_INT 258
#define CONSTANT_FLOAT 259
#define STRING_LITERAL 260
#define VECTOR_LITERAL 261
#define LE_OP 262
#define GE_OP 263
#define EQ_OP 264
#define NE_OP 265
#define AND_OP 266
#define OR_OP 267
#define TYPE_NAME 268
#define UNK_269 269
#define IF 270
#define ELSE 271
#define SWITCH 272
#define WHILE 273
#define DO 274
#define FOR 275
#define GOTO 276
#define CONTINUE 277
#define BREAK 278
#define RETURN 279
#define CALL 280
#define YYERRCODE 256
short yylhs[] = {                                        -1,
    1,    1,    1,    1,    1,    1,    3,    3,    3,    3,
    4,    4,    6,    6,    7,    7,    8,    8,    8,    8,
    9,    9,    9,   10,   10,   10,   10,   10,   11,   11,
   11,   12,   12,   13,   13,   14,   14,   15,   15,   16,
   16,    5,    5,    2,    2,   17,   17,   17,   17,   17,
   17,   18,   19,   19,    0,    0,   20,   20,   21,   21,
   22,   22,   22,   23,   23,   23,
};
short yylen[] = {                                         2,
    1,    1,    1,    1,    1,    3,    1,    4,    3,    4,
    1,    3,    1,    1,    1,    2,    1,    3,    3,    3,
    1,    3,    3,    1,    3,    3,    3,    3,    1,    3,
    3,    1,    3,    1,    3,    1,    3,    1,    3,    1,
    3,    1,    3,    1,    3,    1,    1,    1,    1,    1,
    1,    3,    2,    3,    1,    2,    1,    2,    5,    7,
    5,    7,    7,    3,    3,    2,
};
short yydefred[] = {                                      0,
    0,    2,    3,    4,    5,    0,    0,    0,    0,    0,
    0,    0,    0,   13,   14,    0,   57,    0,    7,    0,
    0,   44,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   55,   46,   47,   48,   49,   50,   51,
    0,    0,    0,    0,    0,    0,   66,    0,    1,    0,
   53,    0,   56,    0,   58,    0,    0,   16,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   52,    0,    0,    0,    0,
   64,   65,    6,   54,   45,    9,    0,   11,    0,   43,
   18,   19,   20,   17,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   10,    0,    8,    0,   61,    0,    0,   12,    0,
    0,    0,   60,   62,   63,
};
short yydgoto[] = {                                      18,
   19,   20,   21,   87,   22,   23,   24,   25,   26,   27,
   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,
   38,   39,   40,
};
short yysindex[] = {                                     34,
  -44,    0,    0,    0,    0,  -19,   -9,   34,   29, -230,
  -16, -202,   98,    0,    0,  -33,    0,   34,    0,  -26,
  -30,    0,   98,   11,  -17,   41,  -58, -226,   37,   -7,
  -10, -170, -169,    0,    0,    0,    0,    0,    0,    0,
   34,   98,   98, -166,  257,   49,    0,   61,    0,  -12,
    0,    9,    0,   98,    0,   -5,   98,    0,   98,   98,
   98,   98,   98,   98,   98,   98,   98,   98,   98,   98,
   98,   98,   98,   98,   98,    0,    3,    4,   81,  257,
    0,    0,    0,    0,    0,    0,   12,    0,  -29,    0,
    0,    0,    0,    0,  -17,  -17,   41,   41,   41,   41,
  -58,  -58, -226,   37,   -7,  -10, -170,   34,   34,   98,
   98,    0,   98,    0, -149,    0,   21,   22,    0,   34,
   64,   34,    0,    0,    0,
};
short yyrindex[] = {                                      0,
   57,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   68,    0,    0,  126,  115,  360,  -35,  461,  387,  491,
  -22,   44,  -36,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  301,  309,  367,  377,  403,  414,
  428,  454,  465,  487,  558,   32,  106,    0,    0,    0,
    0,    0,    0,    0,    1,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,
};
short yygindex[] = {                                    117,
    0,  153,    0,    0,  -43,    0,  636,  -13,   15,    8,
   65,   63,   66,   67,   69,    0,  492,    0,    0,  -28,
    0,    0,    0,
};
#define YYTABLESIZE 825
short yytable[] = {                                      15,
   59,   67,   29,   68,   42,   29,   13,   42,   29,   56,
   85,   14,   88,   41,   54,   90,   80,   54,   38,   62,
   42,   38,   42,   29,   60,   17,   46,   15,   83,   61,
   43,   54,   55,   59,   13,   86,   38,   69,   70,   14,
   59,   15,   47,  108,  109,   59,   54,   54,   13,   95,
   96,  111,  112,   14,   48,  113,   42,   29,   29,   59,
   57,  121,  122,  114,   54,   54,   15,   17,   45,  119,
   38,   59,   39,   13,   71,   39,  101,  102,   14,   97,
   98,   99,  100,   64,   40,   63,   72,   40,   29,   16,
   39,   51,   17,    1,    1,   74,    1,   75,    1,    1,
    1,    1,   40,    1,   15,   15,   79,   81,   15,   15,
   15,   15,   15,   73,   15,    1,    1,    1,    1,   82,
  110,  120,  124,   59,   39,   59,   15,   15,   15,   15,
   15,   16,   52,   84,  104,  103,   40,   13,  105,    0,
  106,    0,   14,  107,    0,    0,   41,    1,    0,   41,
    1,    0,   21,    0,    0,   21,   16,   21,   21,   21,
   15,   15,   17,   17,   41,   50,   17,   17,   17,   17,
   17,    0,   17,   21,   21,    0,   21,    0,    0,    0,
    1,    0,    0,    0,   17,   17,    0,   17,    0,    0,
    0,   15,    0,    0,   77,   78,    0,    0,   41,    0,
    0,    0,    0,   65,   66,    0,    0,   21,   21,   89,
    0,    0,    0,    0,    0,    0,    0,    0,   17,   17,
    0,    0,    0,    1,    2,    3,    4,    5,   29,   29,
   29,   29,    0,    0,    0,    0,    6,    0,   21,    7,
    8,    9,   10,   38,   38,   11,   12,    0,    0,   17,
    0,   49,    2,    3,    4,    5,    0,   59,   59,   59,
   59,   59,  117,  118,    0,    1,    2,    3,    4,    5,
   59,    0,    0,   59,   59,   59,   59,    0,    6,   59,
   59,    7,    8,    9,   10,    0,    0,   11,   12,   15,
    1,    2,    3,    4,    5,    0,   13,   39,   39,    0,
    0,   14,    0,    6,    0,    0,    7,    8,    9,   10,
   40,    0,   11,   12,    0,   17,    0,    0,    1,    1,
    1,    1,    1,    1,    0,    0,    0,    0,    0,   15,
   15,   15,   15,   15,   15,    0,    0,    0,   23,    0,
    0,   23,    0,   23,   23,   23,   22,    0,    0,   22,
    0,   22,   22,   22,   49,    2,    3,    4,    5,   23,
   23,    0,   23,    0,    0,    0,    0,   22,   22,    0,
   22,    0,   41,    0,    0,    0,   21,   21,   21,   21,
   21,   21,    0,    0,    0,    0,    0,   17,   17,   17,
   17,   17,   17,   23,   23,    0,    0,   24,    0,    0,
   24,   22,   22,   24,   27,    0,    0,   27,    0,    0,
   27,    0,    0,    0,   28,    0,    0,   28,   24,   24,
   28,   24,    0,    0,   23,   27,   27,   34,   27,    0,
   34,    0,   22,    0,    0,   28,   28,    0,   28,    0,
   25,    0,    0,   25,    0,   34,   25,    0,    0,    0,
    0,   26,   24,   24,   26,    0,    0,   26,    0,   27,
   27,   25,   25,    0,   25,   30,    0,    0,   30,   28,
   28,   30,   26,   26,    0,   26,    0,    0,    0,   34,
   34,    0,    0,   24,    0,    0,   30,    0,    0,    0,
   27,   31,    0,    0,   31,   25,   25,   31,   32,   44,
   28,   32,   33,    0,   32,   33,   26,   26,   33,   53,
   34,    0,   31,   49,    2,    3,    4,    5,    0,   32,
   30,   30,    0,   33,    0,    0,   25,   35,    0,    0,
   35,   36,   76,    0,   36,    0,    0,   26,    0,    0,
    0,    0,    0,   53,    0,   35,   31,   31,    0,   36,
    0,   30,    0,   32,   32,    0,    0,   33,   33,    0,
    0,    0,   23,   23,   23,   23,   23,   23,    0,    0,
   22,   22,   22,   22,   22,   22,    0,   31,    0,   35,
   35,    0,    0,   36,   32,    0,    0,    0,   33,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   37,  115,
  116,   37,    0,    0,    0,    0,    0,    0,    0,    0,
   35,  123,    0,  125,   36,    0,   37,    0,    0,    0,
    0,   24,   24,   24,   24,   24,   24,    0,   27,   27,
   27,   27,   27,   27,    0,    0,    0,    0,   28,   28,
   28,   28,   28,   28,    0,    0,    0,    0,    0,    0,
   37,    0,   34,   34,    0,    0,    0,    0,   58,    0,
    0,    0,    0,    0,   25,   25,   25,   25,   25,   25,
    0,    0,    0,    0,    0,   26,   26,   26,   26,   26,
   26,   37,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   30,   30,   30,   30,   91,   92,   93,   94,   94,
   94,   94,   94,   94,   94,   94,   94,   94,   94,   94,
   94,    0,    0,    0,    0,    0,    0,   31,   31,   31,
   31,    0,    0,    0,    0,    0,   32,   32,    0,    0,
   33,   33,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   35,   35,    0,    0,   36,   36,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   37,   37,
};
short yycheck[] = {                                      33,
    0,   60,   38,   62,   41,   41,   40,   44,   44,   40,
   54,   45,   56,   58,   44,   59,   45,   44,   41,   37,
   40,   44,   59,   59,   42,   59,  257,   33,   41,   47,
   40,   44,   59,   33,   40,   41,   59,  264,  265,   45,
   40,   33,   59,   41,   41,   45,   44,   44,   40,   63,
   64,   80,   41,   45,  257,   44,   93,   93,   94,   59,
   91,   41,   41,   93,   44,   44,   33,   59,   40,  113,
   93,   61,   41,   40,   38,   44,   69,   70,   45,   65,
   66,   67,   68,   43,   41,   45,   94,   44,  124,  123,
   59,  125,   59,   37,   38,  266,   40,  267,   42,   43,
   44,   45,   59,   47,   37,   38,  273,   59,   41,   42,
   43,   44,   45,  124,   47,   59,   60,   61,   62,   59,
   40,  271,   59,  123,   93,  125,   59,   60,   61,   62,
   33,  123,   16,  125,   72,   71,   93,   40,   73,   -1,
   74,   -1,   45,   75,   -1,   -1,   41,   91,   -1,   44,
   94,   -1,   38,   -1,   -1,   41,  123,   43,   44,   45,
   93,   94,   37,   38,   59,   13,   41,   42,   43,   44,
   45,   -1,   47,   59,   60,   -1,   62,   -1,   -1,   -1,
  124,   -1,   -1,   -1,   59,   60,   -1,   62,   -1,   -1,
   -1,  124,   -1,   -1,   42,   43,   -1,   -1,   93,   -1,
   -1,   -1,   -1,  262,  263,   -1,   -1,   93,   94,   57,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   93,   94,
   -1,   -1,   -1,  257,  258,  259,  260,  261,  264,  265,
  266,  267,   -1,   -1,   -1,   -1,  270,   -1,  124,  273,
  274,  275,  276,  266,  267,  279,  280,   -1,   -1,  124,
   -1,  257,  258,  259,  260,  261,   -1,  257,  258,  259,
  260,  261,  110,  111,   -1,  257,  258,  259,  260,  261,
  270,   -1,   -1,  273,  274,  275,  276,   -1,  270,  279,
  280,  273,  274,  275,  276,   -1,   -1,  279,  280,   33,
  257,  258,  259,  260,  261,   -1,   40,  266,  267,   -1,
   -1,   45,   -1,  270,   -1,   -1,  273,  274,  275,  276,
  267,   -1,  279,  280,   -1,   59,   -1,   -1,  262,  263,
  264,  265,  266,  267,   -1,   -1,   -1,   -1,   -1,  262,
  263,  264,  265,  266,  267,   -1,   -1,   -1,   38,   -1,
   -1,   41,   -1,   43,   44,   45,   38,   -1,   -1,   41,
   -1,   43,   44,   45,  257,  258,  259,  260,  261,   59,
   60,   -1,   62,   -1,   -1,   -1,   -1,   59,   60,   -1,
   62,   -1,  267,   -1,   -1,   -1,  262,  263,  264,  265,
  266,  267,   -1,   -1,   -1,   -1,   -1,  262,  263,  264,
  265,  266,  267,   93,   94,   -1,   -1,   38,   -1,   -1,
   41,   93,   94,   44,   38,   -1,   -1,   41,   -1,   -1,
   44,   -1,   -1,   -1,   38,   -1,   -1,   41,   59,   60,
   44,   62,   -1,   -1,  124,   59,   60,   41,   62,   -1,
   44,   -1,  124,   -1,   -1,   59,   60,   -1,   62,   -1,
   38,   -1,   -1,   41,   -1,   59,   44,   -1,   -1,   -1,
   -1,   38,   93,   94,   41,   -1,   -1,   44,   -1,   93,
   94,   59,   60,   -1,   62,   38,   -1,   -1,   41,   93,
   94,   44,   59,   60,   -1,   62,   -1,   -1,   -1,   93,
   94,   -1,   -1,  124,   -1,   -1,   59,   -1,   -1,   -1,
  124,   38,   -1,   -1,   41,   93,   94,   44,   38,    8,
  124,   41,   38,   -1,   44,   41,   93,   94,   44,   18,
  124,   -1,   59,  257,  258,  259,  260,  261,   -1,   59,
   93,   94,   -1,   59,   -1,   -1,  124,   41,   -1,   -1,
   44,   41,   41,   -1,   44,   -1,   -1,  124,   -1,   -1,
   -1,   -1,   -1,   52,   -1,   59,   93,   94,   -1,   59,
   -1,  124,   -1,   93,   94,   -1,   -1,   93,   94,   -1,
   -1,   -1,  262,  263,  264,  265,  266,  267,   -1,   -1,
  262,  263,  264,  265,  266,  267,   -1,  124,   -1,   93,
   94,   -1,   -1,   93,  124,   -1,   -1,   -1,  124,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   41,  108,
  109,   44,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  124,  120,   -1,  122,  124,   -1,   59,   -1,   -1,   -1,
   -1,  262,  263,  264,  265,  266,  267,   -1,  262,  263,
  264,  265,  266,  267,   -1,   -1,   -1,   -1,  262,  263,
  264,  265,  266,  267,   -1,   -1,   -1,   -1,   -1,   -1,
   93,   -1,  266,  267,   -1,   -1,   -1,   -1,   23,   -1,
   -1,   -1,   -1,   -1,  262,  263,  264,  265,  266,  267,
   -1,   -1,   -1,   -1,   -1,  262,  263,  264,  265,  266,
  267,  124,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  264,  265,  266,  267,   60,   61,   62,   63,   64,
   65,   66,   67,   68,   69,   70,   71,   72,   73,   74,
   75,   -1,   -1,   -1,   -1,   -1,   -1,  264,  265,  266,
  267,   -1,   -1,   -1,   -1,   -1,  266,  267,   -1,   -1,
  266,  267,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  266,  267,   -1,   -1,  266,  267,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  266,  267,
};
#define YYFINAL 18
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 280
#if YYDEBUG
char *yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,"'%'","'&'",0,"'('","')'","'*'","'+'","','","'-'",0,"'/'",0,0,0,0,0,
0,0,0,0,0,"':'","';'","'<'","'='","'>'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,"'['",0,"']'","'^'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,"'{'","'|'","'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"IDENTIFIER","CONSTANT_INT",
"CONSTANT_FLOAT","STRING_LITERAL","VECTOR_LITERAL","LE_OP","GE_OP","EQ_OP",
"NE_OP","AND_OP","OR_OP","TYPE_NAME","UNK_269","IF","ELSE","SWITCH","WHILE",
"DO","FOR","GOTO","CONTINUE","BREAK","RETURN","CALL",
};
char *yyrule[] = {
"$accept : statement_list",
"primary_expression : IDENTIFIER",
"primary_expression : CONSTANT_INT",
"primary_expression : CONSTANT_FLOAT",
"primary_expression : STRING_LITERAL",
"primary_expression : VECTOR_LITERAL",
"primary_expression : '(' expression ')'",
"postfix_expression : primary_expression",
"postfix_expression : postfix_expression '[' expression ']'",
"postfix_expression : postfix_expression '(' ')'",
"postfix_expression : postfix_expression '(' argument_expression_list ')'",
"argument_expression_list : assignment_expression",
"argument_expression_list : argument_expression_list ',' assignment_expression",
"unary_operator : '-'",
"unary_operator : '!'",
"unary_expression : postfix_expression",
"unary_expression : unary_operator unary_expression",
"multiplicative_expression : unary_expression",
"multiplicative_expression : multiplicative_expression '*' unary_expression",
"multiplicative_expression : multiplicative_expression '/' unary_expression",
"multiplicative_expression : multiplicative_expression '%' unary_expression",
"additive_expression : multiplicative_expression",
"additive_expression : additive_expression '+' multiplicative_expression",
"additive_expression : additive_expression '-' multiplicative_expression",
"relational_expression : additive_expression",
"relational_expression : relational_expression '<' additive_expression",
"relational_expression : relational_expression '>' additive_expression",
"relational_expression : relational_expression LE_OP additive_expression",
"relational_expression : relational_expression GE_OP additive_expression",
"equality_expression : relational_expression",
"equality_expression : equality_expression EQ_OP relational_expression",
"equality_expression : equality_expression NE_OP relational_expression",
"and_expression : equality_expression",
"and_expression : and_expression '&' equality_expression",
"exclusive_or_expression : and_expression",
"exclusive_or_expression : exclusive_or_expression '^' and_expression",
"inclusive_or_expression : exclusive_or_expression",
"inclusive_or_expression : inclusive_or_expression '|' exclusive_or_expression",
"logical_and_expression : inclusive_or_expression",
"logical_and_expression : logical_and_expression AND_OP inclusive_or_expression",
"logical_or_expression : logical_and_expression",
"logical_or_expression : logical_or_expression OR_OP logical_and_expression",
"assignment_expression : logical_or_expression",
"assignment_expression : unary_expression '=' assignment_expression",
"expression : assignment_expression",
"expression : expression ',' assignment_expression",
"statement : labeled_statement",
"statement : compound_statement",
"statement : expression_statement",
"statement : selection_statement",
"statement : iteration_statement",
"statement : jump_statement",
"labeled_statement : IDENTIFIER ':' statement",
"compound_statement : '{' '}'",
"compound_statement : '{' statement_list '}'",
"statement_list : statement",
"statement_list : statement_list statement",
"expression_statement : ';'",
"expression_statement : expression ';'",
"selection_statement : IF '(' expression ')' statement",
"selection_statement : IF '(' expression ')' statement ELSE statement",
"iteration_statement : WHILE '(' expression ')' statement",
"iteration_statement : DO statement WHILE '(' expression ')' ';'",
"iteration_statement : FOR '(' expression_statement expression_statement expression ')' statement",
"jump_statement : GOTO IDENTIFIER ';'",
"jump_statement : CALL IDENTIFIER ';'",
"jump_statement : RETURN ';'",
};
#endif
#define yyclearin (yychar=(-1))
#define yyerrok (yyerrflag=0)
#ifndef YYSTACKSIZE
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 300
#endif
#endif
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
#define yystacksize YYSTACKSIZE
short yyss[YYSTACKSIZE];
YYSTYPE yyvs[YYSTACKSIZE];
#line 212 "cog.y"
#include "jk.h"

extern char yytext[];

void yyerror(char* s)
{
    stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCogYACC.c", 406, "PARSER %s: line %d.\n", s, yacc_linenum);
}
#line 414 "y.tab.c"
#define YYABORT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
yyparse()
{
    /*register*/  int yym, yyn, yystate;
#if YYDEBUG
    /*register*/  char *yys;
    extern char *getenv();

    if (yys = getenv("YYDEBUG"))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if (yyn = yydefred[yystate]) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("yydebug: state %d, reading %d (%s)\n", yystate,
                    yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("yydebug: state %d, shifting to state %d\n",
                    yystate, yytable[yyn]);
#endif
        if (yyssp >= yyss + yystacksize - 1)
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#ifdef lint
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#ifdef lint
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("yydebug: state %d, error recovery shifting\
 to state %d\n", *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yyss + yystacksize - 1)
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("yydebug: error recovery discarding state %d\n",
                            *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("yydebug: state %d, error recovery discards token %d (%s)\n",
                    yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("yydebug: state %d, reducing by rule %d (%s)\n",
                yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 1:
#line 37 "cog.y"
{ yyval .as_node = sithCogParse_AddLeaf(COG_OPCODE_PUSHSYMBOL, yyvsp[0].as_int); }
break;
case 2:
#line 38 "cog.y"
{ yyval .as_node = sithCogParse_AddLeaf(COG_OPCODE_PUSHINT, yyvsp[0].as_int); }
break;
case 3:
#line 39 "cog.y"
{ yyval .as_node = sithCogParse_AddLeaf(COG_OPCODE_PUSHFLOAT, yyvsp[0].as_int); }
break;
case 4:
#line 40 "cog.y"
{ yyval .as_node = sithCogParse_AddLeaf(COG_OPCODE_PUSHSYMBOL, yyvsp[0].as_int); }
break;
case 5:
#line 41 "cog.y"
{ yyval .as_node = sithCogParse_AddLeafVector(COG_OPCODE_PUSHVECTOR, yyvsp[0].as_vector); }
break;
case 6:
#line 42 "cog.y"
{ yyval .as_node = yyvsp[-1].as_node; }
break;
case 8:
#line 47 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-3].as_node, yyvsp[-1].as_node, COG_OPCODE_ARRAYINDEX, 0); }
break;
case 9:
#line 48 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, 0, COG_OPCODE_CALLFUNC, 0); }
break;
case 10:
#line 49 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-1].as_node, yyvsp[-3].as_node, COG_OPCODE_CALLFUNC, 0); }
break;
case 12:
#line 54 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_NOP, 0); }
break;
case 13:
#line 58 "cog.y"
{ yyval .as_node = sithCogParse_AddLeaf(COG_OPCODE_NEG, 0); }
break;
case 14:
#line 59 "cog.y"
{ yyval .as_node = sithCogParse_AddLeaf(COG_OPCODE_CMPFALSE, 0); }
break;
case 16:
#line 64 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[0].as_node, yyvsp[-1].as_node, COG_OPCODE_NOP, 0); }
break;
case 18:
#line 69 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_MUL, 0); }
break;
case 19:
#line 70 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_DIV, 0); }
break;
case 20:
#line 71 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_MOD, 0); }
break;
case 22:
#line 76 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_ADD, 0); }
break;
case 23:
#line 77 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_SUB, 0); }
break;
case 25:
#line 82 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_CMPLS, 0); }
break;
case 26:
#line 83 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_CMPGT, 0); }
break;
case 27:
#line 84 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_CMPLE, 0); }
break;
case 28:
#line 85 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_CMPGE, 0); }
break;
case 30:
#line 90 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_CMPEQ, 0); }
break;
case 31:
#line 91 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_CMPNE, 0); }
break;
case 33:
#line 96 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_ANDI, 0); }
break;
case 35:
#line 101 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_XORI, 0); }
break;
case 37:
#line 106 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_ORI, 0); }
break;
case 39:
#line 111 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_CMPAND, 0); }
break;
case 41:
#line 116 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_CMPOR, 0); }
break;
case 43:
#line 121 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_ASSIGN, 0); }
break;
case 45:
#line 126 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, yyvsp[0].as_node, COG_OPCODE_NOP, 0); }
break;
case 52:
#line 139 "cog.y"
{ 
                                                            yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[0].as_node, 0, COG_OPCODE_NOP, 0); 
                                                            yyval .as_node->child_loop_depth = sithCogParse_GetSymbolScriptIdx(yyvsp[-2].as_int);
                                                            }
break;
case 53:
#line 146 "cog.y"
{ yyval .as_node = sithCogParse_AddLeaf(COG_OPCODE_NOP, 0); }
break;
case 54:
#line 147 "cog.y"
{ yyval .as_node = yyvsp[-1].as_node; }
break;
case 56:
#line 152 "cog.y"
{ yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-1].as_node, yyvsp[0].as_node, COG_OPCODE_NOP, 0);  }
break;
case 57:
#line 156 "cog.y"
{ yyval .as_node = sithCogParse_AddLeaf(COG_OPCODE_NOP, 0); }
break;
case 58:
#line 157 "cog.y"
{ /* expression ; */ }
break;
case 59:
#line 161 "cog.y"
{
                                                            sith_cog_parser_node* tmp = sithCogParse_AddLinkingNode(yyvsp[0].as_node, 0, COG_OPCODE_NOP, 0);
                                                            tmp->parent_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            sith_cog_parser_node* tmp2 = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, 0, COG_OPCODE_GOFALSE, tmp->parent_loop_depth);
                                                            yyval .as_node = sithCogParse_AddLinkingNode(tmp2, tmp, COG_OPCODE_NOP, 0);
                                                            }
break;
case 60:
#line 167 "cog.y"
{
                                                            sith_cog_parser_node* tmp = sithCogParse_AddLinkingNode(yyvsp[0].as_node, 0, COG_OPCODE_NOP, 0);
                                                            tmp->child_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            tmp->parent_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            sith_cog_parser_node* tmp2 = sithCogParse_AddLinkingNode(yyvsp[-4].as_node, 0, COG_OPCODE_GOFALSE, tmp->child_loop_depth);
                                                            tmp2 = sithCogParse_AddLinkingNode(tmp2, yyvsp[-2].as_node, COG_OPCODE_GO, tmp->parent_loop_depth);
                                                            yyval .as_node = sithCogParse_AddLinkingNode(tmp2, tmp, COG_OPCODE_NOP, 0);
                                                            }
break;
case 61:
#line 178 "cog.y"
{
                                                            sith_cog_parser_node* tmp = sithCogParse_AddLinkingNode(yyvsp[-2].as_node, 0, COG_OPCODE_GOFALSE, 0);/* expression (cond)*/
                                                            yyval .as_node = sithCogParse_AddLinkingNode(tmp, yyvsp[0].as_node, COG_OPCODE_GO, 0);
                                                            yyval .as_node->parent_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            yyval .as_node->child_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            tmp->value = yyval .as_node->parent_loop_depth;
                                                            yyval .as_node->value = yyval .as_node->child_loop_depth;
                                                            }
break;
case 62:
#line 186 "cog.y"
{
                                                            yyval .as_node = sithCogParse_AddLinkingNode(yyvsp[-5].as_node, yyvsp[-2].as_node, COG_OPCODE_GOTRUE, 0);
                                                            yyval .as_node->child_loop_depth = sithCogParse_IncrementLoopdepth();
                                                            yyval .as_node->value = yyval .as_node->child_loop_depth;
                                                            }
break;
case 63:
#line 191 "cog.y"
{
                                                                                 sith_cog_parser_node* tmp = sithCogParse_AddLinkingNode(yyvsp[0].as_node, 0, COG_OPCODE_NOP, 0);
                                                                                 tmp->parent_loop_depth = sithCogParse_IncrementLoopdepth();
                                                                                 
                                                                                 sith_cog_parser_node* tmp2 = sithCogParse_AddLinkingNode(yyvsp[-3].as_node, 0, COG_OPCODE_GOFALSE, tmp->parent_loop_depth);
                                                                                 tmp2->child_loop_depth = sithCogParse_IncrementLoopdepth();
                                                                                 yyval .as_node = sithCogParse_AddLinkingNode(tmp, yyvsp[-2].as_node, COG_OPCODE_GO, tmp2->child_loop_depth);
                                                                                 tmp2->value = sithCogParse_IncrementLoopdepth();
                                                                                 yyval .as_node->parent_loop_depth = tmp2->value;
                                                                                 sith_cog_parser_node* tmp3 = sithCogParse_AddLinkingNode(yyvsp[-4].as_node, tmp2, COG_OPCODE_NOP, 0);
                                                                                 yyval .as_node = sithCogParse_AddLinkingNode(tmp3, yyval .as_node, COG_OPCODE_NOP, 0);
                                                                                 }
break;
case 64:
#line 206 "cog.y"
{ yyval .as_node = sithCogParse_AddLeaf(COG_OPCODE_GO, sithCogParse_GetSymbolScriptIdx(yyvsp[-1].as_int)); }
break;
case 65:
#line 207 "cog.y"
{ yyval .as_node = sithCogParse_AddLeaf(COG_OPCODE_CALL, sithCogParse_GetSymbolScriptIdx(yyvsp[-1].as_int)); }
break;
case 66:
#line 208 "cog.y"
{ yyval .as_node = sithCogParse_AddLeaf(COG_OPCODE_RET, 0); }
break;
#line 771 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#ifdef YYDEBUG
        if (yydebug)
            printf("yydebug: after reduction, shifting from state 0 to\
 state %d\n", YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("yydebug: state %d, reading %d (%s)\n",
                        YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#ifdef YYDEBUG
    if (yydebug)
        printf("yydebug: after reduction, shifting from state %d \
to state %d\n", *yyssp, yystate);
#endif
    if (yyssp >= yyss + yystacksize - 1)
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    return (1);
yyaccept:
    return (0);
}
