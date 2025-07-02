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
typedef union {
    cog_flex_t as_vector[3];
    float as_float;
    int as_int;
    sith_cog_parser_node* as_node;
} YYSTYPE;
extern YYSTYPE yylval;
