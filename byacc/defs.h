#include <assert.h>
#include <ctype.h>
#include <stdio.h>


#ifdef __APPLE__
#include <stdlib.h>
#include <string.h>
#endif

/*  machine dependent definitions			*/
/*  the following definitions are for the VAX		*/
/*  they might have to be changed for other machines	*/

/*  MAXCHAR is the largest character value		*/
/*  MAXSHORT is the largest value of a C short		*/
/*  MINSHORT is the most negative value of a C short	*/
/*  MAXTABLE is the maximum table size			*/
/*  BITS_PER_WORD is the number of bits in a C unsigned	*/
/*  WORDSIZE computes the number of words needed to	*/
/*	store n bits					*/
/*  BIT returns the value of the n-th bit starting	*/
/*	from r (0-indexed)				*/
/*  SETBIT sets the n-th bit starting from r		*/

#define	MAXCHAR		255
#define	MAXSHORT	32767
#define MINSHORT	-32768
#define MAXTABLE	32500
#define BITS_PER_WORD	32
#define	WORDSIZE(n)	(((n)+(BITS_PER_WORD-1))/BITS_PER_WORD)
#define	BIT(r, n)	((((r)[(n) >> 5]) >> ((n) & 31)) & 1)
#define	SETBIT(r, n)	((r)[(n) >> 5] |= (1 << ((n) & 31)))


/*  character names  */

#define	NUL		'\0'    /*  the null character  */
#define	NEWLINE		'\n'    /*  line feed  */
#define	SP		' '     /*  space  */
#define	BS		'\b'    /*  backspace  */
#define	HT		'\t'    /*  horizontal tab  */
#define	VT		'\013'  /*  vertical tab  */
#define	CR		'\r'    /*  carriage return  */
#define	FF		'\f'    /*  form feed  */
#define	QUOTE		'\''    /*  single quote  */
#define	DOUBLE_QUOTE	'\"'    /*  double quote  */
#define	BACKSLASH	'\\'    /*  backslash  */


/* defines for constructing filenames */

#define	DEFINES_SUFFIX	".tab.h"
#define	OUTPUT_SUFFIX	".tab.c"
#define	VERBOSE_SUFFIX	".output"


/* keyword codes */

#define TOKEN 0
#define LEFT 1
#define RIGHT 2
#define NONASSOC 3
#define MARK 4
#define TEXT 5
#define TYPE 6
#define START 7
#define UNION 8
#define IDENT 9


/*  symbol classes  */

#define UNKNOWN 0
#define TERM 1
#define NONTERM 2


/*  the undefined value  */

#define UNDEFINED (-1)


/*  action codes  */

#define SHIFT 1
#define REDUCE 2
#define ERROR 3


/*  character macros  */

#define IS_IDENT(c)	(isalnum(c) || (c) == '_' || (c) == '.' || (c) == '$')
#define	IS_OCTAL(c)	((c) >= '0' && (c) <= '7')
#define	NUMERIC_VALUE(c)	((c) - '0')


/*  symbol macros  */

#define ISTOKEN(s)	((s) < start_symbol)
#define ISVAR(s)	((s) >= start_symbol)


/*  storage allocation macros  */

#define	FREE(x)		(free((char*)(x)))
#define MALLOC(n)	(malloc((unsigned)(n)))
#define	NEW(t)		((t*)allocate(sizeof(t)))
#define	NEW2(n,t)	((t*)allocate((unsigned)((n)*sizeof(t))))
#define REALLOC(p,n)	(realloc((char*)(p),(unsigned)(n)))


/*  the structure of a symbol table entry  */

typedef struct bucket bucket;
struct bucket
{
    struct bucket *link;
    struct bucket *next;
    char *name;
    char *tag;
    short value;
    short index;
    short prec;
    char class;
    char assoc;
};


/*  the structure of the LR(0) state machine  */

typedef struct core core;
struct core
{
    struct core *next;
    struct core *link;
    short number;
    short accessing_symbol;
    short nitems;
    short items[1];
};


/*  the structure used to record shifts  */

typedef struct shifts shifts;
struct shifts
{
    struct shifts *next;
    short number;
    short nshifts;
    short shift[1];
};


/*  the structure used to store reductions  */

typedef struct reductions reductions;
struct reductions
{
    struct reductions *next;
    short number;
    short nreds;
    short rules[1];
};


/*  the structure used to represent parser actions  */

typedef struct action action;
struct action
{
    struct action *next;
    short symbol;
    short number;
    short prec;
    char action_code;
    char assoc;
    char suppressed;
};


/* global variables */

extern char dflag;
extern char lflag;
extern char tflag;
extern char vflag;

extern char *myname;
extern char *cptr;
extern char *line;
extern int lineno;
extern int outline;

extern char *banner[];
extern char *header[];
extern char *body[];
extern char *trailer[];

extern char *action_file_name;
extern char *defines_file_name;
extern char *input_file_name;
extern char *output_file_name;
extern char *text_file_name;
extern char *union_file_name;
extern char *verbose_file_name;

extern FILE *action_file;
extern FILE *defines_file;
extern FILE *input_file;
extern FILE *output_file;
extern FILE *text_file;
extern FILE *union_file;
extern FILE *verbose_file;

extern int nitems;
extern int nrules;
extern int nsyms;
extern int ntokens;
extern int nvars;
extern int ntags;

extern char unionized;
extern char line_format[];

extern int   start_symbol;
extern char  **symbol_name;
extern short *symbol_value;
extern short *symbol_prec;
extern char  *symbol_assoc;

extern short *ritem;
extern short *rlhs;
extern short *rrhs;
extern short *rprec;
extern char  *rassoc;

extern short **derives;
extern char *nullable;

extern bucket *first_symbol;
extern bucket *last_symbol;

extern int nstates;
extern core *first_state;
extern shifts *first_shift;
extern reductions *first_reduction;
extern short *accessing_symbol;
extern core **state_table;
extern shifts **shift_table;
extern reductions **reduction_table;
extern unsigned *LA;
extern short *LAruleno;
extern short *lookaheads;
extern short *goto_map;
extern short *from_state;
extern short *to_state;

extern action **parser;
extern int SRtotal;
extern int RRtotal;
extern short *SRconflicts;
extern short *RRconflicts;
extern short *defred;
extern short *rules_used;
extern short nunused;
extern short final_state;

/* global functions */

extern char *allocate();
extern bucket *lookup();
extern bucket *make_bucket();


/* system variables */

extern int errno;


/* system functions */
#ifndef __APPLE__
extern void free();
extern char *calloc();
extern char *malloc();
extern char *realloc();
extern char *strcpy();
#endif

void free_itemsets();
void free_itemsets();
void free_shifts();
void free_reductions();
void output_stored_text();
void output_defines();
void output_rule_data();
void output_yydefred();
void output_actions();
void free_parser();
void output_debug();
void output_stype();
void output_table();
void write_section(char* section[]);
void output_trailing_text();
void output_semantic_actions();
void output_rule_data();
void traverse(int i);
void digraph(short** relation);
void fatal(char* msg);
void add_lookback_edge(int stateno, int ruleno, int gotono);
void set_state_table();
void set_accessing_symbol();
void set_shift_table();
void set_reduction_table();
void set_maxrhs();
void initialize_LA();
void initialize_F();
void build_relations();
void compute_FOLLOWS();
void compute_lookaheads();
void set_goto_map();
void open_error(char*);
void no_space();
void token_actions();
void goto_actions();
void sort_actions();
void pack_table();
void output_check();
void output_base();
void save_column(int symbol, int default_state);
int default_goto(int symbol);
int matching_vector(int vector);
int pack_vector(int vector);
void unexpected_EOF();
void tokenized_start(char* c);
void retyped_warning(char* c);
void reprec_warning(char* c);
void syntax_error(int,char*,char*);
void no_grammar();
void terminal_start(char*);
void default_action_warning();
void start_rule(bucket*, int);
void dollar_warning(int,int);
void dollar_error(int,char*,char*);
void untyped_lhs();
void untyped_rhs(int, char*);
void unknown_rhs(int);
void restarted_warning();
void prec_redeclared();
void undefined_goal(char*);
void unterminated_action(int,char*,char*);
void undefined_symbol_warning(char*);
void create_symbol_table();
void free_symbol_table();
void free_symbols();
void unterminated_comment(int,char*,char*);
void unterminated_string(int,char*,char*);
void terminal_lhs(int);
void revalued_warning(char*);
int is_reserved(char*);
void unterminated_union(int,char*,char*);
void unterminated_text(int,char*,char*);
void over_unionized(char*);
void illegal_character(char*);
void used_reserved(char*);
void illegal_tag(int, char*, char*);

void write_section(char* section[]);
void print_gotos(int);
void print_reductions(action*,int);
void print_shifts(action*);
void print_actions(int);
void print_core(int);
void print_nulls(int);
void print_conflicts(int);
void print_state(int);
void log_conflicts();
void log_unused();