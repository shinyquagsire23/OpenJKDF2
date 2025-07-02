D			[0-9]
L			[a-zA-Z_]
H			[a-fA-F0-9]
E			[Ee][+-]?{D}+

%{
#include <stdio.h>
#include "Cog/sithCogParse.h"
#include "jk.h"
#include "y.tab.h"

#define printf(...) _printf(__VA_ARGS__)
#define fwrite(x,y,z,w) _fwrite(x,y,z,w)
#define atoi(x) _atoi(x)
#define exit(x) jk_exit(x)
#define malloc(x) _malloc(x)
#define free(x) _free(x)
#define memcpy(x,y,z) _memcpy(x,y,z)
#define strlen(x) _strlen(x)
#define strcpy(x,y) _strcpy(x,y)

%}

%%

"break"			{ return(BREAK); }
"continue"		{ return(CONTINUE); }
"do"			{ return(DO); }
"else"			{ return(ELSE); }
"for"			{ return(FOR); }
"goto"			{ return(GOTO); }
"if"			{ return(IF); }
"stop"		    { return(RETURN); }
"return"		{ return(RETURN); }
"while"			{ return(WHILE); }
"end"			{ yyterminate(); }
"call"			{ return(CALL); }

{L}({L}|{D})*	{ sithCogParse_LexGetSym(yytext); return(IDENTIFIER); }

0[xX]{H}+		{ _sscanf(yytext, "%x", &yylval.as_int); return(CONSTANT_INT); }
0{D}+		    { _sscanf(yytext, "%i", &yylval.as_int); return(CONSTANT_INT); }
{D}+		    { yylval.as_int = _atoi(yytext); return(CONSTANT_INT); }


{D}+{E}		        { yylval.as_float = _atof(yytext); return(CONSTANT_FLOAT); }
{D}*"."{D}+({E})?	{ yylval.as_float = _atof(yytext); return(CONSTANT_FLOAT); }
{D}+"."{D}*({E})?	{ yylval.as_float = _atof(yytext); return(CONSTANT_FLOAT); }

\"(\\.|[^\\"])*\"	{ sithCogParse_LexAddSymbol(yytext); return(STRING_LITERAL); }
\'(\\.|[^\\'])*\'	{ sithCogParse_LexScanVector3(yytext); return(VECTOR_LITERAL); }

"&&"			{ return(AND_OP); }
"||"			{ return(OR_OP); }
"<="			{ return(LE_OP); }
">="			{ return(GE_OP); }
"=="			{ return(EQ_OP); }
"!="			{ return(NE_OP); }
";"			{ return(';'); }
"{"			{ return('{'); }
"}"			{ return('}'); }
","			{ return(','); }
":"			{ return(':'); }
"="			{ return('='); }
"("			{ return('('); }
")"			{ return(')'); }
"["			{ return('['); }
"]"			{ return(']'); }
"."			{ return('.'); }
"&"			{ return('&'); }
"!"			{ return('!'); }
"~"			{ return('~'); }
"-"			{ return('-'); }
"+"			{ return('+'); }
"*"			{ return('*'); }
\/\/(.*)	{ /* comment */ }
#(.*)		{ /* comment */ }
"/"			{ return('/'); }
"%"			{ return('%'); }
"<"			{ return('<'); }
">"			{ return('>'); }
"^"			{ return('^'); }
"|"			{ return('|'); }

[\n\r]		{ yacc_linenum++; }
[ \t\v\f]	{ }
.			{ /* ignore bad characters */ }

%%
