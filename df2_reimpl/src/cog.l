D			[0-9]
L			[a-zA-Z_]
H			[a-fA-F0-9]
E			[Ee][+-]?{D}+

%{
#include <stdio.h>
#include "rdVector.h"
#include "sithCogParse.h"
#include "y.tab.h"

int linenum = 0;

void sithCogParse_LexScanVector3(char* text);
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

0[xX]{H}+		{ sscanf(yytext, "%x", &yylval.as_int); return(CONSTANT_INT); }
0{D}+		    { sscanf(yytext, "%i", &yylval.as_int); return(CONSTANT_INT); }
{D}+		    { yylval.as_int = atoi(yytext); return(CONSTANT_INT); }


{D}+{E}		        { yylval.as_float = atof(yytext); return(CONSTANT_FLOAT); }
{D}*"."{D}+({E})?	{ yylval.as_float = atof(yytext); return(CONSTANT_FLOAT); }
{D}+"."{D}*({E})?	{ yylval.as_float = atof(yytext); return(CONSTANT_FLOAT); }

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

[\n\r]		{ linenum++; }
[ \t\v\f]	{ }
.			{ /* ignore bad characters */ }

%%

void sithCogParse_LexScanVector3(char* text)
{
    rdVector3 scan_in;
    sscanf(text, "\'%f %f %f\'", &scan_in.x, &scan_in.y, &scan_in.z);
    yylval.as_vector = scan_in;
}
