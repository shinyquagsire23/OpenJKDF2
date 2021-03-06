#! /bin/sh
# This is a shell archive.  Remove anything before this line, then unpack
# it by saving it into a file and typing "sh file".  To overwrite existing
# files, type "sh file -c".  You can also feed this as standard input via
# unshar, or by typing "sh <file", e.g..  If this archive is complete, you
# will see the following message at the end:
#		"End of archive 5 (of 5)."
# Contents:  test/ftp.tab.c
# Wrapped by rsalz@litchi.bbn.com on Mon Apr  2 11:43:45 1990
PATH=/bin:/usr/bin:/usr/ucb ; export PATH
if test -f 'test/ftp.tab.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'test/ftp.tab.c'\"
else
echo shar: Extracting \"'test/ftp.tab.c'\" \(39780 characters\)
sed "s/^X//" >'test/ftp.tab.c' <<'END_OF_FILE'
X#ifndef lint
Xchar yysccsid[] = "@(#)yaccpar	1.4 (Berkeley) 02/25/90";
X#endif
X#line 26 "ftp.y"
X
X#ifndef lint
Xstatic char sccsid[] = "@(#)ftpcmd.y	5.20.1.1 (Berkeley) 3/2/89";
X#endif /* not lint */
X
X#include <sys//param.h>
X#include <sys//socket.h>
X
X#include <netinet//in.h>
X
X#include <arpa//ftp.h>
X
X#include <stdio.h>
X#include <signal.h>
X#include <ctype.h>
X#include <pwd.h>
X#include <setjmp.h>
X#include <syslog.h>
X#include <sys//stat.h>
X#include <time.h>
X
Xextern	struct sockaddr_in data_dest;
Xextern	int logged_in;
Xextern	struct passwd *pw;
Xextern	int guest;
Xextern	int logging;
Xextern	int type;
Xextern	int form;
Xextern	int debug;
Xextern	int timeout;
Xextern	int maxtimeout;
Xextern  int pdata;
Xextern	char hostname[], remotehost[];
Xextern	char proctitle[];
Xextern	char *globerr;
Xextern	int usedefault;
Xextern  int transflag;
Xextern  char tmpline[];
Xchar	**glob();
X
Xstatic	int cmd_type;
Xstatic	int cmd_form;
Xstatic	int cmd_bytesz;
Xchar	cbuf[512];
Xchar	*fromname;
X
Xchar	*index();
X#line 53 "ftp.tab.c"
X#define A 257
X#define B 258
X#define C 259
X#define E 260
X#define F 261
X#define I 262
X#define L 263
X#define N 264
X#define P 265
X#define R 266
X#define S 267
X#define T 268
X#define SP 269
X#define CRLF 270
X#define COMMA 271
X#define STRING 272
X#define NUMBER 273
X#define USER 274
X#define PASS 275
X#define ACCT 276
X#define REIN 277
X#define QUIT 278
X#define PORT 279
X#define PASV 280
X#define TYPE 281
X#define STRU 282
X#define MODE 283
X#define RETR 284
X#define STOR 285
X#define APPE 286
X#define MLFL 287
X#define MAIL 288
X#define MSND 289
X#define MSOM 290
X#define MSAM 291
X#define MRSQ 292
X#define MRCP 293
X#define ALLO 294
X#define REST 295
X#define RNFR 296
X#define RNTO 297
X#define ABOR 298
X#define DELE 299
X#define CWD 300
X#define LIST 301
X#define NLST 302
X#define SITE 303
X#define STAT 304
X#define HELP 305
X#define NOOP 306
X#define MKD 307
X#define RMD 308
X#define PWD 309
X#define CDUP 310
X#define STOU 311
X#define SMNT 312
X#define SYST 313
X#define SIZE 314
X#define MDTM 315
X#define UMASK 316
X#define IDLE 317
X#define CHMOD 318
X#define LEXERR 319
X#define YYERRCODE 256
Xshort yylhs[] = {                                        -1,
X    0,    0,    0,    1,    1,    1,    1,    1,    1,    1,
X    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
X    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
X    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
X    1,    1,    1,    1,    1,    1,    2,    3,    4,    4,
X   12,    5,   13,   13,   13,    6,    6,    6,    6,    6,
X    6,    6,    6,    7,    7,    7,    8,    8,    8,   10,
X   14,   11,    9,
X};
Xshort yylen[] = {                                         2,
X    0,    2,    2,    4,    4,    4,    2,    4,    4,    4,
X    4,    8,    5,    5,    5,    3,    5,    3,    5,    5,
X    2,    5,    4,    2,    3,    5,    2,    4,    2,    5,
X    5,    3,    3,    4,    6,    5,    7,    9,    4,    6,
X    5,    2,    5,    5,    2,    2,    5,    1,    0,    1,
X    1,   11,    1,    1,    1,    1,    3,    1,    3,    1,
X    1,    3,    2,    1,    1,    1,    1,    1,    1,    1,
X    1,    1,    0,
X};
Xshort yydefred[] = {                                      1,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X   73,   73,   73,    0,   73,    0,    0,   73,   73,   73,
X   73,    0,    0,    0,    0,   73,   73,   73,   73,   73,
X    0,   73,   73,    2,    3,   46,    0,    0,   45,    0,
X    7,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X   24,    0,    0,    0,    0,    0,   21,    0,    0,   27,
X   29,    0,    0,    0,    0,    0,   42,    0,    0,   48,
X    0,   50,    0,    0,    0,    0,    0,   60,    0,    0,
X   64,   66,   65,    0,   68,   69,   67,    0,    0,    0,
X    0,    0,    0,   71,    0,   70,    0,    0,   25,    0,
X   18,    0,   16,    0,   73,    0,   73,    0,    0,    0,
X    0,   32,   33,    0,    0,    0,    4,    5,    0,    6,
X    0,    0,    0,   51,   63,    8,    9,   10,    0,    0,
X    0,    0,   11,    0,   23,    0,    0,    0,    0,    0,
X   34,    0,    0,   39,    0,    0,   28,    0,    0,    0,
X    0,    0,    0,   55,   53,   54,   57,   59,   62,   13,
X   14,   15,    0,   47,   22,   26,   19,   17,    0,    0,
X   36,    0,    0,   20,   30,   31,   41,   43,   44,    0,
X    0,   35,   72,    0,   40,    0,    0,    0,   37,    0,
X    0,   12,    0,    0,   38,    0,    0,    0,   52,
X};
Xshort yydgoto[] = {                                       1,
X   34,   35,   71,   73,   75,   80,   84,   88,   45,   95,
X  184,  125,  157,   96,
X};
Xshort yysindex[] = {                                      0,
X -224, -247, -239, -236, -232, -222, -204, -200, -181, -177,
X    0,    0,    0, -166,    0, -161, -199,    0,    0,    0,
X    0, -160, -159, -264, -158,    0,    0,    0,    0,    0,
X -157,    0,    0,    0,    0,    0, -167, -162,    0, -156,
X    0, -250, -198, -165, -155, -154, -153, -151, -150, -152,
X    0, -145, -252, -229, -217, -302,    0, -144, -146,    0,
X    0, -142, -141, -140, -139, -137,    0, -136, -135,    0,
X -134,    0, -133, -132, -130, -131, -128,    0, -249, -127,
X    0,    0,    0, -126,    0,    0,    0, -125, -152, -152,
X -152, -205, -152,    0, -124,    0, -152, -152,    0, -152,
X    0, -143,    0, -173,    0, -171,    0, -152, -123, -152,
X -152,    0,    0, -152, -152, -152,    0,    0, -138,    0,
X -164, -164, -122,    0,    0,    0,    0,    0, -121, -120,
X -118, -148,    0, -117,    0, -116, -115, -114, -113, -112,
X    0, -163, -111,    0, -110, -109,    0, -107, -106, -105,
X -104, -103, -129,    0,    0,    0,    0,    0,    0,    0,
X    0,    0, -101,    0,    0,    0,    0,    0, -100, -102,
X    0,  -98, -102,    0,    0,    0,    0,    0,    0,  -99,
X  -97,    0,    0,  -95,    0,  -96,  -94,  -92,    0, -152,
X  -93,    0,  -91,  -90,    0,  -88,  -87,  -86,    0,
X};
Xshort yyrindex[] = {                                      0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,  -83,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,  -82,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,  -81,  -80,    0, -158,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
X    0,    0,    0,    0,    0,    0,    0,    0,    0,
X};
Xshort yygindex[] = {                                      0,
X    0,    0,    0,    0,    0,    0,    0,    0,   16,  -89,
X  -25,   35,   47,    0,
X};
X#define YYTABLESIZE 190
Xshort yytable[] = {                                     129,
X  130,  131,  104,  134,   59,   60,   76,  136,  137,   77,
X  138,   78,   79,  105,  106,  107,   98,   99,  146,  123,
X  148,  149,   36,  124,  150,  151,  152,   46,   47,   37,
X   49,    2,   38,   52,   53,   54,   55,   39,   58,  100,
X  101,   62,   63,   64,   65,   66,   40,   68,   69,    3,
X    4,  102,  103,    5,    6,    7,    8,    9,   10,   11,
X   12,   13,   81,  132,  133,   41,   82,   83,   42,   14,
X   51,   15,   16,   17,   18,   19,   20,   21,   22,   23,
X   24,   25,   26,   27,   28,   29,   30,   43,   31,   32,
X   33,   44,   85,   86,  154,  140,  141,  143,  144,  155,
X  193,   87,   48,  156,   70,  170,  171,   50,   56,   72,
X   57,   61,   67,   89,   90,   91,   74,  163,   93,   94,
X  142,   92,  145,   97,  108,  109,  110,  111,  139,  112,
X  113,  114,  115,  116,  153,  117,  118,  121,  119,  120,
X  122,  180,  126,  127,  128,  135,  147,  186,  160,  161,
X  124,  162,  164,  165,  166,  167,  168,  159,  173,  169,
X  174,  172,  175,  176,  177,  178,  179,  181,  158,  182,
X  183,  185,  190,  187,  189,  188,  191,  192,  195,  194,
X  196,    0,    0,  198,  197,   73,  199,   49,   56,   58,
X};
Xshort yycheck[] = {                                      89,
X   90,   91,  305,   93,  269,  270,  257,   97,   98,  260,
X  100,  262,  263,  316,  317,  318,  269,  270,  108,  269,
X  110,  111,  270,  273,  114,  115,  116,   12,   13,  269,
X   15,  256,  269,   18,   19,   20,   21,  270,   23,  269,
X  270,   26,   27,   28,   29,   30,  269,   32,   33,  274,
X  275,  269,  270,  278,  279,  280,  281,  282,  283,  284,
X  285,  286,  261,  269,  270,  270,  265,  266,  269,  294,
X  270,  296,  297,  298,  299,  300,  301,  302,  303,  304,
X  305,  306,  307,  308,  309,  310,  311,  269,  313,  314,
X  315,  269,  258,  259,  259,  269,  270,  269,  270,  264,
X  190,  267,  269,  268,  272,  269,  270,  269,  269,  272,
X  270,  270,  270,  269,  269,  269,  273,  266,  269,  272,
X  105,  273,  107,  269,  269,  272,  269,  269,  272,  270,
X  270,  269,  269,  269,  273,  270,  270,  269,  271,  270,
X  269,  271,  270,  270,  270,  270,  270,  173,  270,  270,
X  273,  270,  270,  270,  270,  270,  270,  123,  269,  272,
X  270,  273,  270,  270,  270,  270,  270,  269,  122,  270,
X  273,  270,  269,  273,  270,  273,  271,  270,  270,  273,
X  271,   -1,   -1,  271,  273,  269,  273,  270,  270,  270,
X};
X#define YYFINAL 1
X#ifndef YYDEBUG
X#define YYDEBUG 0
X#endif
X#define YYMAXTOKEN 319
X#if YYDEBUG
Xchar *yyname[] = {
X"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
X0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
X0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
X0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
X0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
X0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
X0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"A","B","C","E","F","I","L","N",
X"P","R","S","T","SP","CRLF","COMMA","STRING","NUMBER","USER","PASS","ACCT",
X"REIN","QUIT","PORT","PASV","TYPE","STRU","MODE","RETR","STOR","APPE","MLFL",
X"MAIL","MSND","MSOM","MSAM","MRSQ","MRCP","ALLO","REST","RNFR","RNTO","ABOR",
X"DELE","CWD","LIST","NLST","SITE","STAT","HELP","NOOP","MKD","RMD","PWD","CDUP",
X"STOU","SMNT","SYST","SIZE","MDTM","UMASK","IDLE","CHMOD","LEXERR",
X};
Xchar *yyrule[] = {
X"$accept : cmd_list",
X"cmd_list :",
X"cmd_list : cmd_list cmd",
X"cmd_list : cmd_list rcmd",
X"cmd : USER SP username CRLF",
X"cmd : PASS SP password CRLF",
X"cmd : PORT SP host_port CRLF",
X"cmd : PASV CRLF",
X"cmd : TYPE SP type_code CRLF",
X"cmd : STRU SP struct_code CRLF",
X"cmd : MODE SP mode_code CRLF",
X"cmd : ALLO SP NUMBER CRLF",
X"cmd : ALLO SP NUMBER SP R SP NUMBER CRLF",
X"cmd : RETR check_login SP pathname CRLF",
X"cmd : STOR check_login SP pathname CRLF",
X"cmd : APPE check_login SP pathname CRLF",
X"cmd : NLST check_login CRLF",
X"cmd : NLST check_login SP STRING CRLF",
X"cmd : LIST check_login CRLF",
X"cmd : LIST check_login SP pathname CRLF",
X"cmd : STAT check_login SP pathname CRLF",
X"cmd : STAT CRLF",
X"cmd : DELE check_login SP pathname CRLF",
X"cmd : RNTO SP pathname CRLF",
X"cmd : ABOR CRLF",
X"cmd : CWD check_login CRLF",
X"cmd : CWD check_login SP pathname CRLF",
X"cmd : HELP CRLF",
X"cmd : HELP SP STRING CRLF",
X"cmd : NOOP CRLF",
X"cmd : MKD check_login SP pathname CRLF",
X"cmd : RMD check_login SP pathname CRLF",
X"cmd : PWD check_login CRLF",
X"cmd : CDUP check_login CRLF",
X"cmd : SITE SP HELP CRLF",
X"cmd : SITE SP HELP SP STRING CRLF",
X"cmd : SITE SP UMASK check_login CRLF",
X"cmd : SITE SP UMASK check_login SP octal_number CRLF",
X"cmd : SITE SP CHMOD check_login SP octal_number SP pathname CRLF",
X"cmd : SITE SP IDLE CRLF",
X"cmd : SITE SP IDLE SP NUMBER CRLF",
X"cmd : STOU check_login SP pathname CRLF",
X"cmd : SYST CRLF",
X"cmd : SIZE check_login SP pathname CRLF",
X"cmd : MDTM check_login SP pathname CRLF",
X"cmd : QUIT CRLF",
X"cmd : error CRLF",
X"rcmd : RNFR check_login SP pathname CRLF",
X"username : STRING",
X"password :",
X"password : STRING",
X"byte_size : NUMBER",
X"host_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER",
X"form_code : N",
X"form_code : T",
X"form_code : C",
X"type_code : A",
X"type_code : A SP form_code",
X"type_code : E",
X"type_code : E SP form_code",
X"type_code : I",
X"type_code : L",
X"type_code : L SP byte_size",
X"type_code : L byte_size",
X"struct_code : F",
X"struct_code : R",
X"struct_code : P",
X"mode_code : S",
X"mode_code : B",
X"mode_code : C",
X"pathname : pathstring",
X"pathstring : STRING",
X"octal_number : NUMBER",
X"check_login :",
X};
X#endif
X#ifndef YYSTYPE
Xtypedef int YYSTYPE;
X#endif
X#define yyclearin (yychar=(-1))
X#define yyerrok (yyerrflag=0)
X#ifndef YYSTACKSIZE
X#ifdef YYMAXDEPTH
X#define YYSTACKSIZE YYMAXDEPTH
X#else
X#define YYSTACKSIZE 300
X#endif
X#endif
Xint yydebug;
Xint yynerrs;
Xint yyerrflag;
Xint yychar;
Xshort *yyssp;
XYYSTYPE *yyvsp;
XYYSTYPE yyval;
XYYSTYPE yylval;
X#define yystacksize YYSTACKSIZE
Xshort yyss[YYSTACKSIZE];
XYYSTYPE yyvs[YYSTACKSIZE];
X#line 658 "ftp.y"
X
Xextern jmp_buf errcatch;
X
X#define	CMD	0	/* beginning of command */
X#define	ARGS	1	/* expect miscellaneous arguments */
X#define	STR1	2	/* expect SP followed by STRING */
X#define	STR2	3	/* expect STRING */
X#define	OSTR	4	/* optional SP then STRING */
X#define	ZSTR1	5	/* SP then optional STRING */
X#define	ZSTR2	6	/* optional STRING after SP */
X#define	SITECMD	7	/* SITE command */
X#define	NSTR	8	/* Number followed by a string */
X
Xstruct tab {
X	char	*name;
X	short	token;
X	short	state;
X	short	implemented;	/* 1 if command is implemented */
X	char	*help;
X};
X
Xstruct tab cmdtab[] = {		/* In order defined in RFC 765 */
X	{ "USER", USER, STR1, 1,	"<sp> username" },
X	{ "PASS", PASS, ZSTR1, 1,	"<sp> password" },
X	{ "ACCT", ACCT, STR1, 0,	"(specify account)" },
X	{ "SMNT", SMNT, ARGS, 0,	"(structure mount)" },
X	{ "REIN", REIN, ARGS, 0,	"(reinitialize server state)" },
X	{ "QUIT", QUIT, ARGS, 1,	"(terminate service)", },
X	{ "PORT", PORT, ARGS, 1,	"<sp> b0, b1, b2, b3, b4" },
X	{ "PASV", PASV, ARGS, 1,	"(set server in passive mode)" },
X	{ "TYPE", TYPE, ARGS, 1,	"<sp> [ A | E | I | L ]" },
X	{ "STRU", STRU, ARGS, 1,	"(specify file structure)" },
X	{ "MODE", MODE, ARGS, 1,	"(specify transfer mode)" },
X	{ "RETR", RETR, STR1, 1,	"<sp> file-name" },
X	{ "STOR", STOR, STR1, 1,	"<sp> file-name" },
X	{ "APPE", APPE, STR1, 1,	"<sp> file-name" },
X	{ "MLFL", MLFL, OSTR, 0,	"(mail file)" },
X	{ "MAIL", MAIL, OSTR, 0,	"(mail to user)" },
X	{ "MSND", MSND, OSTR, 0,	"(mail send to terminal)" },
X	{ "MSOM", MSOM, OSTR, 0,	"(mail send to terminal or mailbox)" },
X	{ "MSAM", MSAM, OSTR, 0,	"(mail send to terminal and mailbox)" },
X	{ "MRSQ", MRSQ, OSTR, 0,	"(mail recipient scheme question)" },
X	{ "MRCP", MRCP, STR1, 0,	"(mail recipient)" },
X	{ "ALLO", ALLO, ARGS, 1,	"allocate storage (vacuously)" },
X	{ "REST", REST, ARGS, 0,	"(restart command)" },
X	{ "RNFR", RNFR, STR1, 1,	"<sp> file-name" },
X	{ "RNTO", RNTO, STR1, 1,	"<sp> file-name" },
X	{ "ABOR", ABOR, ARGS, 1,	"(abort operation)" },
X	{ "DELE", DELE, STR1, 1,	"<sp> file-name" },
X	{ "CWD",  CWD,  OSTR, 1,	"[ <sp> directory-name ]" },
X	{ "XCWD", CWD,	OSTR, 1,	"[ <sp> directory-name ]" },
X	{ "LIST", LIST, OSTR, 1,	"[ <sp> path-name ]" },
X	{ "NLST", NLST, OSTR, 1,	"[ <sp> path-name ]" },
X	{ "SITE", SITE, SITECMD, 1,	"site-cmd [ <sp> arguments ]" },
X	{ "SYST", SYST, ARGS, 1,	"(get type of operating system)" },
X	{ "STAT", STAT, OSTR, 1,	"[ <sp> path-name ]" },
X	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
X	{ "NOOP", NOOP, ARGS, 1,	"" },
X	{ "MKD",  MKD,  STR1, 1,	"<sp> path-name" },
X	{ "XMKD", MKD,  STR1, 1,	"<sp> path-name" },
X	{ "RMD",  RMD,  STR1, 1,	"<sp> path-name" },
X	{ "XRMD", RMD,  STR1, 1,	"<sp> path-name" },
X	{ "PWD",  PWD,  ARGS, 1,	"(return current directory)" },
X	{ "XPWD", PWD,  ARGS, 1,	"(return current directory)" },
X	{ "CDUP", CDUP, ARGS, 1,	"(change to parent directory)" },
X	{ "XCUP", CDUP, ARGS, 1,	"(change to parent directory)" },
X	{ "STOU", STOU, STR1, 1,	"<sp> file-name" },
X	{ "SIZE", SIZE, OSTR, 1,	"<sp> path-name" },
X	{ "MDTM", MDTM, OSTR, 1,	"<sp> path-name" },
X	{ NULL,   0,    0,    0,	0 }
X};
X
Xstruct tab sitetab[] = {
X	{ "UMASK", UMASK, ARGS, 1,	"[ <sp> umask ]" },
X	{ "IDLE", IDLE, ARGS, 1,	"[ <sp> maximum-idle-time ]" },
X	{ "CHMOD", CHMOD, NSTR, 1,	"<sp> mode <sp> file-name" },
X	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
X	{ NULL,   0,    0,    0,	0 }
X};
X
Xstruct tab *
Xlookup(p, cmd)
X	register struct tab *p;
X	char *cmd;
X{
X
X	for (; p->name != NULL; p++)
X		if (strcmp(cmd, p->name) == 0)
X			return (p);
X	return (0);
X}
X
X#include <arpa/telnet.h>
X
X/*
X * getline - a hacked up version of fgets to ignore TELNET escape codes.
X */
Xchar *
Xgetline(s, n, iop)
X	char *s;
X	register FILE *iop;
X{
X	register c;
X	register char *cs;
X
X	cs = s;
X/* tmpline may contain saved command from urgent mode interruption */
X	for (c = 0; tmpline[c] != '\0' && --n > 0; ++c) {
X		*cs++ = tmpline[c];
X		if (tmpline[c] == '\n') {
X			*cs++ = '\0';
X			if (debug)
X				syslog(LOG_DEBUG, "command: %s", s);
X			tmpline[0] = '\0';
X			return(s);
X		}
X		if (c == 0)
X			tmpline[0] = '\0';
X	}
X	while ((c = getc(iop)) != EOF) {
X		c &= 0377;
X		if (c == IAC) {
X		    if ((c = getc(iop)) != EOF) {
X			c &= 0377;
X			switch (c) {
X			case WILL:
X			case WONT:
X				c = getc(iop);
X				printf("%c%c%c", IAC, DONT, 0377&c);
X				(void) fflush(stdout);
X				continue;
X			case DO:
X			case DONT:
X				c = getc(iop);
X				printf("%c%c%c", IAC, WONT, 0377&c);
X				(void) fflush(stdout);
X				continue;
X			case IAC:
X				break;
X			default:
X				continue;	/* ignore command */
X			}
X		    }
X		}
X		*cs++ = c;
X		if (--n <= 0 || c == '\n')
X			break;
X	}
X	if (c == EOF && cs == s)
X		return (NULL);
X	*cs++ = '\0';
X	if (debug)
X		syslog(LOG_DEBUG, "command: %s", s);
X	return (s);
X}
X
Xstatic int
Xtoolong()
X{
X	time_t now;
X	extern char *ctime();
X	extern time_t time();
X
X	reply(421,
X	  "Timeout (%d seconds): closing control connection.", timeout);
X	(void) time(&now);
X	if (logging) {
X		syslog(LOG_INFO,
X			"User %s timed out after %d seconds at %s",
X			(pw ? pw -> pw_name : "unknown"), timeout, ctime(&now));
X	}
X	dologout(1);
X}
X
Xyylex()
X{
X	static int cpos, state;
X	register char *cp, *cp2;
X	register struct tab *p;
X	int n;
X	char c, *strpbrk();
X	char *copy();
X
X	for (;;) {
X		switch (state) {
X
X		case CMD:
X			(void) signal(SIGALRM, toolong);
X			(void) alarm((unsigned) timeout);
X			if (getline(cbuf, sizeof(cbuf)-1, stdin) == NULL) {
X				reply(221, "You could at least say goodbye.");
X				dologout(0);
X			}
X			(void) alarm(0);
X#ifdef SETPROCTITLE
X			if (strncasecmp(cbuf, "PASS", 4) != NULL)
X				setproctitle("%s: %s", proctitle, cbuf);
X#endif /* SETPROCTITLE */
X			if ((cp = index(cbuf, '\r'))) {
X				*cp++ = '\n';
X				*cp = '\0';
X			}
X			if ((cp = strpbrk(cbuf, " \n")))
X				cpos = cp - cbuf;
X			if (cpos == 0)
X				cpos = 4;
X			c = cbuf[cpos];
X			cbuf[cpos] = '\0';
X			upper(cbuf);
X			p = lookup(cmdtab, cbuf);
X			cbuf[cpos] = c;
X			if (p != 0) {
X				if (p->implemented == 0) {
X					nack(p->name);
X					longjmp(errcatch,0);
X					/* NOTREACHED */
X				}
X				state = p->state;
X				*(char **)&yylval = p->name;
X				return (p->token);
X			}
X			break;
X
X		case SITECMD:
X			if (cbuf[cpos] == ' ') {
X				cpos++;
X				return (SP);
X			}
X			cp = &cbuf[cpos];
X			if ((cp2 = strpbrk(cp, " \n")))
X				cpos = cp2 - cbuf;
X			c = cbuf[cpos];
X			cbuf[cpos] = '\0';
X			upper(cp);
X			p = lookup(sitetab, cp);
X			cbuf[cpos] = c;
X			if (p != 0) {
X				if (p->implemented == 0) {
X					state = CMD;
X					nack(p->name);
X					longjmp(errcatch,0);
X					/* NOTREACHED */
X				}
X				state = p->state;
X				*(char **)&yylval = p->name;
X				return (p->token);
X			}
X			state = CMD;
X			break;
X
X		case OSTR:
X			if (cbuf[cpos] == '\n') {
X				state = CMD;
X				return (CRLF);
X			}
X			/* FALLTHROUGH */
X
X		case STR1:
X		case ZSTR1:
X		dostr1:
X			if (cbuf[cpos] == ' ') {
X				cpos++;
X				state = state == OSTR ? STR2 : ++state;
X				return (SP);
X			}
X			break;
X
X		case ZSTR2:
X			if (cbuf[cpos] == '\n') {
X				state = CMD;
X				return (CRLF);
X			}
X			/* FALLTHROUGH */
X
X		case STR2:
X			cp = &cbuf[cpos];
X			n = strlen(cp);
X			cpos += n - 1;
X			/*
X			 * Make sure the string is nonempty and \n terminated.
X			 */
X			if (n > 1 && cbuf[cpos] == '\n') {
X				cbuf[cpos] = '\0';
X				*(char **)&yylval = copy(cp);
X				cbuf[cpos] = '\n';
X				state = ARGS;
X				return (STRING);
X			}
X			break;
X
X		case NSTR:
X			if (cbuf[cpos] == ' ') {
X				cpos++;
X				return (SP);
X			}
X			if (isdigit(cbuf[cpos])) {
X				cp = &cbuf[cpos];
X				while (isdigit(cbuf[++cpos]))
X					;
X				c = cbuf[cpos];
X				cbuf[cpos] = '\0';
X				yylval = atoi(cp);
X				cbuf[cpos] = c;
X				state = STR1;
X				return (NUMBER);
X			}
X			state = STR1;
X			goto dostr1;
X
X		case ARGS:
X			if (isdigit(cbuf[cpos])) {
X				cp = &cbuf[cpos];
X				while (isdigit(cbuf[++cpos]))
X					;
X				c = cbuf[cpos];
X				cbuf[cpos] = '\0';
X				yylval = atoi(cp);
X				cbuf[cpos] = c;
X				return (NUMBER);
X			}
X			switch (cbuf[cpos++]) {
X
X			case '\n':
X				state = CMD;
X				return (CRLF);
X
X			case ' ':
X				return (SP);
X
X			case ',':
X				return (COMMA);
X
X			case 'A':
X			case 'a':
X				return (A);
X
X			case 'B':
X			case 'b':
X				return (B);
X
X			case 'C':
X			case 'c':
X				return (C);
X
X			case 'E':
X			case 'e':
X				return (E);
X
X			case 'F':
X			case 'f':
X				return (F);
X
X			case 'I':
X			case 'i':
X				return (I);
X
X			case 'L':
X			case 'l':
X				return (L);
X
X			case 'N':
X			case 'n':
X				return (N);
X
X			case 'P':
X			case 'p':
X				return (P);
X
X			case 'R':
X			case 'r':
X				return (R);
X
X			case 'S':
X			case 's':
X				return (S);
X
X			case 'T':
X			case 't':
X				return (T);
X
X			}
X			break;
X
X		default:
X			fatal("Unknown state in scanner.");
X		}
X		yyerror((char *) 0);
X		state = CMD;
X		longjmp(errcatch,0);
X	}
X}
X
Xupper(s)
X	register char *s;
X{
X	while (*s != '\0') {
X		if (islower(*s))
X			*s = toupper(*s);
X		s++;
X	}
X}
X
Xchar *
Xcopy(s)
X	char *s;
X{
X	char *p;
X	extern char *malloc(), *strcpy();
X
X	p = malloc((unsigned) strlen(s) + 1);
X	if (p == NULL)
X		fatal("Ran out of memory.");
X	(void) strcpy(p, s);
X	return (p);
X}
X
Xhelp(ctab, s)
X	struct tab *ctab;
X	char *s;
X{
X	register struct tab *c;
X	register int width, NCMDS;
X	char *type;
X
X	if (ctab == sitetab)
X		type = "SITE ";
X	else
X		type = "";
X	width = 0, NCMDS = 0;
X	for (c = ctab; c->name != NULL; c++) {
X		int len = strlen(c->name);
X
X		if (len > width)
X			width = len;
X		NCMDS++;
X	}
X	width = (width + 8) &~ 7;
X	if (s == 0) {
X		register int i, j, w;
X		int columns, lines;
X
X		lreply(214, "The following %scommands are recognized %s.",
X		    type, "(* =>'s unimplemented)");
X		columns = 76 / width;
X		if (columns == 0)
X			columns = 1;
X		lines = (NCMDS + columns - 1) / columns;
X		for (i = 0; i < lines; i++) {
X			printf("   ");
X			for (j = 0; j < columns; j++) {
X				c = ctab + j * lines + i;
X				printf("%s%c", c->name,
X					c->implemented ? ' ' : '*');
X				if (c + lines >= &ctab[NCMDS])
X					break;
X				w = strlen(c->name) + 1;
X				while (w < width) {
X					putchar(' ');
X					w++;
X				}
X			}
X			printf("\r\n");
X		}
X		(void) fflush(stdout);
X		reply(214, "Direct comments to ftp-bugs@%s.", hostname);
X		return;
X	}
X	upper(s);
X	c = lookup(ctab, s);
X	if (c == (struct tab *)0) {
X		reply(502, "Unknown command %s.", s);
X		return;
X	}
X	if (c->implemented)
X		reply(214, "Syntax: %s%s %s", type, c->name, c->help);
X	else
X		reply(214, "%s%-*s\t%s; unimplemented.", type, width,
X		    c->name, c->help);
X}
X
Xsizecmd(filename)
Xchar *filename;
X{
X	switch (type) {
X	case TYPE_L:
X	case TYPE_I: {
X		struct stat stbuf;
X		if (stat(filename, &stbuf) < 0 ||
X		    (stbuf.st_mode&S_IFMT) != S_IFREG)
X			reply(550, "%s: not a plain file.", filename);
X		else
X			reply(213, "%lu", stbuf.st_size);
X		break;}
X	case TYPE_A: {
X		FILE *fin;
X		register int c, count;
X		struct stat stbuf;
X		fin = fopen(filename, "r");
X		if (fin == NULL) {
X			perror_reply(550, filename);
X			return;
X		}
X		if (fstat(fileno(fin), &stbuf) < 0 ||
X		    (stbuf.st_mode&S_IFMT) != S_IFREG) {
X			reply(550, "%s: not a plain file.", filename);
X			(void) fclose(fin);
X			return;
X		}
X
X		count = 0;
X		while((c=getc(fin)) != EOF) {
X			if (c == '\n')	/* will get expanded to \r\n */
X				count++;
X			count++;
X		}
X		(void) fclose(fin);
X
X		reply(213, "%ld", count);
X		break;}
X	default:
X		reply(504, "SIZE not implemented for Type %c.", "?AEIL"[type]);
X	}
X}
X#line 899 "ftp.tab.c"
X#define YYABORT goto yyabort
X#define YYACCEPT goto yyaccept
X#define YYERROR goto yyerrlab
Xint
Xyyparse()
X{
X    register int yym, yyn, yystate;
X#if YYDEBUG
X    register char *yys;
X    extern char *getenv();
X
X    if (yys = getenv("YYDEBUG"))
X    {
X        yyn = *yys;
X        if (yyn >= '0' && yyn <= '9')
X            yydebug = yyn - '0';
X    }
X#endif
X
X    yynerrs = 0;
X    yyerrflag = 0;
X    yychar = (-1);
X
X    yyssp = yyss;
X    yyvsp = yyvs;
X    *yyssp = yystate = 0;
X
Xyyloop:
X    if (yyn = yydefred[yystate]) goto yyreduce;
X    if (yychar < 0)
X    {
X        if ((yychar = yylex()) < 0) yychar = 0;
X#if YYDEBUG
X        if (yydebug)
X        {
X            yys = 0;
X            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
X            if (!yys) yys = "illegal-symbol";
X            printf("yydebug: state %d, reading %d (%s)\n", yystate,
X                    yychar, yys);
X        }
X#endif
X    }
X    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
X            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
X    {
X#if YYDEBUG
X        if (yydebug)
X            printf("yydebug: state %d, shifting to state %d\n",
X                    yystate, yytable[yyn]);
X#endif
X        if (yyssp >= yyss + yystacksize - 1)
X        {
X            goto yyoverflow;
X        }
X        *++yyssp = yystate = yytable[yyn];
X        *++yyvsp = yylval;
X        yychar = (-1);
X        if (yyerrflag > 0)  --yyerrflag;
X        goto yyloop;
X    }
X    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
X            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
X    {
X        yyn = yytable[yyn];
X        goto yyreduce;
X    }
X    if (yyerrflag) goto yyinrecovery;
X#ifdef lint
X    goto yynewerror;
X#endif
Xyynewerror:
X    yyerror("syntax error");
X#ifdef lint
X    goto yyerrlab;
X#endif
Xyyerrlab:
X    ++yynerrs;
Xyyinrecovery:
X    if (yyerrflag < 3)
X    {
X        yyerrflag = 3;
X        for (;;)
X        {
X            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
X                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
X            {
X#if YYDEBUG
X                if (yydebug)
X                    printf("yydebug: state %d, error recovery shifting\
X to state %d\n", *yyssp, yytable[yyn]);
X#endif
X                if (yyssp >= yyss + yystacksize - 1)
X                {
X                    goto yyoverflow;
X                }
X                *++yyssp = yystate = yytable[yyn];
X                *++yyvsp = yylval;
X                goto yyloop;
X            }
X            else
X            {
X#if YYDEBUG
X                if (yydebug)
X                    printf("yydebug: error recovery discarding state %d\n",
X                            *yyssp);
X#endif
X                if (yyssp <= yyss) goto yyabort;
X                --yyssp;
X                --yyvsp;
X            }
X        }
X    }
X    else
X    {
X        if (yychar == 0) goto yyabort;
X#if YYDEBUG
X        if (yydebug)
X        {
X            yys = 0;
X            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
X            if (!yys) yys = "illegal-symbol";
X            printf("yydebug: state %d, error recovery discards token %d (%s)\n",
X                    yystate, yychar, yys);
X        }
X#endif
X        yychar = (-1);
X        goto yyloop;
X    }
Xyyreduce:
X#if YYDEBUG
X    if (yydebug)
X        printf("yydebug: state %d, reducing by rule %d (%s)\n",
X                yystate, yyn, yyrule[yyn]);
X#endif
X    yym = yylen[yyn];
X    yyval = yyvsp[1-yym];
X    switch (yyn)
X    {
Xcase 2:
X#line 99 "ftp.y"
X {
X			fromname = (char *) 0;
X		}
Xbreak;
Xcase 4:
X#line 106 "ftp.y"
X {
X			user((char *) yyvsp[-1]);
X			free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 5:
X#line 111 "ftp.y"
X {
X			pass((char *) yyvsp[-1]);
X			free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 6:
X#line 116 "ftp.y"
X {
X			usedefault = 0;
X			if (pdata >= 0) {
X				(void) close(pdata);
X				pdata = -1;
X			}
X			reply(200, "PORT command successful.");
X		}
Xbreak;
Xcase 7:
X#line 125 "ftp.y"
X {
X			passive();
X		}
Xbreak;
Xcase 8:
X#line 129 "ftp.y"
X {
X			switch (cmd_type) {
X
X			case TYPE_A:
X				if (cmd_form == FORM_N) {
X					reply(200, "Type set to A.");
X					type = cmd_type;
X					form = cmd_form;
X				} else
X					reply(504, "Form must be N.");
X				break;
X
X			case TYPE_E:
X				reply(504, "Type E not implemented.");
X				break;
X
X			case TYPE_I:
X				reply(200, "Type set to I.");
X				type = cmd_type;
X				break;
X
X			case TYPE_L:
X#if NBBY == 8
X				if (cmd_bytesz == 8) {
X					reply(200,
X					    "Type set to L (byte size 8).");
X					type = cmd_type;
X				} else
X					reply(504, "Byte size must be 8.");
X#else /* NBBY == 8 */
X				UNIMPLEMENTED for NBBY != 8
X#endif /* NBBY == 8 */
X			}
X		}
Xbreak;
Xcase 9:
X#line 164 "ftp.y"
X {
X			switch (yyvsp[-1]) {
X
X			case STRU_F:
X				reply(200, "STRU F ok.");
X				break;
X
X			default:
X				reply(504, "Unimplemented STRU type.");
X			}
X		}
Xbreak;
Xcase 10:
X#line 176 "ftp.y"
X {
X			switch (yyvsp[-1]) {
X
X			case MODE_S:
X				reply(200, "MODE S ok.");
X				break;
X
X			default:
X				reply(502, "Unimplemented MODE type.");
X			}
X		}
Xbreak;
Xcase 11:
X#line 188 "ftp.y"
X {
X			reply(202, "ALLO command ignored.");
X		}
Xbreak;
Xcase 12:
X#line 192 "ftp.y"
X {
X			reply(202, "ALLO command ignored.");
X		}
Xbreak;
Xcase 13:
X#line 196 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL)
X				retrieve((char *) 0, (char *) yyvsp[-1]);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 14:
X#line 203 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL)
X				store((char *) yyvsp[-1], "w", 0);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 15:
X#line 210 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL)
X				store((char *) yyvsp[-1], "a", 0);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 16:
X#line 217 "ftp.y"
X {
X			if (yyvsp[-1])
X				send_file_list(".");
X		}
Xbreak;
Xcase 17:
X#line 222 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL) 
X				send_file_list((char *) yyvsp[-1]);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 18:
X#line 229 "ftp.y"
X {
X			if (yyvsp[-1])
X				retrieve("/bin/ls -lgA", "");
X		}
Xbreak;
Xcase 19:
X#line 234 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL)
X				retrieve("/bin/ls -lgA %s", (char *) yyvsp[-1]);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 20:
X#line 241 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL)
X				statfilecmd((char *) yyvsp[-1]);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 21:
X#line 248 "ftp.y"
X {
X			statcmd();
X		}
Xbreak;
Xcase 22:
X#line 252 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL)
X				delete((char *) yyvsp[-1]);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 23:
X#line 259 "ftp.y"
X {
X			if (fromname) {
X				renamecmd(fromname, (char *) yyvsp[-1]);
X				free(fromname);
X				fromname = (char *) 0;
X			} else {
X				reply(503, "Bad sequence of commands.");
X			}
X			free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 24:
X#line 270 "ftp.y"
X {
X			reply(225, "ABOR command successful.");
X		}
Xbreak;
Xcase 25:
X#line 274 "ftp.y"
X {
X			if (yyvsp[-1])
X				cwd(pw->pw_dir);
X		}
Xbreak;
Xcase 26:
X#line 279 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL)
X				cwd((char *) yyvsp[-1]);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 27:
X#line 286 "ftp.y"
X {
X			help(cmdtab, (char *) 0);
X		}
Xbreak;
Xcase 28:
X#line 290 "ftp.y"
X {
X			register char *cp = (char *)yyvsp[-1];
X
X			if (strncasecmp(cp, "SITE", 4) == 0) {
X				cp = (char *)yyvsp[-1] + 4;
X				if (*cp == ' ')
X					cp++;
X				if (*cp)
X					help(sitetab, cp);
X				else
X					help(sitetab, (char *) 0);
X			} else
X				help(cmdtab, (char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 29:
X#line 305 "ftp.y"
X {
X			reply(200, "NOOP command successful.");
X		}
Xbreak;
Xcase 30:
X#line 309 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL)
X				makedir((char *) yyvsp[-1]);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 31:
X#line 316 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL)
X				removedir((char *) yyvsp[-1]);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 32:
X#line 323 "ftp.y"
X {
X			if (yyvsp[-1])
X				pwd();
X		}
Xbreak;
Xcase 33:
X#line 328 "ftp.y"
X {
X			if (yyvsp[-1])
X				cwd("..");
X		}
Xbreak;
Xcase 34:
X#line 333 "ftp.y"
X {
X			help(sitetab, (char *) 0);
X		}
Xbreak;
Xcase 35:
X#line 337 "ftp.y"
X {
X			help(sitetab, (char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 36:
X#line 341 "ftp.y"
X {
X			int oldmask;
X
X			if (yyvsp[-1]) {
X				oldmask = umask(0);
X				(void) umask(oldmask);
X				reply(200, "Current UMASK is %03o", oldmask);
X			}
X		}
Xbreak;
Xcase 37:
X#line 351 "ftp.y"
X {
X			int oldmask;
X
X			if (yyvsp[-3]) {
X				if ((yyvsp[-1] == -1) || (yyvsp[-1] > 0777)) {
X					reply(501, "Bad UMASK value");
X				} else {
X					oldmask = umask(yyvsp[-1]);
X					reply(200,
X					    "UMASK set to %03o (was %03o)",
X					    yyvsp[-1], oldmask);
X				}
X			}
X		}
Xbreak;
Xcase 38:
X#line 366 "ftp.y"
X {
X			if (yyvsp[-5] && (yyvsp[-1] != NULL)) {
X				if (yyvsp[-3] > 0777)
X					reply(501,
X				"CHMOD: Mode value must be between 0 and 0777");
X				else if (chmod((char *) yyvsp[-1], yyvsp[-3]) < 0)
X					perror_reply(550, (char *) yyvsp[-1]);
X				else
X					reply(200, "CHMOD command successful.");
X			}
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 39:
X#line 380 "ftp.y"
X {
X			reply(200,
X			    "Current IDLE time limit is %d seconds; max %d",
X				timeout, maxtimeout);
X		}
Xbreak;
Xcase 40:
X#line 386 "ftp.y"
X {
X			if (yyvsp[-1] < 30 || yyvsp[-1] > maxtimeout) {
X				reply(501,
X			"Maximum IDLE time must be between 30 and %d seconds",
X				    maxtimeout);
X			} else {
X				timeout = yyvsp[-1];
X				(void) alarm((unsigned) timeout);
X				reply(200,
X				    "Maximum IDLE time set to %d seconds",
X				    timeout);
X			}
X		}
Xbreak;
Xcase 41:
X#line 400 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL)
X				store((char *) yyvsp[-1], "w", 1);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 42:
X#line 407 "ftp.y"
X {
X#ifdef unix
X#ifdef BSD
X			reply(215, "UNIX Type: L%d Version: BSD-%d",
X				NBBY, BSD);
X#else /* BSD */
X			reply(215, "UNIX Type: L%d", NBBY);
X#endif /* BSD */
X#else /* unix */
X			reply(215, "UNKNOWN Type: L%d", NBBY);
X#endif /* unix */
X		}
Xbreak;
Xcase 43:
X#line 428 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL)
X				sizecmd((char *) yyvsp[-1]);
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 44:
X#line 445 "ftp.y"
X {
X			if (yyvsp[-3] && yyvsp[-1] != NULL) {
X				struct stat stbuf;
X				if (stat((char *) yyvsp[-1], &stbuf) < 0)
X					perror_reply(550, "%s", (char *) yyvsp[-1]);
X				else if ((stbuf.st_mode&S_IFMT) != S_IFREG) {
X					reply(550, "%s: not a plain file.",
X						(char *) yyvsp[-1]);
X				} else {
X					register struct tm *t;
X					struct tm *gmtime();
X					t = gmtime(&stbuf.st_mtime);
X					reply(213,
X					    "19%02d%02d%02d%02d%02d%02d",
X					    t->tm_year, t->tm_mon+1, t->tm_mday,
X					    t->tm_hour, t->tm_min, t->tm_sec);
X				}
X			}
X			if (yyvsp[-1] != NULL)
X				free((char *) yyvsp[-1]);
X		}
Xbreak;
Xcase 45:
X#line 467 "ftp.y"
X {
X			reply(221, "Goodbye.");
X			dologout(0);
X		}
Xbreak;
Xcase 46:
X#line 472 "ftp.y"
X {
X			yyerrok;
X		}
Xbreak;
Xcase 47:
X#line 477 "ftp.y"
X {
X			char *renamefrom();
X
X			if (yyvsp[-3] && yyvsp[-1]) {
X				fromname = renamefrom((char *) yyvsp[-1]);
X				if (fromname == (char *) 0 && yyvsp[-1]) {
X					free((char *) yyvsp[-1]);
X				}
X			}
X		}
Xbreak;
Xcase 49:
X#line 493 "ftp.y"
X {
X			*(char **)&(yyval ) = "";
X		}
Xbreak;
Xcase 52:
X#line 504 "ftp.y"
X {
X			register char *a, *p;
X
X			a = (char *)&data_dest.sin_addr;
X			a[0] = yyvsp[-10]; a[1] = yyvsp[-8]; a[2] = yyvsp[-6]; a[3] = yyvsp[-4];
X			p = (char *)&data_dest.sin_port;
X			p[0] = yyvsp[-2]; p[1] = yyvsp[0];
X			data_dest.sin_family = AF_INET;
X		}
Xbreak;
Xcase 53:
X#line 516 "ftp.y"
X {
X		yyval  = FORM_N;
X	}
Xbreak;
Xcase 54:
X#line 520 "ftp.y"
X {
X		yyval  = FORM_T;
X	}
Xbreak;
Xcase 55:
X#line 524 "ftp.y"
X {
X		yyval  = FORM_C;
X	}
Xbreak;
Xcase 56:
X#line 530 "ftp.y"
X {
X		cmd_type = TYPE_A;
X		cmd_form = FORM_N;
X	}
Xbreak;
Xcase 57:
X#line 535 "ftp.y"
X {
X		cmd_type = TYPE_A;
X		cmd_form = yyvsp[0];
X	}
Xbreak;
Xcase 58:
X#line 540 "ftp.y"
X {
X		cmd_type = TYPE_E;
X		cmd_form = FORM_N;
X	}
Xbreak;
Xcase 59:
X#line 545 "ftp.y"
X {
X		cmd_type = TYPE_E;
X		cmd_form = yyvsp[0];
X	}
Xbreak;
Xcase 60:
X#line 550 "ftp.y"
X {
X		cmd_type = TYPE_I;
X	}
Xbreak;
Xcase 61:
X#line 554 "ftp.y"
X {
X		cmd_type = TYPE_L;
X		cmd_bytesz = NBBY;
X	}
Xbreak;
Xcase 62:
X#line 559 "ftp.y"
X {
X		cmd_type = TYPE_L;
X		cmd_bytesz = yyvsp[0];
X	}
Xbreak;
Xcase 63:
X#line 565 "ftp.y"
X {
X		cmd_type = TYPE_L;
X		cmd_bytesz = yyvsp[0];
X	}
Xbreak;
Xcase 64:
X#line 572 "ftp.y"
X {
X		yyval  = STRU_F;
X	}
Xbreak;
Xcase 65:
X#line 576 "ftp.y"
X {
X		yyval  = STRU_R;
X	}
Xbreak;
Xcase 66:
X#line 580 "ftp.y"
X {
X		yyval  = STRU_P;
X	}
Xbreak;
Xcase 67:
X#line 586 "ftp.y"
X {
X		yyval  = MODE_S;
X	}
Xbreak;
Xcase 68:
X#line 590 "ftp.y"
X {
X		yyval  = MODE_B;
X	}
Xbreak;
Xcase 69:
X#line 594 "ftp.y"
X {
X		yyval  = MODE_C;
X	}
Xbreak;
Xcase 70:
X#line 600 "ftp.y"
X {
X		/*
X		 * Problem: this production is used for all pathname
X		 * processing, but only gives a 550 error reply.
X		 * This is a valid reply in some cases but not in others.
X		 */
X		if (logged_in && yyvsp[0] && strncmp((char *) yyvsp[0], "~", 1) == 0) {
X			*(char **)&(yyval ) = *glob((char *) yyvsp[0]);
X			if (globerr != NULL) {
X				reply(550, globerr);
X				yyval  = NULL;
X			}
X			free((char *) yyvsp[0]);
X		} else
X			yyval  = yyvsp[0];
X	}
Xbreak;
Xcase 72:
X#line 622 "ftp.y"
X {
X		register int ret, dec, multby, digit;
X
X		/*
X		 * Convert a number that was read as decimal number
X		 * to what it would be if it had been read as octal.
X		 */
X		dec = yyvsp[0];
X		multby = 1;
X		ret = 0;
X		while (dec) {
X			digit = dec%10;
X			if (digit > 7) {
X				ret = -1;
X				break;
X			}
X			ret += digit * multby;
X			multby *= 8;
X			dec /= 10;
X		}
X		yyval  = ret;
X	}
Xbreak;
Xcase 73:
X#line 647 "ftp.y"
X {
X		if (logged_in)
X			yyval  = 1;
X		else {
X			reply(530, "Please login with USER and PASS.");
X			yyval  = 0;
X		}
X	}
Xbreak;
X#line 1678 "ftp.tab.c"
X    }
X    yyssp -= yym;
X    yystate = *yyssp;
X    yyvsp -= yym;
X    yym = yylhs[yyn];
X    if (yystate == 0 && yym == 0)
X    {
X#ifdef YYDEBUG
X        if (yydebug)
X            printf("yydebug: after reduction, shifting from state 0 to\
X state %d\n", YYFINAL);
X#endif
X        yystate = YYFINAL;
X        *++yyssp = YYFINAL;
X        *++yyvsp = yyval;
X        if (yychar < 0)
X        {
X            if ((yychar = yylex()) < 0) yychar = 0;
X#if YYDEBUG
X            if (yydebug)
X            {
X                yys = 0;
X                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
X                if (!yys) yys = "illegal-symbol";
X                printf("yydebug: state %d, reading %d (%s)\n",
X                        YYFINAL, yychar, yys);
X            }
X#endif
X        }
X        if (yychar == 0) goto yyaccept;
X        goto yyloop;
X    }
X    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
X            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
X        yystate = yytable[yyn];
X    else
X        yystate = yydgoto[yym];
X#ifdef YYDEBUG
X    if (yydebug)
X        printf("yydebug: after reduction, shifting from state %d \
Xto state %d\n", *yyssp, yystate);
X#endif
X    if (yyssp >= yyss + yystacksize - 1)
X    {
X        goto yyoverflow;
X    }
X    *++yyssp = yystate;
X    *++yyvsp = yyval;
X    goto yyloop;
Xyyoverflow:
X    yyerror("yacc stack overflow");
Xyyabort:
X    return (1);
Xyyaccept:
X    return (0);
X}
END_OF_FILE
if [[ 39780 -ne `wc -c <'test/ftp.tab.c'` ]]; then
    echo shar: \"'test/ftp.tab.c'\" unpacked with wrong size!
fi
# end of 'test/ftp.tab.c'
fi
echo shar: End of archive 5 \(of 5\).
cp /dev/null ark5isdone
MISSING=""
for I in 1 2 3 4 5 ; do
    if test ! -f ark${I}isdone ; then
	MISSING="${MISSING} ${I}"
    fi
done
if test "${MISSING}" = "" ; then
    echo You have unpacked all 5 archives.
    rm -f ark[1-9]isdone
else
    echo You still need to unpack the following archives:
    echo "        " ${MISSING}
fi
##  End of shell archive.
exit 0
