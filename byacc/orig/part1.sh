#! /bin/sh
# This is a shell archive.  Remove anything before this line, then unpack
# it by saving it into a file and typing "sh file".  To overwrite existing
# files, type "sh file -c".  You can also feed this as standard input via
# unshar, or by typing "sh <file", e.g..  If this archive is complete, you
# will see the following message at the end:
#		"End of archive 1 (of 5)."
# Contents:  ACKNOWLEDGEMENTS MANIFEST Makefile NEW_FEATURES
#   NO_WARRANTY README closure.c defs.h error.c main.c manpage
#   symtab.c test test/error.output test/error.tab.c test/error.tab.h
#   test/error.y test/ftp.tab.h verbose.c warshall.c
# Wrapped by rsalz@litchi.bbn.com on Mon Apr  2 11:43:41 1990
PATH=/bin:/usr/bin:/usr/ucb ; export PATH
if test -f 'ACKNOWLEDGEMENTS' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'ACKNOWLEDGEMENTS'\"
else
echo shar: Extracting \"'ACKNOWLEDGEMENTS'\" \(750 characters\)
sed "s/^X//" >'ACKNOWLEDGEMENTS' <<'END_OF_FILE'
X     Berkeley Yacc owes much to the unflagging efforts of Keith Bostic.
XHis badgering kept me working on it long after I was ready to quit.
X
X     Berkeley Yacc is based on the excellent algorithm for computing LALR(1)
Xlookaheads developed by Tom Pennello and Frank DeRemer.  The algorithm is
Xdescribed in their almost impenetrable article in TOPLAS 4,4.
X
X     Finally, much of the credit for the latest version must go to those
Xwho pointed out deficiencies of my earlier releases.  Among the most
Xprolific contributors were
X
X	  Benson I. Margulies
X	  Dave Gentzel
X	  Peter S. Housel
X	  Dale Smith
X	  Ozan Yigit
X	  John Campbell
X	  Bill Sommerfeld
X	  Paul Hilfinger
X	  Gary Bridgewater
X	  Dave Bakken
X	  Dan Lanciani
X	  Richard Sargent
X	  Parag Patel
END_OF_FILE
if [[ 750 -ne `wc -c <'ACKNOWLEDGEMENTS'` ]]; then
    echo shar: \"'ACKNOWLEDGEMENTS'\" unpacked with wrong size!
fi
# end of 'ACKNOWLEDGEMENTS'
fi
if test -f 'MANIFEST' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'MANIFEST'\"
else
echo shar: Extracting \"'MANIFEST'\" \(995 characters\)
sed "s/^X//" >'MANIFEST' <<'END_OF_FILE'
X   File Name		Archive #	Description
X-----------------------------------------------------------
X ACKNOWLEDGEMENTS           1	
X MANIFEST                   1	
X Makefile                   1	
X NEW_FEATURES               1	
X NO_WARRANTY                1	
X README                     1	
X closure.c                  1	
X defs.h                     1	
X error.c                    1	
X lalr.c                     2	
X lr0.c                      2	
X main.c                     1	
X manpage                    1	
X mkpar.c                    2	
X output.c                   3	
X reader.c                   4	
X skeleton.c                 2	
X symtab.c                   1	
X test                       1	
X test/error.output          1	
X test/error.tab.c           1	
X test/error.tab.h           1	
X test/error.y               1	
X test/ftp.output            3	
X test/ftp.tab.c             5	
X test/ftp.tab.h             1	
X test/ftp.y                 4	
X verbose.c                  1	
X warshall.c                 1	
END_OF_FILE
if [[ 995 -ne `wc -c <'MANIFEST'` ]]; then
    echo shar: \"'MANIFEST'\" unpacked with wrong size!
fi
# end of 'MANIFEST'
fi
if test -f 'Makefile' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'Makefile'\"
else
echo shar: Extracting \"'Makefile'\" \(1365 characters\)
sed "s/^X//" >'Makefile' <<'END_OF_FILE'
XDEST	      = .
X
XHDRS	      = defs.h
X
XCFLAGS	      = -O
X
XLDFLAGS	      =
X
XLIBS	      =
X
XLINKER	      = cc
X
XMAKEFILE      = Makefile
X
XOBJS	      = closure.o \
X		error.o \
X		lalr.o \
X		lr0.o \
X		main.o \
X		mkpar.o \
X		output.o \
X		reader.o \
X		skeleton.o \
X		symtab.o \
X		verbose.o \
X		warshall.o
X
XPRINT	      = pr -f -l88
X
XPROGRAM	      = yacc
X
XSRCS	      = closure.c \
X		error.c \
X		lalr.c \
X		lr0.c \
X		main.c \
X		mkpar.c \
X		output.c \
X		reader.c \
X		skeleton.c \
X		symtab.c \
X		verbose.c \
X		warshall.c
X
Xall:		$(PROGRAM)
X
X$(PROGRAM):     $(OBJS) $(LIBS)
X		@echo -n "Loading $(PROGRAM) ... "
X		@$(LINKER) $(LDFLAGS) $(OBJS) $(LIBS) -o $(PROGRAM)
X		@echo "done"
X
Xclean:;		@rm -f $(OBJS)
X
Xdepend:;	@mkmf -f $(MAKEFILE) PROGRAM=$(PROGRAM) DEST=$(DEST)
X
Xindex:;		@ctags -wx $(HDRS) $(SRCS)
X
Xinstall:	$(PROGRAM)
X		@echo Installing $(PROGRAM) in $(DEST)
X		@install -s $(PROGRAM) $(DEST)
X
Xlisting:;	@$(PRINT) Makefile $(HDRS) $(SRCS) | lpr
X
Xlint:;		@lint $(SRCS)
X
Xprogram:        $(PROGRAM)
X
Xtags:           $(HDRS) $(SRCS); @ctags $(HDRS) $(SRCS)
X
Xupdate:		$(DEST)/$(PROGRAM)
X
X$(DEST)/$(PROGRAM): $(SRCS) $(LIBS) $(HDRS)
X		@make -f $(MAKEFILE) DEST=$(DEST) install
X###
Xclosure.o: defs.h
Xerror.o: defs.h
Xlalr.o: defs.h
Xlr0.c: defs.h
Xmain.o: defs.h
Xmkpar.o: defs.h
Xoutput.o: defs.h
Xreader.o: defs.h
Xskeleton.o: defs.h
Xsymtab.o: defs.h
Xverbose.o: defs.h
Xwarshall.o: defs.h
END_OF_FILE
if [[ 1365 -ne `wc -c <'Makefile'` ]]; then
    echo shar: \"'Makefile'\" unpacked with wrong size!
fi
# end of 'Makefile'
fi
if test -f 'NEW_FEATURES' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'NEW_FEATURES'\"
else
echo shar: Extracting \"'NEW_FEATURES'\" \(2541 characters\)
sed "s/^X//" >'NEW_FEATURES' <<'END_OF_FILE'
X     This version of Berkeley Yacc has been extensively reorganized and
Xcontains many new features.  It is an amalgam of three earlier versions
Xof Berkeley Yacc.  It is largely untested, so expect it to contain bugs.
XWhen bugs are found report them to corbett@berkeley.edu.  Please
Xinclude small examples if possible.
X
X     Despite my pleas not to be told of undocumented features of AT&T Yacc,
XI have received unsolicited descriptions of such features.  Telling me of
Xsuch features places the public-domain status of Berkeley Yacc at risk.
XPlease do not send me descriptions of undocumented features.  On the
Xother hand, I would be very interested in learning of documented
Xfeatures I have not implemented.
X
X     The -l and -t options have been implemented.  The -l option tells
XYacc not to include #line directives in the code it produces.  The -t
Xoption causes debugging code to be included in the compiled parser.
X
X     The code for error recovery has been changed to implement the same
Xalgorithm as AT&T Yacc.  There will still be differences in the way
Xerror recovery works because AT&T Yacc uses more default reductions
Xthan Berekeley Yacc.
X
X     The environment variable TMPDIR determines the directory where
Xtemporary files will be created.  If TMPDIR is defined, temporary files
Xwill be created in the directory whose pathname is the value of TMPDIR.
XBy default, temporary files are created in /tmp.
X
X     The keywords are now case-insensitive.  For example, %nonassoc,
X%NONASSOC, %NonAssoc, and %nOnAsSoC are all equivalent.
X
X     Commas and semicolons that are not part of C code are treated as
Xcommentary.
X
X     Line-end comments, as in BCPL, are permitted.  Line-end comments
Xbegin with // and end at the next end-of-line.  Line-end comments are
Xpermitted in C code; they are converted to C comments on output.
X
X     The form of y.output files has been changed to look more like
Xthose produced by AT&T Yacc.
X
X     A new kind of declaration has been added.  The form of the declaration
Xis
X
X	  %ident string
X
Xwhere string is a sequence of characters begining with a double quote
Xand ending with either a double quote or the next end-of-line, whichever
Xcomes first.  The declaration will cause a #ident directive to be written
Xnear the start of the output file.
X
X     If a parser has been compiled with debugging code, that code can be
Xenabled by setting an environment variable.  If the environment variable
XYYDEBUG is set to 0, debugging output is suppressed.  If it is set to 1,
Xdebugging output is written to standard output.
END_OF_FILE
if [[ 2541 -ne `wc -c <'NEW_FEATURES'` ]]; then
    echo shar: \"'NEW_FEATURES'\" unpacked with wrong size!
fi
# end of 'NEW_FEATURES'
fi
if test -f 'NO_WARRANTY' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'NO_WARRANTY'\"
else
echo shar: Extracting \"'NO_WARRANTY'\" \(156 characters\)
sed "s/^X//" >'NO_WARRANTY' <<'END_OF_FILE'
X     Berkeley Yacc is distributed with no warranty whatever.  The author
Xand any other contributors take no responsibility for the consequences of
Xits use.
END_OF_FILE
if [[ 156 -ne `wc -c <'NO_WARRANTY'` ]]; then
    echo shar: \"'NO_WARRANTY'\" unpacked with wrong size!
fi
# end of 'NO_WARRANTY'
fi
if test -f 'README' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'README'\"
else
echo shar: Extracting \"'README'\" \(1041 characters\)
sed "s/^X//" >'README' <<'END_OF_FILE'
X    Berkeley Yacc is an LALR(1) parser generator.  Berkeley Yacc has been made
Xas compatible as possible with AT&T Yacc.  Berkeley Yacc can accept any input
Xspecification that conforms to the AT&T Yacc documentation.  Specifications
Xthat take advantage of undocumented features of AT&T Yacc will probably be
Xrejected.
X
X    Berkeley Yacc is distributed with no warranty whatever.  The code is certain
Xto contain errors.  Neither the author nor any contributor takes responsibility
Xfor any consequences of its use.
X
X    Berkeley Yacc is in the public domain.  The data structures and algorithms
Xused in Berkeley Yacc are all either taken from documents available to the
Xgeneral public or are inventions of the author.  Anyone may freely distribute
Xsource or binary forms of Berkeley Yacc whether unchanged or modified.
XDistributers may charge whatever fees they can obtain for Berkeley Yacc.
XPrograms generated by Berkeley Yacc may be distributed freely.
X
X    Bugs may be reported to
X
X			  corbett@berkeley.edu
X
XDo not expect rapid responses.
END_OF_FILE
if [[ 1041 -ne `wc -c <'README'` ]]; then
    echo shar: \"'README'\" unpacked with wrong size!
fi
# end of 'README'
fi
if test -f 'closure.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'closure.c'\"
else
echo shar: Extracting \"'closure.c'\" \(4358 characters\)
sed "s/^X//" >'closure.c' <<'END_OF_FILE'
X#include "defs.h"
X
Xshort *itemset;
Xshort *itemsetend;
Xunsigned *ruleset;
X
Xstatic unsigned *first_derives;
Xstatic unsigned *EFF;
X
X
Xset_EFF()
X{
X    register unsigned *row;
X    register int symbol;
X    register short *sp;
X    register int rowsize;
X    register int i;
X    register int rule;
X
X    rowsize = WORDSIZE(nvars);
X    EFF = NEW2(nvars * rowsize, unsigned);
X
X    row = EFF;
X    for (i = start_symbol; i < nsyms; i++)
X    {
X	sp = derives[i];
X	for (rule = *sp; rule > 0; rule = *++sp)
X	{
X	    symbol = ritem[rrhs[rule]];
X	    if (ISVAR(symbol))
X	    {
X		symbol -= start_symbol;
X		SETBIT(row, symbol);
X	    }
X	}
X	row += rowsize;
X    }
X
X    reflexive_transitive_closure(EFF, nvars);
X
X#ifdef	DEBUG
X    print_EFF();
X#endif
X}
X
X
Xset_first_derives()
X{
X  register unsigned *rrow;
X  register unsigned *vrow;
X  register int j;
X  register unsigned mask;
X  register unsigned cword;
X  register short *rp;
X
X  int rule;
X  int i;
X  int rulesetsize;
X  int varsetsize;
X
X  rulesetsize = WORDSIZE(nrules);
X  varsetsize = WORDSIZE(nvars);
X  first_derives = NEW2(nvars * rulesetsize, unsigned) - ntokens * rulesetsize;
X
X  set_EFF();
X
X  rrow = first_derives + ntokens * rulesetsize;
X  for (i = start_symbol; i < nsyms; i++)
X    {
X      vrow = EFF + ((i - ntokens) * varsetsize);
X      cword = *vrow++;
X      mask = 1;
X      for (j = start_symbol; j < nsyms; j++)
X	{
X	  if (cword & mask)
X	    {
X	      rp = derives[j];
X	      while ((rule = *rp++) >= 0)
X		{
X		  SETBIT(rrow, rule);
X		}
X	    }
X
X	  mask <<= 1;
X	  if (mask == 0)
X	    {
X	      cword = *vrow++;
X	      mask = 1;
X	    }
X	}
X
X      vrow += varsetsize;
X      rrow += rulesetsize;
X    }
X
X#ifdef	DEBUG
X  print_first_derives();
X#endif
X
X  FREE(EFF);
X}
X
X
Xclosure(nucleus, n)
Xshort *nucleus;
Xint n;
X{
X    register int ruleno;
X    register unsigned word;
X    register unsigned mask;
X    register short *csp;
X    register unsigned *dsp;
X    register unsigned *rsp;
X    register int rulesetsize;
X
X    short *csend;
X    unsigned *rsend;
X    int symbol;
X    int itemno;
X
X    rulesetsize = WORDSIZE(nrules);
X    rsp = ruleset;
X    rsend = ruleset + rulesetsize;
X    for (rsp = ruleset; rsp < rsend; rsp++)
X	*rsp = 0;
X
X    csend = nucleus + n;
X    for (csp = nucleus; csp < csend; ++csp)
X    {
X	symbol = ritem[*csp];
X	if (ISVAR(symbol))
X	{
X	    dsp = first_derives + symbol * rulesetsize;
X	    rsp = ruleset;
X	    while (rsp < rsend)
X		*rsp++ |= *dsp++;
X	}
X    }
X
X    ruleno = 0;
X    itemsetend = itemset;
X    csp = nucleus;
X    for (rsp = ruleset; rsp < rsend; ++rsp)
X    {
X	word = *rsp;
X	if (word == 0)
X	    ruleno += BITS_PER_WORD;
X	else
X	{
X	    mask = 1;
X	    while (mask)
X	    {
X		if (word & mask)
X		{
X		    itemno = rrhs[ruleno];
X		    while (csp < csend && *csp < itemno)
X			*itemsetend++ = *csp++;
X		    *itemsetend++ = itemno;
X		    while (csp < csend && *csp == itemno)
X			++csp;
X		}
X
X		    mask <<= 1;
X		    ++ruleno;
X	    }
X	}
X    }
X
X    while (csp < csend)
X	*itemsetend++ = *csp++;
X
X#ifdef	DEBUG
X  print_closure(n);
X#endif
X}
X
X
X
Xfinalize_closure()
X{
X  FREE(itemset);
X  FREE(ruleset);
X  FREE(first_derives + ntokens * WORDSIZE(nrules));
X}
X
X
X#ifdef	DEBUG
X
Xprint_closure(n)
Xint n;
X{
X  register short *isp;
X
X  printf("\n\nn = %d\n\n", n);
X  for (isp = itemset; isp < itemsetend; isp++)
X    printf("   %d\n", *isp);
X}
X
X
Xprint_EFF()
X{
X    register int i, j, k;
X    register unsigned *rowp;
X    register unsigned word;
X    register unsigned mask;
X
X    printf("\n\nEpsilon Free Firsts\n");
X
X    for (i = start_symbol; i < nsyms; i++)
X    {
X	printf("\n%s", symbol_name[i]);
X	rowp = EFF + ((i - start_symbol) * WORDSIZE(nvars));
X	word = *rowp++;
X
X	mask = 1;
X	for (j = 0; j < nvars; j++)
X	{
X	    if (word & mask)
X		printf("  %s", symbol_name[start_symbol + j]);
X
X	    mask <<= 1;
X	    if (mask == 0)
X	    {
X		word = *rowp++;
X		mask = 1;
X	    }
X	}
X    }
X}
X
X
Xprint_first_derives()
X{
X  register int i;
X  register int j;
X  register unsigned *rp;
X  register unsigned cword;
X  register unsigned mask;
X
X  printf("\n\n\nFirst Derives\n");
X
X  for (i = start_symbol; i < nsyms; i++)
X    {
X      printf("\n%s derives\n", symbol_name[i]);
X      rp = first_derives + i * WORDSIZE(nrules);
X      cword = *rp++;
X      mask = 1;
X      for (j = 0; j <= nrules; j++)
X        {
X	  if (cword & mask)
X	    printf("   %d\n", j);
X
X	  mask <<= 1;
X	  if (mask == 0)
X	    {
X	      cword = *rp++;
X	      mask = 1;
X	    }
X	}
X    }
X
X  fflush(stdout);
X}
X
X#endif
END_OF_FILE
if [[ 4358 -ne `wc -c <'closure.c'` ]]; then
    echo shar: \"'closure.c'\" unpacked with wrong size!
fi
# end of 'closure.c'
fi
if test -f 'defs.h' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'defs.h'\"
else
echo shar: Extracting \"'defs.h'\" \(5738 characters\)
sed "s/^X//" >'defs.h' <<'END_OF_FILE'
X#include <assert.h>
X#include <ctype.h>
X#include <stdio.h>
X
X
X/*  machine dependent definitions			*/
X/*  the following definitions are for the VAX		*/
X/*  they might have to be changed for other machines	*/
X
X/*  MAXCHAR is the largest character value		*/
X/*  MAXSHORT is the largest value of a C short		*/
X/*  MINSHORT is the most negative value of a C short	*/
X/*  MAXTABLE is the maximum table size			*/
X/*  BITS_PER_WORD is the number of bits in a C unsigned	*/
X/*  WORDSIZE computes the number of words needed to	*/
X/*	store n bits					*/
X/*  BIT returns the value of the n-th bit starting	*/
X/*	from r (0-indexed)				*/
X/*  SETBIT sets the n-th bit starting from r		*/
X
X#define	MAXCHAR		255
X#define	MAXSHORT	32767
X#define MINSHORT	-32768
X#define MAXTABLE	32500
X#define BITS_PER_WORD	32
X#define	WORDSIZE(n)	(((n)+(BITS_PER_WORD-1))/BITS_PER_WORD)
X#define	BIT(r, n)	((((r)[(n) >> 5]) >> ((n) & 31)) & 1)
X#define	SETBIT(r, n)	((r)[(n) >> 5] |= (1 << ((n) & 31)))
X
X
X/*  character names  */
X
X#define	NUL		'\0'    /*  the null character  */
X#define	NEWLINE		'\n'    /*  line feed  */
X#define	SP		' '     /*  space  */
X#define	BS		'\b'    /*  backspace  */
X#define	HT		'\t'    /*  horizontal tab  */
X#define	VT		'\013'  /*  vertical tab  */
X#define	CR		'\r'    /*  carriage return  */
X#define	FF		'\f'    /*  form feed  */
X#define	QUOTE		'\''    /*  single quote  */
X#define	DOUBLE_QUOTE	'\"'    /*  double quote  */
X#define	BACKSLASH	'\\'    /*  backslash  */
X
X
X/* defines for constructing filenames */
X
X#define	DEFINES_SUFFIX	".tab.h"
X#define	OUTPUT_SUFFIX	".tab.c"
X#define	VERBOSE_SUFFIX	".output"
X
X
X/* keyword codes */
X
X#define TOKEN 0
X#define LEFT 1
X#define RIGHT 2
X#define NONASSOC 3
X#define MARK 4
X#define TEXT 5
X#define TYPE 6
X#define START 7
X#define UNION 8
X#define IDENT 9
X
X
X/*  symbol classes  */
X
X#define UNKNOWN 0
X#define TERM 1
X#define NONTERM 2
X
X
X/*  the undefined value  */
X
X#define UNDEFINED (-1)
X
X
X/*  action codes  */
X
X#define SHIFT 1
X#define REDUCE 2
X#define ERROR 3
X
X
X/*  character macros  */
X
X#define IS_IDENT(c)	(isalnum(c) || (c) == '_' || (c) == '.' || (c) == '$')
X#define	IS_OCTAL(c)	((c) >= '0' && (c) <= '7')
X#define	NUMERIC_VALUE(c)	((c) - '0')
X
X
X/*  symbol macros  */
X
X#define ISTOKEN(s)	((s) < start_symbol)
X#define ISVAR(s)	((s) >= start_symbol)
X
X
X/*  storage allocation macros  */
X
X#define	FREE(x)		(free((char*)(x)))
X#define MALLOC(n)	(malloc((unsigned)(n)))
X#define	NEW(t)		((t*)allocate(sizeof(t)))
X#define	NEW2(n,t)	((t*)allocate((unsigned)((n)*sizeof(t))))
X#define REALLOC(p,n)	(realloc((char*)(p),(unsigned)(n)))
X
X
X/*  the structure of a symbol table entry  */
X
Xtypedef struct bucket bucket;
Xstruct bucket
X{
X    struct bucket *link;
X    struct bucket *next;
X    char *name;
X    char *tag;
X    short value;
X    short index;
X    short prec;
X    char class;
X    char assoc;
X};
X
X
X/*  the structure of the LR(0) state machine  */
X
Xtypedef struct core core;
Xstruct core
X{
X    struct core *next;
X    struct core *link;
X    short number;
X    short accessing_symbol;
X    short nitems;
X    short items[1];
X};
X
X
X/*  the structure used to record shifts  */
X
Xtypedef struct shifts shifts;
Xstruct shifts
X{
X    struct shifts *next;
X    short number;
X    short nshifts;
X    short shift[1];
X};
X
X
X/*  the structure used to store reductions  */
X
Xtypedef struct reductions reductions;
Xstruct reductions
X{
X    struct reductions *next;
X    short number;
X    short nreds;
X    short rules[1];
X};
X
X
X/*  the structure used to represent parser actions  */
X
Xtypedef struct action action;
Xstruct action
X{
X    struct action *next;
X    short symbol;
X    short number;
X    short prec;
X    char action_code;
X    char assoc;
X    char suppressed;
X};
X
X
X/* global variables */
X
Xextern char dflag;
Xextern char lflag;
Xextern char tflag;
Xextern char vflag;
X
Xextern char *myname;
Xextern char *cptr;
Xextern char *line;
Xextern int lineno;
Xextern int outline;
X
Xextern char *banner[];
Xextern char *header[];
Xextern char *body[];
Xextern char *trailer[];
X
Xextern char *action_file_name;
Xextern char *defines_file_name;
Xextern char *input_file_name;
Xextern char *output_file_name;
Xextern char *text_file_name;
Xextern char *union_file_name;
Xextern char *verbose_file_name;
X
Xextern FILE *action_file;
Xextern FILE *defines_file;
Xextern FILE *input_file;
Xextern FILE *output_file;
Xextern FILE *text_file;
Xextern FILE *union_file;
Xextern FILE *verbose_file;
X
Xextern int nitems;
Xextern int nrules;
Xextern int nsyms;
Xextern int ntokens;
Xextern int nvars;
Xextern int ntags;
X
Xextern char unionized;
Xextern char line_format[];
X
Xextern int   start_symbol;
Xextern char  **symbol_name;
Xextern short *symbol_value;
Xextern short *symbol_prec;
Xextern char  *symbol_assoc;
X
Xextern short *ritem;
Xextern short *rlhs;
Xextern short *rrhs;
Xextern short *rprec;
Xextern char  *rassoc;
X
Xextern short **derives;
Xextern char *nullable;
X
Xextern bucket *first_symbol;
Xextern bucket *last_symbol;
X
Xextern int nstates;
Xextern core *first_state;
Xextern shifts *first_shift;
Xextern reductions *first_reduction;
Xextern short *accessing_symbol;
Xextern core **state_table;
Xextern shifts **shift_table;
Xextern reductions **reduction_table;
Xextern unsigned *LA;
Xextern short *LAruleno;
Xextern short *lookaheads;
Xextern short *goto_map;
Xextern short *from_state;
Xextern short *to_state;
X
Xextern action **parser;
Xextern int SRtotal;
Xextern int RRtotal;
Xextern short *SRconflicts;
Xextern short *RRconflicts;
Xextern short *defred;
Xextern short *rules_used;
Xextern short nunused;
Xextern short final_state;
X
X/* global functions */
X
Xextern char *allocate();
Xextern bucket *lookup();
Xextern bucket *make_bucket();
X
X
X/* system variables */
X
Xextern int errno;
X
X
X/* system functions */
X
Xextern void free();
Xextern char *calloc();
Xextern char *malloc();
Xextern char *realloc();
Xextern char *strcpy();
END_OF_FILE
if [[ 5738 -ne `wc -c <'defs.h'` ]]; then
    echo shar: \"'defs.h'\" unpacked with wrong size!
fi
# end of 'defs.h'
fi
if test -f 'error.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'error.c'\"
else
echo shar: Extracting \"'error.c'\" \(6051 characters\)
sed "s/^X//" >'error.c' <<'END_OF_FILE'
X/* routines for printing error messages  */
X
X#include "defs.h"
X
X
Xfatal(msg)
Xchar *msg;
X{
X    fprintf(stderr, "%s: f - %s\n", myname, msg);
X    done(2);
X}
X
X
Xno_space()
X{
X    fprintf(stderr, "%s: f - out of space\n", myname);
X    done(2);
X}
X
X
Xopen_error(filename)
Xchar *filename;
X{
X    fprintf(stderr, "%s: f - cannot open \"%s\"\n", myname, filename);
X    done(2);
X}
X
X
Xunexpected_EOF()
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", unexpected end-of-file\n",
X	    myname, lineno, input_file_name);
X    done(1);
X}
X
X
Xprint_pos(st_line, st_cptr)
Xchar *st_line;
Xchar *st_cptr;
X{
X    register char *s;
X
X    if (st_line == 0) return;
X    for (s = st_line; *s != '\n'; ++s)
X    {
X	if (isprint(*s) || *s == '\t')
X	    putc(*s, stderr);
X	else
X	    putc('?', stderr);
X    }
X    putc('\n', stderr);
X    for (s = st_line; s < st_cptr; ++s)
X    {
X	if (*s == '\t')
X	    putc('\t', stderr);
X	else
X	    putc(' ', stderr);
X    }
X    putc('^', stderr);
X    putc('\n', stderr);
X}
X
X
Xsyntax_error(st_lineno, st_line, st_cptr)
Xint st_lineno;
Xchar *st_line;
Xchar *st_cptr;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", syntax error\n",
X	    myname, st_lineno, input_file_name);
X    print_pos(st_line, st_cptr);
X    done(1);
X}
X
X
Xunterminated_comment(c_lineno, c_line, c_cptr)
Xint c_lineno;
Xchar *c_line;
Xchar *c_cptr;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", unmatched /*\n",
X	    myname, c_lineno, input_file_name);
X    print_pos(c_line, c_cptr);
X    done(1);
X}
X
X
Xunterminated_string(s_lineno, s_line, s_cptr)
Xint s_lineno;
Xchar *s_line;
Xchar *s_cptr;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", unterminated string\n",
X	    myname, s_lineno, input_file_name);
X    print_pos(s_line, s_cptr);
X    done(1);
X}
X
X
Xunterminated_text(t_lineno, t_line, t_cptr)
Xint t_lineno;
Xchar *t_line;
Xchar *t_cptr;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", unmatched %%{\n",
X	    myname, t_lineno, input_file_name);
X    print_pos(t_line, t_cptr);
X    done(1);
X}
X
X
Xunterminated_union(u_lineno, u_line, u_cptr)
Xint u_lineno;
Xchar *u_line;
Xchar *u_cptr;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", unterminated %%union \
Xdeclaration\n", myname, u_lineno, input_file_name);
X    print_pos(u_line, u_cptr);
X    done(1);
X}
X
X
Xover_unionized(u_cptr)
Xchar *u_cptr;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", too many %%union \
Xdeclarations\n", myname, lineno, input_file_name);
X    print_pos(line, u_cptr);
X    done(1);
X}
X
X
Xillegal_tag(t_lineno, t_line, t_cptr)
Xint t_lineno;
Xchar *t_line;
Xchar *t_cptr;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", illegal tag\n",
X	    myname, t_lineno, input_file_name);
X    print_pos(t_line, t_cptr);
X    done(1);
X}
X
X
Xillegal_character(c_cptr)
Xchar *c_cptr;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", illegal character\n",
X	    myname, lineno, input_file_name);
X    print_pos(line, c_cptr);
X    done(1);
X}
X
X
Xused_reserved(s)
Xchar *s;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", illegal use of reserved symbol \
X%s\n", myname, lineno, input_file_name, s);
X    done(1);
X}
X
X
Xtokenized_start(s)
Xchar *s;
X{
X     fprintf(stderr, "%s: e - line %d of \"%s\", the start symbol %s cannot be \
Xdeclared to be a token\n", myname, lineno, input_file_name, s);
X     done(1);
X}
X
X
Xretyped_warning(s)
Xchar *s;
X{
X    fprintf(stderr, "%s: w - line %d of \"%s\", the type of %s has been \
Xredeclared\n", myname, lineno, input_file_name, s);
X}
X
X
Xreprec_warning(s)
Xchar *s;
X{
X    fprintf(stderr, "%s: w - line %d of \"%s\", the precedence of %s has been \
Xredeclared\n", myname, lineno, input_file_name, s);
X}
X
X
Xrevalued_warning(s)
Xchar *s;
X{
X    fprintf(stderr, "%s: w - line %d of \"%s\", the value of %s has been \
Xredeclared\n", myname, lineno, input_file_name, s);
X}
X
X
Xterminal_start(s)
Xchar *s;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", the start symbol %s is a \
Xtoken\n", myname, lineno, input_file_name, s);
X    done(1);
X}
X
X
Xrestarted_warning()
X{
X    fprintf(stderr, "%s: w - line %d of \"%s\", the start symbol has been \
Xredeclared\n", myname, lineno, input_file_name);
X}
X
X
Xno_grammar()
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", no grammar has been \
Xspecified\n", myname, lineno, input_file_name);
X    done(1);
X}
X
X
Xterminal_lhs(s_lineno)
Xint s_lineno;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", a token appears on the lhs \
Xof a production\n", myname, s_lineno, input_file_name);
X    done(1);
X}
X
X
Xprec_redeclared()
X{
X    fprintf(stderr, "%s: w - line %d of  \"%s\", conflicting %%prec \
Xspecifiers\n", myname, lineno, input_file_name);
X}
X
X
Xunterminated_action(a_lineno, a_line, a_cptr)
Xint a_lineno;
Xchar *a_line;
Xchar *a_cptr;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", unterminated action\n",
X	    myname, a_lineno, input_file_name);
X    print_pos(a_line, a_cptr);
X    done(1);
X}
X
X
Xdollar_warning(a_lineno, i)
Xint a_lineno;
Xint i;
X{
X    fprintf(stderr, "%s: w - line %d of \"%s\", $%d references beyond the \
Xend of the current rule\n", myname, a_lineno, input_file_name, i);
X}
X
X
Xdollar_error(a_lineno, a_line, a_cptr)
Xint a_lineno;
Xchar *a_line;
Xchar *a_cptr;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", illegal $-name\n",
X	    myname, a_lineno, input_file_name);
X    print_pos(a_line, a_cptr);
X    done(1);
X}
X
X
Xuntyped_lhs()
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", $$ is untyped\n",
X	    myname, lineno, input_file_name);
X    done(1);
X}
X
X
Xuntyped_rhs(i, s)
Xint i;
Xchar *s;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", $%d (%s) is untyped\n",
X	    myname, lineno, input_file_name, i, s);
X    done(1);
X}
X
X
Xunknown_rhs(i)
Xint i;
X{
X    fprintf(stderr, "%s: e - line %d of \"%s\", $%d is untyped\n",
X	    myname, lineno, input_file_name, i);
X    done(1);
X}
X
X
Xdefault_action_warning()
X{
X    fprintf(stderr, "%s: w - line %d of \"%s\", the default action assigns an \
Xundefined value to $$\n", myname, lineno, input_file_name);
X}
X
X
Xundefined_goal(s)
Xchar *s;
X{
X    fprintf(stderr, "%s: e - the start symbol %s is undefined\n", myname, s);
X    done(1);
X}
X
X
Xundefined_symbol_warning(s)
Xchar *s;
X{
X    fprintf(stderr, "%s: w - the symbol %s is undefined\n", myname, s);
X}
END_OF_FILE
if [[ 6051 -ne `wc -c <'error.c'` ]]; then
    echo shar: \"'error.c'\" unpacked with wrong size!
fi
# end of 'error.c'
fi
if test -f 'main.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'main.c'\"
else
echo shar: Extracting \"'main.c'\" \(5864 characters\)
sed "s/^X//" >'main.c' <<'END_OF_FILE'
X#include <signal.h>
X#include "defs.h"
X
Xchar dflag;
Xchar lflag;
Xchar tflag;
Xchar vflag;
X
Xchar *prefix = "y";
Xchar *myname = "yacc";
Xchar *temp_form = "yacc.XXXXXXX";
X
Xint lineno;
Xint outline;
X
Xchar *action_file_name;
Xchar *defines_file_name;
Xchar *input_file_name = "";
Xchar *output_file_name;
Xchar *text_file_name;
Xchar *union_file_name;
Xchar *verbose_file_name;
X
XFILE *action_file;	/*  a temp file, used to save actions associated    */
X			/*  with rules until the parser is written	    */
XFILE *defines_file;	/*  y.tab.h					    */
XFILE *input_file;	/*  the input file				    */
XFILE *output_file;	/*  y.tab.c					    */
XFILE *text_file;	/*  a temp file, used to save text until all	    */
X			/*  symbols have been defined			    */
XFILE *union_file;	/*  a temp file, used to save the union		    */
X			/*  definition until all symbol have been	    */
X			/*  defined					    */
XFILE *verbose_file;	/*  y.output					    */
X
Xint nitems;
Xint nrules;
Xint nsyms;
Xint ntokens;
Xint nvars;
X
Xint   start_symbol;
Xchar  **symbol_name;
Xshort *symbol_value;
Xshort *symbol_prec;
Xchar  *symbol_assoc;
X
Xshort *ritem;
Xshort *rlhs;
Xshort *rrhs;
Xshort *rprec;
Xchar  *rassoc;
Xshort **derives;
Xchar *nullable;
X
Xextern char *mktemp();
Xextern char *getenv();
X
X
Xdone(k)
Xint k;
X{
X    if (action_file) { fclose(action_file); unlink(action_file_name); }
X    if (text_file) { fclose(text_file); unlink(text_file_name); }
X    if (union_file) { fclose(union_file); unlink(union_file_name); }
X    exit(k);
X}
X
X
Xonintr()
X{
X    done(1);
X}
X
X
Xset_signals()
X{
X#ifdef SIGINT
X    if (signal(SIGINT, SIG_IGN) != SIG_IGN)
X	signal(SIGINT, onintr);
X#endif
X#ifdef SIGTERM
X    if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
X	signal(SIGTERM, onintr);
X#endif
X#ifdef SIGHUP
X    if (signal(SIGHUP, SIG_IGN) != SIG_IGN)
X	signal(SIGHUP, onintr);
X#endif
X}
X
X
Xusage()
X{
X    fprintf(stderr, "usage: %s [-dltv] [-b prefix] filename\n", myname);
X    exit(1);
X}
X
X
Xgetargs(argc, argv)
Xint argc;
Xchar *argv[];
X{
X    register int i;
X    register char *s;
X
X    if (argc > 0) myname = argv[0];
X    for (i = 1; i < argc; ++i)
X    {
X	s = argv[i];
X	if (*s != '-') break;
X	switch (*++s)
X	{
X	case '\0':
X	    input_file = stdin;
X	    if (i + 1 < argc) usage();
X	    return;
X
X	case '_':
X	    ++i;
X	    goto no_more_options;
X
X	case 'b':
X	    if (*++s || ++i >= argc) usage();
X	    prefix = argv[i];
X	    continue;
X
X	case 'd':
X	    dflag = 1;
X	    break;
X
X	case 'l':
X	    lflag = 1;
X	    break;
X
X	case 't':
X	    tflag = 1;
X	    break;
X
X	case 'v':
X	    vflag = 1;
X	    break;
X
X	default:
X	    usage();
X	}
X
X	for (;;)
X	{
X	    switch (*++s)
X	    {
X	    case '\0':
X		goto end_of_option;
X
X	    case 'd':
X		dflag = 1;
X		break;
X
X	    case 'l':
X		lflag = 1;
X		break;
X
X	    case 't':
X		tflag = 1;
X		break;
X
X	    case 'v':
X		vflag = 1;
X		break;
X
X	    default:
X		usage();
X	    }
X	}
Xend_of_option:;
X    }
X
Xno_more_options:;
X    if (i + 1 != argc) usage();
X    input_file_name = argv[i];
X}
X
X
Xchar *
Xallocate(n)
Xunsigned n;
X{
X    register char *p;
X
X    p = calloc((unsigned) 1, n);
X    if (!p) no_space();
X    return (p);
X}
X
X
Xcreate_file_names()
X{
X    int i, len;
X    char *tmpdir;
X
X    tmpdir = getenv("TMPDIR");
X    if (tmpdir == 0) tmpdir = "/tmp";
X
X    len = strlen(tmpdir);
X    i = len + 13;
X    if (len && tmpdir[len-1] != '/')
X	++i;
X
X    action_file_name = MALLOC(i);
X    if (action_file_name == 0) no_space();
X    text_file_name = MALLOC(i);
X    if (text_file_name == 0) no_space();
X    union_file_name = MALLOC(i);
X    if (union_file_name == 0) no_space();
X
X    strcpy(action_file_name, tmpdir);
X    strcpy(text_file_name, tmpdir);
X    strcpy(union_file_name, tmpdir);
X
X    if (len && tmpdir[len - 1] != '/')
X    {
X	action_file_name[len] = '/';
X	text_file_name[len] = '/';
X	union_file_name[len] = '/';
X	++len;
X    }
X
X    strcpy(action_file_name + len, temp_form);
X    strcpy(text_file_name + len, temp_form);
X    strcpy(union_file_name + len, temp_form);
X
X    action_file_name[len + 5] = 'a';
X    text_file_name[len + 5] = 't';
X    union_file_name[len + 5] = 'u';
X
X    mktemp(action_file_name);
X    mktemp(text_file_name);
X    mktemp(union_file_name);
X
X    len = strlen(prefix);
X    if (dflag)
X    {
X	/*  the number 7 below is the size of ".tab.h"; sizeof is not used  */
X	/*  because of a C compiler that thinks sizeof(".tab.h") == 6	    */
X	defines_file_name = MALLOC(len + 7);
X	if (defines_file_name == 0) no_space();
X	strcpy(defines_file_name, prefix);
X	strcpy(defines_file_name + len, DEFINES_SUFFIX);
X    }
X
X    output_file_name = MALLOC(len + 7);
X    if (output_file_name == 0) no_space();
X    strcpy(output_file_name, prefix);
X    strcpy(output_file_name + len, OUTPUT_SUFFIX);
X
X    if (vflag)
X    {
X	verbose_file_name = MALLOC(len + 8);
X	if (verbose_file_name == 0) no_space();
X	strcpy(verbose_file_name, prefix);
X	strcpy(verbose_file_name + len, VERBOSE_SUFFIX);
X    }
X}
X
X
Xopen_files()
X{
X    create_file_names();
X
X    if (input_file == 0)
X    {
X	input_file = fopen(input_file_name, "r");
X	if (input_file == 0) open_error(input_file_name);
X    }
X
X    action_file = fopen(action_file_name, "w");
X    if (action_file == 0) open_error(action_file_name);
X
X    text_file = fopen(text_file_name, "w");
X    if (text_file == 0) open_error(text_file_name);
X
X    if (vflag)
X    {
X	verbose_file = fopen(verbose_file_name, "w");
X	if (verbose_file == 0) open_error(verbose_file_name);
X    }
X
X    if (dflag)
X    {
X	defines_file = fopen(defines_file_name, "w");
X	if (defines_file == 0) open_error(defines_file_name);
X	union_file = fopen(union_file_name, "w");
X	if (union_file ==  0) open_error(union_file_name);
X    }
X
X    output_file = fopen(output_file_name, "w");
X    if (output_file == 0) open_error(output_file_name);
X}
X
X
Xint
Xmain(argc, argv)
Xint argc;
Xchar *argv[];
X{
X    set_signals();
X    getargs(argc, argv);
X    open_files();
X    reader();
X    lr0();
X    lalr();
X    make_parser();
X    verbose();
X    output();
X    done(0);
X    /*NOTREACHED*/
X}
END_OF_FILE
if [[ 5864 -ne `wc -c <'main.c'` ]]; then
    echo shar: \"'main.c'\" unpacked with wrong size!
fi
# end of 'main.c'
fi
if test -f 'manpage' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'manpage'\"
else
echo shar: Extracting \"'manpage'\" \(2394 characters\)
sed "s/^X//" >'manpage' <<'END_OF_FILE'
X.\"	%W%	%R% (Berkeley) %E%
X.\"
X.TH YACC 1 "December 10, 1989"
X.UC 6
X.SH NAME
XYacc \- an LALR(1) parser generator
X.SH SYNOPSIS
X.B yacc [ -dltv ] [ -b
X.I prefix
X.B ]
X.I filename
X.SH DESCRIPTION
X.I Yacc
Xreads the grammar specification in the file
X.I filename
Xand generates an LR(1) parser for it.
XThe parsers consist of a set of LALR(1) parsing tables and a driver routine
Xwritten in the C programming language.
X.I Yacc
Xnormally writes the parse tables and the driver routine to the file
X.IR y.tab.c.
X.PP
XThe following options are available:
X.RS
X.TP
X\fB-b \fIprefix\fR
XThe
X.B -b
Xoption changes the prefix prepended to the output file names to
Xthe string denoted by
X.IR prefix.
XThe default prefix is the character
X.IR y.
X.TP
X.B -d
XThe \fB-d\fR option causes the header file
X.IR y.tab.h
Xto be written.
X.TP
X.B -l
XIf the
X.B -l
Xoption is not specified,
X.I yacc
Xwill insert \#line directives in the generated code.
XThe \#line directives let the C compiler relate errors in the
Xgenerated code to the user's original code.
XIf the \fB-l\fR option is specified,
X.I yacc
Xwill not insert the \#line directives.
X\&\#line directives specified by the user will be retained.
X.TP
X.B -t
XThe
X.B -t
Xoption will change the preprocessor directives generated by
X.I yacc
Xso that debugging statements will be incorporated in the compiled code.
X.TP
X.B -v
XThe
X.B -v
Xoption causes a human-readable description of the generated parser to
Xbe written to the file
X.IR y.output.
X.RE
X.PP
XIf the environment variable TMPDIR is set, the string denoted by
XTMPDIR will be used as the name of the directory where the temporary
Xfiles are created.
X.SH TABLES
XThere is a program \fI:yyfix\fR
Xthat extracts tables from \fIyacc\fR-generated
Xfiles.
XThe program takes the names of the tables as its command-line arguments.
XThe names of the tables generated by this version of
X.I yacc
Xare
X.IR yylhs,
X.IR yylen,
X.IR yydefred,
X.IR yydgoto,
X.IR yysindex,
X.IR yyrindex,
X.IR yygindex,
X.IR yytable,
Xand
X.IR yycheck.
XTwo additional tables,
X.I yyname
Xand
X.I yyrule,
Xare created if YYDEBUG is defined and nonzero.
X.SH FILES
X.IR y.tab.c
X.br
X.IR y.tab.h
X.br
X.IR y.output
X.br
X.IR /tmp/yacc.aXXXXXX
X.br
X.IR /tmp/yacc.tXXXXXX
X.br
X.IR /tmp/yacc.uXXXXXX
X.SH DIAGNOSTICS
XIf there are rules that are never reduced, the number of such rules is
Xreported on standard error.
XIf there are any LALR(1) conflicts, the number of conflicts is reported
Xon standard error.
END_OF_FILE
if [[ 2394 -ne `wc -c <'manpage'` ]]; then
    echo shar: \"'manpage'\" unpacked with wrong size!
fi
# end of 'manpage'
fi
if test -f 'symtab.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'symtab.c'\"
else
echo shar: Extracting \"'symtab.c'\" \(1841 characters\)
sed "s/^X//" >'symtab.c' <<'END_OF_FILE'
X#include "defs.h"
X
X
X/* TABLE_SIZE is the number of entries in the symbol table. */
X/* TABLE_SIZE must be a power of two.			    */
X
X#define	TABLE_SIZE 1024
X
X
Xbucket **symbol_table;
Xbucket *first_symbol;
Xbucket *last_symbol;
X
X
Xint
Xhash(name)
Xchar *name;
X{
X    register char *s;
X    register int c, k;
X
X    assert(name && *name);
X    s = name;
X    k = *s;
X    while (c = *++s)
X	k = (31*k + c) & (TABLE_SIZE - 1);
X
X    return (k);
X}
X
X
Xbucket *
Xmake_bucket(name)
Xchar *name;
X{
X    register bucket *bp;
X
X    assert(name);
X    bp = (bucket *) MALLOC(sizeof(bucket));
X    if (bp == 0) no_space();
X    bp->link = 0;
X    bp->next = 0;
X    bp->name = MALLOC(strlen(name) + 1);
X    if (bp->name == 0) no_space();
X    bp->tag = 0;
X    bp->value = UNDEFINED;
X    bp->index = 0;
X    bp->prec = 0;
X    bp-> class = UNKNOWN;
X    bp->assoc = TOKEN;
X
X    if (bp->name == 0) no_space();
X    strcpy(bp->name, name);
X
X    return (bp);
X}
X
X
Xbucket *
Xlookup(name)
Xchar *name;
X{
X    register bucket *bp, **bpp;
X
X    bpp = symbol_table + hash(name);
X    bp = *bpp;
X
X    while (bp)
X    {
X	if (strcmp(name, bp->name) == 0) return (bp);
X	bpp = &bp->link;
X	bp = *bpp;
X    }
X
X    *bpp = bp = make_bucket(name);
X    last_symbol->next = bp;
X    last_symbol = bp;
X
X    return (bp);
X}
X
X
Xcreate_symbol_table()
X{
X    register int i;
X    register bucket *bp;
X
X    symbol_table = (bucket **) MALLOC(TABLE_SIZE*sizeof(bucket *));
X    if (symbol_table == 0) no_space();
X    for (i = 0; i < TABLE_SIZE; i++)
X	symbol_table[i] = 0;
X
X    bp = make_bucket("error");
X    bp->index = 1;
X    bp->class = TERM;
X
X    first_symbol = bp;
X    last_symbol = bp;
X    symbol_table[hash("error")] = bp;
X}
X
X
Xfree_symbol_table()
X{
X    FREE(symbol_table);
X    symbol_table = 0;
X}
X
X
Xfree_symbols()
X{
X    register bucket *p, *q;
X
X    for (p = first_symbol; p; p = q)
X    {
X	q = p->next;
X	FREE(p);
X    }
X}
END_OF_FILE
if [[ 1841 -ne `wc -c <'symtab.c'` ]]; then
    echo shar: \"'symtab.c'\" unpacked with wrong size!
fi
# end of 'symtab.c'
fi
if test ! -d 'test' ; then
    echo shar: Creating directory \"'test'\"
    mkdir 'test'
fi
if test -f 'test/error.output' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'test/error.output'\"
else
echo shar: Extracting \"'test/error.output'\" \(262 characters\)
sed "s/^X//" >'test/error.output' <<'END_OF_FILE'
X   0  $accept : S $end
X
X   1  S : error
X
Xstate 0
X	$accept : . S $end  (0)
X
X	error  shift 1
X	.  error
X
X	S  goto 2
X
X
Xstate 1
X	S : error .  (1)
X
X	.  reduce 1
X
X
Xstate 2
X	$accept : S . $end  (0)
X
X	$end  accept
X
X
X2 terminals, 2 nonterminals
X2 grammar rules, 3 states
END_OF_FILE
if [[ 262 -ne `wc -c <'test/error.output'` ]]; then
    echo shar: \"'test/error.output'\" unpacked with wrong size!
fi
# end of 'test/error.output'
fi
if test -f 'test/error.tab.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'test/error.tab.c'\"
else
echo shar: Extracting \"'test/error.tab.c'\" \(6307 characters\)
sed "s/^X//" >'test/error.tab.c' <<'END_OF_FILE'
X#ifndef lint
Xchar yysccsid[] = "@(#)yaccpar	1.4 (Berkeley) 02/25/90";
X#endif
X#define YYERRCODE 256
Xshort yylhs[] = {                                        -1,
X    0,
X};
Xshort yylen[] = {                                         2,
X    1,
X};
Xshort yydefred[] = {                                      0,
X    1,    0,
X};
Xshort yydgoto[] = {                                       2,
X};
Xshort yysindex[] = {                                   -256,
X    0,    0,
X};
Xshort yyrindex[] = {                                      0,
X    0,    0,
X};
Xshort yygindex[] = {                                      0,
X};
X#define YYTABLESIZE 0
Xshort yytable[] = {                                       1,
X};
Xshort yycheck[] = {                                     256,
X};
X#define YYFINAL 2
X#ifndef YYDEBUG
X#define YYDEBUG 0
X#endif
X#define YYMAXTOKEN 0
X#if YYDEBUG
Xchar *yyname[] = {
X"end-of-file",
X};
Xchar *yyrule[] = {
X"$accept : S",
X"S : error",
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
X#line 4 "error.y"
Xmain(){printf("yyparse() = %d\n",yyparse());}
Xyylex(){return-1;}
Xyyerror(s)char*s;{printf("%s\n",s);}
X#line 71 "error.tab.c"
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
if [[ 6307 -ne `wc -c <'test/error.tab.c'` ]]; then
    echo shar: \"'test/error.tab.c'\" unpacked with wrong size!
fi
# end of 'test/error.tab.c'
fi
if test -f 'test/error.tab.h' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'test/error.tab.h'\"
else
echo shar: Extracting \"'test/error.tab.h'\" \(0 characters\)
sed "s/^X//" >'test/error.tab.h' <<'END_OF_FILE'
END_OF_FILE
if [[ 0 -ne `wc -c <'test/error.tab.h'` ]]; then
    echo shar: \"'test/error.tab.h'\" unpacked with wrong size!
fi
# end of 'test/error.tab.h'
fi
if test -f 'test/error.y' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'test/error.y'\"
else
echo shar: Extracting \"'test/error.y'\" \(117 characters\)
sed "s/^X//" >'test/error.y' <<'END_OF_FILE'
X%%
XS: error
X%%
Xmain(){printf("yyparse() = %d\n",yyparse());}
Xyylex(){return-1;}
Xyyerror(s)char*s;{printf("%s\n",s);}
END_OF_FILE
if [[ 117 -ne `wc -c <'test/error.y'` ]]; then
    echo shar: \"'test/error.y'\" unpacked with wrong size!
fi
# end of 'test/error.y'
fi
if test -f 'test/ftp.tab.h' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'test/ftp.tab.h'\"
else
echo shar: Extracting \"'test/ftp.tab.h'\" \(1038 characters\)
sed "s/^X//" >'test/ftp.tab.h' <<'END_OF_FILE'
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
END_OF_FILE
if [[ 1038 -ne `wc -c <'test/ftp.tab.h'` ]]; then
    echo shar: \"'test/ftp.tab.h'\" unpacked with wrong size!
fi
# end of 'test/ftp.tab.h'
fi
if test -f 'verbose.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'verbose.c'\"
else
echo shar: Extracting \"'verbose.c'\" \(6579 characters\)
sed "s/^X//" >'verbose.c' <<'END_OF_FILE'
X#include "defs.h"
X
X
Xstatic short *null_rules;
X
Xverbose()
X{
X    register int i;
X
X    if (!vflag) return;
X
X    null_rules = (short *) MALLOC(nrules*sizeof(short));
X    if (null_rules == 0) no_space();
X    fprintf(verbose_file, "\f\n");
X    for (i = 0; i < nstates; i++)
X	print_state(i);
X    FREE(null_rules);
X
X    if (nunused)
X	log_unused();
X    if (SRtotal || RRtotal)
X	log_conflicts();
X
X    fprintf(verbose_file, "\n\n%d terminals, %d nonterminals\n", ntokens,
X	    nvars);
X    fprintf(verbose_file, "%d grammar rules, %d states\n", nrules - 2, nstates);
X}
X
X
Xlog_unused()
X{
X    register int i;
X    register short *p;
X
X    fprintf(verbose_file, "\n\nRules never reduced:\n");
X    for (i = 3; i < nrules; ++i)
X    {
X	if (!rules_used[i])
X	{
X	    fprintf(verbose_file, "\t%s :", symbol_name[rlhs[i]]);
X	    for (p = ritem + rrhs[i]; *p >= 0; ++p)
X		fprintf(verbose_file, " %s", symbol_name[*p]);
X	    fprintf(verbose_file, "  (%d)\n", i - 2);
X	}
X    }
X}
X
X
Xlog_conflicts()
X{
X    register int i;
X
X    fprintf(verbose_file, "\n\n");
X    for (i = 0; i < nstates; i++)
X    {
X	if (SRconflicts[i] || RRconflicts[i])
X	{
X	    fprintf(verbose_file, "State %d contains ", i);
X	    if (SRconflicts[i] == 1)
X		fprintf(verbose_file, "1 shift/reduce conflict");
X	    else if (SRconflicts[i] > 1)
X		fprintf(verbose_file, "%d shift/reduce conflicts",
X			SRconflicts[i]);
X	    if (SRconflicts[i] && RRconflicts[i])
X		fprintf(verbose_file, ", ");
X	    if (RRconflicts[i] == 1)
X		fprintf(verbose_file, "1 reduce/reduce conflict");
X	    else if (RRconflicts[i] > 1)
X		fprintf(verbose_file, "%d reduce/reduce conflicts",
X			RRconflicts[i]);
X	    fprintf(verbose_file, ".\n");
X	}
X    }
X}
X
X
Xprint_state(state)
Xint state;
X{
X    if (state)
X	fprintf(verbose_file, "\n\n");
X    if (SRconflicts[state] || RRconflicts[state])
X	print_conflicts(state);
X    fprintf(verbose_file, "state %d\n", state);
X    print_core(state);
X    print_nulls(state);
X    print_actions(state);
X}
X
X
Xprint_conflicts(state)
Xint state;
X{
X    register int symbol;
X    register action *p, *q, *r;
X
X    for (p = parser[state]; p; p = q->next)
X    {
X	q = p;
X	if (p->action_code == ERROR || p->suppressed == 2)
X	    continue;
X
X	symbol = p->symbol;
X	while (q->next && q->next->symbol == symbol)
X	    q = q->next;
X	if (state == final_state && symbol == 0)
X	{
X	    r = p;
X	    for (;;)
X	    {
X		fprintf(verbose_file, "%d: shift/reduce conflict \
X(accept, reduce %d) on $end\n", state, r->number - 2);
X		if (r == q) break;
X		r = r->next;
X	    }
X	}
X	else if (p != q)
X	{
X	    r = p->next;
X	    if (p->action_code == SHIFT)
X	    {
X		for (;;)
X		{
X		    if (r->action_code == REDUCE && p->suppressed != 2)
X			fprintf(verbose_file, "%d: shift/reduce conflict \
X(shift %d, reduce %d) on %s\n", state, p->number, r->number - 2,
X				symbol_name[symbol]);
X		    if (r == q) break;
X		    r = r->next;
X		}
X	    }
X	    else
X	    {
X		for (;;)
X		{
X		    if (r->action_code == REDUCE && p->suppressed != 2)
X			fprintf(verbose_file, "%d: reduce/reduce conflict \
X(reduce %d, reduce %d) on %s\n", state, p->number - 2, r->number - 2,
X				symbol_name[symbol]);
X		    if (r == q) break;
X		    r = r->next;
X		}
X	    }
X	}
X    }
X}
X
X
Xprint_core(state)
Xint state;
X{
X    register int i;
X    register int k;
X    register int rule;
X    register core *statep;
X    register short *sp;
X    register short *sp1;
X
X    statep = state_table[state];
X    k = statep->nitems;
X
X    for (i = 0; i < k; i++)
X    {
X	sp1 = sp = ritem + statep->items[i];
X
X	while (*sp >= 0) ++sp;
X	rule = -(*sp);
X	fprintf(verbose_file, "\t%s : ", symbol_name[rlhs[rule]]);
X
X        for (sp = ritem + rrhs[rule]; sp < sp1; sp++)
X	    fprintf(verbose_file, "%s ", symbol_name[*sp]);
X
X	putc('.', verbose_file);
X
X	while (*sp >= 0)
X	{
X	    fprintf(verbose_file, " %s", symbol_name[*sp]);
X	    sp++;
X	}
X	fprintf(verbose_file, "  (%d)\n", -2 - *sp);
X    }
X}
X
X
Xprint_nulls(state)
Xint state;
X{
X    register action *p;
X    register int i, j, k, nnulls;
X
X    nnulls = 0;
X    for (p = parser[state]; p; p = p->next)
X    {
X	if (p->action_code == REDUCE &&
X		(p->suppressed == 0 || p->suppressed == 1))
X	{
X	    i = p->number;
X	    if (rrhs[i] + 1 == rrhs[i+1])
X	    {
X		for (j = 0; j < nnulls && i > null_rules[j]; ++j)
X		    continue;
X
X		if (j == nnulls)
X		{
X		    ++nnulls;
X		    null_rules[j] = i;
X		}
X		else if (i != null_rules[j])
X		{
X		    ++nnulls;
X		    for (k = nnulls - 1; k > j; --k)
X			null_rules[k] = null_rules[k-1];
X		    null_rules[j] = i;
X		}
X	    }
X	}
X    }
X
X    for (i = 0; i < nnulls; ++i)
X    {
X	j = null_rules[i];
X	fprintf(verbose_file, "\t%s : .  (%d)\n", symbol_name[rlhs[j]],
X		j - 2);
X    }
X    fprintf(verbose_file, "\n");
X}
X
X
Xprint_actions(stateno)
Xint stateno;
X{
X    register action *p;
X    register shifts *sp;
X    register int as;
X
X    if (stateno == final_state)
X	fprintf(verbose_file, "\t$end  accept\n");
X
X    p = parser[stateno];
X    if (p)
X    {
X	print_shifts(p);
X	print_reductions(p, defred[stateno]);
X    }
X
X    sp = shift_table[stateno];
X    if (sp && sp->nshifts > 0)
X    {
X	as = accessing_symbol[sp->shift[sp->nshifts - 1]];
X	if (ISVAR(as))
X	    print_gotos(stateno);
X    }
X}
X
X
Xprint_shifts(p)
Xregister action *p;
X{
X    register int count;
X    register action *q;
X
X    count = 0;
X    for (q = p; q; q = q->next)
X    {
X	if (q->suppressed < 2 && q->action_code == SHIFT)
X	    ++count;
X    }
X
X    if (count > 0)
X    {
X	for (; p; p = p->next)
X	{
X	    if (p->action_code == SHIFT && p->suppressed == 0)
X		fprintf(verbose_file, "\t%s  shift %d\n",
X			    symbol_name[p->symbol], p->number);
X	}
X    }
X}
X
X
Xprint_reductions(p, defred)
Xregister action *p;
Xregister int defred;
X{
X    register int k, anyreds;
X    register action *q;
X
X    anyreds = 0;
X    for (q = p; q ; q = q->next)
X    {
X	if (q->action_code == REDUCE && q->suppressed < 2)
X	{
X	    anyreds = 1;
X	    break;
X	}
X    }
X
X    if (anyreds == 0)
X	fprintf(verbose_file, "\t.  error\n");
X    else
X    {
X	for (; p; p = p->next)
X	{
X	    if (p->action_code == REDUCE && p->number != defred)
X	    {
X		k = p->number - 2;
X		if (p->suppressed == 0)
X		    fprintf(verbose_file, "\t%s  reduce %d\n",
X			    symbol_name[p->symbol], k);
X	    }
X	}
X
X        if (defred > 0)
X	    fprintf(verbose_file, "\t.  reduce %d\n", defred - 2);
X    }
X}
X
X
Xprint_gotos(stateno)
Xint stateno;
X{
X    register int i, k;
X    register int as;
X    register short *to_state;
X    register shifts *sp;
X
X    putc('\n', verbose_file);
X    sp = shift_table[stateno];
X    to_state = sp->shift;
X    for (i = 0; i < sp->nshifts; ++i)
X    {
X	k = to_state[i];
X	as = accessing_symbol[k];
X	if (ISVAR(as))
X	    fprintf(verbose_file, "\t%s  goto %d\n", symbol_name[as], k);
X    }
X}
END_OF_FILE
if [[ 6579 -ne `wc -c <'verbose.c'` ]]; then
    echo shar: \"'verbose.c'\" unpacked with wrong size!
fi
# end of 'verbose.c'
fi
if test -f 'warshall.c' -a "${1}" != "-c" ; then 
  echo shar: Will not clobber existing file \"'warshall.c'\"
else
echo shar: Extracting \"'warshall.c'\" \(1205 characters\)
sed "s/^X//" >'warshall.c' <<'END_OF_FILE'
X#include "defs.h"
X
Xtransitive_closure(R, n)
Xunsigned *R;
Xint n;
X{
X    register int rowsize;
X    register unsigned mask;
X    register unsigned *rowj;
X    register unsigned *rp;
X    register unsigned *rend;
X    register unsigned *ccol;
X    register unsigned *relend;
X    register unsigned *cword;
X    register unsigned *rowi;
X
X    rowsize = WORDSIZE(n);
X    relend = R + n*rowsize;
X
X    cword = R;
X    mask = 1;
X    rowi = R;
X    while (rowi < relend)
X    {
X	ccol = cword;
X	rowj = R;
X
X	while (rowj < relend)
X	{
X	    if (*ccol & mask)
X	    {
X		rp = rowi;
X		rend = rowj + rowsize;
X		while (rowj < rend)
X		    *rowj++ |= *rp++;
X	    }
X	    else
X	    {
X		rowj += rowsize;
X	    }
X
X	    ccol += rowsize;
X	}
X
X	mask <<= 1;
X	if (mask == 0)
X	{
X	    mask = 1;
X	    cword++;
X	}
X
X	rowi += rowsize;
X    }
X}
X
Xreflexive_transitive_closure(R, n)
Xunsigned *R;
Xint n;
X{
X    register int rowsize;
X    register unsigned mask;
X    register unsigned *rp;
X    register unsigned *relend;
X
X    transitive_closure(R, n);
X
X    rowsize = WORDSIZE(n);
X    relend = R + n*rowsize;
X
X    mask = 1;
X    rp = R;
X    while (rp < relend)
X    {
X	*rp |= mask;
X	mask <<= 1;
X	if (mask == 0)
X	{
X	    mask = 1;
X	    rp++;
X	}
X
X	rp += rowsize;
X    }
X}
END_OF_FILE
if [[ 1205 -ne `wc -c <'warshall.c'` ]]; then
    echo shar: \"'warshall.c'\" unpacked with wrong size!
fi
# end of 'warshall.c'
fi
echo shar: End of archive 1 \(of 5\).
cp /dev/null ark1isdone
MISSING=""
for I in 1 2 3 4 5 ; do
    if test ! -f ark${I}isdone ; then
	MISSING="${MISSING} ${I}"
    fi
done
if [[ "${MISSING}" = "" ]]; then
    echo You have unpacked all 5 archives.
    rm -f ark[1-9]isdone
else
    echo You still need to unpack the following archives:
    echo "        " ${MISSING}
fi
##  End of shell archive.
exit 0
