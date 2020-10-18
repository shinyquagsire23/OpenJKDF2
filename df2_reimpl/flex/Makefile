# make file for "flex" tool

# @(#) $Header: Makefile,v 2.3 89/06/20 17:27:12 vern Exp $ (LBL)

# Porting considerations:
#
#    For System V Unix machines, add -DSYS_V to CFLAGS.
#    For Vax/VMS, add -DSYS_V to CFLAGS.
#    For MS-DOS, add "-DMS_DOS -DSYS_V" to CFLAGS.  Create \tmp if not present.
#         You will also want to rename flex.skel to something with a three
#         character extension, change SKELETON_FILE below appropriately,
#    For Amiga, add "-DAMIGA -DSYS_V" to CFLAGS.
#
# A long time ago, flex was successfully built using Microsoft C and
# the following options: /AL, /stack:10000, -LARGE, -Ml, -Mt128, -DSYS_V


# the first time around use "make first_flex"


SKELETON_DIR = .
SKELETON_FILE = flex.skel
SKELFLAGS = -DDEFAULT_SKELETON_FILE=\"$(SKELETON_DIR)/$(SKELETON_FILE)\"
CFLAGS = -O
LDFLAGS = -s

FLEX_FLAGS =
FLEX = ./flex
CC = cc

FLEXOBJS = \
	ccl.o \
	dfa.o \
	ecs.o \
	gen.o \
	main.o \
	misc.o \
	nfa.o \
	parse.o \
	scan.o \
	sym.o \
	tblcmp.o \
	yylex.o

FLEX_C_SOURCES = \
	ccl.c \
	dfa.c \
	ecs.c \
	gen.c \
	main.c \
	misc.c \
	nfa.c \
	parse.c \
	scan.c \
	sym.c \
	tblcmp.c \
	yylex.c

flex : $(FLEXOBJS)
	$(CC) $(CFLAGS) -o flex $(LDFLAGS) $(FLEXOBJS)

first_flex:
	cp initscan.c scan.c
	make $(MFLAGS) flex

parse.h parse.c : parse.y
	$(YACC) -d parse.y
	@mv y.tab.c parse.c
	@mv y.tab.h parse.h

scan.c : scan.l
	$(FLEX) -ist $(FLEX_FLAGS) scan.l >scan.c

scan.o : scan.c parse.h

main.o : main.c
	$(CC) $(CFLAGS) -c $(SKELFLAGS) main.c

flex.man : flex.1
	nroff -man flex.1 >flex.man

lint : $(FLEX_C_SOURCES)
	lint $(FLEX_C_SOURCES) > flex.lint

distrib :
	mv scan.c initscan.c
	chmod 444 initscan.c
	$(MAKE) $(MFLAGS) clean

clean :
	rm -f core errs flex *.o parse.c *.lint parse.h flex.man tags

tags :
	ctags $(FLEX_C_SOURCES)

vms :	flex.man
	$(MAKE) $(MFLAGS) distrib

test :
	$(FLEX) -ist $(FLEX_FLAGS) scan.l | diff scan.c -
