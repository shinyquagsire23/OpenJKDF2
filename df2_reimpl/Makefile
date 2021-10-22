CC := i686-w64-mingw32-gcc
TARGET := df2_reimpl.dll
TARGET_WIN := df2_reimpl_win.dll

SRC := src
OBJ := build

SOURCES := $(wildcard $(SRC)/*.c $(SRC)/*/*.c) #$(SRC)/Cog/lex.yy.c $(SRC)/Cog/y.tab.c
OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES))
ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

CFLAGS := -I$(ROOT_DIR)/$(SRC) -DQOL_IMPROVEMENTS -DWIN32 -DTARGET_HAS_DPLAY -Wuninitialized -fno-trapping-math

FLEX_BIN := $(ROOT_DIR)/flex/flex
YACC_BIN := $(ROOT_DIR)/byacc/yacc

GLOBALS_C := $(ROOT_DIR)/$(SRC)/globals.c
GLOBALS_C_COG := $(ROOT_DIR)/$(SRC)/globals.c.cog

GLOBALS_H := $(ROOT_DIR)/$(SRC)/globals.h
GLOBALS_H_COG := $(ROOT_DIR)/$(SRC)/globals.h.cog

SYMBOLS_FILE := $(ROOT_DIR)/symbols.syms

#CFLAGS=

all: initial $(OBJ) $(TARGET) $(TARGET_WIN)
clean:
	rm -rf $(OBJ)
	rm -f $(TARGET)
	rm -f $(SRC)/Cog/lex.yy.c $(SRC)/Cog/y.tab.c
	rm -f $(GLOBALS_C)
	rm -f $(GLOBALS_H)
	touch $(GLOBALS_C)
	touch $(GLOBALS_H)
	touch -m $(SYMBOLS_FILE)
	touch -m $(GLOBALS_H_COG)
	touch -m $(GLOBALS_C_COG)
	touch $(SRC)/Cog/lex.yy.c
	touch $(SRC)/Cog/y.tab.c

clean_cog:
	rm -f $(SRC)/Cog/lex.yy.c $(SRC)/Cog/y.tab.c

initial: clean_cog $(FLEX_BIN) $(YACC_BIN) $(GLOBALS_H) $(GLOBALS_C)
	@echo Generating COG lex/yacc...
	cd $(SRC)/Cog && $(FLEX_BIN) -i cog.l
	cd $(SRC)/Cog && $(YACC_BIN) -d cog.y

$(OBJ):
	@mkdir -p $(OBJ)

$(FLEX_BIN):
	cd $(ROOT_DIR)/flex && make

$(YACC_BIN):
	cd $(ROOT_DIR)/byacc && make

$(GLOBALS_H): $(GLOBALS_H_COG) $(SYMBOLS_FILE)
	cog -d -D symbols_fpath="$(SYMBOLS_FILE)" $(GLOBALS_H_COG) > $(GLOBALS_H)

$(GLOBALS_C): $(GLOBALS_C_COG) $(SYMBOLS_FILE)
	cog -d -D symbols_fpath="$(SYMBOLS_FILE)" $(GLOBALS_C_COG) > $(GLOBALS_C)

#$(SRC)/Cog/lex.yy.c : $(FLEX_BIN) $(SRC)/Cog/cog.l
#	cd $(SRC)/Cog && $(FLEX_BIN) -i cog.l

#$(SRC)/Cog/y.tab.c : $(YACC_BIN) $(SRC)/Cog/cog.y
#	cd $(SRC)/Cog && $(YACC_BIN) -d cog.y

$(OBJ)/%.o: $(SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c -g -o $@ $< $(CFLAGS)

$(TARGET_WIN): $(OBJECTS)
	$(CC) -o $@ -g -shared $^ -Wl,--subsystem,windows -Wl,-Map=output.map -static-libgcc -fno-trapping-math

$(TARGET): $(OBJECTS)
	$(CC) -o $@ -g -shared $^ -Wl,--subsystem,windows -Wl,-Map=output.map -Wl,-e_hook_init -nostartfiles -static -static-libgcc -static-libstdc++ -fno-trapping-math
