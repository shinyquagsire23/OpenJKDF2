CC := i686-w64-mingw32-gcc
TARGET := df2_reimpl_kvm.dll
TARGET_WIN := df2_reimpl.dll

SRC := src
OBJ := build

SOURCES := $(wildcard $(SRC)/*.c $(SRC)/*/*.c) #$(SRC)/Cog/lex.yy.c $(SRC)/Cog/y.tab.c
OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES))
ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

CFLAGS := -I$(ROOT_DIR)/$(SRC) -I$(ROOT_DIR)/$(SRC)/external/libsmacker -DQOL_IMPROVEMENTS -DWIN32 -DARCH_X86 -DTARGET_HAS_DPLAY -Wuninitialized -fno-trapping-math

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

initial: clean_cog $(FLEX_BIN) $(YACC_BIN)
	@echo Generating COG lex/yacc...
	cd $(SRC)/Cog && $(FLEX_BIN) -i cog.l
	cd $(SRC)/Cog && $(YACC_BIN) -d cog.y
	@echo Generating globals...
	cog -d -D symbols_fpath="$(SYMBOLS_FILE)" $(GLOBALS_H_COG) > $(GLOBALS_H)
	cog -d -D symbols_fpath="$(SYMBOLS_FILE)" $(GLOBALS_C_COG) > $(GLOBALS_C)

$(OBJ):
	@mkdir -p $(OBJ)

$(FLEX_BIN):
	cd $(ROOT_DIR)/flex && make

$(YACC_BIN):
	cd $(ROOT_DIR)/byacc && make

$(OBJ)/%.o: $(SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c -g -o $@ $< $(CFLAGS)

$(TARGET_WIN): $(OBJECTS)
	$(CC) -o $@ -g -shared $^ -Wl,--subsystem,windows -Wl,-Map=output.map -static-libgcc -fno-trapping-math

$(TARGET): $(OBJECTS)
	$(CC) -o $@ -g -shared $^ -Wl,--subsystem,windows -Wl,-Map=output.map -Wl,-e_hook_init -nostartfiles -static -static-libgcc -static-libstdc++ -fno-trapping-math
