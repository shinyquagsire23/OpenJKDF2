#
# Common paths
#
FLEX_BIN := $(ROOT_DIR)/flex/flex
YACC_BIN := $(ROOT_DIR)/byacc/yacc

GLOBALS_C := $(ROOT_DIR)/$(SRC)/globals.c
GLOBALS_C_COG := $(ROOT_DIR)/$(SRC)/globals.c.cog

GLOBALS_H := $(ROOT_DIR)/$(SRC)/globals.h
GLOBALS_H_COG := $(ROOT_DIR)/$(SRC)/globals.h.cog

SYMBOLS_FILE := $(ROOT_DIR)/symbols.syms

#
# Common flag configs
#

ifeq ($(OPENJKDF2_USE_BLOBS), 1)
	OPENJKDF2_NO_ASAN := 1
endif

# 64-bit cannot use JK.EXE as a binary blob
ifneq ($(OPENJKDF2_NO_ASAN), 1)
ifneq ($(OPENJKDF2_USE_BLOBS), 1)
	CFLAGS += -fsanitize=address -fsanitize=float-divide-by-zero
	LDFLAGS += -fsanitize=address -fsanitize=float-divide-by-zero -static-libsan

#	CFLAGS += -fsanitize=leak
#	LDFLAGS += -fsanitize=leak
endif
endif

ifeq ($(DEBUG_QOL_CHEATS), 1)
	CFLAGS += -DDEBUG_QOL_CHEATS
endif

#
# Common pre-build steps
#
.PHONY: initial all

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

initial: $(FLEX_BIN) $(YACC_BIN)
	@echo Generating COG lex/yacc...
	cd $(SRC)/Cog && $(FLEX_BIN) -i cog.l
	cd $(SRC)/Cog && $(YACC_BIN) -d cog.y
	@echo Generating globals...
	cog -d -D symbols_fpath="$(SYMBOLS_FILE)" $(GLOBALS_H_COG) > $(GLOBALS_H)
	cog -d -D symbols_fpath="$(SYMBOLS_FILE)" $(GLOBALS_C_COG) > $(GLOBALS_C)

$(OBJ): | initial $(SRC)/Cog/lex.yy.c $(SRC)/Cog/y.tab.c
	@mkdir -p $(OBJ)

$(FLEX_BIN): | clean_cog
	cd $(ROOT_DIR)/flex && make

$(YACC_BIN): | clean_cog $(FLEX_BIN)
	cd $(ROOT_DIR)/byacc && make