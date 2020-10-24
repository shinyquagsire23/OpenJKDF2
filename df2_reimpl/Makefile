CC := i686-w64-mingw32-gcc
TARGET := df2_reimpl.dll

SRC := src
OBJ := build

SOURCES := $(wildcard $(SRC)/*.c $(SRC)/*/*.c) $(SRC)/Cog/lex.yy.c $(SRC)/Cog/y.tab.c
OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES))
ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

CFLAGS := -I$(ROOT_DIR)/$(SRC)

FLEX_BIN := $(ROOT_DIR)/flex/flex
YACC_BIN := $(ROOT_DIR)/byacc/yacc

#CFLAGS=

all: $(OBJ) $(TARGET)
clean:
	rm -rf $(OBJ)
	rm -f $(TARGET)
	rm $(SRC)/Cog/lex.yy.c $(SRC)/Cog/y.tab.c

$(OBJ):
	@mkdir -p $(OBJ)

$(FLEX_BIN):
	cd $(ROOT_DIR)/flex && make

$(YACC_BIN):
	cd $(ROOT_DIR)/byacc && make

$(SRC)/Cog/lex.yy.c : $(FLEX_BIN) $(SRC)/Cog/cog.l
	cd $(SRC)/Cog && $(FLEX_BIN) -i cog.l

$(SRC)/Cog/y.tab.c : $(YACC_BIN) $(SRC)/Cog/cog.y
	cd $(SRC)/Cog && $(YACC_BIN) -d cog.y

$(OBJ)/%.o: $(SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ -s -shared $^ -Wl,--subsystem,windows -Wl,-Map=output.map -Wl,-e_hook_init -nostartfiles
