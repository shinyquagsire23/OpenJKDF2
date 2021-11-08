CC := i686-w64-mingw32-gcc
TARGET := df2_reimpl_kvm.dll
TARGET_WIN := df2_reimpl.dll

SRC := src
OBJ := build

SOURCES := $(wildcard $(SRC)/*.c $(SRC)/*/*.c) #$(SRC)/Cog/lex.yy.c $(SRC)/Cog/y.tab.c
OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES))
ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

CFLAGS := -I$(ROOT_DIR)/$(SRC) -I$(ROOT_DIR)/$(SRC)/external/libsmacker -DQOL_IMPROVEMENTS -DWIN32 -DARCH_X86 -DTARGET_HAS_DPLAY -Wuninitialized -fno-trapping-math

all: $(TARGET) $(TARGET_WIN)
include common.mk

$(OBJ)/%.o: $(SRC)/%.c | $(OBJ) initial
	@mkdir -p $(dir $@)
	$(CC) -c -g -o $@ $< $(CFLAGS)

$(TARGET_WIN): $(OBJECTS)
	$(CC) -o $@ -g -shared $^ -Wl,--subsystem,windows -Wl,-Map=output.map -static-libgcc -fno-trapping-math

$(TARGET): $(OBJECTS)
	$(CC) -o $@ -g -shared $^ -Wl,--subsystem,windows -Wl,-Map=output.map -Wl,-e_hook_init -nostartfiles -static -static-libgcc -static-libstdc++ -fno-trapping-math
