SRC := src

SOURCES := $(wildcard $(SRC)/*.c $(SRC)/*/*.c) #$(SRC)/Cog/lex.yy.c $(SRC)/Cog/y.tab.c

SOURCES += $(wildcard $(SRC)/Platform/Common/*.c)

ifeq ($(TARGET_USE_LIBSMACKER), 1)
	SOURCES += $(SRC)/external/libsmacker/smacker.c $(SRC)/external/libsmacker/smk_bitstream.c $(SRC)/external/libsmacker/smk_hufftree.c
endif

ifeq ($(TARGET_USE_SDL2), 1)
	SOURCES += $(wildcard $(SRC)/Platform/SDL2/*.c)
endif

SOURCES += $(SRC)/external/fcaseopen/fcaseopen.c
OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES))
ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))