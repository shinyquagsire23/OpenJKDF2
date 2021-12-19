SRC := src

SOURCES := $(wildcard $(SRC)/*.c $(SRC)/*/*.c) #$(SRC)/Cog/lex.yy.c $(SRC)/Cog/y.tab.c
SOURCES_CXX := $(wildcard $(SRC)/*.cpp $(SRC)/*/*.cpp)
SOURCES_M := $(wildcard $(SRC)/*.m $(SRC)/*/*.m)

SOURCES += $(wildcard $(SRC)/Platform/Common/*.c)
SOURCES_CXX += $(wildcard $(SRC)/Platform/Common/*.cpp)

ifeq ($(TARGET_USE_LIBSMACKER), 1)
	SOURCES += $(SRC)/external/libsmacker/smacker.c $(SRC)/external/libsmacker/smk_bitstream.c $(SRC)/external/libsmacker/smk_hufftree.c
endif

ifeq ($(TARGET_USE_SDL2), 1)
	SOURCES += $(wildcard $(SRC)/Platform/SDL2/*.c)
endif

ifeq ($(TARGET_USE_OPENGL), 1)
	SOURCES += $(wildcard $(SRC)/Platform/GL/*.c)
endif

ifeq ($(TARGET_USE_D3D), 1)
	SOURCES += $(wildcard $(SRC)/Platform/D3D/*.c)
endif

ifeq ($(TARGET_POSIX), 1)
	SOURCES += $(wildcard $(SRC)/Platform/Posix/*.c)
endif

ifeq ($(TARGET_LINUX), 1)
	SOURCES_CXX += $(wildcard $(SRC)/external/nativefiledialog-extended/nfd_gtk.cpp)
endif

ifeq ($(TARGET_MACOS), 1)
	SOURCES += $(wildcard $(SRC)/external/nativefiledialog-extended/nfd_cocoa.m)
endif

ifeq ($(TARGET_WIN32), 1)
	SOURCES += $(wildcard $(SRC)/Platform/Win32/*.c)

	# Win64 can use the registry fine, even if stdlib is POSIX
	SOURCES := $(filter-out $(SRC)/Platform/Posix/wuRegistry.c, $(SOURCES))

	SOURCES_CXX += $(wildcard $(SRC)/external/nativefiledialog-extended/nfd_win.cpp)
	LDFLAGS += -lole32 -luuid
endif

CFLAGS += -I$(SRC)/external/nativefiledialog-extended
#LDFLAGS += -I$(SRC)/external/nativefiledialog-extended

SOURCES += $(SRC)/external/fcaseopen/fcaseopen.c
OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES))
OBJECTS += $(patsubst $(SRC)/%.cpp, $(OBJ)/%.o, $(SOURCES_CXX))
OBJECTS += $(patsubst $(SRC)/%.m, $(OBJ)/%.o, $(SOURCES_M))
ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
