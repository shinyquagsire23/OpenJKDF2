ifeq ($(OS),Windows_NT)
	PREFIX ?=
	RM = del
else
	PREFIX ?= i686-w64-mingw32-
endif


CC = $(PREFIX)gcc
CXX = $(PREFIX)g++

CFLAGS = -g
CXXFLAGS = $(CFLAGS)

INCLUDES = -I$(CURDIR)/../include

LDFLAGS = -static-libgcc -static-libstdc++ -L$(CURDIR)/../lib
LIBS = -lexchndl


all: sample.exe

sample.exe: sample.cpp

%.exe: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	-$(RM) sample.exe

.PHONE: all clean
