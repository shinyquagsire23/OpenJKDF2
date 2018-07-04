CONFIG += debug
LIBS += -lunicorn -lpthread  -lstdc++fs
HEADERS += main.h dlls/kernel32.h dlls/user32.h dlls/gdi32.h dlls/comctl32.h dlls/advapi32.h dlls/ole32.h dlls/ddraw.h
SOURCES += main.cpp dlls/kernel32.cpp dlls/user32.cpp dlls/gdi32.cpp dlls/comctl32.cpp dlls/advapi32.cpp dlls/ole32.cpp dlls/ddraw.cpp
