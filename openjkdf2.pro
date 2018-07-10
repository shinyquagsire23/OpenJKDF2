CONFIG += debug
LIBS += -lunicorn -lpthread  -lstdc++fs
HEADERS += main.h uc_utils.h loaders/exe.h dlls/kernel32.h dlls/user32.h dlls/gdi32.h dlls/comctl32.h dlls/advapi32.h dlls/ole32.h dlls/ddraw.h dlls/dplay/IDirectPlay3.h dlls/dsound/IDirectSound.h dlls/dsound/dsound.h dlls/nmm.h dlls/dinput/dinput.h dlls/dinput/IDirectInputA.h
SOURCES += main.cpp uc_utils.cpp loaders/exe.cpp dlls/kernel32.cpp dlls/user32.cpp dlls/gdi32.cpp dlls/comctl32.cpp dlls/advapi32.cpp dlls/ole32.cpp dlls/ddraw.cpp dlls/winutils.cpp dlls/dplay/IDirectPlay3.cpp dlls/dsound/IDirectSound.cpp dlls/dsound/dsound.cpp dlls/dinput/IDirectInputA.cpp
