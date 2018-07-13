CONFIG += debug
LIBS += -lunicorn -lpthread  -lstdc++fs -lSDL2
HEADERS += main.h uc_utils.h loaders/exe.h dlls/kernel32.h dlls/user32.h dlls/gdi32.h dlls/comctl32.h dlls/advapi32.h dlls/ole32.h dlls/ddraw.h dlls/dplay/IDirectPlay3.h dlls/dsound/IDirectSound.h dlls/dsound/dsound.h dlls/nmm.h dlls/dinput/dinput.h dlls/dinput/IDirectInputA.h dlls/dplay/dplay.h dlls/dplay/IDirectPlayLobby3.h dlls/smackw32.h
SOURCES += main.cpp uc_utils.cpp loaders/exe.cpp dlls/kernel32.cpp dlls/user32.cpp dlls/gdi32.cpp dlls/comctl32.cpp dlls/advapi32.cpp dlls/ole32.cpp dlls/ddraw.cpp dlls/winutils.cpp dlls/dplay/IDirectPlay3.cpp dlls/dsound/IDirectSound.cpp dlls/dsound/dsound.cpp dlls/dinput/IDirectInputA.cpp dlls/dplay/dplay.cpp dlls/dplay/IDirectPlayLobby3.cpp dlls/smackw32.cpp
CFLAGS += -Wno-unused-parameter
CXXFLAGS += -Wno-unused-parameter
