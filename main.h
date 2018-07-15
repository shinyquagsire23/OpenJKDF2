#ifndef MAIN_H
#define MAIN_H

#include <unicorn/unicorn.h>
#include <stdint.h>

#include <QMetaMethod>

#include <map>
#include <string>
#include <vector>

#include "dlls/kernel32.h"
#include "dlls/user32.h"
#include "dlls/gdi32.h"
#include "dlls/comctl32.h"
#include "dlls/advapi32.h"
#include "dlls/ole32.h"
#include "dlls/nmm.h"
#include "dlls/ddraw.h"
#include "dlls/dsound/dsound.h"
#include "dlls/dplay/dplay.h"
#include "dlls/dinput/dinput.h"
#include "dlls/dplay/IDirectPlay3.h"
#include "dlls/dplay/IDirectPlayLobby3.h"
#include "dlls/dsound/IDirectSound.h"
#include "dlls/dsound/IDirectSoundBuffer.h"
#include "dlls/dinput/IDirectInputA.h"
#include "dlls/dinput/IDirectInputDeviceA.h"
#include "dlls/smackw32.h"

#include <SDL2/SDL.h>

#include "vm.h"

extern std::map<std::string, ImportTracker*> import_store;
extern std::map<std::string, QObject*> interface_store;

extern ComCtl32 *comctl32;
extern AdvApi32 *advapi32;
extern Ole32 *ole32;
extern DDraw *ddraw;
extern IDirectPlay3 *idirectplay3;
extern IDirectSound* idirectsound;
extern IDirectInputA* idirectinputa;
extern DSound* dsound;
extern DInput* dinput;

extern SDL_Window* displayWindow;
extern SDL_Renderer* displayRenderer;
extern SDL_RendererInfo displayRendererInfo;
extern SDL_Event event;

void *uc_ptr_to_real_ptr(uint32_t uc_ptr);
uint32_t real_ptr_to_uc_ptr(void* real_ptr);
uint32_t import_get_hook_addr(std::string name);
void register_import(std::string dll, std::string name, uint32_t import_addr);

#endif // MAIN_H
