#ifndef _JKGUI_MODS_H
#define _JKGUI_MODS_H

#include "types.h"

#if defined(PLATFORM_POSIX)
#include <locale.h>
#endif

#include "SDL2_helper.h"

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

void jkGuiMods_Startup();
void jkGuiMods_Shutdown();

void jkGuiMods_Show();
void jkGuiMods_PopulateEntries(Darray *pListDisplayed, jkGuiElement *element);

#endif // _JKGUI_MODS_H