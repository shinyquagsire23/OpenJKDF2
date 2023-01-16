#ifndef _JKGUI_MODS_H
#define _JKGUI_MODS_H

#include "types.h"

#if defined(PLATFORM_POSIX)
#include <locale.h>
#endif

#if defined(SDL2_RENDER)
#include <SDL.h>
#ifndef _WIN32
#include <unistd.h>
#endif // _WIN32
#include <sys/types.h>
#include <stdbool.h>
#if defined(LINUX) || defined(MACOS)
#include <pwd.h>
#endif // defined(LINUX) || defined(MACOS)
#include "nfd.h"
#endif // defined(SDL2_RENDER)

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

void jkGuiMods_Startup();
void jkGuiMods_Shutdown();

void jkGuiMods_Show();
void jkGuiMods_PopulateEntries(Darray *list, jkGuiElement *element);

#endif // _JKGUI_MODS_H