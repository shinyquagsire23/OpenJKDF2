#ifndef MAIN_H
#define MAIN_H

#include <unicorn/unicorn.h>
#include <stdint.h>

#include <QMetaMethod>

#include <map>
#include <string>
#include <vector>

#include <SDL2/SDL.h>
#include "3rdparty/imgui/imgui.h"

#include "vm.h"

extern std::map<std::string, ImportTracker*> import_store;
extern std::map<std::string, QObject*> interface_store;

extern SDL_Window* displayWindow;
extern SDL_Renderer* displayRenderer;
extern SDL_RendererInfo displayRendererInfo;
extern SDL_Event event;
extern ImGuiIO io;

uint32_t import_get_hook_addr(std::string dll, std::string name);
void register_hook(std::string dll, std::string name, uint32_t hook_addr);
void register_import(std::string dll, std::string name, uint32_t import_addr);

#endif // MAIN_H
