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

extern SDL_Window* displayWindow;
extern SDL_Renderer* displayRenderer;
extern SDL_RendererInfo displayRendererInfo;
extern SDL_Event event;
extern ImGuiIO io;

#endif // MAIN_H
