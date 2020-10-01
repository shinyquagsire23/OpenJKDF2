#ifndef RENDERER_H
#define RENDERER_H

#include <string>

#include <GL/glew.h>
#include <SDL2/SDL.h>
#include "3rdparty/imgui/imgui.h"

int renderer_spawnthread(SDL_Window* window, SDL_Renderer* renderer, SDL_GLContext context);
int renderer_jointhread();

void renderer_feedwindowinfo(std::string title, GLint texID, GLint palTexID, ImVec2 dims, void (*onTexDestroy)(void*), void (*onVblank)(void*), void* destroyExtra);
void renderer_waitforvblank();
void renderer_print(std::string new_line);

#endif // RENDERER_H
