#ifndef _PLATFORM_GL_JKGM_H
#define _PLATFORM_GL_JKGM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SDL2_RENDER

#include "types.h"

#ifdef MACOS
#define GL_SILENCE_DEPRECATION
#include <SDL.h>
#include <OpenGL/gl.h>
#elif defined(ARCH_WASM)
#include <emscripten.h>
#include <SDL.h>
#include <SDL_opengles2.h>
#else
#include <GL/glew.h>
#include <SDL.h>
#include <GL/gl.h>
#endif

int jkgm_std3D_AddToTextureCache(stdVBuffer *vbuf, rdDDrawSurface *texture, int is_alpha_tex, int no_alpha, rdMaterial* material, int cel);
void* jkgm_alloc_aligned(size_t amt);

#endif //SDL2_RENDER

#ifdef __cplusplus
}
#endif

#endif // _PLATFORM_GL_JKGM_H