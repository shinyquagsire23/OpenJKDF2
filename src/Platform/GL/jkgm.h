#ifndef _PLATFORM_GL_JKGM_H
#define _PLATFORM_GL_JKGM_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

void* jkgm_alloc_aligned(size_t amt);
void jkgm_aligned_free(void* p);

#ifdef SDL2_RENDER
#ifndef ARCH_WASM

#ifdef MACOS
#define GL_SILENCE_DEPRECATION
#include <SDL.h>
#include <OpenGL/gl.h>
#elif defined(ARCH_WASM)
#ifdef __cplusplus
}
#endif
#include <emscripten.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <SDL.h>
#include <SDL_opengles2.h>
#else
#include <GL/glew.h>
#include <SDL.h>
#include <GL/gl.h>
#endif

void jkgm_startup();
void jkgm_populate_cache();
void jkgm_populate_shortcuts(stdVBuffer *vbuf, rdDDrawSurface *texture, rdMaterial* material, int is_alpha_tex, int mipmap_level, int cel);
int jkgm_std3D_AddToTextureCache(stdVBuffer *vbuf, rdDDrawSurface *texture, int is_alpha_tex, int no_alpha, rdMaterial* material, int cel);
void jkgm_free_cache_entry(jkgm_cache_entry_t* entry);
void jkgm_write_png(const char *pFname, int width, int height, uint8_t* paFramebuffer);

#endif // ARCH_WASM
#endif //SDL2_RENDER

#ifdef __cplusplus
}
#endif

#endif // _PLATFORM_GL_JKGM_H