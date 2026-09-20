#ifndef _OPENJKDF2_IOS_ANGLE_H
#define _OPENJKDF2_IOS_ANGLE_H

// iOS renders GLES3 through ANGLE (Metal backend) instead of through
// SDL's GL context. SDL3's UIKit video backend only knows EAGL -- Apple's
// deprecated in-OS GLES -- and offers no EGL at all, so the engine would have
// had to be ported off GLSL ES entirely. Driving ANGLE directly keeps
// resource/shaders/*.glsl byte-for-byte identical to the Android/WASM path:
// ANGLE compiles the same `#version 300 es` sources to MSL at runtime.
//
// SDL still owns the window, events, audio and gamepads; only the GL context,
// the drawable and the present belong to this file. Everything here is a
// drop-in for the SDL_GL_* call it replaces (see src/Win95/Window.c).

#ifdef TARGET_IOS

#include <stdint.h>

typedef struct SDL_Window SDL_Window;

// Creates the CAMetalLayer-backed EGL surface + GLES3 context for pWindow and
// makes it current. Returns 1 on success, 0 on failure (see iosAngle_GetError).
int iosAngle_CreateContext(SDL_Window* pWindow);

// Tears down surface/context/display and the SDL metal view, in that order.
void iosAngle_DestroyContext(void);

// eglSwapBuffers; no-op if there is no current surface.
void iosAngle_SwapBuffers(void);

// eglSwapInterval. 0 = tear, 1 = vsync. iOS always composites on vsync, so 0
// only means "don't block", it can't actually tear.
void iosAngle_SetSwapInterval(int interval);

// NOTE: there is deliberately no drawable-size accessor here. SDL sizes the
// metal view's CAMetalLayer itself (window bounds x nativeScale, since the window
// is created SDL_WINDOW_HIGH_PIXEL_DENSITY) and ANGLE renders into that same
// layer, so SDL_GetWindowSizeInPixels() in Window.c is already the drawable size
// -- and unlike eglQuerySurface it cannot lag a frame behind a layer resize.

// Human-readable reason the last call failed, or "" if there wasn't one.
const char* iosAngle_GetError(void);

#endif // TARGET_IOS

#endif // _OPENJKDF2_IOS_ANGLE_H
