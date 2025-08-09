#ifndef _OPENJKDF2_SDL2_HELPER_H
#define _OPENJKDF2_SDL2_HELPER_H

#ifdef SDL2_RENDER
//#ifndef ARCH_WASM

#ifdef MACOS
#define GL_SILENCE_DEPRECATION
#include <SDL.h>
#include <GL/glew.h>
#include <OpenGL/gl.h>
#elif defined(ARCH_WASM)

// emscripten.h doesn't like extern C
#ifdef __cplusplus
//}
#endif
#include <emscripten.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <SDL.h>
#define GL_GLEXT_PROTOTYPES 1
#include <SDL_opengles2.h>
#include <GLES3/gl3.h>
#include <GLES3/gl2ext.h>

//HACK
#define GL_UNSIGNED_SHORT_5_6_5_REV       0x8364
#define GL_UNSIGNED_SHORT_1_5_5_5_REV     0x8366

// emscripten.h doesn't like extern C
#ifdef __cplusplus
}
#endif
#elif defined(TARGET_ANDROID)
#include <SDL.h>
#include <SDL_opengles2.h>
#include <GLES3/gl3.h>
#include <GLES3/gl3ext.h>
#define GL_UNSIGNED_SHORT_5_6_5_REV       0x8364
#define GL_UNSIGNED_SHORT_1_5_5_5_REV     0x8366
#include <SDL_main.h>
#include <android/log.h>

#define TAG "OpenJKDF2"

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,    TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,     TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,     TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,    TAG, __VA_ARGS__)

// TODO why?
#ifndef GL_BGRA
#define GL_BGRA 0x80E1
#endif

#ifndef GL_BGR
#define GL_BGR 0x80E0
#endif

#elif defined(TARGET_SWITCH)
#include <SDL2/SDL.h>
#include <SDL2/SDL_opengles2.h>
#include <GLES3/gl3.h>
#include <GLES3/gl3ext.h>
#else


#include <GL/glew.h>
#include <SDL.h>
#include <GL/gl.h>
#endif // MACOS ... else

#ifdef WIN32
#define GL_R8 GL_RED
#endif // WIN32

//#endif // !ARCH_WASM
#endif // SDL2_RENDER




#endif // _OPENJKDF2_SDL2_HELPER_H