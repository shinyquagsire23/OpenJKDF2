#ifndef OPENJKDF2_CAPTURE_UI_H
#define OPENJKDF2_CAPTURE_UI_H
// Include after SDL declarations. Keep capture policy at every desktop API call,
// including error paths and window recreation, rather than relying on focus.
#include "Main/stdCapture.h"
#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif
extern int Window_bRenderProbe;
#ifdef __cplusplus
}
#endif
static inline int stdCapture_UiSuppressed(void) {
    return stdCapture_IsRequested() || Window_bRenderProbe;
}
static inline bool capture_MessageBox(SDL_MessageBoxFlags flags, const char* title, const char* text, SDL_Window* window) {
    if (stdCapture_UiSuppressed()) { fprintf(stderr, "%s: %s\n", title, text); return false; }
    return SDL_ShowSimpleMessageBox(flags, title, text, window);
}
#define SDL_ShowSimpleMessageBox capture_MessageBox
#define SDL_RaiseWindow(w) (stdCapture_UiSuppressed() ? false : SDL_RaiseWindow(w))
#define SDL_SetWindowFullscreen(w,f) (stdCapture_UiSuppressed() ? false : SDL_SetWindowFullscreen(w,f))
#define SDL_SetWindowRelativeMouseMode(w,f) (stdCapture_UiSuppressed() ? false : SDL_SetWindowRelativeMouseMode(w,f))
#define SDL_StartTextInput(w) (stdCapture_UiSuppressed() ? false : SDL_StartTextInput(w))
#define SDL_WarpMouseInWindow(w,x,y) (stdCapture_UiSuppressed() ? (void)0 : SDL_WarpMouseInWindow(w,x,y))
#define SDL_ShowCursor() (stdCapture_UiSuppressed() ? false : SDL_ShowCursor())
#define SDL_HideCursor() (stdCapture_UiSuppressed() ? false : SDL_HideCursor())
#define SDL_OpenURL(url) (stdCapture_UiSuppressed() ? false : SDL_OpenURL(url))
#define SDL_CreateWindow(title,w,h,flags) SDL_CreateWindow(title,w,h,stdCapture_UiSuppressed() ? (((flags) | SDL_WINDOW_HIDDEN | SDL_WINDOW_NOT_FOCUSABLE) & ~(SDL_WINDOW_FULLSCREEN | SDL_WINDOW_KEYBOARD_GRABBED | SDL_WINDOW_MOUSE_GRABBED)) : (flags))
#endif
