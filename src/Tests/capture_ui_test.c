// No SDL or window system is linked. Check the production wrapper policies.
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
typedef int SDL_MessageBoxFlags;
typedef struct SDL_Window { int flags; } SDL_Window;
enum { SDL_WINDOW_HIDDEN=1, SDL_WINDOW_NOT_FOCUSABLE=2, SDL_WINDOW_FULLSCREEN=4,
    SDL_WINDOW_KEYBOARD_GRABBED=8, SDL_WINDOW_MOUSE_GRABBED=16 };
static int requested, calls;
int Window_bRenderProbe;
static SDL_Window window;
int stdCapture_IsRequested(void) { return requested; }
static bool SDL_ShowSimpleMessageBox(int f,const char* t,const char* x,SDL_Window* w) { (void)f;(void)t;(void)x;(void)w;calls++;return true; }
static bool SDL_RaiseWindow(SDL_Window* w) { (void)w;calls++;return true; }
static bool SDL_SetWindowFullscreen(SDL_Window* w,bool f) { (void)w;(void)f;calls++;return true; }
static bool SDL_SetWindowRelativeMouseMode(SDL_Window* w,bool f) { (void)w;(void)f;calls++;return true; }
static bool SDL_StartTextInput(SDL_Window* w) { (void)w;calls++;return true; }
static void SDL_WarpMouseInWindow(SDL_Window* w,float x,float y) { (void)w;(void)x;(void)y;calls++; }
static bool SDL_ShowCursor(void) { calls++;return true; }
static bool SDL_HideCursor(void) { calls++;return true; }
static bool SDL_OpenURL(const char* u) { (void)u;calls++;return true; }
static SDL_Window* SDL_CreateWindow(const char* t,int w,int h,int f) { (void)t;(void)w;(void)h;calls++;window.flags=f;return &window; }
#include "Platform/SDL2/stdCaptureUi.h"
static void actions(void) {
    SDL_ShowSimpleMessageBox(0,"test","expected diagnostic",&window);
    SDL_RaiseWindow(&window); SDL_SetWindowFullscreen(&window,true);
    SDL_SetWindowRelativeMouseMode(&window,true); SDL_StartTextInput(&window);
    SDL_WarpMouseInWindow(&window,1,2); SDL_ShowCursor(); SDL_HideCursor(); SDL_OpenURL("test:");
}
int main(void) {
    actions(); assert(calls == 9);
    requested = 1; actions(); assert(calls == 9);
    requested = 0; Window_bRenderProbe = 1; actions(); assert(calls == 9);
    SDL_CreateWindow("probe",64,64,SDL_WINDOW_FULLSCREEN|SDL_WINDOW_KEYBOARD_GRABBED|SDL_WINDOW_MOUSE_GRABBED);
    assert(calls == 10); assert(window.flags == (SDL_WINDOW_HIDDEN|SDL_WINDOW_NOT_FOCUSABLE));
    requested = 1; Window_bRenderProbe = 0;
    SDL_CreateWindow("capture",64,64,SDL_WINDOW_FULLSCREEN|SDL_WINDOW_KEYBOARD_GRABBED|SDL_WINDOW_MOUSE_GRABBED);
    assert(calls == 11); assert(window.flags == (SDL_WINDOW_HIDDEN|SDL_WINDOW_NOT_FOCUSABLE));
    requested = 0; SDL_CreateWindow("regular",64,64,SDL_WINDOW_FULLSCREEN);
    assert(calls == 12 && window.flags == SDL_WINDOW_FULLSCREEN);
    puts("capture and render-probe UI wrapper tests passed; no window system linked");
}
