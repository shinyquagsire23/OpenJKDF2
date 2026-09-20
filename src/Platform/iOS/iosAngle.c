// See iosAngle.h for why iOS does not use SDL_GL_*.

#include "Platform/iOS/iosAngle.h"

#ifdef TARGET_IOS

#include <stdio.h>
#include <string.h>

#include <SDL.h>
#include <SDL_metal.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>

#include "stdPlatform.h"

static SDL_MetalView iosAngle_metalView = NULL;
static EGLDisplay    iosAngle_display   = EGL_NO_DISPLAY;
static EGLSurface    iosAngle_surface   = EGL_NO_SURFACE;
static EGLContext    iosAngle_context   = EGL_NO_CONTEXT;
static char          iosAngle_errorMsg[256] = {0};

static int iosAngle_Fail(const char* pWhat)
{
    snprintf(iosAngle_errorMsg, sizeof(iosAngle_errorMsg), "%s (EGL error 0x%04x)", pWhat, (unsigned)eglGetError());
    stdPlatform_Printf("iosAngle: %s\n", iosAngle_errorMsg);
    return 0;
}

const char* iosAngle_GetError(void)
{
    return iosAngle_errorMsg;
}

// ANGLE picks a backend per-display rather than per-build, so ask explicitly for
// Metal. The generic eglGetDisplay(EGL_DEFAULT_DISPLAY) would also land on Metal
// on Apple platforms today, but only by default-ordering -- naming it means a
// future ANGLE that prefers something else here still does what we tested.
static EGLDisplay iosAngle_GetMetalDisplay(void)
{
    PFNEGLGETPLATFORMDISPLAYEXTPROC pGetPlatformDisplayEXT =
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");

    if (pGetPlatformDisplayEXT) {
        const EGLint aDisplayAttribs[] = {
            EGL_PLATFORM_ANGLE_TYPE_ANGLE, EGL_PLATFORM_ANGLE_TYPE_METAL_ANGLE,
            EGL_NONE
        };
        EGLDisplay display = pGetPlatformDisplayEXT(EGL_PLATFORM_ANGLE_ANGLE, EGL_DEFAULT_DISPLAY, aDisplayAttribs);
        if (display != EGL_NO_DISPLAY) {
            return display;
        }
        stdPlatform_Printf("iosAngle: Metal platform display unavailable, falling back to the default display\n");
    }

    return eglGetDisplay(EGL_DEFAULT_DISPLAY);
}

int iosAngle_CreateContext(SDL_Window* pWindow)
{
    iosAngle_errorMsg[0] = 0;

    if (iosAngle_context != EGL_NO_CONTEXT) {
        iosAngle_DestroyContext();
    }

    // SDL3 hands out a UIView whose backing layer is a CAMetalLayer, already
    // sized and content-scaled for the window (SDL_WINDOW_HIGH_PIXEL_DENSITY is
    // honoured here). ANGLE's Metal backend takes any CALayer as its
    // EGLNativeWindowType and uses a CAMetalLayer as-is, so this is a direct handoff
    // with no intermediate blit -- the game renders into the layer the compositor
    // shows.
    iosAngle_metalView = SDL_Metal_CreateView(pWindow);
    if (!iosAngle_metalView) {
        snprintf(iosAngle_errorMsg, sizeof(iosAngle_errorMsg), "SDL_Metal_CreateView failed: %s", SDL_GetError());
        stdPlatform_Printf("iosAngle: %s\n", iosAngle_errorMsg);
        return 0;
    }

    void* pLayer = SDL_Metal_GetLayer(iosAngle_metalView);
    if (!pLayer) {
        snprintf(iosAngle_errorMsg, sizeof(iosAngle_errorMsg), "SDL_Metal_GetLayer failed: %s", SDL_GetError());
        stdPlatform_Printf("iosAngle: %s\n", iosAngle_errorMsg);
        goto fail;
    }

    iosAngle_display = iosAngle_GetMetalDisplay();
    if (iosAngle_display == EGL_NO_DISPLAY) {
        iosAngle_Fail("eglGetDisplay failed");
        goto fail;
    }

    EGLint eglMajor = 0, eglMinor = 0;
    if (!eglInitialize(iosAngle_display, &eglMajor, &eglMinor)) {
        iosAngle_Fail("eglInitialize failed");
        goto fail;
    }
    stdPlatform_Printf("iosAngle: EGL %d.%d, %s\n", eglMajor, eglMinor, eglQueryString(iosAngle_display, EGL_VENDOR));

    // Matches what the engine asks SDL for elsewhere: 8888 colour, 24-bit depth,
    // 8-bit stencil, no multisampling.
    const EGLint aConfigAttribs[] = {
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT,
        EGL_SURFACE_TYPE,    EGL_WINDOW_BIT,
        EGL_RED_SIZE,        8,
        EGL_GREEN_SIZE,      8,
        EGL_BLUE_SIZE,       8,
        EGL_ALPHA_SIZE,      8,
        EGL_DEPTH_SIZE,      24,
        EGL_STENCIL_SIZE,    8,
        EGL_NONE
    };

    EGLConfig config = NULL;
    EGLint numConfigs = 0;
    if (!eglChooseConfig(iosAngle_display, aConfigAttribs, &config, 1, &numConfigs) || numConfigs < 1) {
        iosAngle_Fail("eglChooseConfig found no GLES3 config");
        goto fail;
    }

    iosAngle_surface = eglCreateWindowSurface(iosAngle_display, config, (EGLNativeWindowType)pLayer, NULL);
    if (iosAngle_surface == EGL_NO_SURFACE) {
        iosAngle_Fail("eglCreateWindowSurface failed");
        goto fail;
    }

    const EGLint aContextAttribs[] = {
        EGL_CONTEXT_MAJOR_VERSION, 3,
        EGL_CONTEXT_MINOR_VERSION, 0,
        EGL_NONE
    };
    iosAngle_context = eglCreateContext(iosAngle_display, config, EGL_NO_CONTEXT, aContextAttribs);
    if (iosAngle_context == EGL_NO_CONTEXT) {
        iosAngle_Fail("eglCreateContext failed");
        goto fail;
    }

    if (!eglMakeCurrent(iosAngle_display, iosAngle_surface, iosAngle_surface, iosAngle_context)) {
        iosAngle_Fail("eglMakeCurrent failed");
        goto fail;
    }

    stdPlatform_Printf("iosAngle: %s / %s\n",
                       (const char*)glGetString(GL_RENDERER),
                       (const char*)glGetString(GL_VERSION));
    return 1;

fail:
    iosAngle_DestroyContext();
    return 0;
}

void iosAngle_DestroyContext(void)
{
    if (iosAngle_display != EGL_NO_DISPLAY) {
        eglMakeCurrent(iosAngle_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);

        if (iosAngle_context != EGL_NO_CONTEXT) {
            eglDestroyContext(iosAngle_display, iosAngle_context);
        }
        if (iosAngle_surface != EGL_NO_SURFACE) {
            eglDestroySurface(iosAngle_display, iosAngle_surface);
        }
        eglTerminate(iosAngle_display);
    }

    iosAngle_context = EGL_NO_CONTEXT;
    iosAngle_surface = EGL_NO_SURFACE;
    iosAngle_display = EGL_NO_DISPLAY;

    // The view has to outlive the surface that draws into its layer, so it goes last.
    if (iosAngle_metalView) {
        SDL_Metal_DestroyView(iosAngle_metalView);
        iosAngle_metalView = NULL;
    }
}

void iosAngle_SwapBuffers(void)
{
    if (iosAngle_display == EGL_NO_DISPLAY || iosAngle_surface == EGL_NO_SURFACE) {
        return;
    }
    eglSwapBuffers(iosAngle_display, iosAngle_surface);
}

void iosAngle_SetSwapInterval(int interval)
{
    if (iosAngle_display == EGL_NO_DISPLAY) {
        return;
    }
    eglSwapInterval(iosAngle_display, interval ? 1 : 0);
}

#endif // TARGET_IOS
