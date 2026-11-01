// Real OpenGL byte-readback regression. Synthetic pixels only; no game assets.
// Uses an isolated EGL surfaceless pbuffer, never an application window.
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GL/gl.h>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>
#include "Platform/GL/jkgm_pixel_unpack.hpp"
#include "Platform/GL/jkgm_texture_upload.hpp"

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
const std::array<GLenum, 4> unpack_names = {
    GL_UNPACK_ALIGNMENT, GL_UNPACK_ROW_LENGTH,
    GL_UNPACK_SKIP_PIXELS, GL_UNPACK_SKIP_ROWS};
std::array<GLint, 4> state() {
    std::array<GLint, 4> result{};
    for (std::size_t i=0; i<result.size(); ++i) glGetIntegerv(unpack_names[i], &result[i]);
    return result;
}
void set_state(const std::array<GLint, 4>& values) {
    for (std::size_t i=0; i<values.size(); ++i) glPixelStorei(unpack_names[i], values[i]);
}
void early_return() { const JkgmScopedPixelUnpack guard; }
std::vector<unsigned char> pixels(int width, int height, int channels) {
    std::vector<unsigned char> result(static_cast<std::size_t>(width*height*channels));
    for (int y=0; y<height; ++y)
        for (int x=0; x<width; ++x)
            for (int c=0; c<channels; ++c)
                result[static_cast<std::size_t>((y*width+x)*channels+c)] =
                    static_cast<unsigned char>((x*17+y*43+c*79)%256);
    return result;
}
}

int main() {
    EGLDisplay display = eglGetPlatformDisplay(EGL_PLATFORM_SURFACELESS_MESA, nullptr, nullptr);
    require(display != EGL_NO_DISPLAY, "No isolated surfaceless EGL display");
    EGLint major=0, minor=0;
    require(eglInitialize(display,&major,&minor), "EGL initialization failed");
    require(eglBindAPI(EGL_OPENGL_API), "Desktop OpenGL API unavailable");
    const EGLint config_args[] = {EGL_SURFACE_TYPE,EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE,EGL_OPENGL_BIT,EGL_RED_SIZE,8,EGL_GREEN_SIZE,8,
        EGL_BLUE_SIZE,8,EGL_NONE};
    EGLConfig config{}; EGLint count=0;
    require(eglChooseConfig(display,config_args,&config,1,&count) && count==1, "No EGL config");
    const EGLint pbuffer_args[] = {EGL_WIDTH,1,EGL_HEIGHT,1,EGL_NONE};
    EGLSurface surface=eglCreatePbufferSurface(display,config,pbuffer_args);
    require(surface!=EGL_NO_SURFACE, "Pbuffer creation failed");
    EGLContext context=eglCreateContext(display,config,EGL_NO_CONTEXT,nullptr);
    require(context!=EGL_NO_CONTEXT, "OpenGL context creation failed");
    require(eglMakeCurrent(display,surface,surface,context), "Cannot bind private context");
    std::cout << "Renderer: " << glGetString(GL_RENDERER) << '\n';
    std::cout << "OpenGL: " << glGetString(GL_VERSION) << '\n';
    GLuint texture=0; glGenTextures(1,&texture); glBindTexture(GL_TEXTURE_2D,texture);
    glPixelStorei(GL_PACK_ALIGNMENT,1);
    glPixelStorei(GL_PACK_ROW_LENGTH,0);
    glPixelStorei(GL_PACK_SKIP_PIXELS,0);
    glPixelStorei(GL_PACK_SKIP_ROWS,0);

    // Demonstrate the original defect without reading beyond the input buffer.
    auto original=pixels(1254,4,3);
    auto padded=original; padded.resize(3764U*4U,0xCC);
    set_state({4,0,0,0});
    glTexImage2D(GL_TEXTURE_2D,0,GL_RGB8,1254,4,0,GL_RGB,GL_UNSIGNED_BYTE,padded.data());
    std::vector<unsigned char> actual(original.size());
    glGetTexImage(GL_TEXTURE_2D,0,GL_RGB,GL_UNSIGNED_BYTE,actual.data());
    require(actual!=original, "Unprotected control did not expose the expected row mismatch");
    require(glGetError()==GL_NO_ERROR, "Control GL operation failed");

    // Save/restore checks are independent from the upload-format matrix.
    for (int alignment : {1,2,4,8}) {
        const std::array<GLint,4> incoming={alignment,19,3,2};
        set_state(incoming);
        {
            const JkgmScopedPixelUnpack guard;
            require(state()==std::array<GLint,4>{1,0,0,0}, "Unpack state not normalized");
        }
        require(state()==incoming, "Caller unpack state not restored");
        early_return();
        require(state()==incoming, "Early-return state restoration failed");
    }
    int cases=0;
    for (GLenum format : {GL_RGB,GL_RGBA,GL_BGR,GL_BGRA}) {
        const int width=1254, height=4;
        const int channels=(format==GL_RGBA || format==GL_BGRA)?4:3;
        const auto expected=pixels(width,height,channels);
        // Reserve enough bytes for a deliberately broken unpack implementation;
        // the negative control must show a mismatch, not read past an allocation.
        auto input=expected;
        input.resize(static_cast<std::size_t>((width+11)*8*(height+3)),0xCC);
        std::vector<unsigned char> output(expected.size());
        const std::array<GLint,4> incoming={8,width+11,3,2};
        set_state(incoming);
        jkgm_upload_texture_2d(channels==4?GL_RGBA8:GL_RGB8,
            width,height,format,input.data());
        require(state()==incoming, "Production upload failed to restore unpack state");
        GLint pack_alignment=0; glGetIntegerv(GL_PACK_ALIGNMENT,&pack_alignment);
        require(pack_alignment==1, "Unrelated pack state changed");
        glGetTexImage(GL_TEXTURE_2D,0,format,GL_UNSIGNED_BYTE,output.data());
        require(glGetError()==GL_NO_ERROR, "Upload/readback GL error");
        require(expected==output, "Production upload changed decoded channel bytes");
        ++cases;
    }
    glDeleteTextures(1,&texture);
    eglMakeCurrent(display,EGL_NO_SURFACE,EGL_NO_SURFACE,EGL_NO_CONTEXT);
    eglDestroyContext(display,context); eglDestroySurface(display,surface); eglTerminate(display);
    std::cout << "PASS: " << cases << " production byte-readback cases, four restoration states, and unprotected negative control\n";
}
