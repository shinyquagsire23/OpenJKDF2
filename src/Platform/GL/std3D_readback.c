#include "Platform/GL/std3D_readback.h"
#include "SDL2_helper.h"
#include <stdint.h>

int std3D_ReadbackSize(int width, int height, size_t* bytes)
{
    if (!bytes) return 0;
    *bytes = 0;
    if (width <= 0 || height <= 0 || (size_t)width > SIZE_MAX / 3 / (size_t)height) return 0;
    *bytes = (size_t)width * (size_t)height * 3;
    return 1;
}

int std3D_ReadbackRgb(unsigned int framebuffer, int width, int height,
    unsigned char* pixels, size_t capacity, int rejectPriorError,
    unsigned int* priorError, unsigned int* captureError)
{
    size_t bytes;
    if (priorError) *priorError = GL_NO_ERROR;
    if (captureError) *captureError = GL_NO_ERROR;
    if (!pixels || !std3D_ReadbackSize(width, height, &bytes) || capacity < bytes) return 0;

    GLenum prior = glGetError();
    if (priorError) *priorError = prior;
    if (prior != GL_NO_ERROR) {
        if (rejectPriorError) return 0;
        /* Keep legacy screenshots usable after unrelated GL errors. Bound the
         * drain so a persistently lost context cannot stall the render thread. */
        for (unsigned int i = 0; i < 16 && glGetError() != GL_NO_ERROR; ++i) { }
    }

    GLint readFbo, readBuffer, packBuffer, alignment, rowLength, skipRows, skipPixels;
    glGetIntegerv(GL_READ_FRAMEBUFFER_BINDING, &readFbo);
    glGetIntegerv(GL_READ_BUFFER, &readBuffer);
    glGetIntegerv(GL_PIXEL_PACK_BUFFER_BINDING, &packBuffer);
    glGetIntegerv(GL_PACK_ALIGNMENT, &alignment);
    glGetIntegerv(GL_PACK_ROW_LENGTH, &rowLength);
    glGetIntegerv(GL_PACK_SKIP_ROWS, &skipRows);
    glGetIntegerv(GL_PACK_SKIP_PIXELS, &skipPixels);
    GLenum error = glGetError();
    if (error != GL_NO_ERROR) {
        if (captureError) *captureError = error;
        return 0;
    }

    glBindFramebuffer(GL_READ_FRAMEBUFFER, framebuffer);
    error = glGetError();
    if (error != GL_NO_ERROR) {
        glBindFramebuffer(GL_READ_FRAMEBUFFER, readFbo);
        if (captureError) *captureError = error;
        return 0;
    }
    /* Read-buffer selection belongs to the framebuffer, not the context. */
    GLint sourceReadBuffer;
    glGetIntegerv(GL_READ_BUFFER, &sourceReadBuffer);
    error = glGetError();
    if (error == GL_NO_ERROR) {
        glReadBuffer(framebuffer ? GL_COLOR_ATTACHMENT0 : GL_BACK);
        glBindBuffer(GL_PIXEL_PACK_BUFFER, 0);
        glPixelStorei(GL_PACK_ALIGNMENT, 1);
        glPixelStorei(GL_PACK_ROW_LENGTH, 0);
        glPixelStorei(GL_PACK_SKIP_ROWS, 0);
        glPixelStorei(GL_PACK_SKIP_PIXELS, 0);
        error = glGetError();
        if (error == GL_NO_ERROR) {
            glReadPixels(0, 0, width, height, GL_RGB, GL_UNSIGNED_BYTE, pixels);
            error = glGetError();
        }
        glPixelStorei(GL_PACK_ALIGNMENT, alignment);
        glPixelStorei(GL_PACK_ROW_LENGTH, rowLength);
        glPixelStorei(GL_PACK_SKIP_ROWS, skipRows);
        glPixelStorei(GL_PACK_SKIP_PIXELS, skipPixels);
        glBindBuffer(GL_PIXEL_PACK_BUFFER, packBuffer);
        glReadBuffer(sourceReadBuffer);
    }
    glBindFramebuffer(GL_READ_FRAMEBUFFER, readFbo);
    glReadBuffer(readBuffer);
    GLenum restoreError = glGetError();
    if (error == GL_NO_ERROR) error = restoreError;
    if (captureError) *captureError = error;
    return error == GL_NO_ERROR;
}
