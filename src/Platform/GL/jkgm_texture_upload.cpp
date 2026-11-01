// The host test uses desktop GL declarations without initializing SDL. The
// production build retains the platform's normal GL/GLES declarations.
#ifdef OPENJKDF2_GL_HOST_TEST
#include <GL/gl.h>
#elif defined(SDL2_RENDER) && defined(TARGET_CAN_JKGM)
#include "SDL2_helper.h"
#endif

#if defined(OPENJKDF2_GL_HOST_TEST) || (defined(SDL2_RENDER) && defined(TARGET_CAN_JKGM))
#include "jkgm_texture_upload.hpp"
#include "jkgm_pixel_unpack.hpp"

void jkgm_upload_texture_2d(GLint internal_format, GLsizei width, GLsizei height,
                           GLenum format, const void* pixels)
{
    const JkgmScopedPixelUnpack pixel_unpack;
    glTexImage2D(GL_TEXTURE_2D, 0, internal_format, width, height, 0,
                 format, GL_UNSIGNED_BYTE, pixels);
}
#endif
